#pragma once
#include "RawSurfaceDecoder.h"
#include "DispatchEndpoint.h"
#include <memory>
#include <thread>
#include <pthread.h>

namespace titan_surface {
// The owner retains the real registered mapper/context/owner for each Reader call.
// This adapter discovers no addresses and creates no Android runtime objects.
class MapperPipeline final {
    // A violation closes this pipeline generation, without changing global sessions.
    // Work retains this state and its owning thread identity after pipeline destruction.
    struct ReaderAffinity {
        // The DSO must stay loaded through all pthread-key destructor calls.
        inline static pthread_once_t keyOnce = PTHREAD_ONCE_INIT;
        inline static pthread_key_t key;
        inline static int keyError = 0;
        static void destroyToken(void* value) {
            delete static_cast<std::shared_ptr<const char>*>(value);
        }
        static void createKey() { keyError = pthread_key_create(&key, destroyToken); }
        static std::shared_ptr<const char> threadToken() {
            if (pthread_once(&keyOnce, createKey) != 0 || keyError != 0) return {};
            auto* token = static_cast<std::shared_ptr<const char>*>(pthread_getspecific(key));
            if (!token) {
                token = new std::shared_ptr<const char>(std::make_shared<const char>(0));
                if (pthread_setspecific(key, token) != 0) { delete token; return {}; }
            }
            return *token;
        }
        const std::thread::id owner = std::this_thread::get_id();
        const std::shared_ptr<const char> ownerToken = threadToken();
        std::atomic<bool> failed{false};
        bool isOwner() const {
            return ownerToken && owner == std::this_thread::get_id() && ownerToken == threadToken();
        }
        void reject(DispatchEndpoint& endpoint) {
            if (!failed.exchange(true)) endpoint.core().invalidateReader();
        }
        bool accept(DispatchEndpoint& endpoint) {
            if (!isOwner()) { reject(endpoint); return false; }
            return !failed.load();
        }
        void maintain(const std::shared_ptr<DispatchEndpoint>& endpoint, Time when) {
            // Repeat invalidation on the owner to cover overlap with reject().
            if (failed.load()) endpoint->core().invalidateReader();
            maintainDispatchEndpoint(endpoint, when);
        }
    };
public:
    struct DispatchWork {
        std::shared_ptr<DispatchEndpoint> endpoint;
        std::vector<DispatchCore::Batch> batches;
        std::shared_ptr<ReaderAffinity> affinity;
        // Caller must release Reader mutex first. Safe after MapperPipeline destruction.
        void dispatch(Time when) const {
            if (!endpoint || !affinity) return;
            if (!affinity->isOwner()) { affinity->reject(*endpoint); return; }
            for (const auto& batch : batches) {
                if (affinity->failed.load()) break;
                endpoint->core().dispatch(batch);
            }
            affinity->maintain(endpoint, when);
        }
    };
    // Must run on the owning Reader thread under its mutex with a live registration.
    static std::unique_ptr<MapperPipeline> create(
            titan_cp3_probe::Registration registration,
            std::shared_ptr<const void> owner,
            titan_cp3_probe::Callbacks callbacks, std::string descriptor,
            int32_t typingRaw, Config config, std::shared_ptr<Sink> sink) {
        if (!ReaderAffinity::threadToken()) return {};
        if (!owner || !sink || typingRaw < 0 || typingRaw == registration.rawId ||
            !config.valid() || !titan_cp3_probe::bind(registration, callbacks, descriptor)) return {};
        auto endpoint = std::make_shared<DispatchEndpoint>(
            Identity{registration.rawId, "mtk-pad", true, true}, typingRaw, config, std::move(sink));
        return std::unique_ptr<MapperPipeline>(new MapperPipeline(registration,
            std::move(owner), callbacks, std::move(descriptor), typingRaw, std::move(endpoint)));
    }
    std::shared_ptr<DispatchEndpoint> endpoint() const { return endpoint_; }
    bool live() const { return affinity_->isOwner() && !affinity_->failed.load() && live_; }
    // Reader phase only. Supply the current authoritative registration; never revive a generation.
    void surface(const titan_cp3_probe::Registration& current, const void* bytes, size_t size) {
        if (!affinity_->accept(*endpoint_) || !live_) return;
        auto frame = decoder_.consume(current, bytes, size);
        if (!decoder_.authorized()) {
            live_ = false;
            invalidate(frame ? frame->when : lastTime_);
            return;
        }
        if (frame) {
            lastTime_ = std::max(lastTime_, frame->when);
            if (!frame->valid) invalidate(frame->when);
            else enqueue(endpoint_->core().frame(*frame), frame->when);
        }
    }
    // Separate keyboard hook: no surface packet or SYN_REPORT is needed.
    // rawId comes from the raw notification, never the aggregate logical device id.
    bool keyboard(const void* bytes, size_t size) {
        if (!affinity_->accept(*endpoint_) || !live_) return false;
        auto event = titan_cp3_probe::rawEvent(bytes, size, typingRaw_);
        if (!event || event->type != EV_KEY || event->value < 0 || event->value > 2 ||
            event->when < lastKeyTime_) return false;
        lastKeyTime_ = event->when;
        endpoint_->core().invalidateReader();
        { std::lock_guard<std::mutex> lock(queueMutex_); queue_.clear(); }
        enqueue(endpoint_->core().key(event->when,
            Key{typingRaw_, event->code, event->value != 0, event->value == 2}), event->when);
        return true;
    }
    void reset(Time when) { // Reader phase; full lift is required before rearming.
        if (!affinity_->accept(*endpoint_) || !live_) return;
        const auto frame = decoder_.reset(when);
        invalidate(frame.when);
    }
    void removal(Time when) { // Reader phase; call before registered objects are freed.
        if (!affinity_->accept(*endpoint_) || !live_) return;
        const auto frame = decoder_.removal(when);
        live_ = false;
        invalidate(frame.when);
    }
    // The creating Reader thread owns production and ordered outside-lock dispatch.
    // Explicit boundary: take while/after Reader is locked, dispatch only after unlock.
    DispatchWork takePending() {
        DispatchWork work{endpoint_, {}, affinity_};
        if (!affinity_->accept(*endpoint_)) {
            if (affinity_->isOwner()) {
                std::lock_guard<std::mutex> lock(queueMutex_);
                queue_.clear();
            }
            return work;
        }
        std::lock_guard<std::mutex> lock(queueMutex_);
        work.batches.swap(queue_);
        return work;
    }
    void drain(Time when) { takePending().dispatch(when); } // Outside Reader mutex only.
private:
    MapperPipeline(titan_cp3_probe::Registration registration, std::shared_ptr<const void> owner,
            titan_cp3_probe::Callbacks callbacks, std::string descriptor, int32_t typingRaw,
            std::shared_ptr<DispatchEndpoint> endpoint)
        : owner_(std::move(owner)), endpoint_(std::move(endpoint)),
          decoder_(registration, callbacks, std::move(descriptor)), typingRaw_(typingRaw) {}
    void invalidate(Time when) {
        lastTime_ = std::max(lastTime_, when);
        endpoint_->core().invalidateReader();
        auto batch = endpoint_->core().frame({lastTime_, {}, false});
        std::lock_guard<std::mutex> lock(queueMutex_);
        queue_.clear();
        queue_.push_back(std::move(batch));
    }
    void enqueue(DispatchCore::Batch batch, Time when) {
        if (batch.motions.empty()) return;
        bool overflow = false;
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            overflow = queue_.size() >= 256;
            if (!overflow) queue_.push_back(std::move(batch));
        }
        if (overflow) { decoder_.reset(when); invalidate(when); }
    }
    // No destructor callback: owner must call removal under Reader lock and drain after
    // unlocking, then retire the endpoint using the existing endpoint lifecycle API.
    std::shared_ptr<ReaderAffinity> affinity_ = std::make_shared<ReaderAffinity>();
    std::shared_ptr<const void> owner_;
    std::shared_ptr<DispatchEndpoint> endpoint_;
    RawSurfaceDecoder decoder_;
    int32_t typingRaw_;
    bool live_ = true;
    Time lastTime_ = 0, lastKeyTime_ = 0;
    std::mutex queueMutex_;
    std::vector<DispatchCore::Batch> queue_;
};
}
