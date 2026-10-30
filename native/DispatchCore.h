#pragma once
#include "TitanSurfaceScrollPolicy.h"
#include "TitanSessionRegistry.h"
#include "ReaderThreadIdentity.h"
#include <atomic>
#include <mutex>

namespace titan_surface {
// Implementations invoke the retained CP3 listener synchronously, outside Reader mutex.
struct Sink {
    virtual ~Sink() = default;
    virtual void generated(const Motion&) noexcept = 0;
    virtual void physicalDown() noexcept = 0;
    virtual void physicalEnd() noexcept = 0;
};
class DispatchCore final {
public:
    struct Batch {
        unsigned long long session, fence, stroke, readerRevision;
        std::vector<Motion> motions;
    };
    DispatchCore(Identity identity, int32_t typingRaw, Config config, Sink& sink)
        : typingGuard(typingRaw), policy(std::move(identity), typingGuard, config), sink(sink) {
        policy.setAllowed(0, false);
    }
    // Reader phase only: no listener calls. May run under Reader mutex.
    Batch frame(const Frame& frame) {
        std::lock_guard<std::mutex> lock(stateMutex);
        if (closing.load() || revisionExhausted.load()) return {};
        auto out = synchronize(frame.when);
        append(out.motions, policy.frame(frame));
        for (const auto& motion : out.motions) if (motion.action == Action::Down) ++stroke;
        out.stroke = stroke;
        return out;
    }
    Batch key(Time when, const Key& key) {
        std::lock_guard<std::mutex> lock(stateMutex);
        if (closing.load() || revisionExhausted.load()) return {};
        auto out = synchronize(when);
        if (typingGuard.key(when, key)) append(out.motions, policy.typing(when));
        return out;
    }
    // Reader phase: invalidates even batches already moved to the dispatch queue.
    // No listener is called. drain/maintain delivers cancellation after Reader unlock.
    void invalidateReader() {
        std::lock_guard<std::mutex> lock(stateMutex);
        const auto revision = readerRevision.load();
        if (revision == ~0ULL) revisionExhausted.store(true);
        else readerRevision.store(revision + 1);
    }
    // Dispatch phase only: caller MUST have released Reader mutex.
    void dispatch(const Batch& batch) {
        if (!readerThread.isOwner() || callbackOwner == this) return; // Reader-only callback boundary.
        std::lock_guard<std::mutex> lock(dispatchMutex);
        if (closing.load()) return;
        maintainLocked(batch.motions.empty() ? 0 : batch.motions.front().when);
        if (batch.session != titan_surface_session_snapshot_v1() ||
            batch.fence != fence.load() || batch.readerRevision != readerRevision.load() || revisionExhausted.load()) return;
        for (const auto& motion : batch.motions) {
            if (closing.load() || batch.session != titan_surface_session_snapshot_v1() || batch.fence != fence.load() || batch.readerRevision != readerRevision.load() || revisionExhausted.load()) break;
            if (motion.action == Action::Down) {
                if ((batch.session & 1ULL) == 0 || (batch.fence & 1ULL) || active) continue;
                active = true;
                deliveredStroke = batch.stroke;
                deliveredSession = batch.session;
                deliveredFence = batch.fence;
                deliveredRevision = batch.readerRevision;
            } else if (!active || deliveredStroke != batch.stroke) continue;
            delivered = motion;
            if (motion.action == Action::Up || motion.action == Action::Cancel) active = false;
            invoke(motion);
            maintainLocked(motion.when);
        }
    }
    // JNI Handler may commit state from another thread. It never emits input.
    // Registry publication wakes Reader; its next maintenance performs cancellation.
    bool commit(bool allowed, unsigned long long ticket, Time when) {
        if (callbackOwner == this || closing.load()) return false;
        std::lock_guard<std::mutex> lock(dispatchMutex);
        if (closing.load()) return false;
        const bool accepted = titan_surface_session_commit_v1(allowed, ticket);
        (void)when;
        return accepted;
    }
    // Reader idle wake dispatch phase: no raw frame is needed to deliver CANCEL.
    void maintain(Time when) {
        if (!readerThread.isOwner() || callbackOwner == this) return;
        std::lock_guard<std::mutex> lock(dispatchMutex);
        if (closing.load()) finishRetirement(when);
        else maintainLocked(when);
    }
    // Any thread can block new delivery. Only Reader may finish cancellation.
    // False means pending; the retained owner must wake Reader and retry/finalize
    // on that thread after leaving its mutex and any callback.
    bool retire(Time when) {
        auto last = retirementTime.load();
        while (last < when && !retirementTime.compare_exchange_weak(last, when)) {}
        closing.store(true);
        if (!readerThread.isOwner() || callbackOwner == this) return false;
        std::lock_guard<std::mutex> lock(dispatchMutex);
        finishRetirement(when);
        return true;
    }
    bool isReaderThread() const { return readerThread.isOwner(); }
    bool usesSink(const Sink* value) const { return &sink == value; }
    bool retirementComplete() const { return retired.load(); }
    // Intercept actual physical DOWN at original dispatch boundary, not batch end.
    bool physicalDown(Time when) {
        if (!readerThread.isOwner() || callbackOwner == this) return false; // Reader boundary only.
        std::lock_guard<std::mutex> lock(dispatchMutex);
        if (closing.load()) return false;
        advanceFence(true);
        cancel(when);
        maintainLocked(when);
        auto* previousOwner = callbackOwner;
        callbackOwner = this;
        sink.physicalDown();
        callbackOwner = previousOwner;
        maintainLocked(when);
        return true;
    }
    // Only after ALL touchscreen contacts end (final UP, CANCEL, or device loss).
    // Caller has released Reader mutex; invoke the retained physical end synchronously.
    bool physicalEnd(Time when) {
        if (!readerThread.isOwner() || callbackOwner == this) return false;
        std::lock_guard<std::mutex> lock(dispatchMutex);
        if (closing.load()) return false;
        auto* previousOwner = callbackOwner;
        callbackOwner = this;
        sink.physicalEnd();
        callbackOwner = previousOwner;
        maintainLocked(when);
        advanceFence(false);
        return true;
    }
private:
    // Low bit blocks while physical contacts remain; every transition changes generation.
    // Exhaustion permanently blocks instead of reusing a tag.
    void advanceFence(bool physicalHeld) {
        const auto previous = fence.load();
        const auto generation = previous & ~1ULL;
        fence.store(generation >= ~1ULL - 2ULL ? ~0ULL
                : (generation + 2ULL) | static_cast<unsigned long long>(physicalHeld));
    }
    Batch synchronize(Time when) {
        const auto session = titan_surface_session_snapshot_v1();
        const auto currentFence = fence.load();
        Batch out{session, currentFence, stroke, readerRevision.load(), {}};
        if (session != readerSession || currentFence != readerFence) {
            out.motions = policy.interrupt(when);
            readerSession = session;
            readerFence = currentFence;
        }
        append(out.motions, policy.setAllowed(when, (session & 1ULL) && !(currentFence & 1ULL)));
        return out;
    }
    static void append(std::vector<Motion>& to, const std::vector<Motion>& from) {
        to.insert(to.end(), from.begin(), from.end());
    }
    void invoke(const Motion& motion) {
        auto* previous = callbackOwner;
        callbackOwner = this;
        sink.generated(motion);
        callbackOwner = previous;
    }
    void cancel(Time when) {
        if (!active) return;
        active = false; // A reentrant stage during CANCEL cannot recurse cancellation.
        delivered.action = Action::Cancel;
        delivered.when = std::max(delivered.when, when);
        invoke(delivered);
    }
    void finishRetirement(Time when) {
        if (!retired) {
            cancel(std::max(when, retirementTime.load()));
            retired.store(true);
        }
    }
    void maintainLocked(Time when) {
        if (active && (deliveredSession != titan_surface_session_snapshot_v1() ||
                       deliveredFence != fence.load() || deliveredRevision != readerRevision.load() || revisionExhausted.load())) cancel(when);
    }
    ReaderThreadIdentity readerThread;
    std::atomic<Time> retirementTime{0};
    TypingGuard typingGuard;
    Policy policy;
    Sink& sink;
    std::mutex stateMutex, dispatchMutex;
    std::atomic<unsigned long long> fence{0}, readerRevision{0};
    std::atomic<bool> revisionExhausted{false};
    unsigned long long deliveredRevision = 0;
    unsigned long long readerSession = 0, readerFence = 0, stroke = 0, deliveredStroke = 0;
    std::atomic<bool> closing{false};
    unsigned long long deliveredSession = 0, deliveredFence = 0;
    bool active = false;
    std::atomic<bool> retired{false};
    Motion delivered{};
    inline static thread_local DispatchCore* callbackOwner = nullptr;
};
}
