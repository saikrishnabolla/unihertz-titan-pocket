#pragma once
#include <cstdint>
#include <limits>
#include <mutex>

namespace titan {
// Owner supplies these pointers only after construction and retires before teardown.
// wake must be noexcept, must not reenter this registry or acquire a Reader lock,
// and must keep all callback code and opaque storage alive until retire returns.
using Wake = void (*)(void*) noexcept;
struct ReaderToken {
    void* reader = nullptr;
    std::uint64_t generation = 0;
};

// Exactly one original reader is expected. An ambiguous second registration
// quarantines the current registration until its matching token is retired.
class OpaqueReaderRegistry final {
public:
    ReaderToken registerReader(void* reader, void* hub, Wake wake) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!reader || !hub || !wake || exhausted_) return {};
        if (token_.generation) {
            quarantined_ = true;
            return {};
        }
        return install(reader, hub, wake);
    }
    ReaderToken replace(ReaderToken previous, void* reader, void* hub, Wake wake) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!matches(previous) || !reader || !hub || !wake || exhausted_ || quarantined_)
            return {};
        clear();
        return install(reader, hub, wake);
    }
    bool retire(ReaderToken token) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!matches(token)) return false;
        clear();
        return true;
    }
    // Feed the actual atomic session snapshot AFTER its successful publication.
    // Concurrent publishers may arrive out of order; older snapshots cannot
    // overwrite newer state. The high 63 bits are a non-reusing generation.
    bool publish(std::uint64_t state) {
        std::lock_guard<std::mutex> guard(mutex_);
        const bool exhaustedBlock = state == (std::numeric_limits<std::uint64_t>::max() - 1) &&
                                    session_ == std::numeric_limits<std::uint64_t>::max();
        if ((state >> 1) <= (session_ >> 1) && !exhaustedBlock) return false;
        session_ = state;
        if (token_.generation && !quarantined_) wake_(hub_);
        return true;
    }
    bool wakeRegistered(ReaderToken token) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!matches(token) || quarantined_) return false;
        wake_(hub_);
        return true;
    }
    std::uint64_t snapshot() {
        std::lock_guard<std::mutex> guard(mutex_);
        return session_;
    }
private:
    bool matches(ReaderToken token) const {
        return token.generation && token.generation == token_.generation &&
               token.reader == token_.reader;
    }
    ReaderToken install(void* reader, void* hub, Wake wake) {
        if (lastGeneration_ == std::numeric_limits<std::uint64_t>::max()) {
            exhausted_ = true;
            return {};
        }
        token_ = {reader, ++lastGeneration_};
        hub_ = hub;
        wake_ = wake;
        // Wake after every installation, including an already published gate.
        wake_(hub_);
        return token_;
    }
    void clear() {
        token_ = {};
        hub_ = nullptr;
        wake_ = nullptr;
        quarantined_ = false;
    }
    std::mutex mutex_;
    ReaderToken token_;
    void* hub_ = nullptr;
    Wake wake_ = nullptr;
    std::uint64_t lastGeneration_ = 0;
    std::uint64_t session_ = 0;
    bool quarantined_ = false;
    bool exhausted_ = false;
};
}
