#pragma once
#include "DispatchCore.h"
#include <memory>
namespace titan_surface {
// sink must be non-null. Sink storage and core are retained together for every operation.
// The Reader keeps its own shared_ptr until producers and dispatch work quiesce.
class DispatchEndpoint final {
public:
    DispatchEndpoint(Identity identity, int32_t typingRaw, Config config,
                     std::shared_ptr<Sink> sink)
        : sink_(std::move(sink)), core_(std::move(identity), typingRaw, config, *sink_) {}
    DispatchCore& core() { return core_; }
private:
    std::shared_ptr<Sink> sink_;
    DispatchCore core_;
};
// Bind exactly one fully constructed Reader endpoint; reject replacement until
// matching retirement finishes. Caller must stage before a new Reader binding.
bool bindDispatchEndpoint(std::shared_ptr<DispatchEndpoint> endpoint);
// Request outside Reader mutex. Stops JNI acquisition immediately and retains
// the global owner while retirement is pending. Reader alone cancels and finishes
// retirement outside its mutex/callbacks. False requires an owner-thread retry;
// the pending request wakes Reader and cannot be undone by another bind.
bool retireDispatchEndpoint(const std::shared_ptr<DispatchEndpoint>& endpoint, Time when);
// Canonical Reader idle boundary. Finishes pending cancellation before releasing
// the bound global owner. No callback or ownership release occurs on other threads.
void maintainDispatchEndpoint(const std::shared_ptr<DispatchEndpoint>& endpoint, Time when);
}
extern "C" __attribute__((visibility("default"))) bool titan_surface_dispatch_commit_v1(bool allowed,
        unsigned long long ticket, titan_surface::Time when) noexcept;
