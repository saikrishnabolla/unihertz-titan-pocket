#include "FailureReset.h"
namespace titan_reset {
FailureReset::FailureReset(NativeCalls native,RuntimeCalls runtime,Binding binding,
        void* listener,std::shared_ptr<const void> owner,void* context)
    : native_(native),runtime_(runtime),binding_(binding),listener_(listener),
      owner_(std::move(owner)),context_(context) {
    configured_=native_.resetConstruct && native_.queueConstruct && native_.queueNotifyReset &&
        native_.queueFlush && native_.queueDestroy && runtime_.latchAndWake && runtime_.capture &&
        runtime_.validate && runtime_.now && runtime_.nextId && readerThread_.isOwner() &&
        binding_.reader && binding_.mapper && binding_.deviceOwner && binding_.readerGeneration &&
        binding_.mapperGeneration && binding_.rawId>0 && binding_.logicalDeviceId>0 &&
        listener_ && owner_ && context_;
}
bool FailureReset::request() noexcept {
    if (!configured_) return false;
    bool previous=false;
    if (!requested_.compare_exchange_strong(previous,true)) return false;
    runtime_.latchAndWake(context_,binding_);
    return true;
}
bool FailureReset::structural(const Snapshot& s,int64_t now) const {
    return s.binding==binding_ && now>=0 && s.observedAt>=0 && s.observedAt<=now &&
        s.validUntil>=now && s.targetMemberVerified && s.listenerOwnershipRetained &&
        s.originalModuleAbiPinned && s.permanentFailureLatched && s.fullLiftRequired &&
        s.aggregateResetScopeAccepted;
}
bool FailureReset::drain() noexcept {
    if (!configured_ || !readerThread_.isOwner() || !requested_.load() ||
        attempted_.load() || running_) return false;
    running_=true;
    struct Guard {bool& running;~Guard(){running=false;}} guard{running_};
    Snapshot snapshot;int64_t when;
    if (!runtime_.capture(context_,binding_,listener_,snapshot) ||
        !runtime_.now(context_,when) || !structural(snapshot,when) ||
        !runtime_.validate(context_,binding_,listener_,snapshot,when)) return false;
    int32_t id;
    if (!runtime_.nextId(context_,id) || !runtime_.now(context_,when) ||
        !structural(snapshot,when) ||
        !runtime_.validate(context_,binding_,listener_,snapshot,when)) return false;
    // NotifyDeviceResetArgs is a 24-byte trivial original object. Its original
    // constructor writes only id/eventTime/deviceId. There is no invented D2,
    // sidecar variant construction or sidecar variant destruction.
    alignas(8) std::byte reset[24]{};
    alignas(8) std::byte queue[40];
    attempted_.store(true); // Before entering any original native code.
    native_.resetConstruct(reset,id,when,binding_.logicalDeviceId);
    native_.queueConstruct(queue,listener_);
    native_.queueNotifyReset(queue,reset); // Original copies 24 bytes, writes tag6.
    native_.queueFlush(queue);
    native_.queueDestroy(queue);
    flushed_.store(true);
    return true;
}
}
