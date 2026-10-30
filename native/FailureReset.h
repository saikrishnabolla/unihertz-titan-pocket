#pragma once
#include "ReaderThreadIdentity.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
namespace titan_reset {
struct ResetValue {
    int32_t id;
    int64_t eventTime;
    int32_t logicalDeviceId;
};
static_assert(sizeof(ResetValue)==24 && alignof(ResetValue)==8);
static_assert(offsetof(ResetValue,id)==0 && offsetof(ResetValue,eventTime)==8 &&
              offsetof(ResetValue,logicalDeviceId)==16);
static_assert(std::is_trivially_destructible_v<ResetValue>);
struct Binding {
    const void* reader;
    const void* mapper;
    const void* deviceOwner;
    uint64_t readerGeneration;
    uint64_t mapperGeneration;
    int32_t rawId;
    int32_t logicalDeviceId;
    bool operator==(const Binding&) const = default;
};
struct Snapshot {
    Binding binding{};
    int64_t observedAt=-1, validUntil=-1;
    bool targetMemberVerified=false;
    bool listenerOwnershipRetained=false;
    bool originalModuleAbiPinned=false;
    bool permanentFailureLatched=false;
    bool fullLiftRequired=false;
    // Reset is for the WHOLE logical device, including other keys/raw members.
    bool aggregateResetScopeAccepted=false;
};
struct NativeCalls {
    void (*resetConstruct)(void*,int32_t,int64_t,int32_t);
    void (*queueConstruct)(void*,void*);
    void (*queueNotifyReset)(void*,const void*);
    void (*queueFlush)(void*);
    void (*queueDestroy)(void*);
};
struct RuntimeCalls {
    // Any-thread, noexcept: permanently block this generation, require full lift,
    // then wake Reader after publication. Must not emit native input or take a
    // Reader mutex. It runs at most once per helper, before reset is permitted.
    void (*latchAndWake)(void*,const Binding&) noexcept;
    // Outside Reader mutex: read only published/retained registration state.
    bool (*capture)(void*,const Binding&,void* listener,Snapshot&) noexcept;
    bool (*validate)(void*,const Binding&,void* listener,const Snapshot&,int64_t) noexcept;
    bool (*now)(void*,int64_t&) noexcept;
    // The actual original Reader context getNextId, retaining context ownership.
    bool (*nextId)(void*,int32_t&) noexcept;
};
class FailureReset final {
public:
    FailureReset(NativeCalls native,RuntimeCalls runtime,Binding binding,
                 void* listener,std::shared_ptr<const void> owner,void* context);
    FailureReset(const FailureReset&)=delete;
    FailureReset& operator=(const FailureReset&)=delete;
    bool configured() const {return configured_;}
    // Any thread. Never clears. false means already requested or not configured.
    bool request() noexcept;
    // Reader-only, outside Reader mutex/callbacks. One native attempt maximum.
    // true means this call flushed the original reset through the native queue;
    // it does NOT prove Dispatcher has processed the queued reset yet.
    bool drain() noexcept;
    bool requested() const {return requested_.load();}
    bool attempted() const {return attempted_.load();}
    bool flushed() const {return flushed_.load();}
private:
    bool structural(const Snapshot&,int64_t) const;
    const NativeCalls native_;
    const RuntimeCalls runtime_;
    const Binding binding_;
    void* const listener_;
    const std::shared_ptr<const void> owner_;
    void* const context_;
    titan_surface::ReaderThreadIdentity readerThread_;
    bool configured_=false,running_=false;
    std::atomic<bool> requested_{false},attempted_{false},flushed_{false};
};
}
