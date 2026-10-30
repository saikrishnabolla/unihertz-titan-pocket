#pragma once
#include "ReaderThreadIdentity.h"
#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
namespace titan_physical {
enum class PhysicalClass { Other, PhysicalTouchscreen, Unavailable };
enum class Membership { Present, ProvenAbsent, Unknown };
struct Motion {int64_t when;int32_t device;uint32_t source;int32_t action;};
struct Calls {
 // Consult a retained COPIED native inventory, including physical/virtual identity
 // and actual touchscreen capability. Never classify from source bits alone.
 // Other includes proven unknown/virtual/non-touchscreen devices. Unavailable
 // means the inventory/ownership/generation cannot currently be trusted.
 PhysicalClass (*classify)(void*,const Motion&) noexcept;
 // Only ProvenAbsent authorizes removal on InputDevicesChanged. This must prove
 // absence from a COMPLETE current logical-device inventory; Unknown keeps hold.
 Membership (*membership)(void*,int32_t logicalDeviceId) noexcept;
};
enum class Route { PassThrough, PhysicalDown, PhysicalEnd };
enum class Failure { None, Unconfigured, WrongThread, NestedNotification, BadTag,
 BadTime, BadAction, MissingDown, Overflow, InventoryUnavailable, BadCompletion, Exhausted };
struct Decision {
 Route route=Route::PassThrough;
 Failure failure=Failure::None;
 bool invalidatePending=false;
 bool requireLift=false;
 uint64_t token=0;
 int64_t when=-1;
 int32_t logicalDeviceId=0;
};
class PhysicalArbitration final {
public:
 PhysicalArbitration(Calls calls,void* context,std::shared_ptr<const void> owner);
 PhysicalArbitration(const PhysicalArbitration&)=delete;
 PhysicalArbitration& operator=(const PhysicalArbitration&)=delete;
 // Trusted final-v2 hook only: original is a complete live CP3 NotifyArgs variant
 // (tag at160). No borrowed pointer escapes this call. Caller is Reader outside
 // its mutex; callbacks consult published copies and acquire no Reader mutex.
 // On Down: route through ProductionSink::routePhysical(Down) BEFORE original.
 // On End: routePhysical(End) forwards original BEFORE releasing the core hold.
 // PassThrough: retain the boundary's exact-once original path. Metadata always
 // invalidates pending batches BEFORE forwarding, even if holds remain.
 // Failure: permanent disable + full-lift requirement; caller must cancel/block
 // generated output before preserving its original forwarding path. No Sink or
 // original listener is called by this class, including on failure.
 Decision begin(const void* original,int64_t boundaryTime) noexcept;
 // Call only after exact original forwarding completed (including fallback if
 // routePhysical returned false). Commits held-device removal after forwarding.
 // No pending Decision can authorize new generated output before this call.
 // orderingSucceeded means requested routePhysical/invalidation completed. A
 // fallback original after routePhysical failure must pass false and disable.
 bool afterOriginal(const Decision&,bool originalForwarded,bool orderingSucceeded) noexcept;
 bool disabled() const noexcept{return disabled_.load();}
 bool requiresLift() const noexcept{return lift_.load();}
 unsigned held() const noexcept{return count_.load();}
private:
 int find(int32_t)const noexcept;
 Decision fail(Failure) noexcept;
 void remove(unsigned) noexcept;
 Calls calls_{};void* const context_;const std::shared_ptr<const void> owner_;
 titan_surface::ReaderThreadIdentity reader_;
 std::array<int32_t,16> ids_{};
 std::atomic<unsigned> count_{0};
 std::atomic<bool> disabled_{false},lift_{false};
 uint64_t sequence_=0,pendingToken_=0;
 uint16_t removeMask_=0;
};
}
