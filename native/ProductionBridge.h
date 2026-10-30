#pragma once
#include "RuntimePrerequisites.h"
#include "InventoryRuntime.h"
#include "ProductionSnapshots.h"
#include "ReaderNotifyBoundary.h"
#include "DispatchEndpoint.h"
#include "FailureReset.h"
namespace titan_runtime {
struct BridgeChecks {
 // Retained copied registration/inventory only. terminal=true permits retained
 // terminal ownership after new-input invalidation. Never query original getters.
 bool (*inventoryValid)(void*,const titan_inventory::Surface&,bool terminal) noexcept;
 // The runtime's original-Reader-lock scope proof; no mutex acquisition here.
 bool (*readerLocked)(void*) noexcept;
};
class ProductionBridge final {
public:
 // nativeLifetime must retain the registered native objects, checkContext and
 // every BridgeChecks dependency through all Sink/PC calls. It must not own this
 // bridge; the Sink retains callback State and State holds only a weak endpoint.
 static std::shared_ptr<ProductionBridge> create(titan_inventory::Surface,
  titan_native::Binding,void* readerContext,void* listener,
  std::shared_ptr<const RuntimePrerequisites>,std::shared_ptr<const void> nativeLifetime,
  BridgeChecks,void* checkContext,std::shared_ptr<titan_reset::FailureReset> reset={});
 std::shared_ptr<titan_native::ProductionSink> sink()const noexcept;
 // After MapperPipeline creates its endpoint; rejects replacement/foreign Sink.
 bool bindCore(const std::shared_ptr<titan_surface::DispatchEndpoint>&) noexcept;
 // Original Reader lock only: calls original viewport and global-meta getters,
 // freezes their values, and records monotonic time. No Sink callback occurs.
 bool recordLocked(int64_t eventTime,int64_t readTime) noexcept;
 void drained() noexcept;
 // After physical arbitration authorizes phase. Exact borrowed notification scope
 // only; a false result leaves OriginalNotification's fallback path intact.
 bool routePhysical(titan_native::PhysicalPhase,OriginalNotification&,int64_t when) noexcept;
 // Target-only PC copy hook; handles synchronous initial Down and terminal
 // matching without requiring sink.active() on initial Down.
 bool matchesGenerated(const void* nativeMotion,size_t bytes)const noexcept;
 void invalidate() noexcept;
 void retireOwnership() noexcept;
 bool healthy()const noexcept;
 static bool monotonicNow(int64_t&) noexcept;
private:
 struct State;
 explicit ProductionBridge(std::shared_ptr<State>);
 std::shared_ptr<State> state_;
 std::shared_ptr<titan_native::ProductionSink> sink_;
};
}
