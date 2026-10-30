#include "MapperPipeline.h"
#include "RawPacketHandoff.h"
#include "final-hooks.h"
#include "RuntimePrerequisites.h"
#include "NativeReaderOwner.h"
#include "InventoryRuntime.h"
#include "NativeReaderThread.h"
#include "ProductionBridge.h"
#include "PhysicalArbitration.h"
#include "FailureReset.h"
#include "ReaderNotifyBoundary.h"
#include "TitanReaderLifecycle.h"
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <vector>
#ifdef __ANDROID__
#include <android/log.h>
#endif
void titan_cp3_lifecycle_reader_constructed_v1(void*,void*,void(*)(void*)noexcept)noexcept;
void titan_cp3_lifecycle_reader_retiring_v1(void*)noexcept;
namespace titan_runtime {
namespace {
class Runtime;
struct Generation;
std::atomic<Runtime*> published{nullptr};
thread_local Runtime* locked=nullptr;
struct ReaderScope {Runtime* previous;explicit ReaderScope(Runtime* r):previous(locked){locked=r;}~ReaderScope(){locked=previous;}};
void report(const char* stage)noexcept {
#ifdef __ANDROID__
 __android_log_print(ANDROID_LOG_INFO,"TitanSurfaceRuntime","stage=%s",stage);
#else
 (void)stage;
#endif
}
void reportOnce(unsigned bit,const char* stage)noexcept {
 static std::atomic<uint64_t> seen{0};
 const uint64_t mask=uint64_t{1}<<bit;
 if(!(seen.fetch_or(mask,std::memory_order_relaxed)&mask))report(stage);
}
struct Generation final {
 Runtime* runtime;
 const titan_inventory::Surface surface;
 const titan_native::Binding binding;
 const Target* const target;
 std::atomic<bool> valid{true},retirePending{false},resetRequested{false},retired{false};
 std::shared_ptr<std::atomic<bool>> nativeQuiesced=std::make_shared<std::atomic<bool>>(false);
 std::shared_ptr<titan_reset::FailureReset> reset;
 std::shared_ptr<ProductionBridge> bridge;
 std::unique_ptr<titan_surface::MapperPipeline> pipeline;
 Generation(Runtime* r,titan_inventory::Surface s,titan_native::Binding b,const Target* t)
  :runtime(r),surface(std::move(s)),binding(b),target(t){}
};
class Runtime final {
public:
 const std::shared_ptr<const RuntimePrerequisites> prerequisites;
 const std::shared_ptr<NativeReaderOwner> owner;
 void* const reader;
 titan_inventory::InventoryRuntime inventory;
 std::atomic<bool> failed{false};
 std::atomic<Generation*> current{nullptr};
 std::unique_ptr<Generation> generation;
 std::map<void*,std::unique_ptr<titan_surface::RawPacketHandoff>> handoffs;
 std::atomic<const titan_surface::ReaderThreadIdentity*> dispatchIdentity{nullptr};
 std::atomic<bool> foreignInvalidation{false},nativeRetained{true};
 std::unique_ptr<titan_physical::PhysicalArbitration> physical;
 Runtime(std::shared_ptr<const RuntimePrerequisites> p,std::shared_ptr<NativeReaderOwner> o,void* r)
  :prerequisites(std::move(p)),owner(std::move(o)),reader(r),
   inventory({prerequisites->metadata,prerequisites->hooks->context().touchpadVtable,
    titan_inventory::nativeReaderThread,prerequisites,prerequisites->hooks->context().keyboardVtable}){}
 static int64_t now(){int64_t n=0;ProductionBridge::monotonicNow(n);return n;}
 void invalidate(bool permanent=false)noexcept {
  if(permanent){reportOnce(0,"permanently-disabled");failed.store(true);}
  const auto* identity=dispatchIdentity.load(std::memory_order_acquire);
  if(!identity||!identity->isOwner()) {foreignInvalidation.store(true);if(nativeRetained.load())titan_cp3_reader_wake_v1();return;}
  if(auto* g=current.load(std::memory_order_acquire)) {
   g->valid.store(false);g->retirePending.store(true);if(g->bridge)g->bridge->invalidate();
   if(g->pipeline)g->pipeline->endpoint()->core().invalidateReader();
  }
 }
 static bool readerLocked(void* p)noexcept{return locked==static_cast<Generation*>(p)->runtime;}
 static bool valid(void* p,const titan_inventory::Surface& s,bool terminal)noexcept {
  auto& g=*static_cast<Generation*>(p);auto& r=*g.runtime;
  if(g.retired.load()||!r.nativeRetained.load()||s.mapper!=g.surface.mapper||s.context!=g.surface.context||
     s.mapperGeneration!=g.surface.mapperGeneration||s.readerGeneration!=g.surface.readerGeneration)return false;
  if(terminal)return true;
  return !r.failed.load()&&g.valid.load()&&r.inventory.currentCursorSnapshot(g.target);
 }
 static titan_physical::PhysicalClass classify(void* p,const titan_physical::Motion& motion)noexcept {
  return static_cast<Runtime*>(p)->inventory.classify(motion.device,motion.source);
 }
 static titan_physical::Membership membership(void* p,int32_t logical)noexcept {
  return static_cast<Runtime*>(p)->inventory.membership(logical);
 }
 static void resetLatch(void* p,const titan_reset::Binding&)noexcept {
  auto& g=*static_cast<Generation*>(p);g.resetRequested.store(true);g.runtime->invalidate(true);
  titan_cp3_reader_wake_v1();
 }
 static bool resetTarget(const Generation& g)noexcept {
  const auto current=g.runtime->inventory.targetSnapshot();
  return current&&current->surface.context==g.surface.context&&current->surface.owner==g.surface.owner&&
   current->surface.raw==g.binding.rawId&&current->surface.logical==g.binding.logicalDeviceId&&
   current->surface.descriptor==g.surface.descriptor&&current->readerGeneration==g.binding.readerGeneration;
 }
 static bool resetCapture(void* p,const titan_reset::Binding& b,void* listener,titan_reset::Snapshot& s)noexcept {
  auto& g=*static_cast<Generation*>(p);auto& r=*g.runtime;
  if(locked==&r||!r.owner->isReaderThread()||!r.owner->alive()||g.retired.load()||
     listener!=r.owner->listener()||!g.resetRequested.load()||!resetTarget(g)||b.rawId!=g.binding.rawId||b.logicalDeviceId!=g.binding.logicalDeviceId)return false;
  s.binding=b;s.observedAt=now();if(s.observedAt>INT64_MAX-500000000)return false;s.validUntil=s.observedAt+500000000;
  s.targetMemberVerified=true;s.listenerOwnershipRetained=true;s.originalModuleAbiPinned=true;
  s.permanentFailureLatched=true;s.fullLiftRequired=true;s.aggregateResetScopeAccepted=true;return true;
 }
 static bool resetValidate(void* p,const titan_reset::Binding& b,void* listener,const titan_reset::Snapshot& s,int64_t when)noexcept {
  auto& g=*static_cast<Generation*>(p);auto& r=*g.runtime;
  return locked!=&r&&r.owner->isReaderThread()&&r.owner->alive()&&!g.retired.load()&&
   listener==r.owner->listener()&&g.resetRequested.load()&&resetTarget(g)&&s.binding==b&&s.observedAt<=when&&s.validUntil>=when&&
   s.targetMemberVerified&&s.listenerOwnershipRetained&&s.originalModuleAbiPinned&&s.permanentFailureLatched&&s.fullLiftRequired&&s.aggregateResetScopeAccepted;
 }
 static bool resetNow(void*,int64_t& n)noexcept{return ProductionBridge::monotonicNow(n);}
 static bool resetId(void* p,int32_t& id)noexcept {
  auto& g=*static_cast<Generation*>(p);auto& r=*g.runtime;
  if(locked==&r||!r.owner->isReaderThread()||!r.owner->alive()||g.retired.load())return false;
  id=r.prerequisites->hooks->context().getNextId(r.owner->readerContext());return true;
 }
 bool ensurePhysical() {
  if(physical)return !physical->disabled();
  if(!owner->isReaderThread())return false;
  if(!dispatchIdentity.load())dispatchIdentity.store(new titan_surface::ReaderThreadIdentity,std::memory_order_release);
  if(!current.load())foreignInvalidation.store(false);
  physical=std::make_unique<titan_physical::PhysicalArbitration>(titan_physical::Calls{classify,membership},this,owner->lifetime());
  return true;
 }
 Generation* setup(void* mapper) {
  if(failed.load()||!owner->alive()||!owner->isReaderThread()||locked!=this){reportOnce(1,"setup-owner-rejected");return nullptr;}
  if(auto* g=current.load())return g;
  // Metadata is copied only after the previous completed loop/notify boundary.
  auto surface=inventory.surface(mapper);auto* target=inventory.cursorSnapshot();
  if(!surface){reportOnce(2,"setup-no-surface");return nullptr;}
  if(!target||!inventory.currentCursorSnapshot(target)){reportOnce(3,"setup-no-target");return nullptr;}
  if(!ensurePhysical()||physical->held()){reportOnce(4,"setup-physical-held");return nullptr;}
  auto view=titan_display::readOriginalViewport(mapper,surface->context,owner->readerContext(),surface->mapperAddressPoint,prerequisites->originals.policy);
  if(!view){reportOnce(5,"setup-viewport-rejected");return nullptr;}
  titan_native::Binding b{reader,mapper,surface->owner,surface->readerGeneration,surface->mapperGeneration,surface->rawId,surface->logicalId};
  auto next=std::make_unique<Generation>(this,*surface,b,target);auto* g=next.get();
  titan_reset::Binding resetBinding{b.reader,b.mapper,b.deviceOwner,b.readerGeneration,b.mapperGeneration,b.rawId,b.logicalDeviceId};
  const auto& native=prerequisites->originals.native;
  titan_reset::NativeCalls calls{prerequisites->hooks->reset().construct,native.queueConstruct,
   prerequisites->hooks->reset().notify,native.queueFlush,native.queueDestroy};
  g->reset=std::make_shared<titan_reset::FailureReset>(calls,
   titan_reset::RuntimeCalls{resetLatch,resetCapture,resetValidate,resetNow,resetId},resetBinding,owner->listener(),owner->lifetime(),g);
  if(!g->reset->configured()){reportOnce(6,"setup-reset-rejected");failed.store(true);return nullptr;}
  g->bridge=ProductionBridge::create(*surface,b,owner->readerContext(),owner->listener(),prerequisites,owner->lifetime(),
   BridgeChecks{valid,readerLocked},g,g->reset);
  if(!g->bridge||!g->bridge->healthy()){reportOnce(7,"setup-bridge-rejected");failed.store(true);return nullptr;}
  titan_cp3_probe::Registration reg{mapper,surface->context,surface->owner,surface->contextAddressPoint,surface->mapperAddressPoint,surface->rawId,surface->mapperGeneration,true};
  const titan_surface::Config config{1,1,6,300000000,0,720,0,360};
  g->pipeline=titan_surface::MapperPipeline::create(reg,owner->lifetime(),
   {prerequisites->metadata.identifier,prerequisites->metadata.classes},surface->descriptor,surface->keyboardRawId,config,g->bridge->sink());
  if(!g->pipeline||!g->bridge->bindCore(g->pipeline->endpoint())){reportOnce(8,"setup-pipeline-rejected");failed.store(true);return nullptr;}
  if(!titan_surface::bindDispatchEndpoint(g->pipeline->endpoint())){reportOnce(9,"setup-dispatch-rejected");failed.store(true);return nullptr;}
  if(!owner->attachEndpoint(g->pipeline->endpoint(),g->nativeQuiesced)) {
   // No input can be emitted yet. Retire on the outside-lock boundary.
   g->valid.store(false);g->retirePending.store(true);failed.store(true);
  }
  generation=std::move(next);current.store(g,std::memory_order_release);report("bound");return g;
 }
 bool process(void* mapper,const TitanCp3RawEvent32* raw) {
  if(!raw||!owner->alive()||!nativeRetained.load())return false;
  ReaderScope scope(this);reportOnce(10,"raw-callback");
  auto found=handoffs.find(mapper);auto surface=inventory.surface(mapper);
  if(!surface) {
   reportOnce(11,"raw-no-surface");
   if(found==handoffs.end())return false;
   found->second->unavailable();return found->second->owned();
  }
  if(raw->deviceId!=surface->rawId){invalidate();return false;}
  titan_cp3_probe::Registration reg{mapper,surface->context,surface->owner,surface->contextAddressPoint,surface->mapperAddressPoint,surface->rawId,surface->mapperGeneration,true};
  if(found==handoffs.end()) {
   found=handoffs.emplace(mapper,std::make_unique<titan_surface::RawPacketHandoff>(reg,
    titan_cp3_probe::Callbacks{prerequisites->metadata.identifier,prerequisites->metadata.classes},surface->descriptor)).first;
  }
  auto& handoff=*found->second;const auto observation=handoff.observe(reg,raw,sizeof(*raw));
  auto* g=current.load();
  if(g&&g->surface.mapper==mapper) {
   if(!g->valid.load()||g->retirePending.load()||!inventory.matches(g->surface)||handoff.quarantined()) {
    invalidate();if(!observation.neutralBoundary)handoff.quarantine();
   } else if(observation.consumeOriginalSuppression) {
    if(raw->type==0&&raw->code==0&&!g->bridge->recordLocked(raw->when,raw->readTime)) {invalidate();handoff.quarantine();}
    else {
     g->pipeline->surface(reg,raw,sizeof(*raw));
     if(!g->pipeline->live()){invalidate();handoff.quarantine();}
    }
   }
  }
  // Ownership of this report never changes. A new pipeline starts only AFTER
  // the original full-lift report and is primed with the same empty frame.
  if(observation.neutralBoundary) {
   reportOnce(12,"raw-full-lift");
   if(failed.load()&&!current.load())handoff.releaseOwnership();
   else if(!current.load()) {
    auto* next=setup(mapper);
    if(next) {
     if(!next->bridge->recordLocked(raw->when,raw->readTime)){invalidate();handoff.quarantine();}
     else {
      next->pipeline->surface(reg,raw,sizeof(*raw));
      if(!handoff.takeOwnership()){invalidate();handoff.quarantine();}
     }
    }
   }
  }
  return observation.consumeOriginalSuppression;
 }
 void keyboard(void* mapper,const void* raw) {
  ReaderScope scope(this);auto* g=current.load();if(!g||!g->valid.load()||!owner->alive())return;
  auto context=inventory.keyboardContext(mapper);
  if(!context||context->name!="aw9523-key"||context->rawId!=g->surface.keyboardRawId)return;
  g->pipeline->keyboard(raw,sizeof(TitanCp3RawEvent32));
 }
 void drain(void* candidate) {
  if(candidate!=reader||!owner->alive()||!owner->isReaderThread()||locked==this){reportOnce(14,"drain-owner-rejected");return;}
  reportOnce(15,"reader-drain");
  if(!inventory.readerBoundary(reader)){reportOnce(13,"drain-inventory-rejected");invalidate(true);}
  ensurePhysical();if(foreignInvalidation.exchange(false))invalidate();const auto when=now();auto* g=current.load();
  if(g) {
   g->pipeline->drain(when);
   if(!g->bridge->healthy()){g->valid.store(false);g->retirePending.store(true);}
   auto endpoint=g->pipeline->endpoint();
   if(g->retirePending.load()||endpoint->core().retirementComplete()) {
    titan_surface::retireDispatchEndpoint(endpoint,when);
    if(g->bridge->sink()->active())g->reset->request();
    if(g->reset->requested())g->reset->drain();
    g->bridge->drained();
    if(endpoint->core().retirementComplete()&&(!g->bridge->sink()->active()||g->reset->flushed())) {
     g->nativeQuiesced->store(true);
     g->valid.store(false);g->bridge->retireOwnership();g->retired.store(true);current.store(nullptr);report("retired");
    }
   } else g->bridge->drained();
  }
  owner->maintenance(when);
  if(g&&g->retired.load())generation.reset();
 }
 bool notify(OriginalNotification& original) {
  if(original.reader()!=reader||original.listener()!=owner->listener()||!owner->alive()||!owner->isReaderThread())return true;
  if(locked==this){invalidate(true);return false;}
  if(!inventory.readerBoundary(reader)||!ensurePhysical()){reportOnce(18,"notify-inventory-rejected");invalidate(true);return false;}
  const auto when=now();auto decision=physical->begin(original.variant(),when);
  auto* g=current.load();bool ordered=true;
  if(decision.invalidatePending) {
   invalidate(decision.failure!=titan_physical::Failure::None||physical->disabled());
   if(g)g->pipeline->endpoint()->core().maintain(when);
  }
  if(g&&decision.route!=titan_physical::Route::PassThrough) {
   auto phase=decision.route==titan_physical::Route::PhysicalDown?titan_native::PhysicalPhase::Down:titan_native::PhysicalPhase::End;
   ordered=g->bridge->routePhysical(phase,original,decision.when);
  }
  original.forward();
  if(!physical->afterOriginal(decision,original.forwarded()&&!original.failed(),ordered))invalidate(true);
  return !failed.load();
 }
 bool controller(int32_t logical,uint32_t sources)const {
  // This callback may hold PC mutex on another thread: atomic copies only.
  if(failed.load()||!nativeRetained.load()||(sources&0x100008u)!=0x100008u)return false;
  auto* target=inventory.cursorSnapshot();
  return target&&target->surface.logical==logical&&inventory.currentCursorSnapshot(target);
 }
 bool motion(const void* original)const {
  const auto* identity=dispatchIdentity.load(std::memory_order_acquire);
  if(!nativeRetained.load()||!identity||!identity->isOwner())return false;
  auto* g=current.load(std::memory_order_acquire);return g&&g->bridge->matchesGenerated(original,160);
 }
};
bool notifyHandler(void* p,OriginalNotification& n)noexcept{return static_cast<Runtime*>(p)->notify(n);}
Runtime* get()noexcept{return published.load(std::memory_order_acquire);}
}
}
using namespace titan_runtime;
extern "C" void titan_cp3_reader_constructed_v1(void* reader,void* hub,void(*wake)(void*)noexcept)noexcept {
 titan_cp3_lifecycle_reader_constructed_v1(reader,hub,wake);
 if(!titan_cp3_reader_ready_v1())return;
 if(auto* existing=get()){existing->invalidate(true);return;}
 auto pre=resolveRuntimePrerequisites();if(!pre){report("prerequisites-rejected");return;}
 auto owner=NativeReaderOwner::create(reader,hub,wake,pre);if(!owner){report("owner-rejected");return;}
 auto* runtime=new Runtime(pre,owner,reader);
 if(!runtime->inventory.readerConstructed(reader,hub,{true,true,owner->startsEmpty()})){report("inventory-rejected");return;}
 Runtime* expected=nullptr;if(!published.compare_exchange_strong(expected,runtime)){runtime->invalidate(true);return;}
 if(!readerNotifyBoundary().bind(reader,notifyHandler,runtime,owner->lifetime()))runtime->invalidate(true);
 report("ready");
}
extern "C" void titan_cp3_context_constructed_v1(const void* context)noexcept {
 if(auto* r=get();r&&r->nativeRetained.load()){ReaderScope scope(r);r->invalidate();if(!r->inventory.contextConstructed(context)){reportOnce(16,"context-construction-rejected");r->invalidate(true);}}
}
extern "C" void titan_cp3_context_retiring_v1(const void* context)noexcept {
 if(auto* r=get();r&&r->nativeRetained.load()){ReaderScope scope(r);r->invalidate();if(!r->inventory.contextRetiring(context))r->invalidate(true);}
}
extern "C" void titan_cp3_mapper_constructed_v1(void* mapper,const void* context)noexcept {
 if(auto* r=get();r&&r->nativeRetained.load()){ReaderScope scope(r);if(!r->inventory.mapperConstructed(mapper,context)){reportOnce(17,"mapper-construction-rejected");r->invalidate(true);}}
}
extern "C" void titan_cp3_mapper_retiring_v1(void* mapper)noexcept {
 if(auto* r=get();r&&r->nativeRetained.load()){ReaderScope scope(r);r->invalidate();r->inventory.mapperRetiring(mapper);r->handoffs.erase(mapper);}
}
extern "C" void titan_cp3_mapper_reset_v1(void* mapper,int64_t)noexcept {
 if(auto* r=get();r&&r->nativeRetained.load()){ReaderScope scope(r);r->invalidate();r->inventory.mapperReset(mapper);}
}
extern "C" void titan_cp3_mapper_reconfigured_v1(void* mapper,int64_t)noexcept {
 if(auto* r=get();r&&r->nativeRetained.load()){ReaderScope scope(r);r->invalidate();r->inventory.mapperReconfigured(mapper);}
}
extern "C" bool titan_cp3_mapper_process_v1(void* mapper,const TitanCp3RawEvent32* raw)noexcept {
 if(auto* r=get())return r->process(mapper,raw);return false;
}
extern "C" void titan_cp3_keyboard_process_v1(void* mapper,const void* raw)noexcept {if(auto* r=get())r->keyboard(mapper,raw);}
extern "C" void titan_cp3_reader_drain_v1(void* reader)noexcept {if(auto* r=get())r->drain(reader);}
extern "C" bool titan_cp3_cursor_motion_v1(const void*,const void* motion)noexcept {if(auto* r=get())return r->motion(motion);return false;}
extern "C" bool titan_cp3_cursor_controller_v1(const void*,const void*,int32_t id,uint32_t source)noexcept {if(auto* r=get())return r->controller(id,source);return false;}
extern "C" int32_t titan_cp3_reader_stop_gate_v1(void* reader)noexcept {
 if(auto* r=get();r&&reader==r->reader){auto status=r->owner->readerStopGate(Runtime::now(),std::chrono::milliseconds(2000));if(status==0)r->nativeRetained.store(false);return status;}return 0;
}
extern "C" int32_t titan_cp3_manager_stop_gate_v1(void* manager)noexcept {
 if(auto* r=get()){auto status=r->owner->managerStopGate(manager,Runtime::now(),std::chrono::milliseconds(2000));if(!r->owner->alive())r->nativeRetained.store(false);return status;}return 0;
}
extern "C" void titan_cp3_reader_retiring_v1(void* reader)noexcept {
 if(auto* r=get();r&&reader==r->reader){r->owner->readerRetiring(reader,Runtime::now());r->nativeRetained.store(false);r->invalidate(true);r->inventory.readerRetiring(reader);readerNotifyBoundary().disable();}
 titan_cp3_lifecycle_reader_retiring_v1(reader);
}
extern "C" void titan_cp3_manager_retiring_v1(void* manager)noexcept {
 if(auto* r=get()){r->owner->managerRetiring(manager,Runtime::now());if(!r->owner->alive())r->nativeRetained.store(false);}
}
