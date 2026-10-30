#include "ProductionBridge.h"
#include <ctime>
#include <cstring>
#include <limits>
namespace titan_runtime {
struct ProductionBridge::State final {
 const titan_inventory::Surface surface;
 const titan_native::Binding binding;
 void* const readerContext;void* const listener;
 const std::shared_ptr<const RuntimePrerequisites> prerequisites;
 const std::shared_ptr<const void> nativeLifetime;
 const BridgeChecks checks;void* const checkContext;
 const std::shared_ptr<titan_reset::FailureReset> reset;
 ProductionSnapshots snapshots;
 titan_surface::ReaderThreadIdentity readerThread;
 std::atomic<bool> failed{false},nativeRetired{false};
 std::mutex endpointMutex;
 std::weak_ptr<titan_surface::DispatchEndpoint> endpoint;
 titan_native::ProductionSink* sink=nullptr;
 bool coreBound=false,pendingTerminal=false;
 OriginalNotification* original=nullptr;
 titan_native::PhysicalPhase phase=titan_native::PhysicalPhase::Down;
 State(titan_inventory::Surface s,titan_native::Binding b,void* rc,void* l,
  std::shared_ptr<const RuntimePrerequisites> p,std::shared_ptr<const void> lifetime,
  BridgeChecks c,void* ctx,std::shared_ptr<titan_reset::FailureReset> r)
  :surface(std::move(s)),binding(b),readerContext(rc),listener(l),prerequisites(std::move(p)),
   nativeLifetime(std::move(lifetime)),checks(c),checkContext(ctx),reset(std::move(r)),
   snapshots(binding,nativeLifetime) {}
 bool outside()const noexcept{return readerThread.isOwner()&&!checks.readerLocked(checkContext)&&!nativeRetired.load();}
 bool inventory(bool terminal)const noexcept{
  return !nativeRetired.load()&&(terminal||!failed.load())&&checks.inventoryValid(checkContext,surface,terminal);
 }
 std::shared_ptr<titan_surface::DispatchEndpoint> core()noexcept{std::lock_guard lock(endpointMutex);return endpoint.lock();}
 void fail(bool nativeFailure=false)noexcept{
  failed.store(true);snapshots.invalidate();
  if(auto e=core())e->core().invalidateReader();
  // request() only latches/wakes. Native reset delivery belongs to Reader drain.
  if(nativeFailure&&!nativeRetired.load()&&reset&&sink&&sink->active())reset->request();
 }
 static bool capture(void* p,const titan_native::Binding& b,titan_surface::Action a,int64_t when,
  const titan_native::DisplaySnapshot* retained,titan_native::DisplaySnapshot& out)noexcept{
  auto& s=*(State*)p;const bool terminal=a==titan_surface::Action::Up||a==titan_surface::Action::Cancel;
  if(!s.outside()||!s.inventory(terminal))return false;
  int64_t now;if(!ProductionBridge::monotonicNow(now))return false;
  s.pendingTerminal=terminal;return s.snapshots.capture(b,a,when,retained,now,out);
 }
 static bool validate(void* p,const titan_native::Binding& b,const titan_native::DisplaySnapshot& view,
  titan_surface::Action a,int64_t when)noexcept{
  auto& s=*(State*)p;const bool terminal=a==titan_surface::Action::Up||a==titan_surface::Action::Cancel;
  int64_t now;return s.outside()&&s.inventory(terminal)&&ProductionBridge::monotonicNow(now)&&s.snapshots.validate(b,view,a,when,now);
 }
 static bool now(void* p,int64_t& value)noexcept{auto& s=*(State*)p;return s.outside()&&ProductionBridge::monotonicNow(value);}
 static bool nextId(void* p,int32_t& id)noexcept{
  auto& s=*(State*)p;
  if(!s.outside()||!s.inventory(s.pendingTerminal)||!s.prerequisites->hooks->context().getNextId)return false;
  id=s.prerequisites->hooks->context().getNextId(s.readerContext);return true;
 }
 static void failure(void* p,titan_native::Failure)noexcept{((State*)p)->fail(true);}
 static bool physical(void* p,const titan_native::Binding& b,void* listener,const void* original,
  titan_native::PhysicalPhase phase)noexcept{
  auto& s=*(State*)p;
  return s.outside()&&s.inventory(true)&&b==s.binding&&listener==s.listener&&s.original&&
   !s.original->forwarded()&&s.phase==phase&&s.original->reader()==s.binding.reader&&
   s.original->listener()==listener&&s.original->variant()==original;
 }
 static void forward(void* p,void* listener,const void* original)noexcept{
  auto& s=*(State*)p;
  if(!s.readerThread.isOwner()||!s.original||s.original->listener()!=listener||s.original->variant()!=original){s.fail();return;}
  // Never condition original forwarding on feature health after admission.
  s.original->forward();
 }
};
ProductionBridge::ProductionBridge(std::shared_ptr<State> state):state_(std::move(state)){}
std::shared_ptr<ProductionBridge> ProductionBridge::create(titan_inventory::Surface surface,
 titan_native::Binding binding,void* readerContext,void* listener,
 std::shared_ptr<const RuntimePrerequisites> prerequisites,std::shared_ptr<const void> nativeLifetime,
 BridgeChecks checks,void* context,std::shared_ptr<titan_reset::FailureReset> reset){
 if(!prerequisites||!prerequisites->hooks||!prerequisites->originals.modules||!nativeLifetime||
  !readerContext||!listener||!context||!checks.inventoryValid||!checks.readerLocked||
  !binding.reader||!binding.mapper||!binding.deviceOwner||!binding.readerGeneration||!binding.mapperGeneration||
  binding.rawId<=0||binding.logicalDeviceId<=0||surface.mapper!=binding.mapper||surface.owner!=binding.deviceOwner||
  surface.rawId!=binding.rawId||surface.logicalId!=binding.logicalDeviceId||surface.readerGeneration!=binding.readerGeneration||
  surface.mapperGeneration!=binding.mapperGeneration||surface.contextAddressPoint!=prerequisites->metadata.contextVtable||
  surface.mapperAddressPoint!=prerequisites->hooks->context().touchpadVtable||
  !prerequisites->hooks->context().getNextId||!prerequisites->hooks->context().getGlobalMetaState)return {};
 auto state=std::make_shared<State>(std::move(surface),binding,readerContext,listener,std::move(prerequisites),std::move(nativeLifetime),checks,context,std::move(reset));
 auto bridge=std::shared_ptr<ProductionBridge>(new ProductionBridge(state));
 titan_native::ProductionCalls calls{State::capture,State::validate,State::now,State::nextId,State::failure,State::physical,State::forward};
 bridge->sink_=std::make_shared<titan_native::ProductionSink>(state->prerequisites->originals.native,listener,state,binding,calls,state.get());
 state->sink=bridge->sink_.get();return bridge;
}
std::shared_ptr<titan_native::ProductionSink> ProductionBridge::sink()const noexcept{return sink_;}
bool ProductionBridge::bindCore(const std::shared_ptr<titan_surface::DispatchEndpoint>& endpoint)noexcept{
 auto& s=*state_;
 if(!s.readerThread.isOwner()||s.coreBound||!endpoint||!endpoint->core().isReaderThread()||!endpoint->core().usesSink(sink_.get()))return false;
 {std::lock_guard lock(s.endpointMutex);s.endpoint=endpoint;s.coreBound=true;}
 if(s.failed.load())endpoint->core().invalidateReader();return true;
}
bool ProductionBridge::recordLocked(int64_t when,int64_t readTime)noexcept{
 auto& s=*state_;
 if(!s.readerThread.isOwner()||!s.checks.readerLocked(s.checkContext)||!s.inventory(false)){s.fail();return false;}
 const auto viewport=titan_display::readOriginalViewport(s.surface.mapper,s.surface.context,s.readerContext,
  s.surface.mapperAddressPoint,s.prerequisites->originals.policy);
 if(!viewport){s.fail();return false;}
 const int32_t meta=s.prerequisites->hooks->context().getGlobalMetaState(s.readerContext);
 int64_t now;
 if(!monotonicNow(now)||!s.inventory(false)||!s.snapshots.recordLocked(*viewport,meta,when,readTime,now,true,true)){s.fail();return false;}
 return true;
}
void ProductionBridge::drained()noexcept{auto& s=*state_;if(!s.outside()){s.fail();return;}s.snapshots.drained();}
bool ProductionBridge::routePhysical(titan_native::PhysicalPhase phase,OriginalNotification& original,int64_t when)noexcept{
 auto& s=*state_;auto endpoint=s.core();
 if(!s.outside()||!endpoint||s.original||original.forwarded()||original.failed()||original.listener()!=s.listener||original.reader()!=s.binding.reader||!original.variant())return false;
 s.original=&original;s.phase=phase;
 const bool result=sink_->routePhysical(endpoint->core(),phase,original.variant(),when);
 s.original=nullptr;
 if(result&&!original.forwarded()){s.fail();return false;}
 return result;
}
bool ProductionBridge::matchesGenerated(const void* motion,size_t bytes)const noexcept{
 auto& s=*state_;if(!s.outside()||!motion||bytes!=160)return false;
 int32_t action;std::memcpy(&action,(const char*)motion+32,sizeof(action));
 const bool terminal=action==1||action==3;
 return s.inventory(terminal)&&sink_->matchesGeneratedMotion(motion,bytes);
}
void ProductionBridge::invalidate()noexcept{state_->fail();}
void ProductionBridge::retireOwnership()noexcept{auto& s=*state_;s.nativeRetired.store(true);s.snapshots.retireOwnership();s.fail();}
bool ProductionBridge::healthy()const noexcept{return !state_->failed.load()&&!state_->nativeRetired.load()&&sink_->healthy()&&state_->snapshots.healthy();}
bool ProductionBridge::monotonicNow(int64_t& out)noexcept{
 timespec ts{};if(clock_gettime(CLOCK_MONOTONIC,&ts)||ts.tv_sec<0||ts.tv_nsec<0||ts.tv_nsec>=1000000000||
  uint64_t(ts.tv_sec)>uint64_t(INT64_MAX)/1000000000)return false;
 const auto seconds=int64_t(ts.tv_sec)*1000000000;
 if(seconds>INT64_MAX-ts.tv_nsec)return false;out=seconds+ts.tv_nsec;return true;
}
}
