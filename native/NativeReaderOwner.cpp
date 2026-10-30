#include "NativeReaderOwner.h"
#include "NativeOwnerCore.h"
#include "ProcessMapping.h"
#ifdef __ANDROID__
#include <android/log.h>
#endif
#include "RuntimePrerequisites.h"
#include "StopCoordinator.h"
#include <cstdio>
#include <pthread.h>
namespace titan_runtime {
namespace {
void reject(const char* reason,bool tagged=false)noexcept {
#ifdef __ANDROID__
 __android_log_print(ANDROID_LOG_INFO,"TitanSurfaceRuntime","owner-reason=%s tagged=%d",reason,tagged?1:0);
#else
 (void)reason;(void)tagged;
#endif
}
class ProcessMemory final:public titan_native_owner::Memory {
 bool readRetained(uintptr_t address,void* out,size_t size)const noexcept override {
  if(!address||!out||!size||size>UINTPTR_MAX-address)return false;
  std::memcpy(out,reinterpret_cast<const void*>(address),size);return true;
 }
 bool read(uintptr_t address,void* out,size_t size)const noexcept override {
  if(!address||!size||size>UINTPTR_MAX-address)return false;
#if defined(__ANDROID__) && defined(__aarch64__)
  constexpr bool arm64Tagged=true;
#else
  constexpr bool arm64Tagged=false;
#endif
  FILE* file=std::fopen("/proc/self/maps","r");if(!file)return false;char line[1024];bool readable=false;
  while(std::fgets(line,sizeof(line),file)) {
   unsigned long lo{},hi{};char perms[5]{};
   if(std::sscanf(line,"%lx-%lx %4s",&lo,&hi,perms)==3&&titan_native_owner::readableMappingContains(address,size,lo,hi,perms[0]=='r',arm64Tagged)){readable=true;break;}
  }
  std::fclose(file);if(!readable)return false;std::memcpy(out,reinterpret_cast<const void*>(address),size);return true;
 }
};
class Coordinator final:public titan_native_owner::StopOperations {
 titan_surface::StopCoordinator coordinator_;
public:
 explicit Coordinator(std::shared_ptr<titan_surface::DispatchEndpoint> endpoint):coordinator_(std::move(endpoint)){}
 int32_t prepare(int64_t when,std::chrono::milliseconds budget)override{return static_cast<int32_t>(coordinator_.prepare(when,budget));}
 void maintenance(int64_t when)override{coordinator_.maintenance(when);}
 bool safe()const override{return coordinator_.destructionSafe();}
};
struct Lifetime {std::shared_ptr<const RuntimePrerequisites> prerequisites;};
}
struct NativeReaderOwner::State {
 titan_native_owner::Core core;
 std::shared_ptr<const void> lifetime;
 State(titan_native_owner::Layout layout,std::shared_ptr<const RuntimePrerequisites> pre)
  :core(layout,std::make_shared<ProcessMemory>()),lifetime(std::make_shared<const Lifetime>(Lifetime{std::move(pre)})){}
};
std::shared_ptr<NativeReaderOwner> NativeReaderOwner::create(void* reader,void* hub,
    void(*wake)(void*) noexcept,std::shared_ptr<const RuntimePrerequisites> pre)noexcept {
 if(!pre||!pre->hooks||!pre->originals.modules||!pre->metadata.readerContextVtable){reject("prerequisites");return {};}
 [[clang::no_destroy]] static std::mutex singletonMutex;
 [[clang::no_destroy]] static std::weak_ptr<NativeReaderOwner> singleton;
 std::lock_guard singletonLock(singletonMutex);
 if(auto previous=singleton.lock();previous&&!previous->state_->core.retired()){reject("singleton-live");return {};}
 auto base=pre->hooks->base();if(!base||base>UINTPTR_MAX-0x4040d4){reject("module-base");return {};}
 titan_native_owner::Layout layout{base,base+0x3d6b00,reinterpret_cast<uintptr_t>(pre->metadata.readerContextVtable),base+0x3d5f78,base+0x3d89a8,base+0x3d8d08,base+0x4040d4};
 auto state=std::make_shared<State>(layout,std::move(pre));
 if(!state->core.attach(reinterpret_cast<uintptr_t>(reader),reinterpret_cast<uintptr_t>(hub),reinterpret_cast<uintptr_t>(wake))){reject(state->core.attachFailure(),(reinterpret_cast<uintptr_t>(reader)>>56)!=0);return {};}
 auto result=std::shared_ptr<NativeReaderOwner>(new NativeReaderOwner(std::move(state)));singleton=result;return result;
}
void* NativeReaderOwner::reader()const noexcept{return reinterpret_cast<void*>(state_->core.reader());}
void* NativeReaderOwner::listener()const noexcept{return reinterpret_cast<void*>(state_->core.binding().listener);}
void* NativeReaderOwner::readerContext()const noexcept{return reinterpret_cast<void*>(state_->core.binding().readerContext);}
std::shared_ptr<const void> NativeReaderOwner::lifetime()const noexcept{return state_;}
bool NativeReaderOwner::alive()const noexcept{return state_->core.alive();}
bool NativeReaderOwner::startsEmpty()const noexcept{return state_->core.startsEmpty();}
bool NativeReaderOwner::isReaderThread()const noexcept {pthread_t thread=pthread_self();uint64_t id{};static_assert(sizeof(thread)==sizeof(id));std::memcpy(&id,&thread,sizeof(id));return state_->core.isThread(id);}
bool NativeReaderOwner::attachEndpoint(std::shared_ptr<titan_surface::DispatchEndpoint> endpoint,
    std::shared_ptr<const std::atomic<bool>> nativeQuiesced)noexcept {
 return endpoint&&state_->core.attachEndpoint(std::make_shared<titan_native_owner::QuiescedStopOperations>(
     std::make_shared<Coordinator>(std::move(endpoint)),std::move(nativeQuiesced)));
}
int32_t NativeReaderOwner::readerStopGate(int64_t when,std::chrono::milliseconds budget)noexcept{return state_->core.readerStop(when,budget);}
int32_t NativeReaderOwner::managerStopGate(void* manager,int64_t when,std::chrono::milliseconds budget)noexcept{return state_->core.managerStop(reinterpret_cast<uintptr_t>(manager),when,budget);}
void NativeReaderOwner::readerRetiring(void* reader,int64_t when)noexcept{state_->core.readerRetiring(reinterpret_cast<uintptr_t>(reader),when);}
void NativeReaderOwner::managerRetiring(void* manager,int64_t when)noexcept{state_->core.managerRetiring(reinterpret_cast<uintptr_t>(manager),when);}
void NativeReaderOwner::maintenance(int64_t when)noexcept{state_->core.maintenance(when);}
}
