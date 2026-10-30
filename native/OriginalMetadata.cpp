#include "NativeMetadata.h"
#include <atomic>
#include <dlfcn.h>
namespace titan_runtime {
namespace {
std::atomic<NativeClassesGetter> nativeClasses{nullptr};
std::atomic<IdentifierGetter> nativeIdentifier{nullptr};
uint32_t classesCallback(const void* hub,int32_t raw) {
 auto getter=nativeClasses.load();return getter?extractDeviceClasses(getter,hub,raw):0;
}
android::InputDeviceIdentifier identifierCallback(const void*hub,int32_t raw) {
 auto getter=nativeIdentifier.load();return getter?getter(hub,raw):android::InputDeviceIdentifier{};
}
}
// Call during sidecar activation before context discovery. Do not infer a base
// from a device/context pointer. The original exported symbol anchors the image.
std::optional<OriginalTypes> resolveOriginalMetadata() {
 void* classes=dlsym(RTLD_DEFAULT,"_ZNK7android8EventHub16getDeviceClassesEi");
 Dl_info info{};if(!classes || !dladdr(classes,&info) || !info.dli_fbase)return {};
 auto base=reinterpret_cast<uintptr_t>(info.dli_fbase);
 if(reinterpret_cast<uintptr_t>(classes)!=base+0x1d7e10)return {};
 void* identifier=dlsym(RTLD_DEFAULT,"_ZNK7android8EventHub19getDeviceIdentifierEi");
 void* cv=dlsym(RTLD_DEFAULT,"_ZTVN7android18InputDeviceContextE");
 void* rv=dlsym(RTLD_DEFAULT,"_ZTVN7android11InputReader11ContextImplE");
 if(reinterpret_cast<uintptr_t>(identifier)!=base+0x1d7c34 || reinterpret_cast<uintptr_t>(cv)!=base+0x3d62a0 || reinterpret_cast<uintptr_t>(rv)!=base+0x3d6c68)return {};
 const struct {uintptr_t offset;uint32_t word;} words[]={
  {0x1d7e2c,0xaa0803f3},{0x1d7e9c,0xb900026a},
  {0x201a88,0xa9000408},{0x201a90,0xf9000a80},{0x201aa0,0xb9002295},
  {0x201aa4,0xf9000e80},{0x201aac,0xb9002688},{0x20a898,0xa900212a}};
 for(const auto& w:words)if(field<uint32_t>(reinterpret_cast<void*>(base+w.offset),0)!=w.word)return {};
 auto getter=reinterpret_cast<NativeClassesGetter>(classes);
 NativeClassesGetter previous=nullptr;
 if(!nativeClasses.compare_exchange_strong(previous,getter) && previous!=getter)return {};
 auto idGetter=reinterpret_cast<IdentifierGetter>(identifier);IdentifierGetter prior=nullptr;
 if(!nativeIdentifier.compare_exchange_strong(prior,idGetter) && prior!=idGetter)return {};
 return OriginalTypes{reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(cv)+16),reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(rv)+16),identifierCallback,classesCallback};
}
}
