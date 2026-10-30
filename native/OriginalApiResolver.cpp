#include "OriginalApiResolver.h"
#include "ResolverCore.h"
#include <dlfcn.h>
#include <link.h>
#include <vector>
namespace titan_resolver {
namespace {
struct Modules {
    std::vector<void*> handles;
    ~Modules(){for(auto h:handles)dlclose(h);}
};
struct Segment {uintptr_t base,start,end;unsigned permissions;};
class LoadedProbe final:public Probe {
public:
    std::vector<Segment> segments;
    uintptr_t symbol(const char* name) const noexcept override {
        return reinterpret_cast<uintptr_t>(dlsym(RTLD_DEFAULT,name));
    }
    uintptr_t imageBase(uintptr_t value) const noexcept override {
        Dl_info info{};return dladdr(reinterpret_cast<void*>(value),&info)?reinterpret_cast<uintptr_t>(info.dli_fbase):0;
    }
    bool range(uintptr_t base,uintptr_t address,size_t size,unsigned permissions) const noexcept override {
        if(size>UINTPTR_MAX-address)return false;
        for(const auto& s:segments)if(s.base==base&&address>=s.start&&address+size<=s.end&&
            (s.permissions&permissions)==permissions)return true;
        return false;
    }
    bool read(uintptr_t address,void* out,size_t size) const noexcept override {
        for(const auto& s:segments)if(range(s.base,address,size,Read)) {
            std::memcpy(out,reinterpret_cast<const void*>(address),size);return true;
        }
        return false;
    }
};
}
std::optional<ResolvedApis> resolveOriginalApis() noexcept {
    auto retained=std::make_shared<Modules>();LoadedProbe probe;
    // Retain existing images; never load a new candidate from disk.
    for(unsigned image=0;image<3;++image) {
        const SymbolPin* anchor=nullptr;
        for(const auto& s:symbols)if(s.image==image){anchor=&s;break;}
        auto v=probe.symbol(anchor->name);Dl_info info{};
        if(!v||!dladdr(reinterpret_cast<void*>(v),&info)||!info.dli_fname||!info.dli_fbase)return {};
        void* handle=dlopen(info.dli_fname,RTLD_NOW|RTLD_NOLOAD);
        if(!handle)return {};
        if(reinterpret_cast<uintptr_t>(dlsym(handle,anchor->name))!=v){dlclose(handle);return {};}
        retained->handles.push_back(handle);
    }
    dl_iterate_phdr([](dl_phdr_info* info,size_t,void* opaque) {
        auto& p=*static_cast<LoadedProbe*>(opaque);
        for(size_t i=0;i<info->dlpi_phnum;++i) {
            const auto& h=info->dlpi_phdr[i];if(h.p_type!=PT_LOAD)continue;
            auto start=add(info->dlpi_addr,h.p_vaddr);
            if(!start||h.p_memsz>UINTPTR_MAX-*start)continue;
            unsigned permissions=(h.p_flags&PF_R?Read:0)|(h.p_flags&PF_X?Execute:0);
            p.segments.push_back({info->dlpi_addr,*start,*start+h.p_memsz,permissions});
        }
        return 0;
    },&probe);
    auto a=resolve(probe);if(!a)return {};
    titan_native::NativeCalls n{
        reinterpret_cast<titan_native::MotionConstructor>(a->exported[motionConstruct]),
        reinterpret_cast<void(*)(void*)>(a->motionDestroy),
        reinterpret_cast<void(*)(void*,void*)>(a->exported[queueConstruct]),
        reinterpret_cast<void(*)(void*,const void*)>(a->exported[queueNotifyMotion]),
        reinterpret_cast<void(*)(void*)>(a->exported[queueFlush]),
        reinterpret_cast<void(*)(void*)>(a->queueDestroy),
        reinterpret_cast<android::status_t(*)(android::PointerCoords*,int32_t,float)>(a->exported[setAxisValue])};
    titan_display::PolicyCalls p{
        reinterpret_cast<titan_display::GetPolicy>(a->exported[getPolicy]),
        reinterpret_cast<titan_display::GetViewport>(a->exported[getViewport]),
        reinterpret_cast<const void*>(a->readerAddressPoint),
        reinterpret_cast<const void*>(a->policyAddressPoint)};
    return ResolvedApis{n,p,std::move(retained)};
}
}
