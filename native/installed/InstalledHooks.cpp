#include "InstalledHooks.h"
#include "AuthCore.h"
#include <cstdio>
#include <dlfcn.h>
#include <link.h>
#include <vector>
namespace titan_installed {
namespace {
struct Module {void* handle{};~Module(){if(handle)dlclose(handle);}};
struct Segment {uintptr_t base,start,end;unsigned permissions;};
class LoadedProbe final:public Probe {
public:
    std::vector<Segment> segments,mappings;
    uintptr_t symbol(const char* name)const noexcept override{return reinterpret_cast<uintptr_t>(dlsym(RTLD_DEFAULT,name));}
    uintptr_t imageBase(uintptr_t address)const noexcept override {
        Dl_info info{};return dladdr(reinterpret_cast<void*>(address),&info)?reinterpret_cast<uintptr_t>(info.dli_fbase):0;
    }
    bool range(uintptr_t base,uintptr_t address,size_t size,unsigned permissions)const noexcept override {
        if(size>UINTPTR_MAX-address)return false;
        unsigned required=permissions&(Read|Write|Execute);bool inModule=false;
        for(const auto& s:segments)if(s.base==base&&s.start<=address&&address+size<=s.end&&
            (s.permissions&required)==required){inModule=true;break;}
        if(!inModule)return false;
        for(const auto& m:mappings)if(m.start<=address&&address+size<=m.end&&
            (m.permissions&required)==required&&(!(permissions&NoWrite)||!(m.permissions&Write)))return true;
        return false;
    }
    bool read(uintptr_t address,void* out,size_t size)const noexcept override {
        for(const auto& s:segments)if(range(s.base,address,size,Read)) {
            std::memcpy(out,reinterpret_cast<const void*>(address),size);return true;
        }
        return false;
    }
    bool loadMappings() {
        FILE* f=std::fopen("/proc/self/maps","r");if(!f)return false;
        char line[1024];while(std::fgets(line,sizeof(line),f)) {
            unsigned long start{},end{};char p[5]{};
            if(std::sscanf(line,"%lx-%lx %4s",&start,&end,p)!=3||start>=end)continue;
            unsigned flags=(p[0]=='r'?Read:0)|(p[1]=='w'?Write:0)|(p[2]=='x'?Execute:0);
            mappings.push_back({0,start,end,flags});
        }
        bool success=!std::ferror(f)&&!mappings.empty();std::fclose(f);return success;
    }
};
}
std::shared_ptr<const InstalledHooks> resolveInstalledHooks() noexcept {
    LoadedProbe probe;auto anchor=probe.symbol(symbols[0].name);Dl_info info{};
    if(!anchor||!dladdr(reinterpret_cast<void*>(anchor),&info)||!info.dli_fbase||!info.dli_fname)return {};
    auto module=std::make_shared<Module>();module->handle=dlopen(info.dli_fname,RTLD_NOW|RTLD_NOLOAD);
    if(!module->handle||reinterpret_cast<uintptr_t>(dlsym(module->handle,symbols[0].name))!=anchor)return {};
    dl_iterate_phdr([](dl_phdr_info* info,size_t,void* opaque) {
        auto& p=*static_cast<LoadedProbe*>(opaque);
        for(size_t i=0;i<info->dlpi_phnum;++i) {
            const auto& h=info->dlpi_phdr[i];if(h.p_type!=PT_LOAD)continue;
            auto start=checkedAdd(info->dlpi_addr,h.p_vaddr);
            if(!start||h.p_memsz>UINTPTR_MAX-*start)continue;
            unsigned flags=(h.p_flags&PF_R?Read:0)|(h.p_flags&PF_W?Write:0)|(h.p_flags&PF_X?Execute:0);
            p.segments.push_back({info->dlpi_addr,*start,*start+h.p_memsz,flags});
        }
        return 0;
    },&probe);
    if(!probe.loadMappings())return {};
    auto base=validate(probe);if(!base)return {};
    ContextCalls c{reinterpret_cast<int32_t(*)(const void*)>(*base+0x206758),
        reinterpret_cast<int32_t(*)(void*)>(*base+0x20a8f8),reinterpret_cast<const void*>(*base+0x3d7eb0),reinterpret_cast<const void*>(*base+0x3d7540)};
    ResetCalls r{reinterpret_cast<void(*)(void*,int32_t,int64_t,int32_t)>(*base+0x26e678),
        reinterpret_cast<void(*)(void*,const void*)>(*base+0x26aecc)};
    return std::shared_ptr<const InstalledHooks>(new InstalledHooks(*base,c,r,std::move(module)));
}
}
