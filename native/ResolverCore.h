#pragma once
#include "GeneratedPins.h"
#include <array>
#include <cstring>
#include <limits>
#include <optional>
namespace titan_resolver {
enum Permission : unsigned { Read=1, Execute=2 };
struct Probe {
    virtual ~Probe() = default;
    virtual uintptr_t symbol(const char*) const noexcept = 0;
    virtual uintptr_t imageBase(uintptr_t) const noexcept = 0;
    virtual bool range(uintptr_t base,uintptr_t address,size_t size,unsigned permissions) const noexcept = 0;
    virtual bool read(uintptr_t address,void* out,size_t size) const noexcept = 0;
};
struct Addresses {
    std::array<uintptr_t,10> exported{};
    std::array<uintptr_t,3> bases{};
    uintptr_t motionDestroy{},queueDestroy{},readerAddressPoint{},policyAddressPoint{};
};
inline std::optional<uintptr_t> add(uintptr_t base,uintptr_t offset) noexcept {
    if(!base||offset>std::numeric_limits<uintptr_t>::max()-base)return {};
    return base+offset;
}
inline std::optional<Addresses> resolve(const Probe& p) noexcept {
    Addresses a{};
    for(size_t i=0;i<std::size(symbols);++i) {
        const auto& s=symbols[i];auto v=p.symbol(s.name);if(!v)return {};
        auto base=p.imageBase(v);auto expected=add(base,s.offset);
        if(!expected||*expected!=v)return {};
        if(a.bases[s.image]&&a.bases[s.image]!=base)return {};
        a.bases[s.image]=base;a.exported[i]=v;
    }
    for(size_t i=0;i<a.bases.size();++i)for(size_t j=0;j<i;++j)
        if(a.bases[i]==a.bases[j])return {};
    for(const auto& c:code) {
        auto ptr=add(a.bases[c.image],c.offset);
        if(!ptr||!p.range(a.bases[c.image],*ptr,c.size,c.permissions))return {};
        unsigned char chunk[64];
        for(size_t n=0;n<c.size;) {
            size_t count=c.size-n<sizeof(chunk)?c.size-n:sizeof(chunk);
            if(!p.read(*ptr+n,chunk,count)||std::memcmp(chunk,c.bytes+n,count))return {};
            n+=count;
        }
    }
    // Full exported table bounds must be readable before any relocated slot read.
    for(auto [index,length]:{std::pair<size_t,size_t>{queueVtable,0x70},{readerVtable,0xb8},{policyVtable,0x5a8}})
        if(!p.range(a.bases[symbols[index].image],a.exported[index],length,Read))return {};
    auto slot=[&](unsigned image,uintptr_t offset,uintptr_t expected) {
        auto ptr=add(a.bases[image],offset);uintptr_t value{};
        return ptr&&p.range(a.bases[image],*ptr,sizeof(value),Read)&&
            p.read(*ptr,&value,sizeof(value))&&value==expected;
    };
    a.motionDestroy=*add(a.bases[0],0x2588e4);
    a.queueDestroy=*add(a.bases[0],0x26c670);
    a.readerAddressPoint=*add(a.bases[0],0x3d6c78);
    // NativeInputManager's active ReaderPolicy table is +0xa8, proved by VTT
    // relocations. +16 and construction/secondary tables are not accepted.
    a.policyAddressPoint=*add(a.bases[1],0xc64b8);
    if(!slot(0,0x3d8928,0)||!slot(0,0x3d8938,a.queueDestroy)||
       !slot(0,0x3d8940,*add(a.bases[0],0x26c758))||
       !slot(0,0x3d8968,a.exported[queueNotifyMotion])||
       !slot(0,0x3d6c68,0)||!slot(0,0x3d6cd0,a.exported[getPolicy])||
       !slot(1,0xc64a8,0)||!slot(1,0xc6518,a.exported[getViewport]))return {};
    return a;
}
}
