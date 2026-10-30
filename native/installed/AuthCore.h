#pragma once
#include "GeneratedPins.h"
#include <cstring>
#include <optional>
#include <limits>
namespace titan_installed {
enum Permission:unsigned {Read=1,Write=2,Execute=4,NoWrite=8};
struct Probe {
    virtual ~Probe()=default;
    virtual uintptr_t symbol(const char*) const noexcept=0;
    virtual uintptr_t imageBase(uintptr_t) const noexcept=0;
    virtual bool range(uintptr_t base,uintptr_t address,size_t size,unsigned permissions)const noexcept=0;
    virtual bool read(uintptr_t address,void* out,size_t size)const noexcept=0;
};
inline std::optional<uintptr_t> checkedAdd(uintptr_t base,uintptr_t offset) noexcept {
    if(!base||offset>std::numeric_limits<uintptr_t>::max()-base)return {};
    return base+offset;
}
// Pure validation result is internal input to the real retained-module factory.
inline std::optional<uintptr_t> validate(const Probe& p) noexcept {
    uintptr_t base{};
    for(const auto& s:symbols) {
        auto value=p.symbol(s.name);if(!value)return {};
        auto observed=p.imageBase(value);auto expected=checkedAdd(observed,s.offset);
        if(!expected||*expected!=value||(base&&base!=observed))return {};
        base=observed;
    }
    for(const auto& c:bytes) {
        auto address=checkedAdd(base,c.offset);
        if(!address||c.size>UINTPTR_MAX-*address||!p.range(base,*address,c.size,c.permissions|NoWrite))return {};
        unsigned char buffer[64];
        for(size_t i=0;i<c.size;) {
            size_t count=c.size-i<sizeof(buffer)?c.size-i:sizeof(buffer);
            if(!p.read(*address+i,buffer,count)||std::memcmp(buffer,c.bytes+i,count))return {};
            i+=count;
        }
    }
    auto table=checkedAdd(base,0x3d7ea0);
    if(!table||0x118>UINTPTR_MAX-*table||!p.range(base,*table,0x118,Read|NoWrite))return {};
    for(const auto& s:slots) {
        auto address=checkedAdd(base,s.offset);auto expected=s.relocate?checkedAdd(base,s.value):std::optional<uintptr_t>{s.value};uintptr_t actual{};
        if(!address||!expected||!p.range(base,*address,sizeof(actual),Read|NoWrite)||!p.read(*address,&actual,sizeof(actual))||actual!=*expected)return {};
    }
    return base;
}
}
