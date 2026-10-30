#pragma once
#include "official-value-types.h"
#include <cstring>
#include <string_view>
#include <optional>

namespace titan_cp3_probe {
// Offline adapter proof only. Caller must supply live, registered original objects.
struct Registration {
 const void* mapper;
 const void* context;
 const void* owner;
 const void* contextVtableAddressPoint;
 const void* mapperVtableAddressPoint;
 int32_t rawId;
 uint64_t generation;
 bool live;
};
struct ContextSnapshot {
 const void* owner;
 const void* readerContext;
 const void* eventHub;
 int32_t rawId;
 int32_t logicalId;
};
using IdentifierGetter=android::InputDeviceIdentifier (*)(const void*,int32_t);
using ClassesGetter=uint32_t (*)(const void*,int32_t);
struct Callbacks { IdentifierGetter identifier; ClassesGetter classes; };

template<typename T> inline T readField(const void* bytes,size_t offset) {
 T value;std::memcpy(&value,static_cast<const unsigned char*>(bytes)+offset,sizeof(value));return value;
}
inline bool alignedPointer(const void* p) {return p && reinterpret_cast<uintptr_t>(p)%8==0;}
inline std::optional<ContextSnapshot> snapshot(const Registration& r) {
 if(!r.live || !r.generation || r.rawId<=0 || !alignedPointer(r.mapper) ||
    !alignedPointer(r.context) || !alignedPointer(r.owner) ||
    !alignedPointer(r.contextVtableAddressPoint) || !alignedPointer(r.mapperVtableAddressPoint))return {};
 if(readField<const void*>(r.mapper,0)!=r.mapperVtableAddressPoint ||
    readField<const void*>(r.mapper,8)!=r.context ||
    readField<const void*>(r.context,0)!=r.contextVtableAddressPoint)return {};
 ContextSnapshot s{readField<const void*>(r.context,8),readField<const void*>(r.context,16),
   readField<const void*>(r.context,24),readField<int32_t>(r.context,32),readField<int32_t>(r.context,36)};
 if(s.owner!=r.owner || !alignedPointer(s.readerContext) || !alignedPointer(s.eventHub) ||
    s.rawId!=r.rawId || s.logicalId<0)return {};
 return s;
}
inline bool bind(const Registration& r,const Callbacks& c,std::string_view expectedDescriptor) {
 if(!c.identifier || !c.classes || expectedDescriptor.empty())return false;
 auto s=snapshot(r);if(!s)return false;
 auto identifier=c.identifier(s->eventHub,s->rawId);
 if(identifier.name!="mtk-pad" || identifier.descriptor!=expectedDescriptor)return false;
 const uint32_t classes=c.classes(s->eventHub,s->rawId);
 constexpr uint32_t touchpad=65536, external=1073741824, virtualDevice=536870912;
 return (classes&touchpad)!=0 && (classes&(external|virtualDevice))==0;
}
inline std::optional<android::RawEvent> rawEvent(const void* bytes,size_t size,int32_t expectedRawId) {
 if(!bytes || size!=sizeof(android::RawEvent) || expectedRawId<0)return {};
 const int32_t type=readField<int32_t>(bytes,20);
 // Device lifecycle records leave readTime undefined. This parser rejects them before copying it.
 if(type!=0 && type!=1 && type!=3)return {};
 android::RawEvent out;std::memcpy(&out,bytes,sizeof(out));
 if(out.deviceId!=expectedRawId || out.when<0 || out.readTime<0 || out.code<0)return {};
 if((type==0 && out.code>15) || (type==1 && out.code>767) || (type==3 && out.code>63))return {};
 return out;
}
}
