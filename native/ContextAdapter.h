#pragma once
#include "DeviceRegistry.h"
#include <cstring>
namespace titan_runtime {
using IdentifierGetter=android::InputDeviceIdentifier (*)(const void*,int32_t);
using ClassesGetter=uint32_t (*)(const void*,int32_t);
struct OriginalTypes {const void* contextVtable;const void* readerContextVtable;IdentifierGetter identifier;ClassesGetter classes;};
template<class T>T field(const void* p,size_t off){T v;std::memcpy(&v,static_cast<const char*>(p)+off,sizeof(v));return v;}
inline bool aligned(const void*p){return p && reinterpret_cast<uintptr_t>(p)%8==0;}
// Only call from the post-success original InputDeviceContext constructor hook.
// All borrowed native objects must still be alive under Reader serialization.
inline bool contextConstructed(DeviceRegistry& r,const void* p,const OriginalTypes& types) {
 auto reject=[&] {r.reject();return false;};
 if(!aligned(p)||!types.identifier||!types.classes || !aligned(types.contextVtable)||!aligned(types.readerContextVtable))return reject();
 if(field<const void*>(p,0)!=types.contextVtable)return reject();
 const void* owner=field<const void*>(p,8);const void* context=field<const void*>(p,16);const void* hub=field<const void*>(p,24);
 int32_t raw=field<int32_t>(p,32),logical=field<int32_t>(p,36);
 if(!aligned(owner)||!aligned(context)||!aligned(hub)||!inventoryIdPair(raw,logical) ||
    field<const void*>(context,0)!=types.readerContextVtable || field<const void*>(owner,8)!=context || field<int32_t>(owner,16)!=logical)return reject();
 void* reader=field<void*>(context,8);if(!aligned(reader))return reject();
 auto id=types.identifier(hub,raw);auto classes=types.classes(hub,raw);
 if(!inventoryIds(raw,logical,classes))return reject();
 return r.add(reader,hub,{p,owner,raw,logical,classes,std::move(id.name),std::move(id.descriptor),0});
}
}
