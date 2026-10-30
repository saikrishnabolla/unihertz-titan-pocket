#pragma once
#include "ContextAdapter.h"
#include <ftl/flags.h>
#include <type_traits>
namespace android { enum class InputDeviceClass : uint32_t; }
namespace titan_runtime {
static_assert(sizeof(android::InputDeviceIdentifier)==144);
static_assert(offsetof(android::InputDeviceIdentifier,name)==0);
static_assert(offsetof(android::InputDeviceIdentifier,location)==24);
static_assert(offsetof(android::InputDeviceIdentifier,uniqueId)==48);
static_assert(offsetof(android::InputDeviceIdentifier,bus)==72);
static_assert(offsetof(android::InputDeviceIdentifier,descriptor)==80);
static_assert(offsetof(android::InputDeviceIdentifier,nonce)==104);
static_assert(offsetof(android::InputDeviceIdentifier,bluetoothAddress)==112);
using DeviceClasses=android::ftl::Flags<android::InputDeviceClass>;
static_assert(sizeof(DeviceClasses)==4);
static_assert(!std::is_trivially_copy_constructible_v<DeviceClasses>);
// Original CP3 returns Flags through x8. ContextAdapter::ClassesGetter is an
// extraction callback, never a valid type for the original symbol itself.
using NativeClassesGetter=DeviceClasses (*)(const void*,int32_t);
inline uint32_t extractDeviceClasses(NativeClassesGetter getter,const void* hub,int32_t raw) {
 return getter(hub,raw).get();
}
}
namespace titan_runtime { std::optional<OriginalTypes> resolveOriginalMetadata(); }
