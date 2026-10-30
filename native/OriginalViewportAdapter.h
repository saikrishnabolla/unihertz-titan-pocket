#pragma once
#include "DisplayBinding.h"
#include <input/DisplayViewport.h>
#include <type_traits>
namespace titan_display {
// Use the actual retained public value type. In particular optional<DisplayViewport>
// has a nontrivial hidden-result ABI and owns its native std::string.
using GetPolicy = void*(*)(const void*);
using GetViewport = std::optional<android::DisplayViewport>(*)(void*,android::ui::LogicalDisplayId);
struct PolicyCalls {
    GetPolicy getPolicy;
    GetViewport getViewport;
    const void* readerVtable;
    const void* policyVtable;
};
static_assert(sizeof(android::DisplayViewport)==104&&alignof(android::DisplayViewport)==8);
static_assert(sizeof(std::optional<android::DisplayViewport>)==112);
static_assert(!std::is_trivially_destructible_v<std::optional<android::DisplayViewport>>);
static_assert(offsetof(android::DisplayViewport,displayId)==0);
static_assert(offsetof(android::DisplayViewport,orientation)==4);
static_assert(offsetof(android::DisplayViewport,logicalLeft)==8);
static_assert(offsetof(android::DisplayViewport,logicalTop)==12);
static_assert(offsetof(android::DisplayViewport,logicalRight)==16);
static_assert(offsetof(android::DisplayViewport,logicalBottom)==20);
static_assert(offsetof(android::DisplayViewport,isActive)==48);
static_assert(offsetof(android::DisplayViewport,uniqueId)==56);
static_assert(sizeof(android::ui::LogicalDisplayId)==4);
// Invoke only with a registry-authenticated live mapper/context/reader generation,
// under the original Reader lock. Resolver must authenticate both original methods,
// vtable address points and their loaded-module lifetime before supplying calls.
std::optional<Binding> readOriginalViewport(const void* mapper,const void* context,
    const void* readerContext,const void* mapperVtable,const PolicyCalls& calls) noexcept;
} // namespace titan_display
