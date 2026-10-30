#pragma once
#include "OriginalApiResolver.h"
#include "NativeMetadata.h"
#include "installed/InstalledHooks.h"
namespace titan_runtime {
struct RuntimePrerequisites final {
 titan_resolver::ResolvedApis originals;
 OriginalTypes metadata;
 std::shared_ptr<const titan_installed::InstalledHooks> hooks;
};
// Retain the returned object for every hook/API call. This establishes loaded
// code identity only; Reader/mapper/listener/thread ownership is separate.
std::shared_ptr<const RuntimePrerequisites> resolveRuntimePrerequisites()noexcept;
}
