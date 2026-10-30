#pragma once
#include "NativeMotionAdapter.h"
#include "OriginalViewportAdapter.h"
namespace titan_resolver {
struct ResolvedApis {
    titan_native::NativeCalls native;
    titan_display::PolicyCalls policy;
    // Keep this token alive whenever any resolved call/table may be used.
    std::shared_ptr<const void> modules;
};
// Resolves static original calls only. Does not authorize a device, listener,
// Reader generation, display, or event. Caller still owns those lifetime checks.
std::optional<ResolvedApis> resolveOriginalApis() noexcept;
}
