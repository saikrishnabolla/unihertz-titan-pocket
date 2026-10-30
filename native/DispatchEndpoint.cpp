#include "DispatchEndpoint.h"
#include "TitanReaderLifecycle.h"
namespace {
// Never hold binding while taking a core gate or invoking a sink. The retained
// shared owner makes the pointer safe across that unlocked interval.
// Reader module stays loaded for process lifetime. Explicit retirement resets
// bound; shutdown must not schedule CRT destructors for these binding globals.
[[clang::no_destroy]] std::mutex binding;
[[clang::no_destroy]] std::shared_ptr<titan_surface::DispatchEndpoint> bound;
bool retiring = false;
}
namespace titan_surface {
bool bindDispatchEndpoint(std::shared_ptr<DispatchEndpoint> endpoint) {
    if (!endpoint) return false;
    std::lock_guard<std::mutex> lock(binding);
    if (bound || retiring) return false;
    bound = std::move(endpoint);
    return true;
}
bool retireDispatchEndpoint(const std::shared_ptr<DispatchEndpoint>& endpoint, Time when) {
    {
        std::lock_guard<std::mutex> lock(binding);
        if (!endpoint || bound != endpoint) return false;
        retiring = true;
    }
    const bool closed = endpoint->core().retire(when);
    {
        std::lock_guard<std::mutex> lock(binding);
        if (closed) { bound.reset(); retiring = false; }
    }
    if (!closed) titan_cp3_reader_wake_v1();
    return closed;
}
void maintainDispatchEndpoint(const std::shared_ptr<DispatchEndpoint>& endpoint, Time when) {
    if (!endpoint || !endpoint->core().isReaderThread()) return;
    endpoint->core().maintain(when);
    if (!endpoint->core().retirementComplete()) return;
    std::lock_guard<std::mutex> lock(binding);
    if (bound == endpoint && retiring) { bound.reset(); retiring = false; }
}

}
bool titan_surface_dispatch_commit_v1(bool allowed, unsigned long long ticket,
                                      titan_surface::Time when) noexcept {
    std::shared_ptr<titan_surface::DispatchEndpoint> endpoint;
    {
        std::lock_guard<std::mutex> lock(binding);
        if (retiring) return false;
        // No endpoint can bind while this publication is in flight. Session
        // publication only wakes Reader; it never dispatches Sink callbacks.
        if (!bound) return titan_surface_session_commit_v1(allowed, ticket);
        endpoint = bound;
    }
    return endpoint->core().commit(allowed, ticket, when);
}
