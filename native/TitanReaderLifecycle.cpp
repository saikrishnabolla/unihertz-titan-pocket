#include "TitanReaderLifecycle.h"
#include "OpaqueReaderRegistry.h"
#include <atomic>
#include <mutex>
namespace {
[[clang::no_destroy]] titan::OpaqueReaderRegistry readers;
[[clang::no_destroy]] std::mutex lifecycle;
titan::ReaderToken token;
std::atomic<bool> healthy{false};
bool poisoned = false;
}
void titan_cp3_lifecycle_reader_constructed_v1(void* reader, void* hub,
                                    void (*wake)(void*) noexcept) noexcept {
    std::lock_guard<std::mutex> guard(lifecycle);
    healthy.store(false, std::memory_order_release);
    if (poisoned) return;
    const auto installed = readers.registerReader(reader, hub, wake);
    if (!installed.generation) {
        // A failed/duplicate hook cannot authorize gesture delivery later.
        poisoned = true;
        return;
    }
    token = installed;
    healthy.store(true, std::memory_order_release);
    // Initial registry wake can run before readiness is visible to Reader.
    // Repeat it after publication while the lifecycle lock retains this owner.
    if (!readers.wakeRegistered(token)) {
        healthy.store(false, std::memory_order_release);
        poisoned = true;
    }
}
void titan_cp3_lifecycle_reader_retiring_v1(void* reader) noexcept {
    std::lock_guard<std::mutex> guard(lifecycle);
    if (!token.generation || token.reader != reader) return;
    healthy.store(false, std::memory_order_release);
    if (!readers.retire(token)) poisoned = true;
    token = {};
}
bool titan_cp3_reader_ready_v1() noexcept {
    return healthy.load(std::memory_order_acquire);
}
void titan_cp3_reader_session_changed_v1(std::uint64_t snapshot) noexcept {
    readers.publish(snapshot);
}

void titan_cp3_reader_wake_v1() noexcept {
    std::lock_guard<std::mutex> guard(lifecycle);
    if (healthy.load(std::memory_order_acquire) && token.generation)
        readers.wakeRegistered(token);
}
