#include "TitanReaderLifecycle.h"
#include "TitanSessionRegistry.h"
namespace {
alignas(8) unsigned long long state = 0;
unsigned int failed = 0;
}
unsigned long long titan_surface_session_snapshot_v1() noexcept {
    return __atomic_load_n(&state, __ATOMIC_SEQ_CST);
}
void titan_surface_session_publish_v1(bool allowed) noexcept {
    auto previous = __atomic_load_n(&state, __ATOMIC_SEQ_CST);
    for (;;) {
        const auto generation = previous & ~1ULL;
        // Counter exhaustion permanently blocks instead of reusing an old generation.
        const auto next = generation == ~1ULL ? ~1ULL
                : (generation + 2ULL) | static_cast<unsigned long long>(allowed && !__atomic_load_n(&failed, __ATOMIC_SEQ_CST));
        if (__atomic_compare_exchange_n(&state, &previous, next, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            titan_cp3_reader_session_changed_v1(next);
            return;
        }
    }
}

void titan_surface_session_fail_closed_v1() noexcept {
    __atomic_store_n(&failed, 1, __ATOMIC_SEQ_CST);
    titan_surface_session_publish_v1(false);
}
unsigned long long titan_surface_session_stage_v1() noexcept {
    auto previous = __atomic_load_n(&state, __ATOMIC_SEQ_CST);
    for (;;) {
        const auto generation = previous & ~1ULL;
        const auto next = generation == ~1ULL ? ~1ULL : generation + 2ULL;
        if (__atomic_compare_exchange_n(&state, &previous, next, false,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            titan_cp3_reader_session_changed_v1(next);
            return next;
        }
    }
}
bool titan_surface_session_commit_v1(bool allowed, unsigned long long ticket) noexcept {
    // Every commit consumes its ticket; saturation can never authorize input.
    if (!ticket || (ticket & 1ULL) || ticket >= ~1ULL - 2ULL) return false;
    const auto next = (ticket + 2ULL) | static_cast<unsigned long long>(
            allowed && !__atomic_load_n(&failed, __ATOMIC_SEQ_CST));
    auto expected = ticket;
    if (!__atomic_compare_exchange_n(&state, &expected, next, false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) return false;
    titan_cp3_reader_session_changed_v1(next);
    return true;
}
