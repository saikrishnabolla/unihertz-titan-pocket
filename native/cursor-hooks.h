#ifndef TITAN_CP3_CURSOR_HOOKS_V1_H
#define TITAN_CP3_CURSOR_HOOKS_V1_H
#include <stdint.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#define TITAN_CURSOR_NOEXCEPT noexcept
#else
#define TITAN_CURSOR_NOEXCEPT
#endif
/* Called before original processMotion with borrowed original objects. A true
 * result bypasses cursor transformation by copying through original native code.
 * Match only a current generation whose logical identity and generated stream
 * were independently verified. Unknown, stale, ambiguous and unrelated input
 * MUST return false. Do not inspect typed content or call back into Reader. */
bool titan_cp3_cursor_motion_v1(const void *choreographer, const void *motion)
    TITAN_CURSOR_NOEXCEPT;
/* Called under original PointerChoreographer mutex. Arguments are borrowed:
 * InputDeviceInfo at x27, logicalId=[x27], sources=w20. Source alone is never
 * sufficient identity proof. Match a current published target-only aggregate;
 * preserve fingerprint keys, external input, and every unknown mapping by false.
 * Use a lock-free snapshot; never take Reader locks or retain these pointers. */
bool titan_cp3_cursor_controller_v1(const void *choreographer, const void *deviceInfo,
    int32_t logicalId, uint32_t sources) TITAN_CURSOR_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef TITAN_CURSOR_NOEXCEPT
#endif
