#ifndef TITAN_CP3_READER_BOUNDARY_HOOKS_V1_H
#define TITAN_CP3_READER_BOUNDARY_HOOKS_V1_H
#ifdef __cplusplus
extern "C" {
#define TITAN_BOUNDARY_NOEXCEPT noexcept
#else
#define TITAN_BOUNDARY_NOEXCEPT
#endif
/* Runs after each successful original loopOnce return, including idle wakes,
 * outside Reader mutex. Borrow reader only for this call. Acquire and retain a
 * live generation endpoint; maintain and drain in production order. Revalidate
 * session/fence/closing before every emission. Never escape exceptions. */
void titan_cp3_reader_drain_v1(void *reader) TITAN_BOUNDARY_NOEXCEPT;
/* Replaces the original notify call at 0x2060e0. x0/x1 retain original listener
 * and variant; reader comes from x19. x3 receives the unchanged original
 * const notify body at this module +0x2690a8, without runtime symbol lookup. Must synchronously forward the exact
 * original variant once through the original const InputListenerInterface::notify,
 * including unavailable/retired endpoint paths. Do not call this adapter to
 * forward. Never retain variant/listener beyond this call or escape exceptions.
 * Identity, cancellation/hold/fence ordering and forwarding belong to the
 * sidecar. Forward through the supplied pointer exactly once even if feature
 * initialization or symbol resolution fails. The hook has no rejection path. */
typedef void (*TitanCp3OriginalNotify)(void *listener, const void *variant);
void titan_cp3_reader_notify_v1(void *listener, const void *variant, void *reader,
    TitanCp3OriginalNotify forward) TITAN_BOUNDARY_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef TITAN_BOUNDARY_NOEXCEPT
#endif
