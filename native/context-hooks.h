#ifndef TITAN_CP3_CONTEXT_HOOKS_V1_H
#define TITAN_CP3_CONTEXT_HOOKS_V1_H
#ifdef __cplusplus
extern "C" {
#define TITAN_CONTEXT_NOEXCEPT noexcept
#else
#define TITAN_CONTEXT_NOEXCEPT
#endif
/* Post-success original construction. Borrow context only while its original
 * lifetime is live; classify from independently verified original value APIs.
 * Registration must be generation tagged and must reject ambiguous reuse. */
void titan_cp3_context_constructed_v1(const void *context) TITAN_CONTEXT_NOEXCEPT;
/* Before D1/D2 returns and before D0 frees the context. Synchronously invalidate
 * matching identity before return. Do not emit input or take a Reader lock. */
void titan_cp3_context_retiring_v1(const void *context) TITAN_CONTEXT_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef TITAN_CONTEXT_NOEXCEPT
#endif
