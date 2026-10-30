#ifndef TITAN_CP3_MAPPER_HOOKS_V1_H
#define TITAN_CP3_MAPPER_HOOKS_V1_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#define TITAN_NOEXCEPT noexcept
#else
#define TITAN_NOEXCEPT
#endif
struct TitanCp3RawEvent32 {
 int64_t when;
 int64_t readTime;
 int32_t deviceId;
 int32_t type;
 int32_t code;
 int32_t value;
};
/* Called only after the original constructor returns successfully. The context
 * is borrowed. Register a fresh lifetime; verify original object identity and
 * mtk-pad descriptor/classes in the sidecar before enabling consumption. */
void titan_cp3_mapper_constructed_v1(void *mapper, const void *context) TITAN_NOEXCEPT;
/* Must synchronously clear all state and invalidate registration before return.
 * No saved mapper/context reference may outlive this call. Idempotent. */
void titan_cp3_mapper_retiring_v1(void *mapper) TITAN_NOEXCEPT;
/* Clear decoder/policy state before original reset executes. Keep identity only
 * if it still belongs to the live registered generation. Original reset always runs. */
void titan_cp3_mapper_reset_v1(void *mapper, int64_t when) TITAN_NOEXCEPT;
/* true means the sidecar verified this live mtk-pad binding, accepted the raw
 * event, and owns its output. false preserves the original process path.
 * Unknown/unregistered/stale/other-device bindings MUST return false.
 * The wrapper constructs the original empty result list only for true.
 * Must not mutate the event, escape exceptions, or retain the borrowed event. */
bool titan_cp3_mapper_process_v1(void *mapper, const struct TitanCp3RawEvent32 *event) TITAN_NOEXCEPT;
#ifdef __cplusplus
}
static_assert(sizeof(TitanCp3RawEvent32)==32 && alignof(TitanCp3RawEvent32)==8);
static_assert(offsetof(TitanCp3RawEvent32,when)==0 && offsetof(TitanCp3RawEvent32,readTime)==8);
static_assert(offsetof(TitanCp3RawEvent32,deviceId)==16 && offsetof(TitanCp3RawEvent32,type)==20);
static_assert(offsetof(TitanCp3RawEvent32,code)==24 && offsetof(TitanCp3RawEvent32,value)==28);
#endif
#undef TITAN_NOEXCEPT
#endif
