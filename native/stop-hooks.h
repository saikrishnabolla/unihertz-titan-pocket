#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#define STOP_NOEXCEPT noexcept
#else
#define STOP_NOEXCEPT
#endif
// Resolve only the current original Reader and retained coordinator. Return0
// only after retirement is acknowledged, or for a proven unbound original Reader.
// Never call original stop from these callbacks. Timeouts must remain errors.
int32_t titan_cp3_reader_stop_gate_v1(void* reader) STOP_NOEXCEPT;
// Runs before Manager invokes either Reader or Dispatcher stop. Its reader is
// manager+0x28 in this exact CP3. The implementation must validate manager binding.
int32_t titan_cp3_manager_stop_gate_v1(void* manager) STOP_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef STOP_NOEXCEPT
