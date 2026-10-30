#pragma once
#include "cursor-hooks.h"
#include "context-hooks.h"
#include "stop-hooks.h"
#include "mapper-hooks.h"
#include "reader-boundary-hooks.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#define FINAL_NOEXCEPT noexcept
#else
#define FINAL_NOEXCEPT
#endif
void titan_cp3_reader_constructed_v1(void* reader,void* hub,
    void (*wake)(void*) FINAL_NOEXCEPT) FINAL_NOEXCEPT;
void titan_cp3_reader_retiring_v1(void* reader) FINAL_NOEXCEPT;
// Must not return until endpoint callbacks and native borrows have quiesced.
void titan_cp3_manager_retiring_v1(void* manager) FINAL_NOEXCEPT;
// Observe original keyboard RawEvent before native processing. This callback
// cannot consume the event. Borrowed mapper/raw pointers are valid only here.
void titan_cp3_keyboard_process_v1(void* mapper,const void* raw) FINAL_NOEXCEPT;
// Runs after original reconfigure returns, including its native list result.
// Invalidate copied display/capture/meta batches using this mapper's generation.
// The callback does not own or receive the original result list.
void titan_cp3_mapper_reconfigured_v1(void* mapper,int64_t when) FINAL_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef FINAL_NOEXCEPT
