#pragma once
#include <cstdint>
extern "C" {
__attribute__((visibility("default"))) void titan_cp3_reader_constructed_v1(
        void* reader, void* hub, void (*wake)(void*) noexcept) noexcept;
__attribute__((visibility("default"))) void titan_cp3_reader_retiring_v1(void* reader) noexcept;
__attribute__((visibility("default"))) bool titan_cp3_reader_ready_v1() noexcept;
}
void titan_cp3_reader_wake_v1() noexcept;
void titan_cp3_reader_session_changed_v1(std::uint64_t snapshot) noexcept;
