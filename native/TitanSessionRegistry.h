#pragma once
// Bit 0 is permission; the remaining bits identify a session transition.
extern "C" __attribute__((visibility("default"))) unsigned long long titan_surface_session_snapshot_v1() noexcept;
void titan_surface_session_publish_v1(bool allowed) noexcept;

void titan_surface_session_fail_closed_v1() noexcept;
unsigned long long titan_surface_session_stage_v1() noexcept;
bool titan_surface_session_commit_v1(bool allowed, unsigned long long ticket) noexcept;
