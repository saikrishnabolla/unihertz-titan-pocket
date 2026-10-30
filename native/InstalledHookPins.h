#pragma once
#include <stdint.h>
namespace titan_cp3_installed {
struct EntryPin { uintptr_t offset; uint32_t word; uintptr_t target; };
inline constexpr EntryPin entries[] = {
 {0x20440c,0x1407fefd,0x404000}, // reader_constructor_hook
 {0x204d6c,0x1407fcbf,0x404068}, // reader_destructor_hook
 {0x2391b4,0x14072bd2,0x4040fc}, // mapper_constructor_hook
 {0x23953c,0x14072b01,0x404140}, // mapper_destructor_hook
 {0x23b2e4,0x140723b2,0x4041ac}, // mapper_reset_hook
 {0x23b638,0x140722f8,0x404218}, // mapper_process_hook
 {0x220784,0x14079008,0x4047a4}, // keyboard_process_hook
 {0x239eb8,0x14072a56,0x404810}, // mapper_reconfigure_hook
 {0x205a5c,0x1407fb7e,0x404854}, // reader_stop_hook
 {0x27cb14,0x14061f5c,0x404884}, // manager_stop_hook
 {0x27c6e0,0x14062075,0x4048b4}, // manager_destructor_hook
 {0x201a60,0x14080b28,0x404700}, // context_constructor_hook
 {0x201ac0,0x14080b1f,0x40473c}, // context_destructor_hook
 {0x205b70,0x1407f9ca,0x404298}, // reader_loop_hook
 {0x2060e0,0x9407f87b,0x4042cc}, // reader_notify_hook
 {0x25b408,0x1406a3b7,0x4042e4}, // cursor_motion_hook
 {0x259970,0x1406aa7c,0x404360}, // cursor_controller_1_hook
 {0x25998c,0x1406aae9,0x404530}, // cursor_controller_2_hook
};
}
