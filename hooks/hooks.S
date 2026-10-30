.text
.p2align 2
.global reader_constructor_hook
reader_constructor_hook:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 30
 .cfi_same_value 29
 .cfi_same_value 19
 .cfi_same_value 20
 stp x29, x30, [sp, #-64]!
 .cfi_def_cfa_offset 64
 .cfi_offset 29, -64
 .cfi_offset 30, -56
 mov x29, sp
 stp x19, x20, [sp, #16]
 .cfi_offset 19, -48
 .cfi_offset 20, -40
 mov x19, x0
 ldr x20, [x1]
 bl constructor_replay
 str x0, [sp, #32]
 cbz x20, 1f
 ldr x8, [x20]
 adrp x9, expected_vtable_got
 ldr x9, [x9, :lo12:expected_vtable_got]
 add x9, x9, #16
 cmp x8, x9
 b.ne 1f
 mov x0, x19
 mov x1, x20
 adr x2, guarded_wake
 adrp x16, constructed_got
 ldr x16, [x16, :lo12:constructed_got]
 blr x16
1:
 ldr x0, [sp, #32]
 ldp x19, x20, [sp, #16]
 .cfi_same_value 19
 .cfi_same_value 20
 ldp x29, x30, [sp], #64
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_def_cfa_offset 0
 ret
 .cfi_endproc
constructor_replay:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 30
 sub sp, sp, #0x90
 .cfi_def_cfa_offset 144
 b constructor_continuation
 .cfi_endproc
.global reader_destructor_hook
reader_destructor_hook:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 29
 .cfi_same_value 30
 sub sp, sp, #240
 .cfi_def_cfa_offset 240
 stp x29, x30, [sp, #0]
 .cfi_offset 29, -240
 .cfi_offset 30, -232
 stp x0, x1, [sp, #16]
 stp x2, x3, [sp, #32]
 stp x4, x5, [sp, #48]
 stp x6, x7, [sp, #64]
 str x8, [sp, #80]
 stp q0, q1, [sp, #96]
 stp q2, q3, [sp, #128]
 stp q4, q5, [sp, #160]
 stp q6, q7, [sp, #192]
 adrp x16, retiring_got
 ldr x16, [x16, :lo12:retiring_got]
 blr x16
 ldp q0, q1, [sp, #96]
 ldp q2, q3, [sp, #128]
 ldp q4, q5, [sp, #160]
 ldp q6, q7, [sp, #192]
 ldp x0, x1, [sp, #16]
 ldp x2, x3, [sp, #32]
 ldp x4, x5, [sp, #48]
 ldp x6, x7, [sp, #64]
 ldr x8, [sp, #80]
 ldp x29, x30, [sp, #0]
 .cfi_same_value 29
 .cfi_same_value 30
 add sp, sp, #240
 .cfi_def_cfa_offset 0
 sub sp, sp, #0x50
 .cfi_def_cfa_offset 80
 b destructor_continuation
 .cfi_endproc
.global guarded_wake
guarded_wake:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 30
 cbz x0, 2f
 ldr x8, [x0]
 adrp x9, expected_vtable_got
 ldr x9, [x9, :lo12:expected_vtable_got]
 add x9, x9, #16
 cmp x8, x9
 b.ne 2f
 ldr x16, [x8, #0x178]
 br x16
2:
 ret
 .cfi_endproc

// AAPCS64 argument bank and hidden aggregate-result pointer survive the C call.
.macro save_mapper_args
 .cfi_def_cfa sp, 0
 .cfi_same_value 29
 .cfi_same_value 30
 sub sp, sp, #240
 .cfi_def_cfa_offset 240
 stp x29, x30, [sp]
 .cfi_offset 29, -240
 .cfi_offset 30, -232
 stp x0, x1, [sp, #16]
 stp x2, x3, [sp, #32]
 stp x4, x5, [sp, #48]
 stp x6, x7, [sp, #64]
 str x8, [sp, #80]
 stp q0, q1, [sp, #96]
 stp q2, q3, [sp, #128]
 stp q4, q5, [sp, #160]
 stp q6, q7, [sp, #192]
.endm
.macro restore_mapper_args
 ldp q0, q1, [sp, #96]
 ldp q2, q3, [sp, #128]
 ldp q4, q5, [sp, #160]
 ldp q6, q7, [sp, #192]
 ldp x0, x1, [sp, #16]
 ldp x2, x3, [sp, #32]
 ldp x4, x5, [sp, #48]
 ldp x6, x7, [sp, #64]
 ldr x8, [sp, #80]
 ldp x29, x30, [sp]
 .cfi_same_value 29
 .cfi_same_value 30
 add sp, sp, #240
 .cfi_def_cfa_offset 0
.endm

.global mapper_constructor_hook
mapper_constructor_hook:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_same_value 19
 .cfi_same_value 20
 stp x29, x30, [sp, #-64]!
 .cfi_def_cfa_offset 64
 .cfi_offset 29, -64
 .cfi_offset 30, -56
 stp x19, x20, [sp, #16]
 .cfi_offset 19, -48
 .cfi_offset 20, -40
 mov x19, x0
 mov x20, x1
 bl mapper_constructor_replay
 str x0, [sp, #32]
 mov x0, x19
 mov x1, x20
 adrp x16, mapper_constructed_got
 ldr x16, [x16, :lo12:mapper_constructed_got]
 blr x16
 ldr x0, [sp, #32]
 ldp x19, x20, [sp, #16]
 .cfi_same_value 19
 .cfi_same_value 20
 ldp x29, x30, [sp], #64
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_def_cfa_offset 0
 ret
 .cfi_endproc
mapper_constructor_replay:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 30
 sub sp, sp, #240
 .cfi_def_cfa_offset 240
 b mapper_constructor_continuation
 .cfi_endproc

.global mapper_destructor_hook
mapper_destructor_hook:
 .cfi_startproc
 save_mapper_args
 adrp x16, mapper_retiring_got
 ldr x16, [x16, :lo12:mapper_retiring_got]
 blr x16
 restore_mapper_args
 stp x29, x30, [sp, #-48]!
 .cfi_def_cfa_offset 48
 .cfi_offset 29, -48
 .cfi_offset 30, -40
 b mapper_destructor_continuation
 .cfi_endproc

.global mapper_reset_hook
mapper_reset_hook:
 .cfi_startproc
 save_mapper_args
 adrp x16, mapper_reset_got
 ldr x16, [x16, :lo12:mapper_reset_got]
 blr x16
 restore_mapper_args
 sub sp, sp, #160
 .cfi_def_cfa_offset 160
 b mapper_reset_continuation
 .cfi_endproc

.global mapper_process_hook
mapper_process_hook:
 .cfi_startproc
 save_mapper_args
 adrp x16, mapper_process_got
 ldr x16, [x16, :lo12:mapper_process_got]
 blr x16
 mov w17, w0
 restore_mapper_args
 tbnz w17, #0, mapper_process_consumed
 .cfi_remember_state
 sub sp, sp, #256
 .cfi_def_cfa_offset 256
 b mapper_process_continuation
mapper_process_consumed:
 .cfi_restore_state
 // Exact empty-list construction from original process 0x23b7e8..0x23b7ec.
 stp x8, x8, [x8]
 str xzr, [x8, #16]
 ret
 .cfi_endproc

.global reader_loop_hook
reader_loop_hook:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_same_value 19
 stp x29, x30, [sp, #-32]!
 .cfi_def_cfa_offset 32
 .cfi_offset 29, -32
 .cfi_offset 30, -24
 str x19, [sp, #16]
 .cfi_offset 19, -16
 mov x19, x0
 bl reader_loop_replay
 mov x0, x19
 adrp x16, reader_drain_got
 ldr x16, [x16, :lo12:reader_drain_got]
 blr x16
 ldr x19, [sp, #16]
 .cfi_same_value 19
 ldp x29, x30, [sp], #32
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_def_cfa_offset 0
 ret
 .cfi_endproc
reader_loop_replay:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 30
 sub sp, sp, #304
 .cfi_def_cfa_offset 304
 b reader_loop_continuation
 .cfi_endproc

.global reader_notify_hook
reader_notify_hook:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 30
 mov x2, x19
 adrp x3, original_const_notify
 add x3, x3, :lo12:original_const_notify
 adrp x16, reader_notify_got
 ldr x16, [x16, :lo12:reader_notify_got]
 br x16
 .cfi_endproc

.global cursor_motion_hook
cursor_motion_hook:
 .cfi_startproc
 save_mapper_args
 adrp x16, cursor_motion_got
 ldr x16, [x16, :lo12:cursor_motion_got]
 blr x16
 mov w17, w0
 restore_mapper_args
 tbnz w17, #0, cursor_motion_copy
 .cfi_remember_state
 sub sp, sp, #240
 .cfi_def_cfa_offset 240
 b cursor_motion_continuation
cursor_motion_copy:
 .cfi_restore_state
 mov x0, x8
 b original_motion_copy
 .cfi_endproc

.macro cursor_save_all
 sub sp, sp, #768
 stp x0, x1, [sp, #0]
 stp x2, x3, [sp, #16]
 stp x4, x5, [sp, #32]
 stp x6, x7, [sp, #48]
 stp x8, x9, [sp, #64]
 stp x10, x11, [sp, #80]
 stp x12, x13, [sp, #96]
 stp x14, x15, [sp, #112]
 stp x16, x17, [sp, #128]
 stp x18, x19, [sp, #144]
 stp x20, x21, [sp, #160]
 stp x22, x23, [sp, #176]
 stp x24, x25, [sp, #192]
 stp x26, x27, [sp, #208]
 stp x28, x29, [sp, #224]
 str x30, [sp, #240]
 mrs x17, NZCV
 str x17, [sp, #248]
 stp q0, q1, [sp, #256]
 stp q2, q3, [sp, #288]
 stp q4, q5, [sp, #320]
 stp q6, q7, [sp, #352]
 stp q8, q9, [sp, #384]
 stp q10, q11, [sp, #416]
 stp q12, q13, [sp, #448]
 stp q14, q15, [sp, #480]
 stp q16, q17, [sp, #512]
 stp q18, q19, [sp, #544]
 stp q20, q21, [sp, #576]
 stp q22, q23, [sp, #608]
 stp q24, q25, [sp, #640]
 stp q26, q27, [sp, #672]
 stp q28, q29, [sp, #704]
 stp q30, q31, [sp, #736]
.endm
.macro cursor_restore_all
 ldp q0, q1, [sp, #256]
 ldp q2, q3, [sp, #288]
 ldp q4, q5, [sp, #320]
 ldp q6, q7, [sp, #352]
 ldp q8, q9, [sp, #384]
 ldp q10, q11, [sp, #416]
 ldp q12, q13, [sp, #448]
 ldp q14, q15, [sp, #480]
 ldp q16, q17, [sp, #512]
 ldp q18, q19, [sp, #544]
 ldp q20, q21, [sp, #576]
 ldp q22, q23, [sp, #608]
 ldp q24, q25, [sp, #640]
 ldp q26, q27, [sp, #672]
 ldp q28, q29, [sp, #704]
 ldp q30, q31, [sp, #736]
 ldr x17, [sp, #248]
 msr NZCV, x17
 ldp x0, x1, [sp, #0]
 ldp x2, x3, [sp, #16]
 ldp x4, x5, [sp, #32]
 ldp x6, x7, [sp, #48]
 ldp x8, x9, [sp, #64]
 ldp x10, x11, [sp, #80]
 ldp x12, x13, [sp, #96]
 ldp x14, x15, [sp, #112]
 ldp x16, x17, [sp, #128]
 ldp x18, x19, [sp, #144]
 ldp x20, x21, [sp, #160]
 ldp x22, x23, [sp, #176]
 ldp x24, x25, [sp, #192]
 ldp x26, x27, [sp, #208]
 ldp x28, x29, [sp, #224]
 ldr x30, [sp, #240]
 add sp, sp, #768
.endm

.global cursor_controller_1_hook
cursor_controller_1_hook:
 .cfi_startproc
 // Original frame: SP -= 0x160, FP=SP+0x100. Retain original caller unwind.
 .cfi_def_cfa x29, 96
 .cfi_offset 29, -96
 .cfi_offset 30, -88
 .cfi_offset 19, -8
 .cfi_offset 20, -16
 .cfi_offset 21, -24
 .cfi_offset 22, -32
 .cfi_offset 23, -40
 .cfi_offset 24, -48
 .cfi_offset 25, -56
 .cfi_offset 26, -64
 .cfi_offset 27, -72
 .cfi_offset 28, -80
 cursor_save_all
 mov x0, x19
 mov x1, x27
 ldr w2, [x27]
 mov w3, w20
 adrp x16, cursor_controller_got
 ldr x16, [x16, :lo12:cursor_controller_got]
 blr x16
 tbnz w0, #0, cursor_controller_1_skip
 cursor_restore_all
 mov w0, w20
 b cursor_controller_1_continuation
cursor_controller_1_skip:
 cursor_restore_all
 b cursor_controller_skip
 .cfi_endproc

.global cursor_controller_2_hook
cursor_controller_2_hook:
 .cfi_startproc
 // Original frame: SP -= 0x160, FP=SP+0x100. Retain original caller unwind.
 .cfi_def_cfa x29, 96
 .cfi_offset 29, -96
 .cfi_offset 30, -88
 .cfi_offset 19, -8
 .cfi_offset 20, -16
 .cfi_offset 21, -24
 .cfi_offset 22, -32
 .cfi_offset 23, -40
 .cfi_offset 24, -48
 .cfi_offset 25, -56
 .cfi_offset 26, -64
 .cfi_offset 27, -72
 .cfi_offset 28, -80
 cursor_save_all
 mov x0, x19
 mov x1, x27
 ldr w2, [x27]
 mov w3, w20
 adrp x16, cursor_controller_got
 ldr x16, [x16, :lo12:cursor_controller_got]
 blr x16
 tbnz w0, #0, cursor_controller_2_skip
 cursor_restore_all
 mov w0, w20
 b cursor_controller_2_continuation
cursor_controller_2_skip:
 cursor_restore_all
 b cursor_controller_skip
 .cfi_endproc

.global context_constructor_hook
context_constructor_hook:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_same_value 19
 stp x29, x30, [sp, #-64]!
 .cfi_def_cfa_offset 64
 .cfi_offset 29, -64
 .cfi_offset 30, -56
 str x19, [sp, #16]
 .cfi_offset 19, -48
 mov x19, x0
 bl context_constructor_replay
 str x0, [sp, #32]
 mov x0, x19
 adrp x16, context_constructed_got
 ldr x16, [x16, :lo12:context_constructed_got]
 blr x16
 ldr x0, [sp, #32]
 ldr x19, [sp, #16]
 .cfi_same_value 19
 ldp x29, x30, [sp], #64
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_def_cfa_offset 0
 ret
 .cfi_endproc
context_constructor_replay:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 29
 .cfi_same_value 30
 stp x29, x30, [sp, #-48]!
 .cfi_def_cfa_offset 48
 .cfi_offset 29, -48
 .cfi_offset 30, -40
 b context_constructor_continuation
 .cfi_endproc
.global context_destructor_hook
context_destructor_hook:
 .cfi_startproc
 save_mapper_args
 adrp x16, context_retiring_got
 ldr x16, [x16, :lo12:context_retiring_got]
 blr x16
 restore_mapper_args
 ret
 .cfi_endproc

.global keyboard_process_hook
keyboard_process_hook:
 .cfi_startproc
 save_mapper_args
 adrp x16, keyboard_process_got
 ldr x16, [x16, :lo12:keyboard_process_got]
 blr x16
 restore_mapper_args
 sub sp, sp, #112
 .cfi_def_cfa_offset 112
 b keyboard_process_continuation
 .cfi_endproc

.global mapper_reconfigure_hook
mapper_reconfigure_hook:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_same_value 19
 .cfi_same_value 20
 stp x29, x30, [sp, #-64]!
 .cfi_def_cfa_offset 64
 .cfi_offset 29, -64
 .cfi_offset 30, -56
 stp x19, x20, [sp, #16]
 .cfi_offset 19, -48
 .cfi_offset 20, -40
 mov x19, x0
 mov x20, x1
 bl mapper_reconfigure_replay
 str x0, [sp, #32]
 mov x0, x19
 mov x1, x20
 adrp x16, mapper_reconfigured_got
 ldr x16, [x16, :lo12:mapper_reconfigured_got]
 blr x16
 ldr x0, [sp, #32]
 ldp x19, x20, [sp, #16]
 .cfi_same_value 19
 .cfi_same_value 20
 ldp x29, x30, [sp], #64
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_def_cfa_offset 0
 ret
 .cfi_endproc
mapper_reconfigure_replay:
 .cfi_startproc
 .cfi_def_cfa sp, 0
 .cfi_same_value 29
 .cfi_same_value 30
 sub sp, sp, #480
 .cfi_def_cfa_offset 480
 b mapper_reconfigure_continuation
 .cfi_endproc
.text
.p2align 2
.macro gate_hook name,callback,continuation,replay,frame
.global \name
\name:
 .cfi_startproc
 .cfi_def_cfa sp,0
 .cfi_same_value 30
 .cfi_same_value 29
 stp x29,x30,[sp,#-32]!
 .cfi_def_cfa_offset 32
 .cfi_offset 29,-32
 .cfi_offset 30,-24
 str x0,[sp,#16]
 adrp x16,\callback
 ldr x16,[x16,:lo12:\callback]
 blr x16
 cbnz w0,1f
 .cfi_remember_state
 ldr x0,[sp,#16]
 ldp x29,x30,[sp],#32
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_def_cfa_offset 0
 \replay
 .cfi_def_cfa_offset \frame
 .if \frame == 32
 .cfi_offset 29,-32
 .cfi_offset 30,-24
 .endif
 b \continuation
1:
 .cfi_restore_state
 ldp x29,x30,[sp],#32
 .cfi_same_value 29
 .cfi_same_value 30
 .cfi_def_cfa_offset 0
 ret
 .cfi_endproc
.endm
gate_hook reader_stop_hook,reader_stop_gate_got,reader_stop_continuation,"sub sp,sp,#80",80
gate_hook manager_stop_hook,manager_stop_gate_got,manager_stop_continuation,"stp x29,x30,[sp,#-32]!",32

.global manager_destructor_hook
manager_destructor_hook:
 .cfi_startproc
 save_mapper_args
 adrp x16, manager_retiring_got
 ldr x16, [x16, :lo12:manager_retiring_got]
 blr x16
 restore_mapper_args
 stp x29, x30, [sp, #-64]!
 .cfi_def_cfa_offset 64
 .cfi_offset 29, -64
 .cfi_offset 30, -56
 b manager_destructor_continuation
 .cfi_endproc
