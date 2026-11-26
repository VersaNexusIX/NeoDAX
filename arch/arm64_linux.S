.section .note.GNU-stack,"",@progbits

.global dax_platform_info
.global dax_getpid_native
.global dax_write_native

.section .data
dax_arm64_tag:
    .asciz "aarch64-linux"

.section .text
.align 2

dax_platform_info:
    adrp    x0, dax_arm64_tag
    add     x0, x0, :lo12:dax_arm64_tag
    ret

dax_getpid_native:
    mov     x8, #172
    svc     #0
    ret

dax_write_native:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    mov     x8, #64
    svc     #0
    ldp     x29, x30, [sp], #16
    ret
