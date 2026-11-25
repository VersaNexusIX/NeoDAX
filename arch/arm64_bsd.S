.section .note.GNU-stack,"",@progbits

.global dax_platform_info_bsd_arm64
.global dax_getpid_bsd_arm64

.section .data
dax_arm64_bsd_tag:
    .asciz "aarch64-bsd"

.section .text
.align 2

dax_platform_info_bsd_arm64:
    adrp    x0, dax_arm64_bsd_tag
    add     x0, x0, :lo12:dax_arm64_bsd_tag
    ret

dax_getpid_bsd_arm64:
    mov     x8, #20
    svc     #0
    ret
