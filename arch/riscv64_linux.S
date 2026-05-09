.section .note.GNU-stack,"",@progbits

.global dax_platform_info_riscv
.global dax_getpid_riscv
.global dax_write_riscv

.section .data
dax_riscv_tag:
    .asciz "riscv64-linux"

.section .text
.align 2

dax_platform_info_riscv:
    la      a0, dax_riscv_tag
    ret

dax_getpid_riscv:
    li      a7, 172
    ecall
    ret

dax_write_riscv:
    addi    sp, sp, -16
    sd      ra, 8(sp)
    li      a7, 64
    ecall
    ld      ra, 8(sp)
    addi    sp, sp, 16
    ret
