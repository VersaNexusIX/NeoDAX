.section .note.GNU-stack,"",@progbits

.global dax_platform_info_bsd
.global dax_getpid_bsd
.global dax_write_bsd

.section .data
dax_bsd_tag:
    .asciz "x86_64-bsd"

.section .text

dax_platform_info_bsd:
    lea     dax_bsd_tag(%rip), %rax
    ret

dax_getpid_bsd:
    mov     $20, %rax
    syscall
    ret

dax_write_bsd:
    push    %rbp
    mov     %rsp, %rbp
    mov     $4, %rax
    syscall
    pop     %rbp
    ret
