.section .note.GNU-stack,"",@progbits

.global dax_platform_info
.global dax_getpid_native
.global dax_write_native

.section .data
dax_x86_64_tag:
    .asciz "x86_64-linux"

.section .text

dax_platform_info:
    lea     dax_x86_64_tag(%rip), %rax
    ret

dax_getpid_native:
    mov     $39, %rax
    syscall
    ret

dax_write_native:
    push    %rbp
    mov     %rsp, %rbp
    mov     %rdi, %rax
    mov     $1, %rax
    syscall
    pop     %rbp
    ret
