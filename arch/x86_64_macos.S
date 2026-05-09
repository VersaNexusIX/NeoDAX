/* NeoDAX — macOS x86-64 platform stubs (Mach-O syntax) */

.section __TEXT,__text,regular,pure_instructions
.align 4

.global _dax_platform_info_bsd
.global _dax_getpid_bsd
.global _dax_write_bsd
.global _dax_platform_info
.global _dax_getpid_native
.global _dax_write_native

.section __TEXT,__cstring,cstring_literals
dax_x86_macos_tag:
    .asciz "x86_64-macos"

.section __TEXT,__text,regular,pure_instructions
.align 4

_dax_platform_info_bsd:
_dax_platform_info:
    leaq    dax_x86_macos_tag(%rip), %rax
    ret

_dax_getpid_bsd:
_dax_getpid_native:
    /* macOS x86-64 getpid = syscall 0x14 via syscall instruction */
    /* Or just return 0 — not used in core analysis */
    xorl    %eax, %eax
    ret

_dax_write_bsd:
_dax_write_native:
    /* write(fd, buf, count) — macOS syscall 0x2000004 */
    pushq   %rbp
    movq    %rsp, %rbp
    movl    $0x2000004, %eax
    syscall
    popq    %rbp
    ret
