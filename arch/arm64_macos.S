/* NeoDAX — macOS AArch64 platform stubs (Mach-O syntax) */

.section __TEXT,__text,regular,pure_instructions
.align 2

.global _dax_platform_info_bsd_arm64
.global _dax_getpid_bsd_arm64
.global _dax_platform_info
.global _dax_getpid_native
.global _dax_write_native

/* macOS uses leading underscore for C symbols */

.section __TEXT,__cstring,cstring_literals
dax_arm64_macos_tag:
    .asciz "aarch64-macos"

.section __TEXT,__text,regular,pure_instructions
.align 2

_dax_platform_info_bsd_arm64:
_dax_platform_info:
    adrp    x0, dax_arm64_macos_tag@PAGE
    add     x0, x0, dax_arm64_macos_tag@PAGEOFF
    ret

_dax_getpid_bsd_arm64:
_dax_getpid_native:
    /* macOS ARM64 getpid = syscall 20, but use libc via inline C is safer */
    /* Return 0 as fallback — not used in core analysis */
    mov     x0, #0
    ret

_dax_write_native:
    /* write(fd, buf, count) — syscall 4 on macOS */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    mov     x16, #4
    svc     #0x80
    ldp     x29, x30, [sp], #16
    ret
