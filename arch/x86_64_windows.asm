; Windows x86_64 Assembly stub for DAX
; Assemble with: ml64.exe /c /Fo dax_win64.obj dax_win64_asm.asm

_DATA SEGMENT

dax_win64_tag DB "x86_64-windows", 0

_DATA ENDS

_TEXT SEGMENT

PUBLIC dax_platform_info_win64
PUBLIC dax_getpid_win64

dax_platform_info_win64 PROC
    lea     rax, dax_win64_tag
    ret
dax_platform_info_win64 ENDP

dax_getpid_win64 PROC
    sub     rsp, 40
    mov     rcx, -1
    mov     rax, 0
    add     rsp, 40
    ret
dax_getpid_win64 ENDP

_TEXT ENDS

END
