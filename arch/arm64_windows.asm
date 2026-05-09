; Windows ARM64 Assembly stub for DAX
; Assemble with MSVC armasm64

    AREA |.data|, DATA

dax_arm64_win_tag
    DCB "aarch64-windows", 0

    AREA |.text|, CODE, READONLY

    EXPORT dax_platform_info_win_arm64
    EXPORT dax_getpid_win_arm64

dax_platform_info_win_arm64 PROC
    ADRP    x0, dax_arm64_win_tag
    ADD     x0, x0, dax_arm64_win_tag
    RET
    ENDP

dax_getpid_win_arm64 PROC
    STP     x29, x30, [sp, #-16]!
    MOV     x29, sp
    LDP     x29, x30, [sp], #16
    RET
    ENDP

    END
