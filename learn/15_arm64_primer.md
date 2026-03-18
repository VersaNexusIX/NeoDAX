# ARM64 Primer

**Level:** 1 - Basic Analysis
**Prerequisites:** 14_x86_64_primer.md
**What You Will Learn:** Enough ARM64 assembly to read NeoDAX disassembly for Android and Apple Silicon binaries.

## Overview

ARM64 (also called AArch64) is the instruction set used by Apple Silicon Macs, iPhones, Android phones, and many embedded systems. It is a RISC architecture: instructions are fixed-width (4 bytes each) and have a more regular structure than x86-64.

## Registers

ARM64 has 31 general-purpose 64-bit registers named x0 through x30, plus a zero register:

```
x0  - x7  : function arguments and return values
x8        : indirect result location / syscall number
x9  - x15 : temporary (caller-saved)
x16 - x17 : intra-procedure call scratch
x18       : platform register (do not use on iOS)
x19 - x28 : callee-saved registers
x29 (fp)  : frame pointer
x30 (lr)  : link register (return address)
sp        : stack pointer
xzr       : zero register (reads as 0, writes discarded)
```

Each 64-bit x register has a 32-bit alias: `x0` contains the full 64 bits, `w0` refers to the lower 32 bits.

## Calling Convention

Function arguments go in x0 through x7 in order. The return value goes in x0. If a function returns a 128-bit value, x1 holds the upper 64 bits.

## Common Instructions

**Data movement:**
```
mov  x0, x1          ; copy x1 into x0
ldr  x0, [x1]        ; load 8 bytes from memory at x1
ldr  w0, [x1, #4]    ; load 4 bytes from x1+4 into w0
str  x0, [x1]        ; store x0 to memory at x1
adr  x0, label       ; load PC-relative address of label into x0
adrp x0, label@PAGE  ; load page-aligned PC-relative address
add  x0, x0, label@PAGEOFF  ; add page offset (often follows adrp)
```

**Arithmetic:**
```
add  x0, x1, x2      ; x0 = x1 + x2
sub  x0, x1, x2      ; x0 = x1 - x2
mul  x0, x1, x2      ; x0 = x1 * x2
and  x0, x1, x2      ; x0 = x1 & x2
orr  x0, x1, x2      ; x0 = x1 | x2
eor  x0, x1, x2      ; x0 = x1 ^ x2
lsl  x0, x1, #2      ; x0 = x1 << 2
lsr  x0, x1, #1      ; x0 = x1 >> 1 (logical)
asr  x0, x1, #1      ; x0 = x1 >> 1 (arithmetic)
```

**Stack operations:**
```
stp  x29, x30, [sp, #-16]!  ; save frame pointer and link register
ldp  x29, x30, [sp], #16    ; restore frame pointer and link register
```

The `!` means write-back: the address is computed and then written back to the base register. This is the standard ARM64 function prologue.

**Branches:**
```
b    label            ; unconditional branch
bl   label            ; branch with link (call: saves return address in x30/lr)
br   x0               ; branch to address in x0
blr  x0               ; branch with link to address in x0 (indirect call)
ret                   ; return: branch to x30 (lr)
cbz  x0, label        ; branch if x0 == 0
cbnz x0, label        ; branch if x0 != 0
```

**Comparison:**
```
cmp  x0, x1           ; set flags based on x0 - x1
tst  x0, x1           ; set flags based on x0 & x1
b.eq label            ; branch if equal
b.ne label            ; branch if not equal
b.gt label            ; branch if greater (signed)
b.lt label            ; branch if less (signed)
```

## Function Prologue and Epilogue

A typical ARM64 function begins with:

```
stp  x29, x30, [sp, #-32]!   ; allocate 32 bytes, save fp and lr
mov  x29, sp                  ; set frame pointer
```

And ends with:

```
ldp  x29, x30, [sp], #32     ; restore fp and lr, deallocate
ret                            ; return to caller
```

NeoDAX detects these patterns when identifying function boundaries.

## Pointer Authentication

macOS and iOS use pointer authentication (PA) instructions. You may see:

```
paciasp    ; authenticate x30 (lr) using sp
autiasp    ; verify x30 authentication
retaa      ; authenticated return
```

These are security features that make it harder to corrupt return addresses. NeoDAX recognizes them during function detection.

## Practice

On an ARM64 system (Apple Silicon Mac or Android with Termux):

1. Disassemble `/bin/ls` with NeoDAX.
2. Find the function prologue `stp x29, x30, [sp, ...]`.
3. Count how many bytes are allocated on the stack by the first function you see.
4. Find a `bl` instruction and identify the callee from symbol annotations.

## Next

Continue to `16_riscv_primer.md`.
