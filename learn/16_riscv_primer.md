# RISC-V Primer

**Level:** 1 - Basic Analysis
**Prerequisites:** 15_arm64_primer.md
**What You Will Learn:** Enough RISC-V RV64 assembly to understand NeoDAX output for RISC-V binaries.

## Overview

RISC-V is an open-source instruction set architecture. NeoDAX supports the RV64GC variant: the 64-bit base ISA with standard extensions G (general) and C (compressed 16-bit instructions).

RISC-V is increasingly common in embedded systems, research platforms, and some single-board computers. While you may not encounter it as often as x86-64 or ARM64, understanding its basics rounds out your analysis knowledge.

## Registers

RISC-V has 32 registers named x0 through x31 with conventional aliases:

```
x0  (zero) : always reads as 0, writes discarded
x1  (ra)   : return address
x2  (sp)   : stack pointer
x3  (gp)   : global pointer
x4  (tp)   : thread pointer
x5  (t0)   : temporary
x6  (t1)   : temporary
x7  (t2)   : temporary
x8  (s0/fp): saved register / frame pointer
x9  (s1)   : saved register
x10 (a0)   : argument / return value
x11 (a1)   : argument / return value
x12 (a2)   : argument
...
x17 (a7)   : argument / syscall number
x18 (s2) - x27 (s11): saved registers
x28 (t3) - x31 (t6): temporaries
```

## Calling Convention

Arguments go in a0 through a7. Return values go in a0 (and a1 for 128-bit returns). The ra register holds the return address.

## Common Instructions

**Data movement:**
```
mv   a0, a1           ; copy a1 into a0 (pseudo-instruction for add a0, a1, zero)
li   a0, 42           ; load immediate 42 into a0
la   a0, symbol       ; load address of symbol into a0
lw   a0, 4(a1)        ; load 32-bit word from a1+4
ld   a0, 8(a1)        ; load 64-bit doubleword from a1+8
sw   a0, 4(a1)        ; store 32-bit word to a1+4
sd   a0, 8(a1)        ; store 64-bit doubleword to a1+8
```

**Arithmetic:**
```
add  a0, a1, a2       ; a0 = a1 + a2
sub  a0, a1, a2       ; a0 = a1 - a2
addi a0, a1, 4        ; a0 = a1 + 4 (immediate add)
mul  a0, a1, a2       ; a0 = a1 * a2
and  a0, a1, a2       ; a0 = a1 & a2
or   a0, a1, a2       ; a0 = a1 | a2
xor  a0, a1, a2       ; a0 = a1 ^ a2
sll  a0, a1, a2       ; a0 = a1 << a2
srl  a0, a1, a2       ; a0 = a1 >> a2 (logical)
sra  a0, a1, a2       ; a0 = a1 >> a2 (arithmetic)
```

**Branches:**
```
j    label            ; unconditional jump (pseudo for jal zero, label)
jal  ra, label        ; jump and link (call: saves return to ra)
jalr zero, ra, 0      ; return (jump to ra)
beq  a0, a1, label    ; branch if a0 == a1
bne  a0, a1, label    ; branch if a0 != a1
blt  a0, a1, label    ; branch if a0 < a1 (signed)
bge  a0, a1, label    ; branch if a0 >= a1 (signed)
```

## Differences from x86-64 and ARM64

RISC-V has no dedicated push/pop instructions. Stack manipulation is done with explicit `addi sp, sp, -N` and store/load instructions.

There is no dedicated return instruction. The idiom `jalr zero, ra, 0` (sometimes written as `ret` by disassemblers) jumps to the address in ra.

RISC-V has no flags register. Comparisons are done with conditional branch instructions directly.

## Practice

If you have a RISC-V binary:

```bash
./neodax -l myriscvbinary
./neodax myriscvbinary
```

If not, you can cross-compile a small C program using a RISC-V toolchain and analyze the result. The key thing to practice is tracing the calling convention: finding `li a0, X` before a `jal ra, function` and understanding that X is the first argument.

## Next

Continue to `17_string_extraction.md`.
