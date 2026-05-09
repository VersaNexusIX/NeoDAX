# Architecture Cheatsheet

**Level:** Appendix
**What This Is:** Key architecture facts for x86-64, ARM64, and RISC-V side by side.

## Register Summary

| Purpose | x86-64 | ARM64 | RISC-V |
|---------|--------|-------|--------|
| Arg 1 | rdi | x0 | a0 |
| Arg 2 | rsi | x1 | a1 |
| Arg 3 | rdx | x2 | a2 |
| Arg 4 | rcx | x3 | a3 |
| Arg 5 | r8 | x4 | a4 |
| Arg 6 | r9 | x5 | a5 |
| Return | rax | x0 | a0 |
| Stack ptr | rsp | sp | sp |
| Frame ptr | rbp | x29/fp | s0/fp |
| Link reg | (on stack) | x30/lr | ra |
| Zero reg | (none) | xzr | zero |
| Scratch | rax, rcx, rdx, rsi, rdi, r8-r11 | x9-x17 | t0-t6 |
| Saved | rbx, rbp, r12-r15 | x19-x28 | s1-s11 |

## Instruction Width

| Architecture | Instruction Width |
|-------------|------------------|
| x86-64 | Variable (1-15 bytes) |
| ARM64 | Fixed 4 bytes |
| RISC-V | 4 bytes (2 bytes for C extension) |

## Function Call Mechanics

x86-64:
- `call target` pushes RIP then jumps
- `ret` pops and jumps
- Return address is on the stack at [rsp] on function entry

ARM64:
- `bl target` stores return address in x30 (lr)
- `ret` branches to x30
- `blr x0` is an indirect call (calls function pointer in x0)

RISC-V:
- `jal ra, target` stores return address in ra
- `jalr zero, ra, 0` returns (often written as `ret`)
- `jalr ra, t0, 0` is an indirect call

## System Calls

x86-64 Linux:
```
; syscall number in rax
; args: rdi, rsi, rdx, r10, r8, r9
; result in rax
syscall
```

ARM64 Linux:
```
; syscall number in x8
; args: x0, x1, x2, x3, x4, x5
; result in x0
svc #0
```

RISC-V Linux:
```
; syscall number in a7
; args: a0-a5
; result in a0
ecall
```

## Magic Numbers

| Format | Bytes | Value |
|--------|-------|-------|
| ELF | 7F 45 4C 46 | .ELF |
| PE | 4D 5A | MZ |
| Mach-O 64-bit LE | CF FA ED FE | (FEEDFACF) |
| Mach-O FAT | CA FE BA BE | (CAFEBABE) |
| DAXC | 4E 45 4F 58 | NEOX |

## Entropy Thresholds (NeoDAX)

| Range | Classification |
|-------|---------------|
| 0.0 - 3.0 | Very structured (sparse data, ASCII) |
| 3.0 - 6.0 | Normal (compiled code, data) |
| 6.0 - 6.8 | Moderately compressed |
| 6.8 - 7.0 | HIGH (likely compressed or encrypted) |
| 7.0 - 8.0 | PACKED (almost certainly compressed or encrypted) |

## Section Types (NeoDAX Normalization)

| NeoDAX Type | ELF Name | PE Name | Mach-O Name |
|-------------|----------|---------|-------------|
| code | .text | .text | __TEXT,__text |
| data | .data | .data | __DATA,__data |
| rodata | .rodata | .rdata | __TEXT,__cstring |
| bss | .bss | .bss | __DATA,__bss |
| plt | .plt | (none) | __TEXT,__stubs |
| got | .got | (none) | __DATA,__got |
