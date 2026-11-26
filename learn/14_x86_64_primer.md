# x86-64 Primer

**Level:** 1 - Basic Analysis
**Prerequisites:** 13_reading_disassembly.md
**What You Will Learn:** Enough x86-64 assembly to read NeoDAX disassembly output for common programs.

## Registers

x86-64 has 16 general-purpose 64-bit registers:

```
rax  rbx  rcx  rdx
rsi  rdi  rbp  rsp
r8   r9   r10  r11
r12  r13  r14  r15
```

Each register can be accessed at different widths:
- `rax`: 64-bit
- `eax`: lower 32 bits
- `ax`: lower 16 bits
- `al`: lower 8 bits, `ah`: bits 8-15

## Calling Conventions

On Linux (System V AMD64 ABI), function arguments are passed in registers in this order:

```
rdi  rsi  rdx  rcx  r8  r9
```

Additional arguments go on the stack. The return value goes in `rax`.

On Windows (Microsoft x64), the order is:

```
rcx  rdx  r8  r9
```

When you see `mov rdi, <value>` followed by `call <function>`, that value is the first argument to the function.

## Common Instructions

**Data movement:**
```
mov  rax, rbx        ; copy rbx into rax
mov  rax, [rbp-8]    ; load 8 bytes from memory at rbp-8
mov  [rbp-8], rax    ; store rax to memory at rbp-8
lea  rax, [rbp-8]    ; load the address rbp-8 (not the value)
push rbx             ; push rbx onto stack, decrement rsp by 8
pop  rbx             ; pop from stack into rbx, increment rsp by 8
```

**Arithmetic:**
```
add  rax, rbx        ; rax = rax + rbx
sub  rax, 8          ; rax = rax - 8
imul rax, rbx        ; rax = rax * rbx (signed)
xor  rax, rax        ; rax = 0 (common idiom to zero a register)
and  rax, 0xff       ; isolate lower 8 bits
or   rax, rbx        ; bitwise or
shl  rax, 2          ; shift left by 2 (multiply by 4)
shr  rax, 1          ; shift right by 1 (divide by 2)
```

**Comparison and branching:**
```
cmp  rax, 0         ; set flags based on rax - 0
test rax, rax       ; set flags based on rax & rax (checks if zero)
je   0x401200       ; jump if equal (zero flag set)
jne  0x401200       ; jump if not equal
jg   0x401200       ; jump if greater (signed)
jl   0x401200       ; jump if less (signed)
ja   0x401200       ; jump if above (unsigned)
jmp  0x401200       ; unconditional jump
```

**Function calls:**
```
call 0x401234       ; push rip, jump to 0x401234
ret                 ; pop rip and jump to it
```

## Reading a Simple Function

Given this disassembly:

```
0x401000  push   rbp
0x401001  mov    rbp, rsp
0x401004  mov    DWORD PTR [rbp-4], edi   ; save first arg (int)
0x401007  cmp    DWORD PTR [rbp-4], 0     ; compare arg to 0
0x40100b  jle    0x401015                  ; jump if <= 0
0x40100d  mov    eax, 1                    ; return 1
0x401012  pop    rbp
0x401013  ret
0x401015  mov    eax, 0                    ; return 0
0x40101a  pop    rbp
0x40101b  ret
```

This function takes one integer argument, returns 1 if it is positive, and 0 otherwise.

## Stack Frame Layout

The stack grows downward. `rsp` points to the top of the stack (lowest address). Local variables live below `rbp`:

```
[rbp-4]   : 4-byte local variable
[rbp-8]   : another 4-byte local variable
[rbp-16]  : 8-byte local variable or pointer
[rbp+8]   : return address (caller pushed it with call)
[rbp+16]  : first argument if passed on stack
```

## Practice

1. Disassemble `/bin/ls` and find a function that calls `malloc`.
2. What argument is passed to `malloc` (look at `rdi` value before the call)?
3. Find a conditional jump. What is the comparison being made?
4. Identify the prologue and epilogue of any function.

## Next

Continue to `15_arm64_primer.md`.
