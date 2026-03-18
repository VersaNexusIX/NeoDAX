# Common Patterns Reference

**Level:** Appendix
**What This Is:** A reference sheet of common assembly patterns and their meanings.

## Function Boundaries

x86-64 prologue:
```
push   rbp
mov    rbp, rsp
sub    rsp, N         ; N = local variable space
```

x86-64 epilogue:
```
leave                 ; equivalent to: mov rsp, rbp; pop rbp
ret
```

ARM64 prologue:
```
stp    x29, x30, [sp, #-N]!
mov    x29, sp
```

ARM64 epilogue:
```
ldp    x29, x30, [sp], #N
ret
```

## Calling Conventions

x86-64 Linux (arguments):
```
arg1 = rdi
arg2 = rsi
arg3 = rdx
arg4 = rcx
arg5 = r8
arg6 = r9
return = rax
```

ARM64 (arguments):
```
arg1 = x0
arg2 = x1
arg3 = x2
...
arg8 = x7
return = x0
```

## Common Idioms

Zero a register (x86-64):
```
xor    eax, eax       ; faster than mov eax, 0
```

Test if zero:
```
test   rax, rax       ; sets ZF if rax == 0
jz     somewhere      ; jump if zero
```

Multiply by power of 2:
```
shl    rax, 3         ; rax = rax * 8
lea    rax, [rax*4]   ; rax = rax * 4
```

Array access (element size 8):
```
mov    rax, [rbx + rcx*8]    ; rax = array[index]
```

Null check:
```
test   rdi, rdi
jz     handle_null
```

## String Operations

Strlen pattern:
```
; rdi = string pointer
xor    eax, eax
repne  scasb          ; scan for null byte
not    rcx
dec    rcx            ; rcx = string length
```

Copy loop:
```
loop:
  movzx  eax, BYTE PTR [rsi + rcx]
  mov    BYTE PTR [rdi + rcx], al
  inc    rcx
  test   al, al
  jnz    loop
```

## Heap Patterns

Typical allocation:
```
mov    edi, SIZE      ; size argument
call   malloc@plt
test   rax, rax       ; check for NULL
jz     alloc_failed
mov    rbx, rax       ; save pointer
```

Typical free:
```
mov    rdi, rbx       ; pointer argument
call   free@plt
xor    ebx, ebx       ; null out saved pointer (good practice)
```

## Conditional Patterns

Ternary (a > b ? x : y):
```
cmp    rdi, rsi
jle    else_branch
mov    rax, x
jmp    end
else_branch:
mov    rax, y
end:
```

Min/max pattern:
```
cmp    rdi, rsi
cmovg  rdi, rsi       ; rdi = min(rdi, rsi)
```

## Loop Patterns

Counted loop (for i = 0; i < N; i++):
```
xor    ecx, ecx       ; i = 0
loop_top:
  ; loop body using rcx as index
  inc    rcx
  cmp    rcx, N
  jl     loop_top
```

While loop (while *ptr != 0):
```
loop_top:
  movzx  eax, BYTE PTR [rdi]
  test   al, al
  jz     loop_end
  ; body
  inc    rdi
  jmp    loop_top
loop_end:
```
