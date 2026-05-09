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

## NeoDAX C API Patterns

### Safe section iteration (use in plugins and tools)

```c
for (int si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
    dax_section_t *sec = &bin->sections[si];
    if (sec->size == 0 || sec->offset > bin->size) continue;
    if (sec->size > bin->size - sec->offset) continue;   /* overflow-safe */
    uint8_t *code = bin->data + sec->offset;
    /* safe to use code[0..sec->size-1] */
}
```

### Safe function iteration

```c
for (int fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
    dax_func_t *fn = &bin->functions[fi];
    /* use fn->start, fn->end, fn->name */
}
```

### Overflow-safe midpoint (binary search)

```c
int mid = lo + (hi - lo) / 2;   /* safe */
/* NOT: (lo + hi) / 2           ← overflows when lo+hi > INT_MAX */
```

### Null-guard decoder output before string ops

```c
a64_insn_t insn;
a64_decode(raw, addr, &insn);
if (!insn.mnemonic || !insn.operands) { off += 4; continue; }
if (!strcmp(insn.mnemonic, "bl")) { /* ... */ }
```

### Early-return guard pattern

```c
void my_module(dax_binary_t *bin, int fi, FILE *out) {
    DAX_GUARD_BIN(bin);                    /* returns void if bin bad */
    if (!dax_func_idx_ok(bin, fi)) {
        dax_fault_set("fi out of bounds");
        return;
    }
    if (!out) return;
    /* safe from here */
}
```

See `77_fault_isolation.md` for the full guard pattern reference.
