# Function Detection

How NeoDAX identifies function boundaries in stripped and unstripped binaries.

> **Implementation:** `src/analysis.c` — `dax_func_detect()`  
> **CLI flag:** `-f`  
> **JS API:** `bin.functions()`

---

## Strategy Overview

Function detection runs in two phases:

1. **Symbol-guided** — for each symbol of type `SYM_FUNC`, register a function at that address
2. **Heuristic** — scan code bytes for prologue patterns; start a new function when one is found

Both phases run regardless of whether symbols are present. On unstripped binaries, most functions are found via symbols. On stripped binaries, only heuristics are used.

---

## ARM64 Prologue Patterns

NeoDAX recognises these ARM64 function entry sequences:

| Pattern | Example | Notes |
|---------|---------|-------|
| `paciasp` | `paciasp` | Pointer authentication (iOS/macOS security) |
| `autiasp` | `autiasp` | Pointer auth epilogue hint |
| `bti c/j` | `bti c` | Branch target identification |
| `stp x29, x30, [sp, #-N]!` | `stp x29, x30, [sp, #-16]!` | Frame pointer + link register |
| `stp xN, xM, [sp, #-N]!` | `stp x20, x19, [sp, #-32]!` | Any callee-saved pre-index save |
| `sub sp, sp, #N` | `sub sp, sp, #48` | Stack allocation — **most common macOS pattern** |
| Section entry point | `cur_addr == base_addr` | Fallback — guarantees ≥1 function |

### Why `sub sp, sp, #N` matters

Linux ARM64 binaries compiled with `-fno-omit-frame-pointer` use `stp x29,x30` heavily. But macOS ARM64 binaries — especially those compiled with the Apple LLVM toolchain — frequently start functions with just a stack allocation:

```asm
; macOS ARM64 function, no frame pointer
sub  sp, sp, #48        ; ← NeoDAX detects this as function start
stp  x20, x19, [sp, #32]
; ... function body ...
ldp  x20, x19, [sp, #32]
add  sp, sp, #48
ret
```

Without this pattern, all such functions would be missed on macOS stripped binaries.

---

## x86-64 Prologue Patterns

| Pattern | Example |
|---------|---------|
| `push rbp` + `mov rbp, rsp` | Classic frame pointer setup |
| `push rbp` alone | Partial frame setup |
| `sub rsp, N` | Stack allocation |
| `endbr64` | Intel CET indirect branch tracking |
| Symbol at address | Any `SYM_FUNC` entry |

---

## RISC-V Prologue Patterns

| Pattern | Example |
|---------|---------|
| `addi sp, sp, -N` | Stack allocation |
| `sd ra, N(sp)` | Save return address |
| Symbol at address | Any `SYM_FUNC` entry |

---

## Function End Detection

A function ends when:

| Condition | Architecture |
|-----------|-------------|
| `ret` / `retaa` / `retab` | ARM64 |
| `ret` / `retq` | x86-64 |
| `jalr zero, ra, 0` | RISC-V |
| Start of next known function | All |
| End of section | All (fallback) |

When a function is never terminated (e.g. tail calls using `b target` or `br x30`), `fn.end` is set to `fn.start` (unknown boundary). In JS, `bin.functions()` always returns `fn.end >= fn.start`.

---

## Tail Call Detection

Tail calls — `b target` (ARM64) or `jmp target` (x86-64) to a different function — end the current function. NeoDAX handles this in the CFG builder (two-pass): the target is registered as a new block boundary in pass 1; in pass 2, the unconditional branch creates an exit edge.

In function detection (heuristic mode), a tail call to a known symbol ends the current function and may start a new one at the target.

---

## JavaScript API

```js
neodax.withBinary('./binary', bin => {
    const fns = bin.functions();
    // fns is always an array (never null)
    // fns.length >= 1 on any binary with a code section

    fns.forEach(f => {
        console.log(f.name);       // 'main', 'sub_401000', etc.
        console.log(f.start);      // bigint vaddr
        console.log(f.end);        // bigint vaddr (>= start, may equal start if unknown)
        console.log(f.size);       // bigint (end - start, or 0 if unknown)
        console.log(f.insnCount);  // uint32
        console.log(f.hasLoops);   // boolean
        console.log(f.hasCalls);   // boolean
    });

    // Hottest functions by call count
    const hot = bin.hottestFunctions(10);
    hot.forEach(h => console.log(h.callCount, h.function.name));
});
```

---

## CLI Output

```
$ ./neodax -f ./binary

  sub_400690  [0x400690 .. 0x4006b4]  36 bytes  9 insns
  sub_4006c0  [0x4006c0 .. 0x4006d8]  24 bytes  6 insns
  main        [0x4006e0 .. 0x400754]  116 bytes  29 insns  [calls]
```

---

## Limitations

- **Indirect calls** (`blr x8`, `call rax`) — the callee is not known statically; the function boundary is recorded but the callee is not added automatically
- **Tail calls to external symbols** — the call target is outside the section; treated as function exit
- **Obfuscated prologues** — jump-obfuscated or compiler-encrypted function starts are not detected; use `-R` (recursive descent) which follows all reachable code from entry
- **Very small functions** — single-instruction functions (`ret` only) are detected only if a symbol or prologue precedes them
