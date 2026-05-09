# Function Detection

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 18_entry_points_and_flow.md
**What You Will Learn:** How NeoDAX detects functions and what the results tell you.

## Why Function Detection Matters

Functions are the unit of analysis in reverse engineering. When you understand what each function does, you understand the program. Everything else: CFGs, xrefs, decompilation, is built on top of function boundaries.

## How NeoDAX Detects Functions

NeoDAX uses two strategies in combination:

**Symbol-guided detection:** If the binary has symbols, every symbol of type `func` becomes a known function boundary. This is reliable and gives function names.

**Heuristic detection:** For stripped binaries, NeoDAX scans the code sections looking for function prologue patterns:

For x86-64:
- `push rbp` followed by `mov rbp, rsp`
- `sub rsp, N` (stack allocation)
- `endbr64` (Intel CET)

For ARM64:
- `stp x29, x30, [sp, #-N]!` (frame pointer and link register save)
- `sub sp, sp, #N` (stack allocation without frame pointer)
- `paciasp` (pointer authentication)
- `bti c` or `bti j` (branch target identification)

Both strategies run together. On unstripped binaries, symbols give names and heuristics catch any functions that lack symbols.

## Running Function Detection

```bash
./neodax -f /bin/ls
```

Output looks like:

```
sub_401000  [0x401000 .. 0x40106c]  108 bytes  27 insns
main        [0x401070 .. 0x401200]  400 bytes  95 insns  [calls] [loops]
sub_401210  [0x401210 .. 0x401240]  48 bytes   12 insns
```

Each line shows:
- Function name (or `sub_<address>` for unnamed functions)
- Address range
- Size in bytes
- Instruction count
- Flags: `[calls]` if the function calls other functions, `[loops]` if loops are detected

## Function Boundaries

A function boundary has a start address and an end address. The end is where execution leaves the function.

NeoDAX sets the end address at the last `ret` (or equivalent) instruction. If a function uses tail calls (`jmp` to another function), the end is set at the tail call.

For functions where the end cannot be determined (some compiler-generated stubs or obfuscated code), the end address equals the start address, indicating an unknown boundary.

## Hottest Functions

```bash
./neodax -f -r /bin/ls
```

After building cross-references, NeoDAX can identify the most-called functions:

```bash
./neodax -f -r -v /bin/ls
```

Functions that are called many times are candidates for performance-critical routines, common utilities, or important dispatch points.

## Practice

1. Run `./neodax -f /bin/ls` and count the total number of detected functions.
2. Find the largest function by byte count.
3. Find a function with both `[calls]` and `[loops]` flags.
4. Compile a small C program with two or three functions and verify that NeoDAX detects them all.

## Next

Continue to `21_cross_references.md`.
