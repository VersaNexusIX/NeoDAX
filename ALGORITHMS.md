# Analysis Algorithms

Technical explanation of the algorithms used in NeoDAX's analysis engine.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## CFG Builder — Two-Pass Algorithm

**File:** `src/cfg.c`

### The Problem with Single-Pass CFG

A naive single-pass CFG builder decodes instructions linearly. When it hits an unconditional branch (ARM64 `b`, x86-64 `jmp`), it creates an edge to the target — but then continues decoding the bytes immediately following. If those bytes are intentional dead code (jump trick, opaque predicate padding like `0xdeadbeef`), the decoder emits garbage instructions and creates phantom blocks.

### NeoDAX Two-Pass Solution

**Pass 1 — Pre-registration:**
Scan the entire function body. For every branch instruction with a known target address, call `find_or_add_block()` to register that target as a block boundary *before* the main analysis. This creates an empty block placeholder at every reachable address.

**Pass 2 — Main build:**
Walk instructions sequentially. At each unconditional branch:
1. Add a jump edge to the target block
2. Scan forward byte-by-byte (ARM64: 4 bytes at a time) until a **pre-registered block boundary** is found
3. Resume decoding from that boundary — dead bytes are silently skipped

Conditional branches register both the true target and the fall-through address during Pass 1, so neither side is ever treated as dead code.

**Applies to all formats** — ELF, PE, and Mach-O use the same two-pass builder. Mach-O binaries often have jump tricks too (compiler optimisations, obfuscation).

**Result for `nightmare4.c` jump trick:**
```asm
  b  2f              ; unconditional jump
  .byte 0xde,0xad,0xbe,0xef   ; dead bytes — SKIPPED
  .byte 0xff,0xff,0xff,0xff   ; dead bytes — SKIPPED
2:
  add  w0, w0, #7   ; correctly identified as next block
```

---

## Shannon Entropy Analysis

**File:** `src/entropy.c` · Function: `dax_entropy_scan()`

Shannon entropy measures the information density of a byte sequence:

```
H = -∑ pᵢ × log₂(pᵢ)
```

Where `pᵢ` is the probability of byte value `i` (count[i] / window_size).

**Parameters:**
- Window size: 256 bytes
- Step size: 64 bytes (75% overlap)
- High threshold: ≥ 6.8 bits/byte
- Packed/encrypted threshold: ≥ 7.0 bits/byte

**What each range means:**

| Range | Typical Content |
|-------|----------------|
| 0.0 – 1.0 | Mostly null bytes (BSS, alignment padding) |
| 1.0 – 4.0 | Text strings, structured data |
| 4.0 – 5.5 | Code (x86-64 typically 5.0–5.8) |
| 5.5 – 6.8 | Mixed data, ARM64 code |
| 6.8 – 7.0 | High density — compressed tables, lookup arrays |
| 7.0 – 8.0 | Encrypted, compressed, or packed content |

Maximum entropy is 8.0 bits/byte (uniform random distribution).

---

## Recursive Descent Disassembly

**File:** `src/entropy.c` · Function: `dax_rda_section()`

### Algorithm

Uses a BFS (Breadth-First Search) work queue:

1. **Seed the queue** with:
   - Section entry point (start of section)
   - All symbols that fall within the section

2. **For each address in the queue:**
   - If already visited → skip
   - Decode the instruction at this address
   - Add the address to the visited set
   - Enqueue:
     - Fall-through address (for non-unconditional instructions)
     - Branch target (if within the section)
     - Call target (if within the section)
   - For unconditional branches: do NOT enqueue fall-through

3. **Output:** Sort all discovered instructions by address. Gaps between discovered instructions are marked as `[DEAD: 0xstart .. 0xend (N bytes)]`.

### Coverage Metric

After RDA completes, `covered_bytes / total_section_bytes × 100` gives a code coverage percentage.

For Mach-O FAT binaries, NeoDAX selects the ARM64 slice before RDA, so RDA runs on the correct architecture slice. A 60–80% coverage on a typical ELF `.text` section is normal (alignment padding, switch table data, etc. account for the rest). Values below 40% suggest heavy obfuscation.

---

## Instruction Validity Filter

**File:** `src/entropy.c` · Function: `dax_ivf_scan()`

Scans code sections linearly and flags:

### Invalid Opcodes

Bytes that the decoder cannot interpret produce mnemonic `??` (ARM64) or return `len <= 0` (x86-64). Each occurrence is flagged as `INVALID`.

### Privileged Instructions in Userspace

Checked against a table of privileged mnemonics:

- **ARM64:** `msr`, `mrs`, `at`, `dc`, `ic`, `tlbi`, `sys`, `eret`, `drps`, `hlt`, `brk`, `smc`, `hvc`, `wfi`, `wfe`
- **x86-64:** `cli`, `sti`, `hlt`, `in`, `out`, `lidt`, `lgdt`, `rdmsr`, `wrmsr`, `vmcall`, `vmlaunch`, etc.

A userspace binary containing these instructions is either a kernel module disguised as a userspace file, or contains obfuscated code that uses privileged mnemonics as opaque values.

### NOP Runs

A run of 8 or more consecutive `nop`/`endbr64` instructions is flagged as `NOP-RUN`. Normal compilers emit at most 1–7 NOPs for alignment. Longer runs suggest anti-disassembly padding or function erasing.

### INT3 Runs (x86-64 only)

A run of 3 or more `int3` bytes (`0xCC`) is flagged. Single `int3` after function epilogue is normal (debugger trap / padding). Multiple consecutive ones suggest anti-debugging tricks or padding.

### Dead Bytes After Unconditional Branches

When an unconditional branch is detected and the bytes immediately following do not belong to any known function or symbol, they are flagged as `DEAD`. This catches jump tricks, opaque predicates, and anti-disassembly traps.

---

## Symbolic Execution

**File:** `src/symexec.c`

NeoDAX uses a **symbolic expression tree** model:

- Each register starts as a `SEXPR_VAR` node (symbolic, unknown)
- When a register is assigned a constant, it becomes `SEXPR_CONST`
- Binary operations produce `SEXPR_binop(left, right)` nodes
- When both operands of a binary op are concrete, the result is computed numerically (constant folding)

**Supported operations:** `add`, `sub`, `and`, `or`, `eor`/`xor`, `lsl`, `lsr`, `asr`, `mov`, `movz`, `cmp`

**Example trace for `tricky(42)`:**
```
0x790  mov  w8, w0         → w8 = x0_sym     (still symbolic)
0x794  b    0x7a4          → branch taken
0x7a4  add  w0, w0, #7    → w0 = (x0_sym + 0x7)
0x7a8  movz w9, #0x55     → w9 = 0x55        (concrete)
0x7ac  eor  w0, w0, w9    → w0 = ((x0_sym + 0x7) ^ 0x55)
[RET] Symbolic return: ((x0_sym + 0x7) ^ 0x55)
```

---

## SSA Lifting

**File:** `src/decomp.c`

Static Single Assignment form ensures each variable is assigned exactly once. NeoDAX implements a simplified SSA — no phi-node insertion, but each register write creates a new versioned variable:

```
mov  w8, w0      →  r8_1  = r0_0
add  w0, w0, #7  →  r0_2  = r0_0 + 0x7
movz w9, #0x55   →  r9_1  = 0x55
eor  w0, w0, w9  →  r0_3  = r0_2 ^ r9_1
ret              →  ret r0_3
```

The decompiler then renders this as pseudo-C:

```c
int32_t tricky(int arg0) {
  r8 = arg0;
  r0 = arg0 + 0x7;
  r9 = 0x55;
  r0 = r0 ^ r9;
  return r0;
}
```

---

## Concrete Emulator

**File:** `src/emulate.c`

NeoDAX's ARM64 emulator models:

- **32 × 64-bit registers** (`x0`–`x30`, `xzr`/`sp`)
- **CPSR flags** (Z, N, C, V) — updated by `cmp`, `adds`, `subs`, `ands`, `tst`
- **Page-based memory** — 64 pages × 4 KB each, allocated on first write
- **Binary section memory** — `ldr` from unmapped addresses falls back to binary file data (for `.rodata` access)
- **Stack** — virtual stack at `0x7fff0000`, grows downward

Terminates cleanly at:
- `ret` — prints final `x0` as return value
- `bl` external — prints the target address, stops (doesn't follow into library calls)
- `blr` — indirect call, prints target register value
- 8192 instructions — prevents infinite loops

Unimplemented instructions cause a graceful halt with a `"unimplemented: <mnemonic>"` message rather than a crash.
