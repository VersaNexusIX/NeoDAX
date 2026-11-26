# NeoDAX Architecture

This document describes the internal design of NeoDAX - how modules interact, data flows, and the design decisions behind each component.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Overview

NeoDAX is structured as a **layered analysis pipeline**:

```
┌──────────────────────────────────────────────────────────────┐
│  Input: ELF / PE / Raw binary file                           │
└───────────────────────────┬──────────────────────────────────┘
                            │
            ┌───────────────▼──────────────────┐
            │  loader.c  -  Binary Parser       │
            │  ELF32/64 + PE32/PE64+ + Raw      │
            │  Sections, metadata, SHA-256       │
            └───────────────┬──────────────────┘
                            │  dax_binary_t
                            │
            ┌───────────────▼──────────────────┐
            │  dax_guard.h — Fault Isolation    │
            │  DAX_GUARD_BIN / DAX_RUN_PASS     │
            │  dax_clamp_counts() after load    │
            └───────────────┬──────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
   ┌────▼────┐         ┌────▼────┐        ┌─────▼────┐
   │ symbols │         │ disasm  │        │ analysis │
   │ .c      │         │ .c      │        │ .c       │
   │ symtab  │         │ decode  │        │ xrefs    │
   │ dynsym  │         │ x86/    │        │ groups   │
   │ PE exp  │         │ arm64/  │        │ strings  │
   └────┬────┘         │ riscv   │        └──────────┘
        │              └────┬────┘
        │                   │
        └────────┬──────────┘
                 │
         ┌───────▼────────┐
         │  cfg.c          │
         │  Two-pass CFG   │
         │  Pre-register   │
         │  branch targets │
         │  Dead-byte skip │
         └───────┬────────┘
                 │
    ┌────────────┼──────────────────────┐
    │            │                      │
┌───▼───┐  ┌────▼────┐         ┌───────▼──────┐
│ loops │  │callgraph│         │  Advanced (ARM64+RISC-V) │
│ .c    │  │ .c      │         │  symexec.c               │
│       │  │         │         │  decomp.c                │
└───────┘  └─────────┘         │  emulate.c               │
                                └──────────────────────────┘
                 │
         ┌───────▼────────┐
         │  main.c         │
         │  CLI output     │
         │  Banner + table │
         └───────┬────────┘
                 │
        ┌────────▼────────┐
        │  daxc.c          │
        │  .daxc snapshot  │
        └─────────────────┘
```

---

## Microkernel Fault Isolation (`include/dax_guard.h`)

NeoDAX uses a microkernel-inspired fault isolation model. Each analysis pass is an independent "service". A crashing or malformed-data service is fenced off, a diagnostic is emitted, and the pipeline continues to the next pass. No single corrupt binary or bad pointer can crash the entire program.

### Three layers

**1. Input validation macros** — Check pointers, sizes, and counter bounds before any module does real work.

```c
DAX_GUARD_BIN(bin);           // returns void if bin is invalid
DAX_GUARD_BIN_RET(bin, -1);  // returns -1 if bin is invalid
DAX_GUARD_FUNC(bin, fi);      // returns void if func index OOB
DAX_GUARD_FUNC_RET(bin,fi,r); // returns r if func index OOB
```

**2. Safe array accessors** — Return NULL instead of crashing on out-of-bounds.

```c
uint8_t     *p  = dax_sec_ptr(bin, si);    // NULL if OOB or size=0
dax_func_t  *fn = dax_func_ptr(bin, fi);  // NULL if OOB
dax_block_t *b  = dax_block_ptr(bin, bi); // NULL if OOB
dax_symbol_t *s = dax_sym_ptr(bin, si);   // NULL if OOB
```

**3. Pass-level wrapper** — Every top-level call in `main.c` uses `DAX_RUN_PASS`, which clears the global fault register, executes the pass, then checks if it faulted and prints a yellow recovery notice.

```c
DAX_RUN_PASS("cfg-print", opts.color,
    dax_cfg_print(&bin, fi, &opts, stdout));
```

If the pass sets `g_dax_fault` (via `dax_fault_set("reason")`), the pipeline prints:

```
  [!] pass 'cfg-print' recovered from fault — reason
```

…and continues to the next pass. 32 pass wrappers cover every module call in `main.c`.

### Global fault register

```c
volatile int g_dax_fault;       // set by any module on fault
char         g_dax_fault_msg[]; // optional detail string
```

Defined in `main.c`, declared `extern` in `dax_guard.h`. Cleared at the start of each `DAX_RUN_PASS`.

### Counter normalization

After every loader phase and symbol load, `dax_clamp_counts(&bin)` normalizes all `dax_binary_t` counters to their `DAX_MAX_*` upper bounds, preventing arithmetic overflow or negative counts from causing unbounded loops downstream.

### Code window helper

`dax_code_window(bin, fi, &code, &sz, &base, &fn_off, &fn_end)` finds the section containing function `fi`, validates all bounds (including overflow-safe `size > bin->size - offset`), and returns the code pointer and offsets in a single call. Used by `cfg.c`, `emulate.c`, `symexec.c`.

### Loop budget guard

Decode loops that iterate over function bytes use `DAX_BUDGET_INIT(65536)` + `DAX_BUDGET_CHECK()` to prevent infinite spin on corrupt or adversarial data.

---

## Core Data Structures

All analysis state lives in two structs defined in `include/dax.h`.

### `dax_binary_t`

The central object holding all parsed and analyzed data:

```
dax_binary_t
├── data / size          Raw file bytes
├── arch / fmt / os      Architecture, format, OS/ABI
├── entry / base         Entry point, image base
├── image_size           Total mapped image size
├── code_size / data_size Aggregated section sizes
├── sha256 / build_id    File hash, GNU Build-ID
├── is_pie / is_stripped / has_debug  Metadata flags
├── sections[128]        dax_section_t array (stack)
├── symbols*             dax_symbol_t array (heap)
├── xrefs*               dax_xref_t array (heap)
├── functions*           dax_func_t array (heap)
├── blocks*              dax_block_t array (heap)
├── comments*            dax_comment_t array (heap)
└── ustrings*            dax_ustring_t array (heap)
```

All counter fields (`nsections`, `nfunctions`, `nsymbols`, etc.) are clamped to `DAX_MAX_*` constants after every load phase. Never iterate these fields without an `&& i < DAX_MAX_*` guard.

### `dax_opts_t`

Flags controlling what the CLI produces. Each flag corresponds to one analysis pass:

```
show_bytes  show_addr  color  verbose
symbols     demangle   funcs  groups   xrefs  strings
cfg         loops      callgraph  switches
unicode     symexec    ssa    decompile  emulate
section     output_daxc  start_addr  end_addr
```

---

## Module Descriptions

### `loader.c` - Binary Parser
Reads the file into memory and dispatches to ELF, PE, or Mach-O parsing. Detects format by magic bytes: `0x7fELF` → ELF, `MZ` → PE, `0xFEEDFACF`/`0xBEBAFECA` etc → Mach-O.

All section offset arithmetic uses the overflow-safe form `s->size > bin->size - s->offset` (never `s->offset + s->size > bin->size`). ELF string table (`sh_name`) accesses are bounds-checked against `sh_size` before use.

Populates:
- `bin->sections[]` - virtual address, file offset, size, flags, type
- `bin->arch`, `bin->fmt`, `bin->os`
- `bin->entry`, `bin->base`, `bin->image_size`
- `bin->is_pie`, `bin->is_stripped`, `bin->has_debug`
- `bin->build_id` - extracted from `.note.gnu.build-id`

### `symbols.c` - Symbol Loading
Reads ELF `SHT_SYMTAB` and `SHT_DYNSYM` sections, PE export directory. Filters ARM64 mapping symbols (`$x`, `$d`). Calls `dax_demangle()` for each symbol. Results in `bin->symbols[]`.

`add_symbol()` checks `bin->nsymbols < DAX_MAX_SYMBOLS` and `bin->symbols != NULL` before every write. `dax_sym_find()` uses overflow-safe midpoint `lo + (hi - lo) / 2`. ELF symbol table `st_name` is checked against `strtab_size` before pointer arithmetic.

### `analysis.c` - Classification + Xref Builder
- `dax_classify_x86()` / `dax_classify_arm64()` / `dax_classify_riscv()` - map mnemonic strings to `dax_igrp_t` categories
- `dax_xref_build()` - scans code sections decoding every instruction; when a call or branch with a known target is found, adds a `dax_xref_t`
- `dax_switch_detect()` - null-guards `opts` and `bin` before any access
- `dax_sec_classify()` - maps section names to `dax_sec_type_t`

### `disasm.c` - Disassembly Output
Produces annotated disassembly to a `FILE*`. Guards: `DAX_GUARD_BIN_RET` at each entry point, `find_section_by_name` and `find_exec_section` both check `i < DAX_MAX_SECTIONS`. All three architecture entry points (`dax_disasm_x86_64`, `dax_disasm_arm64`, `dax_disasm_riscv64`) null-check `opts` before accessing `opts->color`.

### `cfg.c` - Control Flow Graph Builder

**Two-pass algorithm:**

**Pass 1 (pre-pass):** Scan the entire function body. For every branch/call instruction with a known target, call `find_or_add_block()` to register the target address as a block boundary. Also register conditional fall-through addresses.

**Pass 2 (main pass):** Walk instructions sequentially. At each branch:
- *Conditional* - add true/false edges; `cur` continues to fall-through block
- *Unconditional* - add jump edge; then **skip forward** past dead bytes by scanning for the next pre-registered block boundary. This is the jump-trick fix.
- *Return* - mark block as `is_exit`; continue from next block boundary if any

`find_block_by_addr`, `find_or_add_block`, and `get_or_make_indirect_block` all null-check `bin->blocks` before use.

### `loops.c` - Loop Detection
Implements a simple post-dominator based back-edge detection. A back edge `(A → B)` where `B` dominates `A` indicates a loop. Uses iterative dominator computation on the CFG. All `bin->nblocks` loops capped with `&& i < DAX_MAX_BLOCKS`.

### `unicode.c` - String Scanner
Two independent scanners:

**UTF-8 scanner:** Walks bytes; at each position attempts `dax_utf8_decode()`. Accepts the string if it is NUL-terminated, has ≥ 2 characters, and contains at least one multi-byte sequence (codepoint ≥ U+0080).

**UTF-16LE scanner:** Only runs on sections not in the skip list (`.dynstr`, `.dynsym`, `.strtab`, etc.). For a candidate position:
1. Checks preceding byte is `0x00` (string boundary, not mid-sequence)
2. Decodes code units, counting `wide` (hi-byte ≠ 0) and `surrogate` pairs
3. Rejects if all hi-bytes are 0 (pure null-padded ASCII)
4. Rejects if no codepoint > U+02FF (rejects ELF binary data)
5. Requires ≥ 6 code units and ≥ 3 wide units (or surrogate pair)

### `macho.c` - Mach-O Parser

Handles macOS/iOS/macOS binaries:

**FAT/universal:** `fat_find_slice()` walks the big-endian FAT header (using `bswap32`), selects the ARM64 slice first, falls back to x86-64. File offsets in section structures are **absolute** from the start of the full FAT file - not slice-relative - so `bin->data + section->offset` is always correct.

**Magic constants:** All Mach-O magic values are defined as what a little-endian CPU *reads* from the raw bytes. `MACHO_MAGIC_64_LE = 0xFEEDFACF` (bytes `CF FA ED FE` on disk). `swap=1` only for big-endian files.

**Load command walker:** Iterates `ncmds` load commands. Handles `LC_SEGMENT_64` (sections), `LC_MAIN` (entry point = `text_vmbase + entryoff`), `LC_SYMTAB` (`nlist_64` entries, strips leading `_` from names).

**Section naming:** `__TEXT,__text` → `.text`, `__DATA,__data` → `.data`, etc.

### `entropy.c` - Entropy, RDA, IVF, Poly Map, AIRE

Five detection and intelligence modules in one file. All public entry points begin with `DAX_GUARD_BIN` and null-check `opts`/`out`. Section loops use overflow-safe bounds: `sec->size > bin->size - sec->offset`.

**`dax_entropy_scan()`** - Computes Shannon entropy (`H = -∑pᵢ log₂pᵢ`) over 256-byte sliding windows with 64-byte step. Classifies windows as normal / HIGH (≥ 6.8) / PACKED/ENCRYPTED (≥ 7.0).

**`dax_rda_section()`** - BFS from section entry + all symbols. Uses a `rda_queue_t` (bounded at 16384 entries) and a visited array (bounded at 65536). Output sorted by address with `[DEAD: ...]` markers for gaps.

**`dax_ivf_scan()`** - Linear scan checking each instruction for: invalid mnemonic (`??` or `dw`), privileged ARM64/x86-64 instructions (via static table), NOP-runs, INT3-runs, dead bytes after unconditional branches, SMC patterns, opaque predicates.

**`dax_poly_map()`** - Sliding 48-byte window across all code sections scoring 18 mutation signals.

**`dax_aire_analyze()`** - Post-processes the entire `dax_binary_t` state and synthesizes human-readable insights ranked by confidence. Context block + next-step guide + AIRE memory persistence.

`aire_count_callers()` and `aire_count_callees()` null-check `bin->xrefs` before iteration. `aire_scan_fn()` validates section bounds with overflow-safe arithmetic and null-guards decoder output.

### `symexec.c` - Symbolic Execution (ARM64, RISC-V, x86-64)
Entry points use `DAX_GUARD_BIN`. `dax_symexec_prepass()` checks `bin->functions != NULL`. Section loops use the full overflow-safe check pattern. `dax_symexec_all()` caps with `DAX_MAX_FUNCTIONS`.

### `decomp.c` - NR (NeoDAX Representation) + Decompiler (ARM64, RISC-V, x86-64)

**NR pass:** Lifts binary instructions to a 30-opcode typed IR. Each register write creates a versioned `nr_var_t` with inferred `nr_type_t`. Inter-function linkage: every `NR_CALL` carries `callee_func_idx` resolved against `bin->functions[]`.

**Decompiler pass:** Translates NR statements to pseudo-C with type-aware local declarations, argument inference, tail-call detection, rotation intrinsics.

**Program module:** `dax_decompile_all()` harvests `nr_call_edge_t[]` while lifting all functions and emits a cross-function call graph + SMC-modified function list. Uses `DAX_GUARD_BIN` at entry; iteration capped with `DAX_MAX_FUNCTIONS`.

### `emulate.c` - Concrete Emulator (ARM64 + RISC-V)
`dax_emulate_func()` uses `DAX_GUARD_BIN` + `dax_func_idx_ok()`. All section reads in `emu_read8()` use the overflow-safe pattern: `sec->size > bin->size - sec->offset`, then separate bounds check on the final offset. The PC-section lookup loop is capped with `DAX_MAX_SECTIONS`.

### `dsa.c` - Dynamic Single Assignment
Each DSA phase (`simulate`, `build_chains`, `mark_dead`, `build_phis`, `print`) is independently fenced with a per-phase fault flag (`DSA_FAULT_*`). A fault in simulate does not prevent build_chains from running on whatever data was collected. All counters use `DSA_CLAMP` before any iteration. `nresolved_indirect` and `nsmc_patches` are validated against `DSA_INDIRECT_MAX`/`DSA_SMC_MAX` before use.

---

## JS Binding Architecture

```
NeoDAX JS layer
────────────────────────────────────────────────────
js/index.js            NeoDAXBinary class
                        wraps _handle (napi external)
                        validates file exists
                        converts BigInt ↔ address
          │
          │  require('./neodax.node')
          ▼
js/src/neodax_napi.c    26 N-API functions
                        each gets handle → dax_binary_t*
                        calls ensure_symbols() / ensure_functions()
                        open_memstream() for text output
                        returns napi_value objects/arrays
          │
          │  direct C calls
          ▼
NeoDAX C core (all src/*.c)
────────────────────────────────────────────────────
```

**Handle lifecycle:**
1. `ndx_load()` - `calloc(dax_binary_t)` → `napi_create_external(ptr)`
2. Every other function - `get_handle()` unwraps the external back to `dax_binary_t*`
3. `ndx_close()` - `dax_free_binary()` + `free()` + sets closed flag in JS wrapper

**Text output:** Functions like `disasm`, `symexec`, `ssa`, `decompile`, `emulate` write to a `open_memstream` buffer, then return the buffer as a UTF-8 JS string.

---

## The `.daxc` Snapshot Format

`.daxc` is a binary format for saving and reloading full analysis results. Structure:

```
daxc_header_t          fixed-size header (magic, version, offsets, counts)
sections[]             dax_section_t array
symbols[]              dax_symbol_t array
xrefs[]                dax_xref_t array
functions[]            dax_func_t array
blocks[]               dax_block_t array
comments[]             dax_comment_t array
insns[]                daxc_insn_t array (decoded instructions)
ustrings[]             dax_ustring_t array
```

Magic: `0x584F454E` (`NEOX` in little-endian ASCII). Version: `4`.

---

## Adding a New Architecture

1. Add `ARCH_NEWARCH` to the `dax_arch_t` enum in `include/dax.h`
2. Create `include/newarch.h` with instruction type definitions
3. Create `src/newarch_decode.c` implementing `newarch_decode()`
4. Add a disassembly function `dax_disasm_newarch()` in `src/disasm.c`
5. Add classification `dax_classify_newarch()` in `src/analysis.c`
6. Wire up the new arch in `src/loader.c`, `src/main.c`, `src/cfg.c`
7. Add to `SRCS` in `Makefile`

---

## Adding a New Analysis Module

1. Create `src/mymodule.c`
2. Add `#include "dax_guard.h"` after `#include "dax.h"`
3. Start every public entry point with `DAX_GUARD_BIN(bin)` or `DAX_GUARD_BIN_RET(bin, retval)`
4. Declare public functions in `include/dax.h`
5. Add a flag to `dax_opts_t` (e.g., `int mymodule`)
6. Add CLI flag parsing in `src/main.c`
7. Call the module from `src/main.c` using `DAX_RUN_PASS("mymodule", opts.color, mymodule_fn(&bin, &opts, stdout))`
8. Add the source to `SRCS` in `Makefile` and `LIB_SRCS` in `build_js.sh`
9. Expose via N-API in `js/src/neodax_napi.c` if a JS API is needed
10. Add method to `js/index.js` and type to `js/index.d.ts`

This document describes the internal design of NeoDAX - how modules interact, data flows, and the design decisions behind each component.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Overview

NeoDAX is structured as a **layered analysis pipeline**:

```
┌──────────────────────────────────────────────────────────────┐
│  Input: ELF / PE / Raw binary file                           │
└───────────────────────────┬──────────────────────────────────┘
                            │
            ┌───────────────▼──────────────────┐
            │  loader.c  -  Binary Parser       │
            │  ELF32/64 + PE32/PE64+ + Raw      │
            │  Sections, metadata, SHA-256       │
            └───────────────┬──────────────────┘
                            │  dax_binary_t
        ┌───────────────────┼───────────────────┐
        │                   │                   │
   ┌────▼────┐         ┌────▼────┐        ┌─────▼────┐
   │ symbols │         │ disasm  │        │ analysis │
   │ .c      │         │ .c      │        │ .c       │
   │ symtab  │         │ decode  │        │ xrefs    │
   │ dynsym  │         │ x86/    │        │ groups   │
   │ PE exp  │         │ arm64/  │        │ strings  │
   └────┬────┘         │ riscv   │        └──────────┘
        │              └────┬────┘
        │                   │
        └────────┬──────────┘
                 │
         ┌───────▼────────┐
         │  cfg.c          │
         │  Two-pass CFG   │
         │  Pre-register   │
         │  branch targets │
         │  Dead-byte skip │
         └───────┬────────┘
                 │
    ┌────────────┼──────────────────────┐
    │            │                      │
┌───▼───┐  ┌────▼────┐         ┌───────▼──────┐
│ loops │  │callgraph│         │  Advanced (ARM64+RISC-V) │
│ .c    │  │ .c      │         │  symexec.c               │
│       │  │         │         │  decomp.c                │
└───────┘  └─────────┘         │  emulate.c               │
                                └──────────────────────────┘
                 │
         ┌───────▼────────┐
         │  main.c         │
         │  CLI output     │
         │  Banner + table │
         └───────┬────────┘
                 │
        ┌────────▼────────┐
        │  daxc.c          │
        │  .daxc snapshot  │
        └─────────────────┘
```

---

## Core Data Structures

All analysis state lives in two structs defined in `include/dax.h`.

### `dax_binary_t`

The central object holding all parsed and analyzed data:

```
dax_binary_t
├── data / size          Raw file bytes
├── arch / fmt / os      Architecture, format, OS/ABI
├── entry / base         Entry point, image base
├── image_size           Total mapped image size
├── code_size / data_size Aggregated section sizes
├── sha256 / build_id    File hash, GNU Build-ID
├── is_pie / is_stripped / has_debug  Metadata flags
├── sections[128]        dax_section_t array
├── symbols*             dax_symbol_t array (heap)
├── xrefs*               dax_xref_t array (heap)
├── functions*           dax_func_t array (heap)
├── blocks*              dax_block_t array (heap)
├── comments*            dax_comment_t array (heap)
└── ustrings*            dax_ustring_t array (heap)
```

### `dax_opts_t`

Flags controlling what the CLI produces. Each flag corresponds to one analysis pass:

```
show_bytes  show_addr  color  verbose
symbols     demangle   funcs  groups   xrefs  strings
cfg         loops      callgraph  switches
unicode     symexec    ssa    decompile  emulate
section     output_daxc  start_addr  end_addr
```

---

## Module Descriptions

### `loader.c` - Binary Parser
Reads the file into memory and dispatches to ELF, PE, or Mach-O parsing. Detects format by magic bytes: `0x7fELF` → ELF, `MZ` → PE, `0xFEEDFACF`/`0xBEBAFECA` etc → Mach-O.

Populates:
- `bin->sections[]` - virtual address, file offset, size, flags, type
- `bin->arch`, `bin->fmt`, `bin->os`
- `bin->entry`, `bin->base`, `bin->image_size`
- `bin->is_pie`, `bin->is_stripped`, `bin->has_debug`
- `bin->build_id` - extracted from `.note.gnu.build-id`

### `symbols.c` - Symbol Loading
Reads ELF `SHT_SYMTAB` and `SHT_DYNSYM` sections, PE export directory. Filters ARM64 mapping symbols (`$x`, `$d`). Calls `dax_demangle()` for each symbol. Results in `bin->symbols[]`.

### `analysis.c` - Classification + Xref Builder
- `dax_classify_x86()` / `dax_classify_arm64()` / `dax_classify_riscv()` - map mnemonic strings to `dax_igrp_t` categories
- `dax_xref_build()` - scans code sections decoding every instruction; when a call or branch with a known target is found, adds a `dax_xref_t`
- `dax_sec_classify()` - maps section names to `dax_sec_type_t`

### `disasm.c` - Disassembly Output
Produces annotated disassembly to a `FILE*`. For each instruction it:
1. Decodes using the appropriate architecture decoder
2. Resolves symbols at the address (from `symbols.c`)
3. Resolves string references from `.rodata` (from `dax_resolve_string()`)
4. Colors the mnemonic based on `dax_classify_*()` result
5. Annotates xrefs with callers/callees
6. Prints function boundary headers

`dax_resolve_string()` now handles UTF-8 multi-byte sequences by calling `dax_utf8_decode()`.

### `cfg.c` - Control Flow Graph Builder

**Two-pass algorithm:**

**Pass 1 (pre-pass):** Scan the entire function body. For every branch/call instruction with a known target, call `find_or_add_block()` to register the target address as a block boundary. Also register conditional fall-through addresses.

**Pass 2 (main pass):** Walk instructions sequentially. At each branch:
- *Conditional* - add true/false edges; `cur` continues to fall-through block
- *Unconditional* - add jump edge; then **skip forward** past dead bytes by scanning for the next pre-registered block boundary. This is the jump-trick fix.
- *Return* - mark block as `is_exit`; continue from next block boundary if any

### `loops.c` - Loop Detection
Implements a simple post-dominator based back-edge detection. A back edge `(A → B)` where `B` dominates `A` indicates a loop. Uses iterative dominator computation on the CFG.

### `unicode.c` - String Scanner
Two independent scanners:

**UTF-8 scanner:** Walks bytes; at each position attempts `dax_utf8_decode()`. Accepts the string if it is NUL-terminated, has ≥ 2 characters, and contains at least one multi-byte sequence (codepoint ≥ U+0080).

**UTF-16LE scanner:** Only runs on sections not in the skip list (`.dynstr`, `.dynsym`, `.strtab`, etc.). For a candidate position:
1. Checks preceding byte is `0x00` (string boundary, not mid-sequence)
2. Decodes code units, counting `wide` (hi-byte ≠ 0) and `surrogate` pairs
3. Rejects if all hi-bytes are 0 (pure null-padded ASCII)
4. Rejects if no codepoint > U+02FF (rejects ELF binary data)
5. Requires ≥ 6 code units and ≥ 3 wide units (or surrogate pair)

### `macho.c` - Mach-O Parser

Handles macOS/iOS/macOS binaries:

**FAT/universal:** `fat_find_slice()` walks the big-endian FAT header (using `bswap32`), selects the ARM64 slice first, falls back to x86-64. File offsets in section structures are **absolute** from the start of the full FAT file - not slice-relative - so `bin->data + section->offset` is always correct.

**Magic constants:** All Mach-O magic values are defined as what a little-endian CPU *reads* from the raw bytes. `MACHO_MAGIC_64_LE = 0xFEEDFACF` (bytes `CF FA ED FE` on disk). `swap=1` only for big-endian files.

**Load command walker:** Iterates `ncmds` load commands. Handles `LC_SEGMENT_64` (sections), `LC_MAIN` (entry point = `text_vmbase + entryoff`), `LC_SYMTAB` (`nlist_64` entries, strips leading `_` from names).

**Section naming:** `__TEXT,__text` → `.text`, `__DATA,__data` → `.data`, etc. Stripping the `__` prefix makes Mach-O sections use the same naming convention as ELF.

### `entropy.c` - Entropy, RDA, IVF, Poly Map, AIRE

Five detection and intelligence modules in one file:

**`dax_entropy_scan()`** - Computes Shannon entropy (`H = -∑pᵢ log₂pᵢ`) over 256-byte sliding windows with 64-byte step. Classifies windows as normal / HIGH (≥ 6.8) / PACKED/ENCRYPTED (≥ 7.0).

**`dax_rda_section()`** - BFS from section entry + all symbols. Uses a `rda_queue_t` (bounded at 16384 entries) and a visited array (bounded at 65536). Output sorted by address with `[DEAD: ...]` markers for gaps.

**`dax_ivf_scan()`** - Linear scan checking each instruction for: invalid mnemonic (`??` or `dw`), privileged ARM64/x86-64 instructions (via static table), NOP-runs, INT3-runs, dead bytes after unconditional branches, SMC patterns (4 detection passes: adr+str look-back up to 8 instructions, eor+str XOR mutation stub, store inside poly region, emulator real-time write cross-reference), opaque predicates (`subs xN,xA,xA`, `mrs`→`cmp`→`b.cond`).

**`dax_poly_map()`** - Sliding 48-byte window (tightened from 64 in v1.1.1) across all code sections scoring 18 mutation signals: indirect-dispatch, nop-junk, dead-code, const-obfuscation, opaque-predicate, opcode-subst, xor-arith, rotation-obf, data-dep-branch, antidebug-gate, subst-chain, xor-mutation-loop (new: `poly_is_xor_mutation()`), hash-chain (new: `poly_hash_chain_depth()`), high-entropy (new: byte entropy proxy). Contiguous windows scoring ≥ 3 are merged into `dax_poly_region_t` records in `bin->poly_regions[]`. Obfuscator fingerprinting expanded to 8 categories (OLLVM/Hikari, XOR-poly/custom-packer, XOR+ROR self-decrypt, antidebug+opaque-gate, hash-chain/Tigress, NOP-packer, const-obf/split-imm, packed/encrypted). Must be called before AIRE to populate poly region data.

**`dax_aire_analyze()`** - Post-processes the entire `dax_binary_t` state and synthesizes human-readable insights ranked by confidence. Three output blocks beyond the insight list:

- **Context block** — counts dominant insight category, prints a plain-language focus description and analyst tip tailored to that category.
- **Next-step guide** — emits 3 ranked shell commands chosen based on the dominant category (e.g. `vm-dispatch` → `run vt`, `cfg`, `xrefs`).
- **Memory persistence** — after every run, writes results to `.aire_memory` (binary, up to 32 `aire_memory_entry_t` records, keyed by SHA-256). On the next run for the same binary, reads back the file and prints a `┌─ Memory ─┐` recall banner showing: run count, last timestamp, top finding, last interactive command.

### `symexec.c` - Symbolic Execution (ARM64, RISC-V, x86-64)
Uses a pool of `sym_expr_t` nodes to represent register state as expression trees. Registers start symbolic (`SEXPR_VAR`). Concrete values short-circuit into `SEXPR_CONST`. Binary operations produce `SEXPR_binop(l, r)` nodes. When both operands are concrete, the result is computed numerically. SMC tracking expanded: `smc_write_pc/target/old/new` arrays increased to 128 entries; duplicate writes to the same address recorded as mutation chains in `bin->smc_chain_*`.

### `decomp.c` - NR (NeoDAX Representation) + Decompiler (ARM64, RISC-V, x86-64)

**NR pass:** Lifts binary instructions to a 30-opcode typed IR. Each register write creates a versioned `nr_var_t` with inferred `nr_type_t`. `mov x0, x1` → `r0_2:u64 = r0_1`. Call instructions resolve the callee against `bin->functions[]` and store `callee_func_idx` + `callee_name` in the `nr_stmt_t`. The print layer emits `▸ callers:` and `▸ callees:` per function from xref table and NR scan respectively.

**Decompiler pass:** Translates NR statements to pseudo-C with type-aware local declarations, argument inference (x0–x7), tail-call detection, rotation intrinsics (`__ror`/`__rol`), and resolved call-site annotations.

**Program module:** `dax_decompile_all()` harvests `nr_call_edge_t[]` while lifting all functions and emits a cross-function call graph + SMC-modified function list.

### `emulate.c` - Concrete Emulator (ARM64 + RISC-V)
Models:
- 32 × 64-bit general-purpose registers
- Stack (virtual allocation at `0x7fff0000`)
- Page-based memory (`emu_page_t[256]` - each 4096 bytes)
- Memory reads fall back to binary section data for `ldr` from `.rodata`
- CPSR flags (Z, N, C, V) updated by `cmp`, `adds`, `subs`
- **Real-time SMC capture:** `emu_write8()` checks every byte write against all code sections; writes to executable memory recorded in `bin->emu_smc_write_pc[]`, `bin->emu_smc_target[]` (up to 64 entries)
- Terminates at `ret` (returns `x0`), `bl` (external call), or `EMU_MAX_STEPS` limit

---

## JS Binding Architecture

```
NeoDAX JS layer
────────────────────────────────────────────────────
js/index.js            NeoDAXBinary class
                        wraps _handle (napi external)
                        validates file exists
                        converts BigInt ↔ address
          │
          │  require('./neodax.node')
          ▼
js/src/neodax_napi.c    26 N-API functions
                        each gets handle → dax_binary_t*
                        calls ensure_symbols() / ensure_functions()
                        open_memstream() for text output
                        returns napi_value objects/arrays
          │
          │  direct C calls
          ▼
NeoDAX C core (all src/*.c)
────────────────────────────────────────────────────
```

**Handle lifecycle:**
1. `ndx_load()` - `calloc(dax_binary_t)` → `napi_create_external(ptr)`
2. Every other function - `get_handle()` unwraps the external back to `dax_binary_t*`
3. `ndx_close()` - `dax_free_binary()` + `free()` + sets closed flag in JS wrapper

**Text output:** Functions like `disasm`, `symexec`, `ssa`, `decompile`, `emulate` write to a `open_memstream` buffer, then return the buffer as a UTF-8 JS string.

---

## The `.daxc` Snapshot Format

`.daxc` is a binary format for saving and reloading full analysis results. Structure:

```
daxc_header_t          fixed-size header (magic, version, offsets, counts)
sections[]             dax_section_t array
symbols[]              dax_symbol_t array
xrefs[]                dax_xref_t array
functions[]            dax_func_t array
blocks[]               dax_block_t array
comments[]             dax_comment_t array
insns[]                daxc_insn_t array (decoded instructions)
ustrings[]             dax_ustring_t array
```

Magic: `0x584F454E` (`NEOX` in little-endian ASCII). Version: `4`.

---

## Adding a New Architecture

1. Add `ARCH_NEWARCH` to the `dax_arch_t` enum in `include/dax.h`
2. Create `include/newarch.h` with instruction type definitions
3. Create `src/newarch_decode.c` implementing `newarch_decode()`
4. Add a disassembly function `dax_disasm_newarch()` in `src/disasm.c`
5. Add classification `dax_classify_newarch()` in `src/analysis.c`
6. Wire up the new arch in `src/loader.c`, `src/main.c`, `src/cfg.c`
7. Add to `SRCS` in `Makefile`

---

## Adding a New Analysis Module

1. Create `src/mymodule.c`
2. Declare public functions in `include/dax.h`
3. Add a flag to `dax_opts_t` (e.g., `int mymodule`)
4. Add CLI flag parsing in `src/main.c`
5. Call the module from `src/main.c` at the appropriate point in the pipeline
6. Add the source to `SRCS` in `Makefile` and `LIB_SRCS` in `build_js.sh`
7. Expose via N-API in `js/src/neodax_napi.c` if a JS API is needed
8. Add method to `js/index.js` and type to `js/index.d.ts`
