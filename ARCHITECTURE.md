# NeoDAX Architecture

This document describes the internal design of NeoDAX — how modules interact, data flows, and the design decisions behind each component.

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
            │  loader.c  —  Binary Parser       │
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
│ loops │  │callgraph│         │  Advanced    │
│ .c    │  │ .c      │         │  symexec.c   │
│       │  │         │         │  decomp.c    │
└───────┘  └─────────┘         │  emulate.c   │
                                └──────────────┘
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

### `loader.c` — Binary Parser
Reads the file into memory and dispatches to ELF, PE, or Mach-O parsing. Detects format by magic bytes: `0x7fELF` → ELF, `MZ` → PE, `0xFEEDFACF`/`0xBEBAFECA` etc → Mach-O.

Populates:
- `bin->sections[]` — virtual address, file offset, size, flags, type
- `bin->arch`, `bin->fmt`, `bin->os`
- `bin->entry`, `bin->base`, `bin->image_size`
- `bin->is_pie`, `bin->is_stripped`, `bin->has_debug`
- `bin->build_id` — extracted from `.note.gnu.build-id`

### `symbols.c` — Symbol Loading
Reads ELF `SHT_SYMTAB` and `SHT_DYNSYM` sections, PE export directory. Filters ARM64 mapping symbols (`$x`, `$d`). Calls `dax_demangle()` for each symbol. Results in `bin->symbols[]`.

### `analysis.c` — Classification + Xref Builder
- `dax_classify_x86()` / `dax_classify_arm64()` / `dax_classify_riscv()` — map mnemonic strings to `dax_igrp_t` categories
- `dax_xref_build()` — scans code sections decoding every instruction; when a call or branch with a known target is found, adds a `dax_xref_t`
- `dax_sec_classify()` — maps section names to `dax_sec_type_t`

### `disasm.c` — Disassembly Output
Produces annotated disassembly to a `FILE*`. For each instruction it:
1. Decodes using the appropriate architecture decoder
2. Resolves symbols at the address (from `symbols.c`)
3. Resolves string references from `.rodata` (from `dax_resolve_string()`)
4. Colors the mnemonic based on `dax_classify_*()` result
5. Annotates xrefs with callers/callees
6. Prints function boundary headers

`dax_resolve_string()` now handles UTF-8 multi-byte sequences by calling `dax_utf8_decode()`.

### `cfg.c` — Control Flow Graph Builder

**Two-pass algorithm:**

**Pass 1 (pre-pass):** Scan the entire function body. For every branch/call instruction with a known target, call `find_or_add_block()` to register the target address as a block boundary. Also register conditional fall-through addresses.

**Pass 2 (main pass):** Walk instructions sequentially. At each branch:
- *Conditional* — add true/false edges; `cur` continues to fall-through block
- *Unconditional* — add jump edge; then **skip forward** past dead bytes by scanning for the next pre-registered block boundary. This is the jump-trick fix.
- *Return* — mark block as `is_exit`; continue from next block boundary if any

### `loops.c` — Loop Detection
Implements a simple post-dominator based back-edge detection. A back edge `(A → B)` where `B` dominates `A` indicates a loop. Uses iterative dominator computation on the CFG.

### `unicode.c` — String Scanner
Two independent scanners:

**UTF-8 scanner:** Walks bytes; at each position attempts `dax_utf8_decode()`. Accepts the string if it is NUL-terminated, has ≥ 2 characters, and contains at least one multi-byte sequence (codepoint ≥ U+0080).

**UTF-16LE scanner:** Only runs on sections not in the skip list (`.dynstr`, `.dynsym`, `.strtab`, etc.). For a candidate position:
1. Checks preceding byte is `0x00` (string boundary, not mid-sequence)
2. Decodes code units, counting `wide` (hi-byte ≠ 0) and `surrogate` pairs
3. Rejects if all hi-bytes are 0 (pure null-padded ASCII)
4. Rejects if no codepoint > U+02FF (rejects ELF binary data)
5. Requires ≥ 6 code units and ≥ 3 wide units (or surrogate pair)

### `macho.c` — Mach-O Parser

Handles macOS/iOS/macOS binaries:

**FAT/universal:** `fat_find_slice()` walks the big-endian FAT header (using `bswap32`), selects the ARM64 slice first, falls back to x86-64. File offsets in section structures are **absolute** from the start of the full FAT file — not slice-relative — so `bin->data + section->offset` is always correct.

**Magic constants:** All Mach-O magic values are defined as what a little-endian CPU *reads* from the raw bytes. `MACHO_MAGIC_64_LE = 0xFEEDFACF` (bytes `CF FA ED FE` on disk). `swap=1` only for big-endian files.

**Load command walker:** Iterates `ncmds` load commands. Handles `LC_SEGMENT_64` (sections), `LC_MAIN` (entry point = `text_vmbase + entryoff`), `LC_SYMTAB` (`nlist_64` entries, strips leading `_` from names).

**Section naming:** `__TEXT,__text` → `.text`, `__DATA,__data` → `.data`, etc. Stripping the `__` prefix makes Mach-O sections use the same naming convention as ELF.

### `entropy.c` — Entropy, RDA, IVF

Three detection modules in one file:

**`dax_entropy_scan()`** — Computes Shannon entropy (`H = -∑pᵢ log₂pᵢ`) over 256-byte sliding windows with 64-byte step. Classifies windows as normal / HIGH (≥ 6.8) / PACKED/ENCRYPTED (≥ 7.0).

**`dax_rda_section()`** — BFS from section entry + all symbols. Uses a `rda_queue_t` (bounded at 16384 entries) and a visited array (bounded at 65536). Output sorted by address with `[DEAD: ...]` markers for gaps.

**`dax_ivf_scan()`** — Linear scan checking each instruction for: invalid mnemonic (`??` or `dw`), privileged ARM64/x86-64 instructions (via static table), NOP-runs, INT3-runs, dead bytes after unconditional branches.

### `symexec.c` — Symbolic Execution
Uses a pool of `sym_expr_t` nodes to represent register state as expression trees. Registers start symbolic (`SEXPR_VAR`). Concrete values short-circuit into `SEXPR_CONST`. Binary operations produce `SEXPR_binop(l, r)` nodes. When both operands are concrete, the result is computed numerically.

### `decomp.c` — SSA Lifting + Decompiler
**SSA pass:** Assigns a version number to every register write. `mov w0, w1` becomes `r0_2 = r0_1`. The stmt list is a linear sequence of `ssa_stmt_t` operations.

**Decompiler pass:** Translates SSA statements to C-like IR nodes, then renders them with appropriate indentation and colors.

### `emulate.c` — Concrete Emulator
Models:
- 32 × 64-bit general-purpose registers
- Stack (virtual allocation at `0x7fff0000`)
- Page-based memory (`emu_page_t[64]` — each 4096 bytes)
- Memory reads fall back to binary section data for `ldr` from `.rodata`
- CPSR flags (Z, N, C, V) updated by `cmp`, `adds`, `subs`
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
1. `ndx_load()` — `calloc(dax_binary_t)` → `napi_create_external(ptr)`
2. Every other function — `get_handle()` unwraps the external back to `dax_binary_t*`
3. `ndx_close()` — `dax_free_binary()` + `free()` + sets closed flag in JS wrapper

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
