# Changelog

All notable changes to NeoDAX are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · [Semantic Versioning](https://semver.org/).

---

# Changelog

All notable changes to NeoDAX are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · [Semantic Versioning](https://semver.org/).

---

## [1.1.1] - 2026-04-17

### Microkernel Fault Isolation — Full Codebase Hardening

This release applies a systematic, microkernel-inspired fault isolation model across the entire NeoDAX codebase. The goal: no single malformed binary, corrupt counter, or bad pointer can crash the program. Every analysis pass now operates as an independent service that can fail and recover in isolation.

#### `include/dax_guard.h` — New central guard header

New header providing all fault isolation primitives. Include after `dax.h` in every module.

**Pass-level wrapper:**
- `DAX_RUN_PASS(name, color, stmt)` — clears `g_dax_fault`, executes the pass statement, checks if it faulted, prints a recovery notice if so, then continues. Used for all 32 top-level module calls in `main.c`.

**Input validation macros:**
- `DAX_GUARD_BIN(bin)` — validates `bin` is non-NULL, has `data`, `size > 0`, and all counters within `DAX_MAX_*` bounds. Returns `void` on failure.
- `DAX_GUARD_BIN_RET(bin, retval)` — same, returns `retval` instead.
- `DAX_GUARD_FUNC(bin, fi)` / `DAX_GUARD_FUNC_RET(bin, fi, rv)` — validates function index against `nfunctions` and `DAX_MAX_FUNCTIONS`.
- `DAX_GUARD_SEC(bin, si)` — validates section index.

**Safe array accessors** — return NULL instead of crashing on OOB:
- `dax_sec_ptr(bin, si)` — section byte pointer with overflow-safe `size > bin->size - offset` check
- `dax_func_ptr(bin, fi)` — safe function struct pointer
- `dax_block_ptr(bin, bi)` — safe block struct pointer
- `dax_sym_ptr(bin, si)` — safe symbol struct pointer

**Counter normalization:**
- `dax_clamp_counts(bin)` — normalizes all `dax_binary_t` counters to their `DAX_MAX_*` upper bounds. Called 5 times in `main.c` (after load, after sym-load, after func-detect, after symexec-prepass, after CFG build).

**Code window helper:**
- `dax_code_window(bin, fi, &code, &sz, &base, &fn_off, &fn_end)` — finds the section containing function `fi`, validates all bounds, returns usable pointers in one call.

**Loop budget guard:**
- `DAX_BUDGET_INIT(n)` + `DAX_BUDGET_CHECK()` — prevents infinite decode loops on adversarial data (budget = 65536 instructions per function).

**Global fault register:**
- `g_dax_fault` (volatile int) + `g_dax_fault_msg[256]` — defined in `main.c`, extern in `dax_guard.h`. Set via `dax_fault_set("reason")` from any module. Cleared by `DAX_RUN_PASS` before each call.

#### `src/main.c` — 32 pass wrappers, 5 counter clamps

- All module calls wrapped in `DAX_RUN_PASS`. If any pass faults, the program prints a diagnostic and continues to the next pass.
- `dax_clamp_counts(&bin)` called after: post-load, sym-load, func-detect, symexec-prepass, CFG build.
- Section loops in the ARM64 indirect-target resolver now use full overflow-safe bounds and `DAX_MAX_*` caps.
- `bin.functions != NULL` checked before ARM64 resolver runs.

#### `src/analysis.c`
- `dax_xref_build()` — `DAX_GUARD_BIN_RET` at entry.
- `dax_func_detect()` — `DAX_GUARD_BIN_RET` + `code != NULL && code_size > 0` before decode loop.
- `dax_switch_detect()` — null-guards `opts` and validates `code`/`sz` before use.
- `dax_func_find()` — null-checks `bin->functions` before iteration; loop capped with `DAX_MAX_FUNCTIONS`.
- `dax_xref_find_to()` — validates `bin->xrefs`, `out`, `max > 0` and `nxrefs <= DAX_MAX_XREFS` before loop.

#### `src/cfg.c`
- `dax_cfg_build()` — `DAX_GUARD_BIN_RET` + `func_idx` bounds check + `code != NULL && sz > 0`.
- `dax_cfg_print()` — `DAX_GUARD_BIN_RET` + `dax_func_idx_ok()` + `bin->blocks != NULL`.
- `find_block_by_addr()` — null-checks `bin->blocks` and `nblocks` before loop.
- `find_or_add_block()` — null-checks `bin->blocks`.
- `get_or_make_indirect_block()` — null-checks `bin->blocks`.

#### `src/loader.c`
- `dax_parse_elf()` — guards `bin->data != NULL && bin->size >= 16` before byte access.
- ELF64 and ELF32 `shstrtab` setup: overflow-safe `strsz <= bin->size - stroff` (was `stroff + strsz <= bin->size`). `sh_name` checked against `sh_size` before `strncpy`.
- ELF64 and ELF32 symbol loops: `strtab_size` tracked; `st_name >= strtab_size` skipped.

#### `src/symbols.c`
- `add_symbol()` — checks `bin->symbols != NULL` and `nsymbols < DAX_MAX_SYMBOLS` before every write.
- `dax_sym_load()` — `DAX_GUARD_BIN_RET`; `nsymbols > 0` checked before `qsort`.
- `dax_sym_find()` — null-checks `bin->symbols` and `nsymbols > 0`; uses overflow-safe midpoint `lo + (hi - lo) / 2`.
- `dax_sym_name()` — null-checks `bin`.

#### `src/disasm.c`
- `dax_disasm_x86_64()`, `dax_disasm_arm64()`, `dax_disasm_riscv64()` — `DAX_GUARD_BIN_RET` + `opts != NULL && out != NULL` at each entry.
- `find_section_by_name()`, `find_exec_section()` — null-check `bin` and cap loops with `DAX_MAX_SECTIONS`.

#### `src/loops.c`
- `dax_loop_detect()` — `DAX_GUARD_BIN_RET` + `dax_func_idx_ok()` + `bin->blocks != NULL`.
- `dax_loop_print_all()` — `DAX_GUARD_BIN` + `out != NULL`; loop capped with `DAX_MAX_FUNCTIONS`.
- Block index ternaries capped with `DAX_MAX_BLOCKS`.

#### `src/callgraph.c`
- `cg_build()` — null-checks `bin->xrefs` and `nxrefs >= 0` before building.
- `addr_to_func()` — null-checks `bin->functions`; loop capped with `DAX_MAX_FUNCTIONS`.
- `cg_print_node()` — null-checks `bin`, `cg`, `out`; `sym_idx` access guarded by `bin->symbols != NULL` check before deref.
- `dax_callgraph_print()` — `DAX_GUARD_BIN`; `nfunctions > 0` checked before `calloc`.

#### `src/emulate.c`
- `dax_emulate_func()` — `DAX_GUARD_BIN` + `dax_func_idx_ok()`.
- `dax_emulate_all()` — `DAX_GUARD_BIN`; function limit via `DAX_CLAMP`.
- Section reads in `emu_read8()` and the PC-section lookup use overflow-safe `size > bin->size - offset` and double-check the final computed offset against `bin->size`.

#### `src/symexec.c`
- `dax_symexec_func()` — `DAX_GUARD_BIN`; section loop uses overflow-safe bounds.
- `dax_symexec_all()` — `DAX_GUARD_BIN`; loop capped with `DAX_MAX_FUNCTIONS`.
- `dax_symexec_prepass()` — `DAX_GUARD_BIN` + `bin->functions != NULL`.

#### `src/decomp.c`
- `dax_ssa_lift_func()` — `DAX_GUARD_BIN` + `dax_func_idx_ok()`.
- `dax_ssa_lift_all()` — `DAX_GUARD_BIN` + `out != NULL`; loop capped with `DAX_MAX_FUNCTIONS`.
- `dax_decompile_func()` — `DAX_GUARD_BIN` + `dax_func_idx_ok()`.
- `dax_decompile_all()` — `DAX_GUARD_BIN` + `out != NULL`; `calloc` failure sets `g_dax_fault`; loop capped with `DAX_MAX_FUNCTIONS`.

#### `src/entropy.c`
- `dax_entropy_scan()` — `DAX_GUARD_BIN` + `opts/out` null-check; all section loops use overflow-safe bounds.
- `dax_rda_all()` — `DAX_GUARD_BIN`; section bounds overflow-safe.
- `dax_ivf_scan()` — `DAX_GUARD_BIN` + `opts/out` null-check.
- `aire_count_callers()`, `aire_count_callees()` — null-check `bin->xrefs`; loops capped with `DAX_MAX_XREFS`.
- `aire_scan_fn()` — null-checks `bin`, `fn`, `bin->data`; section loop overflow-safe; `insn.mnemonic`/`insn.operands` null-checked before string ops.
- All `fi`/`i` loops over `nfunctions` capped with `DAX_MAX_FUNCTIONS`; all xref loops capped with `DAX_MAX_XREFS`.

#### `src/dsa.c`
- Per-phase fault flags (`DSA_FAULT_SIMULATE`, `DSA_FAULT_CHAINS`, `DSA_FAULT_DEAD`, `DSA_FAULT_PHIS`, `DSA_FAULT_PRINT`) — each phase checks its own flag before running; if simulate faults, later phases still run on partial data.
- `nresolved_indirect` / `nsmc_patches` validated against `DSA_INDIRECT_MAX` (128) / `DSA_SMC_MAX` (128).
- All counters use `DSA_CLAMP` before iteration.
- Decode loop budget: 65536 instructions per function.
- `insn.mnemonic`/`insn.operands` null-checked after every decode call.

#### `src/interactive.c`
- `dax_interactive()` — `DAX_GUARD_BIN_RET`; `bin->entry` only accessed after guard.
- Function index ternaries capped with `DAX_MAX_FUNCTIONS`; section loops capped with `DAX_MAX_SECTIONS`.

### Stats

| Metric | Count |
|---|---|
| DAX_RUN_PASS wrappers | 32 |
| DAX_GUARD_BIN / DAX_GUARD_BIN_RET calls | 25 |
| DAX_MAX_* bounds guards in loops | 290 |
| dax_clamp_counts() call sites | 5 |
| Overflow-unsafe `offset+size` patterns eliminated | all |



### ARM64 Decoder — Correctness Fixes

#### `src/arm64_decode.c`
- **`movk x-reg` (0xF2800000)** — `movk xN, #imm, lsl #32/48` was decoded as `dw` (unknown). Added `0xF2800000` to the move-wide mask list. All `movk xN` with shift ≥ 32 now decode correctly.
- **`movn w-reg` (0x12800000)** — `movn wN, #imm` was missing from the move-wide list. Added `0x12800000`.
- **`extr`/`ror` class mask** — bit23 is always 1 for this instruction class (`100111`). Corrected mask from `0x13000000` to `0x13800000`, fixing decode of `ror wN/xN` and `extr` 32-bit and 64-bit variants.

#### `src/entropy.c` — IVF false-positive fix
- Removed incorrect heuristic `(r32 >> 24) == 0xF2 → is_embedded_const`. This was causing all `movk x-reg` instructions to be falsely flagged as `INVALID embedded` in the IVF scan.

### dsa.c — Warning Fixes
- Removed redundant `typedef struct dsa_func_t dsa_func_t` (already declared in `dax.h`).
- Fixed `fprintf(out, R)` → `fprintf(out, "%s", R)` to suppress `-Wformat-security`.

### entropy.c — Warning Fix
- `collisions` variable: added `(void)collisions` cast to suppress `-Wunused-but-set-variable`.
- Fixed missing newline before `#undef _DOM` causing preprocessor error.

### Polymorphic Detection — Major Upgrade (`src/entropy.c`)
- Window tightened from 64 → 48 bytes for more precise ARM64 detection.
- **6 new signals:** `xor-arith` (eor/eon density), `ror/extr rotation`, `data-dependent tbz/tbnz branch`, `antidebug gate` (mrs/msr in window), `substitution chain` (def-use depth), `high-entropy` (near-random bytes in code).
- **XOR mutation loop detector** (`poly_is_xor_mutation()`): finds `ldr → eor → str` sequences targeting executable addresses — strong polymorphic stub signal (+3 score).
- **Hash/arithmetic chain depth** (`poly_hash_chain_depth()`): measures consecutive arith ops on the same dest register — detects Tigress-style hash-chain obfuscation.
- **Byte entropy proxy**: counts distinct byte values per window; near-random (≥220/256 distinct) adds +1.
- Total scoring conditions: 6 → 18. Max visible score remains 10/10.
- **Obfuscator fingerprint expanded:** `XOR-poly/custom-packer`, `XOR+ROR self-decrypt`, `antidebug+opaque-gate`, `hash-chain/Tigress`, `packed/encrypted`, `const-obf/split-imm` added alongside existing OLLVM/Hikari and custom-VM.

### SMC Detection — Major Upgrade

#### `include/dax.h`
- `smc_write_pc/target/old/new` arrays expanded 32 → 128 entries.
- Added `smc_chain_addr[32]`, `smc_chain_count[32]`, `nsmc_chains` — tracks addresses written >1× (mutation chains, scored ×2).
- Added `emu_smc_write_pc[64]`, `emu_smc_target[64]`, `emu_smc_new_word[64]`, `nemu_smc` — real-time emulator SMC capture.

#### `src/emulate.c` — Real-time SMC
- `emu_write8()` now detects writes to executable sections during emulation and records them in `bin->emu_smc_*`. Every write to a code address during `dax_emulate_all()` is captured once per target word.

#### `src/symexec.c`
- Limit raised to 128 entries.
- Duplicate writes to same target address now recorded as mutation chains in `bin->smc_chain_*` with per-address repeat counter.

#### `src/entropy.c` — IVF SMC scanner
- Look-back extended from 3 → 8 instructions.
- **Pattern 2: eor+str XOR mutation stub** — detects `eor rN, rN, key` immediately before `str` to exec region.
- **Pattern 3: store inside poly region** — if the storing instruction lies within a known `dax_poly_region`, flags as in-place mutation.
- **Pattern 4: emulator SMC cross-reference** — checks `bin->emu_smc_write_pc[]` for the current address.
- IVF output now shows three sections: symexec patches, emulator real-time captures, mutation chains.

### DSA — Interactive Shell Fix + `dsa all`
- `dsa` without arguments no longer segfaults. Displays usage hint with list of first 10 functions.
- `dsa all` — new subcommand, runs DSA over all functions sequentially.
- Help entry updated: `[func|all]` with correct description.

### DSA — Main Pipeline Integration
- `--dsa` flag added (long option).
- `int dsa` field added to `dax_opts_t`.
- `-X` (everything) now includes `--dsa`.
- DSA dispatched in main pipeline after emulate, before entropy.
- Help text updated with `--dsa` entry.

### NR — NeoDAX Representation (`src/decomp.c` — full rewrite)

The old SSA/IR layer has been replaced by **NR (NeoDAX Representation)**, a richer program IR designed specifically for reverse engineering.

#### Opcode set (was 20 ops → now 30 ops)
- **New arithmetic:** `NR_MUL`, `NR_DIV`, `NR_NEG`
- **New bitwise:** `NR_NOT`, `NR_ROL`, `NR_ROR`
- **New type:** `NR_CAST`, `NR_SEXT`, `NR_ZEXT`
- **New control:** `NR_COND_BR`, `NR_PHI`, `NR_UNDEF`
- **New calls:** `NR_INDIRECT_CALL`, `NR_SYSCALL`
- **New memory:** `NR_MEMCPY`

#### Type system
Every `nr_var_t` carries `nr_type_t`: `NRT_BOOL`, `NRT_U8`, `NRT_U16`, `NRT_U32`, `NRT_U64`, `NRT_PTR`, `NRT_PTR_CODE`, `NRT_FLAGS`. Type is inferred from instruction width and context (`adr/adrp` → `NRT_PTR`, flags reg → `NRT_FLAGS`).

#### Inter-function linkage
- Every `NR_CALL` carries `callee_func_idx` resolved against `bin->functions[]`.
- NR print output shows `▸ callers:` (from xref table) and `▸ callees:` (from NR stmts) per function.
- SMC-modified functions flagged with `⚠` inline.
- `NR_CALL` print shows `[→ func[N] insns=M loops=yes/no]` callee summary.

#### Program-level NR module
- `dax_decompile_all()` lifts all functions, harvests call edges into `nr_call_edge_t[]`, prints a cross-function call graph at end of output showing all caller→callee edges with addresses. SMC-modified functions listed separately.

#### RISC-V NR lifter
Full `nr_lift_riscv()` for RV64: handles all integer ops, all load/store widths, `jal/jalr/ret`, indirect calls.

#### Decompiler upgrade
- Type-aware local variable declarations (inferred from `nr_type_t`).
- Argument heuristic: x0–x7 (ARM64) or a0–a7 (RISC-V) detected as function parameters.
- Tail-call detection: unconditional branch to another function emits `return func(/*tail*/);`.
- `__rol()`/`__ror()` intrinsics for rotation ops.
- `(void)` and `(uint64_t)` casts for type ops.
- Resolved call sites with `/* func[N] */` annotation.

### interactive.c — Bug Fix
- `const char *CR2` renamed to `const char *CReset` — `CR2` conflicts with `termbits.h` system macro `#define CR2 0x00400` on Android/Termux, causing compile error.
- Removed unused variable `C` from `print_help()`.
- `ssa` command help label updated to `NR — NeoDAX Representation`.

### main.c
- `-Q` help text updated: `NR lifting (NeoDAX Representation — inter-function IR)`.
- `-D` help text updated: `decompile (pseudo-C from NR with type inference + resolved calls)`.
- `-X` description updated to include `--dsa`.

---

### AIRE — Context-Aware, Guided, with Memory

#### `src/entropy.c` — `dax_aire_analyze()`
- **Removed "v2" label** — AIRE is just AIRE. All `"AIRE v2"` strings replaced.
- **Context-Aware Focus Banner** — after printing insights, AIRE detects the dominant category across all insights (`vm-dispatch`, `smc`, `poly`, `anti-debug`, `packer`, `func-purpose`, `arch-oddity`) and prints a `┌─ Context ─┐` block with a plain-language description of what kind of binary you're looking at and what to focus on.
- **Next-Step Guide** — a `┌─ Next Steps ─┐` block follows with 3 concrete, ranked shell commands tailored to the dominant context:
  - `vm-dispatch` → `run vt` / `cfg <func>` / `xrefs <addr>`
  - `smc/poly` → `poly` / `run vt` / `entropy`
  - `anti-debug` → `strings` / `symexec <func>` / `xrefs <addr>`
  - `packer` → `entropy` / `run vt` / `cfg <entry>`
  - `func-purpose` → `funcs` / `callgraph` / `decompile <func>`
- **AIRE Memory** — analysis results are persisted to `.aire_memory` (binary file, up to 32 entries). Keyed by SHA-256 of the binary. Tracks: run count, timestamp (ISO-8601), dominant category, top insight summary, top confidence + address, last interactive command. On next run, AIRE prints a `┌─ Memory ─┐` recall banner showing what was found last time.

#### `src/interactive.c`
- After every interactive command, AIRE memory is updated with `last_cmd` for the current binary (matched by SHA-256), so the recall banner stays accurate.

#### `include/dax.h`
- Added `aire_memory_entry_t` and `aire_memory_t` structs
- Added `AIRE_MEMORY_MAX_ENTRIES` (32) and `AIRE_MEMORY_FILE` (`.aire_memory`) macros
- Removed `v2` from `dax_aire_insight_t.insight` field comment

### Version — Unified to 1.1.1
- `setup.sh` banner: was `v1.0.8` → now `v1.1.1`
- All version references point to `DAX_VERSION` in `dax.h` (single source of truth)

### OS Detection — Aligned `setup.sh` ↔ `--detail`
- `setup.sh`: switched from `NAME` to `PRETTY_NAME` in `/etc/os-release` — now shows `Ubuntu 22.04.3 LTS` instead of `Ubuntu`
- `setup.sh`: macOS now appends `sw_vers -productVersion` — shows `macOS 14.4` instead of `macOS / Darwin`
- `main.c --detail`: added fallback chain: `/etc/os-release` → `sw_vers` (macOS) → `uname -sr` — same detection order as `setup.sh`
- Both paths now produce identical OS strings on all supported platforms

---



### VM Dispatcher — Strengthened + Flow Tracing

#### `src/emulate.c`
- **`vm_dispatch_entry_t` struct + `g_vm_trace[512]`** — every `br`/`blr` that resolves to a different function (VM handler pattern) is now recorded automatically during emulation with: `dispatch_pc`, `handler_pc`, `opcode_val` (x0), `ip_val` (x1), `handler_name`, `step_no`
- **`vm_trace_record()`** — internal helper, fires on every indirect branch that looks like a VM dispatch (cross-function `br Xn`, or target in `resolved_indirect_to[]`)
- **VM DISPATCH FLOW TRACE** section printed at end of each `dax_emulate_func()` — shows full dispatch sequence as a table with flow arrows between consecutive dispatches
- **`g_step_state` (`dax_step_state_t`)** — persistent step cursor across interactive shell calls

### Step vs Run — Clear Semantics
- **`step` / `si`** — always continues from the **last stopped PC**; state persists across calls via `g_step_state`
  - `step init [func]` — initialise a step session for a function (sets PC to entry, clears regs)
  - `step [n]` — advance N instructions (default 1) from last PC
  - `step reset` — clear active session
- **`run` / `r`** — always **restarts from the beginning** of the function (clears step state), full trace + register dump
- `dax_step_init()` and `dax_step_next()` are public API (`include/dax.h`)

### Polymorphic Obfuscation Map (`--poly` / `poly` / `pm`)

#### `src/entropy.c` — `dax_poly_map()`
- Sliding 64-byte window scan across all code sections
- **6 scored signals per window:**
  - `indirect-dispatch` — ≥2 `br Xn` / `jalr` / `jmp *reg` in window (+2)
  - `nop-junk` — ≥4 NOPs (junk insertion) (+1)
  - `dead-code` — ≥3 unreachable instructions after unconditional branch (+2)
  - `const-obfuscation` — ≥3 `movk` chains (obfuscated immediates) (+1)
  - `opaque-predicate` — ≥2 `mrs` sysreg reads (opaque predicate source) (+2)
  - `opcode-subst` — same dest reg written by different mnemonics consecutively (+1)
- Contiguous high-score windows merged into `dax_poly_region_t` records stored in `bin->poly_regions[]`
- **Obfuscator fingerprinting:** OLLVM/Hikari, custom VM, NOP-packer, const-obf
- Output: address range, score/10, techniques list, obfuscator guess

### AIRE — Assisted Intelligence Reverse Engineering (`--aire` / `aire` / `ai`)

#### `src/entropy.c` — `dax_aire_analyze()`
- Post-processes all prior analysis results in `dax_binary_t` and generates human-readable insights with confidence scores (0–100)
- **7 rule categories:**
  1. **`vm-dispatch`** — functions with ≥2 resolved indirect dispatches flagged as VM interpreter loops; extreme obfuscation score + dispatch → VMProtect/Themida identification
  2. **`poly`** — each `dax_poly_region_t` generates a contextual insight with obfuscator-specific explanation (OLLVM CFF, custom VM handler cluster, NOP sled)
  3. **`smc`** — `nsmc_patches > 0` → warns static analysis is pre-patch state, recommends dynamic tracing
  4. **`anti-debug`** — `obf_score_antidebug ≥ 2` → timing/sysreg/ptrace technique summary
  5. **`packer`** — sections with entropy ≥ 7.0 bits/byte → identifies encrypted payload + stub pattern
  6. **`func-purpose`** — small functions with ≥4 callers flagged as shared decode/dispatch trampolines; large stripped functions suggest crypto/hash
  7. **`arch-oddity`** — ARM64 with high indirect-branch density outside switch tables
- Insights sorted by confidence (descending), printed with confidence bar `[####.....]`
- All insights stored in `bin->aire_insights[]` for programmatic use

### `include/dax.h` — New Types and Declarations
- `dax_poly_region_t` — polymorphic region: start/end vaddr, mutation_score, technique string, obfuscator name
- `dax_aire_insight_t` — AIRE insight: addr, category, insight text (256 bytes), confidence 0–100
- `dax_step_state_t` — step cursor: active flag, func_idx, pc, regs[32], sp, flags, steps_done, last_halt
- `DAX_POLY_MAX 128`, `DAX_AIRE_MAX 64` capacity constants
- New `dax_opts_t` fields: `poly_map`, `aire`, `vm_trace`
- New function declarations: `dax_poly_map()`, `dax_aire_analyze()`, `dax_vm_trace()`, `dax_step_init()`, `dax_step_next()`
- `extern dax_step_state_t g_step_state`

### `src/main.c` — New CLI Flags
- `--poly` — run polymorphic obfuscation map
- `--aire` — run AIRE (auto-runs poly_map first to populate region data)
- `--vm-trace` — print VM dispatch trace (after emulation)
- `-X` (everything preset) now includes `--poly --aire --vm-trace`

### `src/interactive.c` — Shell Updates
- `aire` / `ai` — AIRE analysis (runs poly_map + aire_analyze)
- `poly` / `pm` — polymorphic obfuscation map
- `vmtrace` / `vt` — VM dispatch flow viewer
- `step` / `si` semantics overhauled: init/advance/reset subcommands
- `run` / `r` explicitly documented as restart (clears step state)
- Help panel updated with all new commands and descriptions

---



### Architecture - Full RISC-V RV64GC Parity

All analysis modules now support RISC-V RV64GC (base + M + A + F + D + C extensions) at the same depth as ARM64 and x86-64.

#### `src/cfg.c`
- Unified `decode_insn()` helper dispatches to `x86_decode`, `a64_decode`, or `rv_decode`
- Unified `classify_any()` dispatches to `dax_classify_x86`, `dax_classify_arm64`, or `dax_classify_riscv`
- Variable-length step (2 or 4 bytes) for RISC-V compressed (C extension) instructions
- `count_insns_in_block()` uses `rv_decode` for RISC-V

#### `src/analysis.c`
- `dax_xref_build()` - RISC-V cross-reference tracking via `rv_decode`
- `dax_func_detect()` - RISC-V prologue: `addi sp, sp, -N` and `c.addi16sp`; tracks `jal` call sites
- `dax_switch_detect()` - RISC-V dispatch: `jalr`/`c.jr` via register after `slt`/`sltu` bounds check

#### `src/entropy.c` - IVF Hardening
- **8 new RISC-V IVF patterns:** indirect branch (`jalr`/`c.jr`), CSR cycle/instret timing anti-debug, `csrr → branch` opaque predicate, `auipc+add+jalr` get-PC thunk, `amo*` atomic abuse, `mul→jalr` hash dispatch, invalid encoding not after branch, CSR opaque sysreg
- **7 new x86-64 IVF patterns:** `cpuid → cmp/test` sandbox detection, `xor reg,reg → jcc` opaque zero, `jmp+int3` anti-debugger byte trick, `mul → jmp[base+idx*scale]` hash dispatch, multi-byte NOP, `call+lea rip` PIC base, `push rbp → call non-exec` PLT stub

#### `src/emulate.c`
- `emu_step_riscv()` - 200+ line concrete RISC-V RV64GC emulator
  - RV64I/M/A/C: full arithmetic, logic, shift, compare, load/store, branch, jump, ecall
  - Compressed C extension: `c.li`, `c.mv`, `c.add`, `c.sub`, `c.and`, `c.or`, `c.xor`, `c.slli`, `c.srli`, `c.srai`, `c.beqz`, `c.bnez`, `c.j`, `c.jr`, `c.jalr`, `c.ld/lw/lwsp/ldsp`, `c.sd/sw/swsp/sdsp`
  - Syscall simulation: `ecall` dispatches to Linux ABI (write, read, exit, brk)
  - Atomic passthrough: `amo*`/`lr`/`sc` are no-ops
  - `rv_reg_idx()` register name resolver (ABI names + `x0`-`x31`)
- `dax_emulate_func()` dispatch updated: `bin->arch == ARCH_RISCV64` → `emu_step_riscv()`
- Arch label in emulation header prints `ARM64`, `RISC-V`, or `X86-64` correctly

#### `src/symexec.c`
- Decode dispatch: RISC-V uses `rv_decode` instead of `a64_decode`
- `rv_reg_se()` resolver for ABI register names (`ra`, `a0`, `s0`, etc.)
- PC advances by decoded instruction length (2 or 4 bytes)

#### `src/decomp.c`
- Both SSA-lift loop and IR-lift loop dispatch to `rv_decode` for RISC-V
- Break conditions extended: `c.jr`, `jalr zero, ra, 0` terminate function

### Fixed - EOX Wizard UX
- Removed `Command:` and `Shell? (Y/N)` prompts - plugin load now goes directly to interactive shell
- Binary prompt retries (up to 5 attempts) with file-exists check before proceeding
- TUI wizard shows plugin list with name + description

### Fixed - Interactive Shell TUI
- All `fprintf` format strings with embedded unicode use byte-level `\xNN` escapes, eliminating `-Wformat-extra-args` warnings on clang 21
- `PCMD` macro: 7 `%s` / 7 args, exactly correct
- `tui_status()` shows: filename, arch, func count, sym count, cursor address
- Box-drawing characters via `\xe2\x94\x82` (valid inside C string literals)

### Fixed - JS Addon (`neodax.node`)
- `hardening.c`, `config.c`, `plugin.c` added to `LIB_SRCS` in `build_js.sh`
- `int main()` guarded with `#ifndef NEODAX_NODE` - no symbol conflict with Node.js
- `-DNEODAX_NODE` added to CFLAGS in `build_js.sh`
- `-ldl` added to all LDFLAGS variants (Linux, BSD, Termux) for `dlopen`
- Platform-specific arch `.S` stub auto-selected by `build_js.sh`

---

## [1.0.9] - 2026

### Added - Plugin System (`-eox`)

- **`src/plugin.c`** - New plugin loader using `dlopen`/`dlsym`:
  - Scans a folder for `.so` / `.dylib` files and loads them at startup
  - Validates magic (`0x584F454EU`) and version (`1`) before calling `neox_plugin_init()`
  - Rejects duplicate plugin names cleanly
  - Load errors printed without aborting analysis
- **`include/dax.h`** - Added `dax_plugin_t`, `dax_plugin_registry_t`, `dax_plugin_hook_t` types and all plugin API declarations
- **`include/plugin.h`** - Plugin API header for external use
- **`src/main.c`** - Wired `-eox <folder>` and `-eox-list` flags:
  - `-eox <folder>` loads all plugins from the given folder
  - `-eox-list` prints loaded plugins and their hooks
  - Plugin `post_load`, `banner`, and `ivf` hooks fire at correct pipeline points
- **`plugins/example_hello/NeoX.c`** - Example post-load + banner plugin
- **`plugins/example_ivf_ext/NeoX.c`** - Example IVF extension: cross-function flow analysis (tail calls, no-return hints, mid-function returns)
- **`PLUGINS.md`** - Complete plugin authoring guide
- **`learn/76_building_plugins.md`** - Updated with full NeoX.c workflow, hook reference, and examples
- **`Makefile`** - Added `src/plugin.c` to SRCS, added `-ldl` to LDFLAGS

### Added - IVF Movement Trace

- **`src/entropy.c` / `dax_ivf_scan()`** - Added **CONTROL FLOW MOVEMENT TRACE** section:
  - For each flagged indirect branch, SMC pattern, thunk, trampoline, hash dispatch, jump table, or VM dispatch - prints a human-readable explanation of **what the code is doing** and **why it is suspicious**
  - Each entry shows: WHAT (technique name), WHY (how it works and why it matters), MOVEMENT (step-by-step data flow), and CALLED FROM (xref source if available)
  - SMC entries cross-reference symexec-confirmed patches
  - Indirect branches show symexec resolution status

---

## [1.0.8] - 2026

### Changed - License

- Relicensed from MIT to **Apache 2.0**. See `LICENSE` for full terms.
- Updated `package.json`, `js/package.json`, `README.md`, `CONTRIBUTING.md`, `web/shared.js`, `web/index.html`, `web/docs.html` to reflect the new license.

### Fixed - DAXC Format (`src/daxc.c`)

- **`dax_daxc_write()`** - Fixed magic and version to use `NEOX` / `DAX_DAXC_VERSION` (was incorrectly hardcoding `DAXC` / `2`). Version now reads from `dax_config_version()` so `config.dax-ng` is the single source of truth.
- **`dax_daxc_to_asm()`** - Completely rewritten. The old implementation tried to `fread()` a binary `daxc_header_t` struct from a file that is now C source text, which always failed. The new implementation text-scans the C source for `#define DAXC_NINSNS` and the `daxc_insns[]` array, matching actual file content.
- **`dax_daxc_read()`** - Added parsing of `daxc_comments[]` table (was previously ignored). Fixed `nfunctions` to reflect actual successfully-parsed count rather than the declared `DAXC_NFUNCS` macro.
- Removed erroneous double `memcpy` of mnemonic bytes into the `bytes[]` field in `collect_insns()`.
- Added `escape_str()` helper to centralize the quote/backslash sanitization that was scattered through the write loop.
- Generated `.daxc` files now include `daxc_neodax_version`, `daxc_arch` strings and a `daxc_header()` function for cleaner standalone output.
- Standalone compiled snapshot now supports `-n` (no color) and `-f` (functions only) flags.

### Changed - `config.dax-ng`

- Added `license = Apache-2.0` field.
- Updated `[daxc]` section: `format_version = 4`, `magic = NEOX`, added `compile_hint`, `run_hint`, `load_hint` fields.
- Added `[server]` section with `port`, `host`, `max_body_bytes`.
- Removed duplicate `tagline` line that appeared after the logo block.

### Changed - REST API Server (`js/server/server.js`)

- Server now reads `config.dax-ng` on startup via `loadDaxNg()`. `PORT`, `HOST`, and `MAX_BODY` are sourced from the config file, overridable by environment variables.
- `HOST` defaults to `127.0.0.1` (from config) instead of `0.0.0.0`.
- `MAX_BODY` uses the `max_body_bytes` config value instead of a hardcoded `5 * 1024 * 1024`.

### Changed - Web UI (`js/server/ui.html`)

- Version updated to `v1.0.8` in header logo and sidebar footer.
- Removed all HTML panel comments (`<!-- OVERVIEW -->`, `<!-- SECTIONS -->`, etc.).

### Updated - Documentation

- `FORMAT_DAXC.md` - Completely rewritten to document the AOT C source format (v4), replacing the old binary format description.
- `learn/66_daxc_snapshots.md` - Rewritten: covers AOT C nature, standalone compilation, `-n`/`-f` flags, `neodax -c` conversion, diffing snapshots, `config.dax-ng` integration.
- `learn/70_rest_api_automation.md` - Rewritten: full endpoint table (all 22 endpoints), curl/Python/JS examples, `/api/analyze` payload shape, batch scan script, error handling.
- `learn/72_web_ui_usage.md` - Rewritten: accurate panel-by-panel description matching actual UI, keyboard shortcuts, tips.
- `learn/84_glossary.md` - Updated DAXC and Snapshot entries to describe AOT C format.
- `learn/INDEX.md` - Updated file count to 68.
- `API.md` - Added Apache 2.0 license note, fixed `DAX_VERSION` to `1.0.8`, rewrote Snapshot section.
- `CLI_REFERENCE.md` - Updated `-o` and `-c` flag descriptions.
- All `web/*.html`, `web/shared.js`, `js/index.d.ts`, `README.md`, `CONTRIBUTING.md`, `FAQ.md`, `BUILDING.md` - version and license updated.

---

## [1.0.0] - 2025

### Added - Mach-O Support

- **`src/macho.c`** - Full Mach-O parser:
  - FAT/universal binary support - selects ARM64 slice first, falls back to x86-64
  - Mach-O 64-bit and 32-bit, little-endian and big-endian
  - Section parsing: `__TEXT,__text` → `.text`, `__DATA,__data` → `.data`, etc.
  - Entry point from `LC_MAIN` load command
  - Symbol table from `LC_SYMTAB` (`nlist_64`), strips leading underscore convention
  - Image/code/data size aggregation from segment vmsize
- **`include/macho.h`** - All required Mach-O structs and constants
- **`arch/arm64_macos.S`** - macOS ARM64 assembly stubs (Mach-O syntax: `@PAGE`/`@PAGEOFF`, `_symbol` names)
- **`arch/x86_64_macos.S`** - macOS x86-64 assembly stubs (Mach-O `__TEXT,__text` sections, syscall `0x2000004`)
- **Makefile**: macOS now uses `arm64_macos.S` / `x86_64_macos.S` instead of broken BSD stubs

### Added - npm Package (Install Without Git Clone)

- **`package.json`** at repo root - proper npm-publishable package:
  - `"main": "js/index.js"`, `"types": "js/index.d.ts"`
  - `"files"` includes `src/`, `include/`, `arch/`, `build_js.sh` so C sources ship with the package
  - `"scripts.install": "node js/scripts/install.js"` - runs on `npm install`
- **`js/scripts/install.js`** - rewritten to work from `node_modules/neodax/`:
  - `PKG_ROOT = __dirname/../..` (works from both `node_modules/neodax/js/scripts/` and git clone)
  - Checks prebuilds → `build_js.sh` → inline compile → graceful failure
  - `node-gyp` header cache search (`~/.cache/node-gyp/VERSION/include/node`)
  - macOS: uses `-D_DARWIN_C_SOURCE -DBUILD_OS_DARWIN`, no `-fPIC`

### Fixed - disasmJson Segfault (x86-64, exit code 139)

`neodax_napi.c` had a local `typedef struct { uint64_t addr; ... } x86_insn_t` with **wrong field order** vs the real `x86_insn_t` in `x86.h`. `x86_decode()` wrote to the real layout but napi read at wrong offsets → OOB read → segfault.

Fix: removed bogus local typedef, added `#include "x86.h"` / `#include "arm64.h"` / `#include "riscv.h"`, used correct fields `insn.address`, `insn.mnemonic`, `insn.ops`, `insn.length`.

### Fixed - Mach-O Magic Constants Inverted

All 6 magic constants in `macho.h` had `_LE` and non-`_LE` values swapped:

```c
// WRONG (was):  MACHO_MAGIC_64_LE = 0xCFFAEDFEU
// CORRECT:      MACHO_MAGIC_64_LE = 0xFEEDFACFU  (bytes CF FA ED FE on disk, read as LE = 0xFEEDFACF)
```

This caused `swap=1` on every real Mach-O binary → all struct fields byte-swapped → `cmdsize = 2,550,136,832` → parse break → 0 sections.

### Fixed - macOS open_memstream / _DARWIN_C_SOURCE

`neodax_napi.c` now sets `_DARWIN_C_SOURCE` before all system headers on Apple platforms, enabling `open_memstream()` which requires BSD POSIX extensions.

### Fixed - ARM64 Function Detection on macOS Stripped Binaries

`analysis.c` prologue detector now recognises:
- `sub sp, sp, #N` - most common macOS ARM64 prologue (stack allocation)
- `stp xN, xM, [sp, #-N]!` - any pre-index register save, not just `x29,x30`
- `autiasp` - pointer authentication epilogue hint
- `cur_addr == base_addr` - section entry point always becomes a function (guarantees ≥1 function even on fully stripped binaries)

### Fixed - RISC-V disasmJson returned empty array

`ndx_disasm_json()` only handled `ARCH_X86_64` and `ARCH_ARM64`. Added `ARCH_RISCV64` branch using `rv_decode()` + `dax_classify_riscv()`.

### Fixed - `rda()` returned `null` (typeof === 'object')

`ndx_rda()` returned `null` when the section wasn't found. Changed to return empty string `""` so `typeof rda() === 'string'` always.

### Fixed - `readBytes()` on Mach-O entry point addresses

Added fallback: when the entry point address is not within any section's vaddr range (common with Mach-O stub areas), estimates file offset via the first code section's `vaddr`/`offset` relationship.

### Fixed - `functions()` start/end on ARM64 stripped binaries

`build_function()` in `neodax_napi.c`: when `fn->end == 0` (function boundary unknown - no `ret` found, e.g. tail-call binaries), uses `fn->start` as fallback so `end >= start` always holds.

### Fixed - Node matrix (Node 18/20/22) build

`build_js.sh` now checks `~/.cache/node-gyp/VERSION/include/node` for headers installed by `node-gyp install`, and supports `NODE_INC` environment variable override.

### Fixed - `build_js.sh` syntax error (unexpected EOF)

Missing `fi` for the `NODE_INC` env-check `if` block.

### Fixed - Compiler warnings

| File | Warning | Fix |
|---|---|---|
| `js/src/neodax_napi.c` | `a64_decode` incompatible pointer (local typedef vs arm64.h) | Remove local typedef |
| `js/src/neodax_napi.c` | 7× misleading-indentation `if(buf)free(buf); return r;` | Add braces, split lines |
| `src/symexec.c` | `snprintf` format-truncation (l/r[128] + operator > bufsz) | Buffer 128→256, `expr_str` 128→512, `#pragma GCC diagnostic` |
| `src/emulate.c` | `halt_reason[64]` too small for function name (max 128B) | `halt_reason` 64→192 |
| `src/macho.c` | `bswap16` defined but not used | Removed |

### Added - CI/CD (6 workflows)

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push/PR | Linux GCC, Linux Clang, Linux ARM64, macOS ARM64, macOS x64, Node 18/20/22 |
| `prebuild.yml` | tag / manual | Compile `.node` on 6 platforms, upload artifacts |
| `publish.yml` | tag / manual | Full pipeline → npm publish → GitHub Release |
| `release.yml` | manual | Bump version → commit → tag → trigger publish |
| `nightly.yml` | daily 02:00 UTC | Regression detection, GitHub issue on failure |
| `codeql.yml` | push/PR/weekly | Static security analysis |

### Added - Documentation (28 files)

`README.md` · `BUILDING.md` · `API.md` · `ARCHITECTURE.md` · `CHANGELOG.md` · `CODE_OF_CONDUCT.md` · `CONTRIBUTING.md` · `SECURITY.md` · `SUPPORT.md` · `NPM_USAGE.md` · `PUBLISHING.md` · `MACHO_SUPPORT.md` · `FORMAT_DAXC.md` · `ALGORITHMS.md` · `CLI_REFERENCE.md` · `EXAMPLES.md` · `FAQ.md` · `FUZZING.md` · `PERFORMANCE.md` · `INTEGRATION.md` · `OBFUSCATION.md` · `UNICODE_DETECTION.md` · `DECOMPILER.md` · `EMULATOR.md` · `CICD_GUIDE.md` · `PORTING.md` · `TROUBLESHOOTING.md` · `js/README.md` · `LICENSE`

---

## [Pre-1.0] - DAX 3.0.0

NeoDAX is a fork of DAX 3.0.0. The original had basic disassembly, single-pass CFG, interactive TUI, no JS bindings, no advanced analysis, ELF/PE only.
