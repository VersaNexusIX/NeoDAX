# Changelog

All notable changes to NeoDAX are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · [Semantic Versioning](https://semver.org/).

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## [1.0.0] — 2025

### Added — Core Engine

- **Binary parser** (`loader.c`): ELF32/ELF64 and PE32/PE64+ with full metadata — SHA-256, GNU Build-ID, PIE/stripped/debug flags, image/code/data size breakdown
- **Disassembly** (`disasm.c`): x86-64, AArch64 (ARM64), RISC-V RV64GC with instruction group coloring, symbol annotation, string cross-references
- **Symbol loading** (`symbols.c`): ELF `.symtab`/`.dynsym`, PE export directory, C++ Itanium ABI demangler
- **Analysis engine** (`analysis.c`): instruction classification into 17 groups, xref builder (call + branch)
- **CFG builder** (`cfg.c`): two-pass algorithm — pre-registers all branch targets before main pass; unconditional branches skip dead bytes rather than decoding `0xdeadbeef` as instructions
- **Loop detection** (`loops.c`): natural loops via dominator analysis, back-edge identification
- **Call graph** (`callgraph.c`): tree-style who-calls-whom output
- **Switch detection**: jump-table pattern recognition
- **Unicode scanner** (`unicode.c`): UTF-8 multi-byte + UTF-16LE/BE with strict false-positive suppression (skips `.dynstr`/`.dynsym`, requires codepoints `> U+02FF`, surrogate pair support)
- **SHA-256** (`sha256.c`): pure-C, zero dependencies

### Added — Advanced Analysis

- **Symbolic execution** (`symexec.c`): expression-tree based register tracking; evaluates concretely when operands are known, symbolic otherwise. ARM64 + x86-64.
- **SSA lifting** (`decomp.c`): Static Single Assignment IR — versioned register writes, `r0_2 = r0_0 + 0x7`
- **Decompiler** (`decomp.c`): SSA → pseudo-C output
- **ARM64 emulator** (`emulate.c`): concrete execution engine with 32-register file, page-based memory model (64 × 4 KB pages), CPSR flags, terminates cleanly at `ret`/`bl`/`blr`
- **Entropy analysis** (`entropy.c`): Shannon entropy sliding window (256B window, 64B step); flags HIGH ≥ 6.8 bits/byte, PACKED/ENCRYPTED ≥ 7.0
- **Recursive descent** (`entropy.c`): BFS from entry + all symbols, marks unreachable byte ranges as `[DEAD: ...]`
- **Instruction validity filter** (`entropy.c`): invalid opcodes, privileged instructions in userspace, NOP-runs ≥ 8, INT3-runs ≥ 3, dead bytes after unconditional branches

### Added — CLI flags

`-P` symexec · `-Q` SSA · `-D` decompile · `-I` emulate (ARM64) · `-e` entropy · `-R` recursive descent · `-V` validity filter · `-X` everything · `-x` all standard

### Added — JavaScript API (30 N-API functions)

`load`, `close`, `info`, `sections`, `symbols`, `functions`, `xrefs`, `xrefsTo`, `xrefsFrom`, `blocks`, `unicodeStrings`, `strings`, `disasm`, `disasmJson`, `analyze`, `symAt`, `funcAt`, `sectionByName`, `sectionAt`, `readBytes`, `hottestFunctions`, `symexec`, `ssa`, `decompile`, `emulate`, `entropy`, `rda`, `ivf`, `version`

### Added — REST API & Web UI

- 26 REST endpoints at `http://localhost:7070/api/*`
- Web UI (`ui.html`, 1066 lines): 16 analysis panels, function selector dropdowns for advanced analysis, real-time search/filter on all tables, dark industrial terminal theme (JetBrains Mono + Space Grotesk)

### Added — npm Package

- `js/package.json`: proper npm-publishable package config
- `js/scripts/install.js`: postinstall — checks prebuilds, falls back to compile, graceful failure
- `js/scripts/build.js`: explicit rebuild with `--force`
- `js/test/basic.js`: 27-test suite covering all major APIs
- `js/prebuilds/`: directory for pre-compiled platform binaries
- `index.js` prebuild lookup: checks `prebuilds/<platform>-<arch>.node` before attempting compile

### Added — CI/CD (6 GitHub Actions workflows)

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push/PR | Build + test: Linux GCC, Linux Clang, Linux ARM64, macOS ARM64, macOS x64, Node 18/20/22 matrix |
| `prebuild.yml` | tag / manual | Compile `.node` on 6 platform combos, upload artifacts + release assets |
| `publish.yml` | tag / manual | Full pipeline: validate → test → prebuild → `npm publish --provenance` → GitHub Release |
| `release.yml` | manual | Bump version, commit, tag, push — triggers publish automatically |
| `nightly.yml` | daily 02:00 UTC | Regression detection; opens GitHub issue on failure, closes on recovery |
| `codeql.yml` | push/PR/weekly | Static security analysis of C source |

### Added — Documentation (18 files)

`README.md`, `BUILDING.md`, `API.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, `NPM_USAGE.md`, `PUBLISHING.md`, `FORMAT_DAXC.md`, `ALGORITHMS.md`, `CLI_REFERENCE.md`, `EXAMPLES.md`, `FAQ.md`, `FUZZING.md`, `PERFORMANCE.md`, `js/README.md`, `LICENSE`, `.github/` templates + workflows

### Changed

- Name: DAX → **NeoDAX** throughout all sources, docs, binaries
- Binary: `dax` → `neodax`
- Magic: `DAXC` → `NEOX` in `.daxc` format
- `dax_binary_t` expanded: `sha256[65]`, `build_id[64]`, `image_size`, `code_size`, `data_size`, `total_insns`, `is_pie`, `is_stripped`, `has_debug`, advanced opts flags
- Section table: FileOffset + Insns columns added, 110-char row width
- `LDFLAGS = -lm` added to Makefile for entropy module (`log2()`)
- `build_js.sh`: `-lm` added to link command; LLD compatibility detection for Termux

### Fixed

- **CFG**: dead bytes after unconditional branches no longer decoded as instructions (two-pass fix)
- **Unicode**: ELF `.dynstr` null-separated ASCII no longer produces CJK false positives (from 85 → ~0 for typical ELF binaries)
- **Termux build**: `isprint`/`stdbool` implicit declaration errors under Clang 21 strict C99
- **Web UI**: overview stat cards showed `0` for xrefs/blocks/functions (fetched before analysis ran — now uses live `S.*` state)
- **Web UI**: disassembly panel was blank on first visit (now auto-triggers `renderDisasm()` on panel switch)
- `strncat` buffer check false alarm in `correct.c` (fixed with `-D_FORTIFY_SOURCE=0`)
- `decomp.c`: GCC `auto` nested functions not valid C99 (converted to `static` file-scope helpers)

### Removed

- Interactive TUI mode (`-i` flag)
- `docs/` mirror directory
- `ROADMAP.md`

---

## [Pre-1.0] — DAX 3.0.0 (predecessor)

NeoDAX is a fork and major rewrite of the original DAX tool. DAX 3.0.0 had basic disassembly across three architectures, a simple single-pass CFG builder, interactive TUI, no JS bindings, and no advanced analysis modules.
