# Changelog

All notable changes to NeoDAX are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2025

### Added — Mach-O Support

- **`src/macho.c`** — Full Mach-O parser:
  - FAT/universal binary support — selects ARM64 slice first, falls back to x86-64
  - Mach-O 64-bit and 32-bit, little-endian and big-endian
  - Section parsing: `__TEXT,__text` → `.text`, `__DATA,__data` → `.data`, etc.
  - Entry point from `LC_MAIN` load command
  - Symbol table from `LC_SYMTAB` (`nlist_64`), strips leading underscore convention
  - Image/code/data size aggregation from segment vmsize
- **`include/macho.h`** — All required Mach-O structs and constants
- **`arch/arm64_macos.S`** — macOS ARM64 assembly stubs (Mach-O syntax: `@PAGE`/`@PAGEOFF`, `_symbol` names)
- **`arch/x86_64_macos.S`** — macOS x86-64 assembly stubs (Mach-O `__TEXT,__text` sections, syscall `0x2000004`)
- **Makefile**: macOS now uses `arm64_macos.S` / `x86_64_macos.S` instead of broken BSD stubs

### Added — npm Package (Install Without Git Clone)

- **`package.json`** at repo root — proper npm-publishable package:
  - `"main": "js/index.js"`, `"types": "js/index.d.ts"`
  - `"files"` includes `src/`, `include/`, `arch/`, `build_js.sh` so C sources ship with the package
  - `"scripts.install": "node js/scripts/install.js"` — runs on `npm install`
- **`js/scripts/install.js`** — rewritten to work from `node_modules/neodax/`:
  - `PKG_ROOT = __dirname/../..` (works from both `node_modules/neodax/js/scripts/` and git clone)
  - Checks prebuilds → `build_js.sh` → inline compile → graceful failure
  - `node-gyp` header cache search (`~/.cache/node-gyp/VERSION/include/node`)
  - macOS: uses `-D_DARWIN_C_SOURCE -DBUILD_OS_DARWIN`, no `-fPIC`

### Fixed — disasmJson Segfault (x86-64, exit code 139)

`neodax_napi.c` had a local `typedef struct { uint64_t addr; ... } x86_insn_t` with **wrong field order** vs the real `x86_insn_t` in `x86.h`. `x86_decode()` wrote to the real layout but napi read at wrong offsets → OOB read → segfault.

Fix: removed bogus local typedef, added `#include "x86.h"` / `#include "arm64.h"` / `#include "riscv.h"`, used correct fields `insn.address`, `insn.mnemonic`, `insn.ops`, `insn.length`.

### Fixed — Mach-O Magic Constants Inverted

All 6 magic constants in `macho.h` had `_LE` and non-`_LE` values swapped:

```c
// WRONG (was):  MACHO_MAGIC_64_LE = 0xCFFAEDFEU
// CORRECT:      MACHO_MAGIC_64_LE = 0xFEEDFACFU  (bytes CF FA ED FE on disk, read as LE = 0xFEEDFACF)
```

This caused `swap=1` on every real Mach-O binary → all struct fields byte-swapped → `cmdsize = 2,550,136,832` → parse break → 0 sections.

### Fixed — macOS open_memstream / _DARWIN_C_SOURCE

`neodax_napi.c` now sets `_DARWIN_C_SOURCE` before all system headers on Apple platforms, enabling `open_memstream()` which requires BSD POSIX extensions.

### Fixed — ARM64 Function Detection on macOS Stripped Binaries

`analysis.c` prologue detector now recognises:
- `sub sp, sp, #N` — most common macOS ARM64 prologue (stack allocation)
- `stp xN, xM, [sp, #-N]!` — any pre-index register save, not just `x29,x30`
- `autiasp` — pointer authentication epilogue hint
- `cur_addr == base_addr` — section entry point always becomes a function (guarantees ≥1 function even on fully stripped binaries)

### Fixed — RISC-V disasmJson returned empty array

`ndx_disasm_json()` only handled `ARCH_X86_64` and `ARCH_ARM64`. Added `ARCH_RISCV64` branch using `rv_decode()` + `dax_classify_riscv()`.

### Fixed — `rda()` returned `null` (typeof === 'object')

`ndx_rda()` returned `null` when the section wasn't found. Changed to return empty string `""` so `typeof rda() === 'string'` always.

### Fixed — `readBytes()` on Mach-O entry point addresses

Added fallback: when the entry point address is not within any section's vaddr range (common with Mach-O stub areas), estimates file offset via the first code section's `vaddr`/`offset` relationship.

### Fixed — `functions()` start/end on ARM64 stripped binaries

`build_function()` in `neodax_napi.c`: when `fn->end == 0` (function boundary unknown — no `ret` found, e.g. tail-call binaries), uses `fn->start` as fallback so `end >= start` always holds.

### Fixed — Node matrix (Node 18/20/22) build

`build_js.sh` now checks `~/.cache/node-gyp/VERSION/include/node` for headers installed by `node-gyp install`, and supports `NODE_INC` environment variable override.

### Fixed — `build_js.sh` syntax error (unexpected EOF)

Missing `fi` for the `NODE_INC` env-check `if` block.

### Fixed — Compiler warnings

| File | Warning | Fix |
|---|---|---|
| `js/src/neodax_napi.c` | `a64_decode` incompatible pointer (local typedef vs arm64.h) | Remove local typedef |
| `js/src/neodax_napi.c` | 7× misleading-indentation `if(buf)free(buf); return r;` | Add braces, split lines |
| `src/symexec.c` | `snprintf` format-truncation (l/r[128] + operator > bufsz) | Buffer 128→256, `expr_str` 128→512, `#pragma GCC diagnostic` |
| `src/emulate.c` | `halt_reason[64]` too small for function name (max 128B) | `halt_reason` 64→192 |
| `src/macho.c` | `bswap16` defined but not used | Removed |

### Added — CI/CD (6 workflows)

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push/PR | Linux GCC, Linux Clang, Linux ARM64, macOS ARM64, macOS x64, Node 18/20/22 |
| `prebuild.yml` | tag / manual | Compile `.node` on 6 platforms, upload artifacts |
| `publish.yml` | tag / manual | Full pipeline → npm publish → GitHub Release |
| `release.yml` | manual | Bump version → commit → tag → trigger publish |
| `nightly.yml` | daily 02:00 UTC | Regression detection, GitHub issue on failure |
| `codeql.yml` | push/PR/weekly | Static security analysis |

### Added — Documentation (28 files)

`README.md` · `BUILDING.md` · `API.md` · `ARCHITECTURE.md` · `CHANGELOG.md` · `CODE_OF_CONDUCT.md` · `CONTRIBUTING.md` · `SECURITY.md` · `SUPPORT.md` · `NPM_USAGE.md` · `PUBLISHING.md` · `MACHO_SUPPORT.md` · `FORMAT_DAXC.md` · `ALGORITHMS.md` · `CLI_REFERENCE.md` · `EXAMPLES.md` · `FAQ.md` · `FUZZING.md` · `PERFORMANCE.md` · `INTEGRATION.md` · `OBFUSCATION.md` · `UNICODE_DETECTION.md` · `DECOMPILER.md` · `EMULATOR.md` · `CICD_GUIDE.md` · `PORTING.md` · `TROUBLESHOOTING.md` · `js/README.md` · `LICENSE`

---

## [Pre-1.0] — DAX 3.0.0

NeoDAX is a fork of DAX 3.0.0. The original had basic disassembly, single-pass CFG, interactive TUI, no JS bindings, no advanced analysis, ELF/PE only.
