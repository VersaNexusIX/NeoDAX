<p align="center">
  <pre align="center">
   ███╗   ██╗███████╗ ██████╗
   ████╗  ██║██╔════╝██╔═══██╗
   ██╔██╗ ██║█████╗  ██║   ██║
   ██║╚██╗██║██╔══╝  ██║   ██║
   ██║ ╚████║███████╗╚██████╔╝
   ╚═╝  ╚═══╝╚══════╝ ╚═════╝
  </pre>
</p>

<p align="center">
  <strong>Multi-architecture binary analysis framework — disassembler, CFG, decompiler, emulator</strong><br>
  C99 · Zero external dependencies · x86-64 · AArch64 · RISC-V
</p>

<p align="center">
  <a href="https://github.com/VersaNexusIX/NeoDAX/releases"><img alt="version" src="https://img.shields.io/badge/version-1.0.0-e3b341?style=flat-square"></a>
  <a href="https://github.com/VersaNexusIX/NeoDAX/blob/main/LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-58a6ff?style=flat-square"></a>
  <img alt="lang" src="https://img.shields.io/badge/lang-C99%20%2F%20JS-3fb950?style=flat-square">
  <img alt="arch" src="https://img.shields.io/badge/arch-x86--64%20%7C%20AArch64%20%7C%20RISC--V-bc8cff?style=flat-square">
  <img alt="platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Android%20%7C%20macOS%20%7C%20BSD-f0883e?style=flat-square">
  <a href="https://github.com/VersaNexusIX/NeoDAX/actions/workflows/ci.yml"><img alt="ci" src="https://img.shields.io/github/actions/workflow/status/VersaNexusIX/NeoDAX/ci.yml?style=flat-square&label=CI"></a>
  <a href="https://www.npmjs.com/package/neodax"><img alt="npm" src="https://img.shields.io/npm/v/neodax?style=flat-square&color=e3b341"></a>
</p>

---

## What is NeoDAX?

NeoDAX is a **self-contained binary analysis framework** — a single codebase with no external library dependencies that disassembles ELF and PE binaries, builds precise control-flow graphs, detects entropy anomalies, recursively follows code, validates instructions, lifts to SSA form, symbolically executes, emulates ARM64, and ships a full JavaScript/TypeScript API with a dark-themed web UI.

---

## Quick Start

```bash
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && make
./neodax -x ./binary
```

**Android / Termux:**
```bash
pkg install nodejs clang make && make
```

**npm (for backend projects):**
```bash
npm install neodax
```

---

## Feature Map

### Core Analysis
| Feature | Flag | Description |
|---|---|---|
| Disassembly | *(default)* | x86-64, AArch64, RISC-V RV64GC |
| Section listing | `-l` | Virtual addr, file offset, size, flags, insn count |
| Hex bytes | `-a` | Show raw bytes alongside instructions |
| Symbol resolution | `-y` | ELF symtab/dynsym, PE exports |
| C++ demangling | `-d` | Itanium ABI demangler |
| Function detection | `-f` | Symbol-guided + heuristic boundary detection |
| Instruction groups | `-g` | Color-code call/branch/ret/stack/syscall/nop |
| Cross-references | `-r` | Build and annotate call + branch xref table |
| String references | `-t` | Annotate `.rodata` string references inline |
| CFG | `-C` | Two-pass builder — jump-trick & opaque predicate aware |
| Loop detection | `-L` | Natural loops via dominator analysis |
| Call graph | `-G` | Who calls whom, tree view |
| Switch tables | `-W` | Jump-table pattern detection |
| Unicode strings | `-u` | UTF-8 + UTF-16LE/BE with strict false-positive filter |
| All standard | `-x` | Enables all of the above |

### Advanced Analysis
| Feature | Flag | JS API | Description |
|---|---|---|---|
| Symbolic Execution | `-P` | `.symexec(idx)` | Track register states as symbolic expressions |
| SSA Lifting | `-Q` | `.ssa(idx)` | Static Single Assignment IR |
| Decompiler | `-D` | `.decompile(idx)` | Pseudo-C from SSA IR |
| Emulator | `-I` | `.emulate(idx, regs)` | Concrete ARM64 execution engine |
| Entropy Analysis | `-e` | `.entropy()` | Shannon entropy — detect packed/encrypted regions |
| Recursive Descent | `-R` | `.rda(section)` | Follow control flow, mark dead bytes |
| Validity Filter | `-V` | `.ivf()` | Invalid opcodes, privileged insns, NOP-runs |
| Everything | `-X` | — | All standard + all advanced |

### JavaScript / Node.js
- **30 N-API functions** — native addon, zero npm dependencies
- **TypeScript declarations** bundled (`index.d.ts`)
- **REST server** with 26+ endpoints at `http://localhost:7070`
- **Web UI** with 16 analysis panels (dark industrial theme)
- `npm install neodax` — auto-compiles or uses prebuilt binary

---

## All CLI Flags

| Flag | Description |
|------|-------------|
| `-a` | Hex bytes alongside instructions |
| `-s <section>` | Target section (default: `.text`) |
| `-S` | All executable sections |
| `-A <addr>` | Start address (hex) |
| `-E <addr>` | End address (hex) |
| `-l` | Section listing with full metadata |
| `-n` | No color output |
| `-v` | Verbose |
| `-y` | Resolve symbols |
| `-d` | Demangle C++ |
| `-f` | Detect functions |
| `-g` | Instruction group coloring |
| `-r` | Cross-reference annotations |
| `-t` | String reference annotations |
| `-C` | Control flow graphs |
| `-L` | Loop detection |
| `-G` | Call graph |
| `-W` | Switch/jump table detection |
| `-u` | Unicode string scan |
| `-P` | Symbolic execution |
| `-Q` | SSA lifting |
| `-D` | Decompile to pseudo-C |
| `-I` | Emulate functions (ARM64) |
| `-e` | Entropy analysis |
| `-R` | Recursive descent disassembly |
| `-V` | Instruction validity filter |
| `-x` | Enable all standard analysis |
| `-X` | Enable everything |
| `-o <file>` | Save `.daxc` snapshot |
| `-c` | Convert `.daxc` → `.S` |
| `-h` | Help |

---

## Supported Formats & Architectures

|         | x86-64 | AArch64 | RISC-V RV64 |
|---------|:------:|:-------:|:-----------:|
| ELF64   | ✓ | ✓ | ✓ |
| ELF32   | ✓ | ✓ | ✓ |
| PE64+   | ✓ | ✓ | — |
| PE32    | ✓ | — | — |
| Raw     | ✓ | ✓ | ✓ |

---

## Repository Structure

```
NeoDAX/
├── src/                    C source (21 files)
├── include/                Headers (dax.h master + arch headers)
├── arch/                   Platform ASM stubs
├── js/
│   ├── src/neodax_napi.c   N-API native addon (30 APIs)
│   ├── index.js            NeoDAXBinary class wrapper
│   ├── index.d.ts          TypeScript declarations
│   ├── server/server.js    REST API server
│   ├── server/ui.html      Web UI (single file, 1066 lines)
│   ├── scripts/            npm install/build automation
│   ├── test/basic.js       27-test suite
│   ├── examples/           6 runnable example scripts
│   └── prebuilds/          Pre-compiled .node binaries
├── .github/
│   ├── workflows/          6 CI/CD workflows
│   └── ISSUE_TEMPLATE/
├── Makefile
└── build_js.sh
```

---

## Documentation

| File | Description |
|------|-------------|
| [BUILDING.md](BUILDING.md) | Build instructions for all platforms |
| [API.md](API.md) | Full C API reference |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Internal module design |
| [js/README.md](js/README.md) | JavaScript API + REST server |
| [NPM_USAGE.md](NPM_USAGE.md) | Using NeoDAX as an npm dependency |
| [PUBLISHING.md](PUBLISHING.md) | CI/CD and npm publish guide |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [SUPPORT.md](SUPPORT.md) | Getting help |
| [FORMAT_DAXC.md](FORMAT_DAXC.md) | .daxc binary snapshot format |
| [ALGORITHMS.md](ALGORITHMS.md) | Analysis algorithm details |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | Complete CLI reference |
| [EXAMPLES.md](EXAMPLES.md) | Usage examples and recipes |
| [FAQ.md](FAQ.md) | Frequently asked questions |
| [FUZZING.md](FUZZING.md) | Fuzzing and robustness testing |
| [DECOMPILER.md](DECOMPILER.md) | SSA lifting and decompiler internals |
| [EMULATOR.md](EMULATOR.md) | ARM64 concrete emulator reference |
| [CICD_GUIDE.md](CICD_GUIDE.md) | Detailed CI/CD workflow documentation |
| [OBFUSCATION.md](OBFUSCATION.md) | Analyzing obfuscated and packed binaries |
| [UNICODE_DETECTION.md](UNICODE_DETECTION.md) | Unicode scanner design and false-positive filtering |
| [INTEGRATION.md](INTEGRATION.md) | IDE, editor, Docker, Python integration |
| [PERFORMANCE.md](PERFORMANCE.md) | Performance guide and benchmarks |

---

## Requirements

- C99 compiler: **GCC ≥ 7** or **Clang ≥ 6** (Clang 21 on Termux ✓)
- **GNU make** (or `gmake` on BSD)
- Zero external libraries
- For JS: **Node.js ≥ 16** with dev headers

---

## License

MIT — see [LICENSE](LICENSE).

<p align="center"><sub>Built by <a href="https://github.com/VersaNexusIX">VersaNexusIX</a></sub></p>
