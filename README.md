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
  C99 · Zero external dependencies · x86-64 · AArch64 · RISC-V · ELF · PE · Mach-O
</p>

<p align="center">
  <a href="https://github.com/VersaNexusIX/NeoDAX/releases"><img alt="version" src="https://img.shields.io/badge/version-1.0.0-e3b341?style=flat-square"></a>
  <a href="https://github.com/VersaNexusIX/NeoDAX/blob/main/LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-58a6ff?style=flat-square"></a>
  <img alt="lang" src="https://img.shields.io/badge/lang-C99%20%2F%20JS-3fb950?style=flat-square">
  <img alt="arch" src="https://img.shields.io/badge/arch-x86--64%20%7C%20AArch64%20%7C%20RISC--V-bc8cff?style=flat-square">
  <img alt="platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Android-f0883e?style=flat-square">
  <a href="https://github.com/VersaNexusIX/NeoDAX/actions/workflows/ci.yml"><img alt="ci" src="https://img.shields.io/github/actions/workflow/status/VersaNexusIX/NeoDAX/ci.yml?style=flat-square&label=CI"></a>
  <a href="https://www.npmjs.com/package/neodax"><img alt="npm" src="https://img.shields.io/npm/v/neodax?style=flat-square&color=e3b341"></a>
</p>

---

## Quick Start

```bash
# Clone and build
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && make
./neodax -x ./binary

# Or install via npm (no git clone needed)
npm install neodax
```

```js
const neodax = require('neodax');

neodax.withBinary('/path/to/binary', bin => {
    console.log(bin.arch, bin.sha256);
    console.log(bin.sections().length, 'sections');
    console.log(bin.functions().length, 'functions');
});
```

**Android / Termux:**
```bash
pkg install nodejs clang make && make
```

---

## Supported Formats & Architectures

|         | x86-64 | AArch64 | RISC-V RV64 |
|---------|:------:|:-------:|:-----------:|
| **ELF64/32** | ✓ | ✓ | ✓ |
| **PE64+/32** | ✓ | ✓ | — |
| **Mach-O 64** | ✓ | ✓ | — |
| **Mach-O FAT** | ✓ | ✓ | — |
| **Raw** | ✓ | ✓ | ✓ |

---

## Feature Map

### Core Analysis
| Feature | Flag | Description |
|---|---|---|
| Disassembly | *(default)* | x86-64, AArch64, RISC-V RV64GC |
| Section listing | `-l` | vaddr, file offset, size, flags, insn count |
| Hex bytes | `-a` | Raw bytes alongside instructions |
| Symbol resolution | `-y` | ELF symtab/dynsym, PE exports, Mach-O nlist |
| C++ demangling | `-d` | Itanium ABI |
| Function detection | `-f` | Symbol-guided + heuristic (ELF, PE, Mach-O) |
| Instruction groups | `-g` | call/branch/ret/stack/syscall color coding |
| Cross-references | `-r` | Call + branch xref table |
| String references | `-t` | Inline `.rodata` annotations |
| CFG | `-C` | Two-pass — jump-trick & opaque predicate aware |
| Loop detection | `-L` | Natural loops via dominator analysis |
| Call graph | `-G` | Who calls whom |
| Switch tables | `-W` | Jump-table pattern detection |
| Unicode strings | `-u` | UTF-8 + UTF-16LE/BE with false-positive filter |
| All standard | `-x` | All of the above |

### Advanced Analysis
| Feature | Flag | JS API | Platform |
|---|---|---|---|
| Symbolic Execution | `-P` | `.symexec(idx)` | ARM64, x86-64 |
| SSA Lifting | `-Q` | `.ssa(idx)` | ARM64 |
| Decompiler | `-D` | `.decompile(idx)` | ARM64 |
| Emulator | `-I` | `.emulate(idx, regs)` | ARM64 |
| Entropy Analysis | `-e` | `.entropy()` | All |
| Recursive Descent | `-R` | `.rda(section)` | ARM64, x86-64 |
| Validity Filter | `-V` | `.ivf()` | ARM64, x86-64 |
| Everything | `-X` | — | — |

---

## npm Usage

```bash
npm install neodax
```

`npm install` automatically compiles the native addon. No git clone, no manual build step.

```js
const neodax = require('neodax');

// One-liner with auto-close
neodax.withBinary('/path/to/binary', bin => {
    const r = bin.analyze();
    console.log(r.functions.length, 'functions,', r.xrefs.length, 'xrefs');
    console.log(bin.decompile(0));   // pseudo-C (ARM64)
    console.log(bin.entropy());      // packed/encrypted detection
});
```

TypeScript declarations included (`js/index.d.ts`) — no `@types/neodax` needed.

See [NPM_USAGE.md](NPM_USAGE.md) for Express, Fastify, Docker, and TypeScript examples.

---

## Web UI

```bash
node js/server/server.js
# → http://localhost:7070/ui
```

16 analysis panels: Overview · Sections · Symbols · Functions · CFG Blocks · Xrefs · Strings · Unicode · Disassembly · Decompiler · SSA · Symbolic Execution · Emulator · Entropy · Recursive Descent · Validity Filter

---

## All CLI Flags

| Flag | Description |
|------|-------------|
| `-a` | Hex bytes |
| `-s <sec>` | Target section (default `.text`) |
| `-S` | All executable sections |
| `-A / -E` | Start / end address (hex) |
| `-l` | Section listing |
| `-n` | No color |
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
| `-x` | All standard analysis |
| `-X` | Everything |
| `-o <file>` | Save `.daxc` snapshot |
| `-c` | Convert `.daxc` → `.S` |
| `-h` | Help |

---

## Documentation

| File | Description |
|------|-------------|
| [BUILDING.md](BUILDING.md) | Build instructions for all platforms |
| [NPM_USAGE.md](NPM_USAGE.md) | Using NeoDAX as an npm dependency |
| [PUBLISHING.md](PUBLISHING.md) | CI/CD and npm publish guide |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | Complete CLI reference with examples |
| [API.md](API.md) | C API reference |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Internal module design |
| [ALGORITHMS.md](ALGORITHMS.md) | CFG, entropy, RDA, SSA algorithms |
| [js/README.md](js/README.md) | JavaScript API + REST server |
| [MACHO_SUPPORT.md](MACHO_SUPPORT.md) | Mach-O / macOS format details |
| [DECOMPILER.md](DECOMPILER.md) | SSA lifting and pseudo-C decompiler |
| [EMULATOR.md](EMULATOR.md) | ARM64 concrete emulator |
| [EXAMPLES.md](EXAMPLES.md) | Usage recipes (CLI, JS, REST) |
| [FAQ.md](FAQ.md) | Frequently asked questions |
| [OBFUSCATION.md](OBFUSCATION.md) | Analyzing obfuscated/packed binaries |
| [UNICODE_DETECTION.md](UNICODE_DETECTION.md) | Unicode scanner design |
| [FORMAT_DAXC.md](FORMAT_DAXC.md) | `.daxc` snapshot format spec |
| [PERFORMANCE.md](PERFORMANCE.md) | Benchmarks and optimization notes |
| [FUZZING.md](FUZZING.md) | AFL++, libFuzzer, ASAN guide |
| [INTEGRATION.md](INTEGRATION.md) | VS Code, Docker, Python, CI integration |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Build and runtime troubleshooting |
| [PORTING.md](PORTING.md) | Porting to new architectures/formats |
| [CICD_GUIDE.md](CICD_GUIDE.md) | GitHub Actions workflows explained |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

---

## Requirements

- C99 compiler: **GCC ≥ 7** or **Clang ≥ 6** (Clang 21 on Termux ✓)
- **GNU make** (or `gmake` on BSD)
- Zero external libraries
- For JS addon / npm: **Node.js ≥ 16** with dev headers

---

## License

MIT — see [LICENSE](LICENSE).

<p align="center"><sub>Built by <a href="https://github.com/VersaNexusIX">VersaNexusIX</a></sub></p>
