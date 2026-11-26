# CLI Reference

Complete reference for the `neodax` command-line tool.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Synopsis

```
neodax [OPTIONS] <binary>
neodax [OPTIONS] -c <file.daxc>
```

---

## Full Flag Reference

### Output Control

| Flag | Description | Example |
|------|-------------|---------|
| `-a` | Show hex bytes alongside each instruction | `neodax -a ./binary` |
| `-n` | No color output (plain text) | `neodax -n ./binary \| less` |
| `-v` | Verbose — extra detail in analysis output | `neodax -v -C ./binary` |
| `-h` | Show help and exit | `neodax -h` |

### Section Selection

| Flag | Description | Example |
|------|-------------|---------|
| `-s <name>` | Disassemble a specific section (default: `.text`) | `neodax -s .plt ./binary` |
| `-S` | Disassemble all executable sections | `neodax -S ./binary` |
| `-l` | List all sections with metadata (no disassembly) | `neodax -l ./binary` |
| `-A <addr>` | Start address in hex | `neodax -A 0x4010 ./binary` |
| `-E <addr>` | End address in hex | `neodax -A 0x4010 -E 0x4100 ./binary` |

### Static Analysis

| Flag | Description |
|------|-------------|
| `-y` | Resolve symbols — annotate addresses with names from the symbol table |
| `-d` | Demangle C++ Itanium ABI names |
| `-f` | Detect function boundaries — print function headers |
| `-g` | Instruction group coloring — call, branch, ret, stack, syscall, nop |
| `-r` | Cross-reference annotations — show what calls or jumps to each address |
| `-t` | Inline string annotations — show string content from `.rodata` |
| `-C` | Build and print control flow graphs |
| `-L` | Loop detection via dominator analysis |
| `-G` | Call graph — who calls whom |
| `-W` | Switch/jump table detection |
| `-u` | Unicode string scanner — UTF-8, UTF-16LE, UTF-16BE |

### Advanced Analysis

| Flag | Description | Platform |
|------|-------------|----------|
| `-P` | Symbolic execution — track register state through a function | ARM64, x86-64, RISC-V |
| `-Q` | NR lifting — NeoDAX Representation (inter-function IR with type inference) | ARM64, RISC-V |
| `-D` | Decompile to pseudo-C — from NR with resolved calls and type-aware locals | ARM64, RISC-V |
| `-I` | Emulate function — concrete execution with real-time SMC detection | ARM64, RISC-V |
| `-e` | Entropy analysis — Shannon entropy sliding window per section | All |
| `-R` | Recursive descent disassembly — follows control flow | ARM64, x86-64, RISC-V |
| `-V` | Instruction validity filter — flags invalid, privileged, dead bytes, and SMC | ARM64, x86-64, RISC-V |
| `--poly` | Polymorphic obfuscation map — mutation cluster detection with XOR, ROR, and hash-chain signals | All |
| `--dsa` | DSA — Dynamic Single Assignment over all functions | ARM64, RISC-V |
| `--aire` | AIRE — context-aware insights, next-step guide, memory recall | All |
| `--vm-trace` | Print VM dispatch flow trace after emulation | ARM64, x86-64, RISC-V |

### Batch Flags

| Flag | Includes |
|------|----------|
| `-x` | `-y -d -f -g -r -t -C -L -G -W -u` — all standard analysis |
| `-X` | Everything in `-x` plus `-P -Q -D -I -e -R -V --poly --aire --vm-trace --dsa` |

### Snapshot

| Flag | Description |
|------|-------------|
| `-o <file>` | Save full analysis as a `.daxc` AOT C source snapshot |
| `-c` | Convert a `.daxc` snapshot to annotated `.S` assembly |

### Plugins

| Flag | Description |
|------|-------------|
| `-eox <folder>` | Load plugins from the specified folder |
| `-eox-list` | List all currently loaded plugins |

### Interactive Mode

| Flag | Description |
|------|-------------|
| `-i` | Launch the interactive REPL shell |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Binary not found or unreadable |
| `2` | Unsupported format |
| `3` | Internal analysis error |

---

## Examples

### Minimal — just disassemble

```bash
./neodax ./binary
```

### Full standard analysis — most useful for everyday reverse engineering

```bash
./neodax -x ./binary
```

### Full analysis including all advanced modules

```bash
./neodax -X ./binary
```

### Disassemble with bytes and symbols, no color (pipe to less)

```bash
./neodax -a -y -n ./binary | less
```

### Symbols, demangling, functions, and CFG only

```bash
./neodax -y -d -f -C ./binary
```

### Show only the .rodata section

```bash
./neodax -s .rodata ./binary
```

### Entropy analysis — detect packed or encrypted regions

```bash
./neodax -e ./binary
```

### Recursive descent — reveal dead bytes after jump tricks

```bash
./neodax -R ./binary
```

### Instruction validity filter — find invalid or privileged instructions

```bash
./neodax -V ./binary
```

### Symbolic execution of all detected functions

```bash
./neodax -f -P ./binary
```

### Decompile all functions to pseudo-C

```bash
./neodax -f -D ./binary
```

### Emulate ARM64 function 0

```bash
./neodax -f -I ./arm64_binary
# Initial registers can be set via the JS API: bin.emulate(0, {'0': 42n})
```

### Save analysis snapshot

```bash
./neodax -x -o analysis.daxc ./binary
```

### Reload snapshot and convert to annotated assembly

```bash
neodax analysis.daxc            # load snapshot
neodax -c analysis.daxc         # convert to .S
clang -O2 -o snap analysis.daxc && ./snap   # compile standalone
```

### Disassemble a specific address range

```bash
./neodax -A 0x4010 -E 0x4100 ./binary
```

### All executable sections with full analysis

```bash
./neodax -S -x ./binary
```

### Plain text output for CI or logging

```bash
./neodax -x -n ./binary > report.txt
```

---

## Output Format

### Banner

Printed before disassembly — shows format, architecture, OS/ABI, entry point, sizes, SHA-256, Build-ID, and flags.

```
 File          : ./binary
 Format        : ELF64
 Arch          : AArch64 (ARM64)
 OS/ABI        : Android
 Entry         : 0x0000000000000690
 Image Size    : 35952 bytes
 Code Size     : 996 bytes
 Data Size     : 302 bytes
 Symbols       : 1
 Functions     : 2
 CFG Blocks    : 11
 Xrefs         : 28
 SHA-256       : 2d83e181...
 PIE           : yes
 Stripped      : yes
```

### Disassembly line format

```
<address>  <mnemonic>   <operands>   ; [comment]
0x0000000000000790  mov       w8, w0        ; [data-move]
0x0000000000000794  b         0x7a4         ; [branch] -> sub_7b0
```

### CFG tree format

```
  CFG  tricky  (3 blocks)
  |
  +-- block_0--------------------< 0x790  3 insns  12 bytes ENTRY
      +--[J]-- block_1-----------< 0x7b0  5 insns  20 bytes EXIT
          +--[->]-- block_2------< 0x7a4  2 insns  8 bytes
```

### Entropy output format

```
  Section              VAddr      Window  Entropy  Classification
  ------------------------------------------------------------------
  .text                0x1000     +0x0     4.21     (normal)
  .data                0x4000     +0x0     7.82     PACKED/ENCRYPTED
```
