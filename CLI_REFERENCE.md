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
| `-y` | Resolve symbols — annotate addresses with names from symbol table |
| `-d` | Demangle C++ Itanium ABI names |
| `-f` | Detect function boundaries — print function headers |
| `-g` | Instruction group coloring — call/branch/ret/stack/syscall/nop |
| `-r` | Cross-reference annotations — show what calls/jumps to each address |
| `-t` | Inline string annotations — show string content from `.rodata` |
| `-C` | Build and print control flow graphs |
| `-L` | Loop detection — natural loops via dominator analysis |
| `-G` | Call graph — who calls whom |
| `-W` | Switch/jump table detection |
| `-u` | Unicode string scanner — UTF-8, UTF-16LE, UTF-16BE |

### Advanced Analysis

| Flag | Description | Platform |
|------|-------------|----------|
| `-P` | Symbolic execution — track register state through function | ARM64, x86-64 |
| `-Q` | SSA lifting — Static Single Assignment intermediate representation | ARM64 |
| `-D` | Decompile to pseudo-C — output from SSA IR | ARM64 |
| `-I` | Emulate function — concrete execution with real register values | ARM64 |
| `-e` | Entropy analysis — Shannon entropy sliding window per section | All |
| `-R` | Recursive descent disassembly — follows control flow | ARM64, x86-64 |
| `-V` | Instruction validity filter — invalid, privileged, dead bytes | ARM64, x86-64 |

### Batch Flags

| Flag | Includes |
|------|----------|
| `-x` | `-y -d -f -g -r -t -C -L -G -W -u` — all standard analysis |
| `-X` | Everything in `-x` plus `-P -Q -D -I -e -R -V` |

### Snapshot

| Flag | Description |
|------|-------------|
| `-o <file>` | Save full analysis snapshot to a `.daxc` file |
| `-c` | Convert an existing `.daxc` file to annotated `.S` assembly |

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

### Full standard analysis — most useful for everyday RE

```bash
./neodax -x ./binary
```

### Full analysis + all advanced modules

```bash
./neodax -X ./binary
```

### Disassemble with bytes and symbols, no color (pipe to less)

```bash
./neodax -a -y -n ./binary | less
```

### Symbols + demangling + functions + CFG only

```bash
./neodax -y -d -f -C ./binary
```

### Show only the .rodata section

```bash
./neodax -s .rodata ./binary
```

### Entropy analysis — detect packed/encrypted regions

```bash
./neodax -e ./binary
```

### Recursive descent — see dead bytes after jump tricks

```bash
./neodax -R ./binary
```

### Instruction validity — find invalid/privileged instructions

```bash
./neodax -V ./binary
```

### Symbolic execution of function at specific address

```bash
./neodax -f -P ./binary
```

### Decompile all functions to pseudo-C

```bash
./neodax -f -D ./binary
```

### Emulate ARM64 function 0 with x0=42

```bash
./neodax -f -I ./arm64_binary
# emulator initial registers can be set via JS API: bin.emulate(0, {'0': 42n})
```

### Save analysis snapshot

```bash
./neodax -x -o analysis.daxc ./binary
```

### Reload snapshot and convert to annotated assembly

```bash
./neodax -c analysis.daxc
```

### Address range — disassemble only 0x4010..0x4100

```bash
./neodax -A 0x4010 -E 0x4100 ./binary
```

### All executable sections + full analysis

```bash
./neodax -S -x ./binary
```

### No color for CI/logging environments

```bash
./neodax -x -n ./binary > report.txt
```

---

## Output Format

### Banner

Printed before disassembly — shows format, arch, OS, entry, sizes, SHA-256, Build-ID, flags.

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
0x0000000000000794  b         0x7a4         ; [branch] → sub_7b0
```

### CFG tree format

```
  CFG  tricky  (3 blocks)
  │
  └── block_0────────────────────< 0x790  3 insns  12 bytes ENTRY
      └─[J]─ block_1────────────────< 0x7b0  5 insns  20 bytes EXIT
          └─[→]─ block_2────────────< 0x7a4  2 insns  8 bytes
```

### Entropy output format

```
  Section              VAddr      Window  Entropy  Classification
  ──────────────────────────────────────────────────────────────
  .text                0x1000     +0x0     4.21     (normal)
  .data                0x4000     +0x0     7.82     PACKED/ENCRYPTED
```
