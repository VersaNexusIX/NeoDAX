# CLI Flag Quick Reference

**Level:** Appendix
**What This Is:** Every NeoDAX CLI flag in one place.

## Core Disassembly

| Flag | Long Form | Description |
|------|-----------|-------------|
| (none) | | Disassemble .text section |
| -s NAME | --section | Disassemble specific section |
| -S | --all-sections | Disassemble all executable sections |
| -A ADDR | --start | Start address for disassembly |
| -E ADDR | --end | End address for disassembly |

## Analysis Flags

| Flag | Description |
|------|-------------|
| -l | List sections |
| -y | Show symbols |
| -f | Detect and list functions |
| -r | Build cross-references |
| -C | Build control flow graphs |
| -L | Detect loops |
| -G | Build call graph |
| -W | Detect switch tables |
| -g | Show instruction groups |
| -t | Extract ASCII strings |
| -u | Extract unicode strings |

## Advanced Analysis

| Flag | Description |
|------|-------------|
| -e | Entropy analysis |
| -R | Recursive descent disassembly |
| -V | Instruction validity filter |
| -P | Symbolic execution (ARM64) |
| -D | Decompiler output (ARM64) |
| -Q | SSA lifting (ARM64) |
| -I | Concrete emulator (ARM64) |

## Meta Flags

| Flag | Description |
|------|-------------|
| -x | Run all standard analysis |
| -X | Run all analysis including advanced |
| -h | Show help |
| -v | Verbose output |
| -n | No color output |
| -a | Show raw bytes |
| -d | Demangle C++ names |

## Input/Output

| Flag | Description |
|------|-------------|
| -o FILE | Save DAXC snapshot |
| -c FILE | Load DAXC snapshot |

## Format-Specific

| Flag | Description |
|------|-------------|
| -m ARCH | Force architecture (for raw binaries) |
| -b ADDR | Set base address (for raw binaries) |

## Examples

Quick look at a binary:
```bash
./neodax -l -y /bin/ls
```

Full analysis, save to file:
```bash
./neodax -n -x /bin/ls > analysis.txt
```

Full analysis with snapshot:
```bash
./neodax -x -o ls.daxc /bin/ls
```

Focus on one address range:
```bash
./neodax -a -A 0x401000 -E 0x401200 /bin/ls
```

C++ demangling:
```bash
./neodax -d -y /path/to/cpp_program
```
