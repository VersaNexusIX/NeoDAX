# CLI Flag Quick Reference

**Level:** Appendix  
**What This Is:** Every NeoDAX CLI flag in one place.

## Core Disassembly

| Flag | Description |
|------|-------------|
| (none) | Disassemble `.text` section |
| `-s NAME` | Disassemble specific section |
| `-S` | Disassemble all executable sections |
| `-A ADDR` | Start address for disassembly (hex) |
| `-E ADDR` | End address for disassembly (hex) |

## Standard Analysis

| Flag | Description |
|------|-------------|
| `-l` | List sections |
| `-y` | Show symbols |
| `-f` | Detect and list functions |
| `-r` | Build cross-references |
| `-C` | Build control flow graphs |
| `-L` | Detect loops |
| `-G` | Build call graph |
| `-W` | Detect switch / dispatch tables |
| `-g` | Show instruction groups (call/branch/ret/arith) |
| `-t` | Extract ASCII strings |
| `-u` | Extract unicode strings |

## Advanced Analysis

| Flag | Description |
|------|-------------|
| `-e` | Entropy analysis — packed / encrypted region detection |
| `-R` | Recursive descent disassembly |
| `-V` | Instruction validity filter — IVF + VM detector + SMC |
| `-P` | Symbolic execution — opaque predicate resolution, SMC tracking |
| `-D` | Pseudo-C decompiler — NR-based, with type inference + resolved calls |
| `-Q` | NR lifting — NeoDAX Representation (inter-function IR) |
| `-I` | Concrete emulator — real register values + real-time SMC capture |
| `--poly` | Polymorphic obfuscation map — 18 signals, XOR/ROR/hash-chain detection |
| `--dsa` | DSA — Dynamic Single Assignment over all functions |
| `--aire` | AIRE — context-aware insights, next-step guide, memory recall |
| `--vm-trace` | Print VM dispatch flow trace after emulation |

## Batch Suites

| Flag | Expands to |
|------|------------|
| `-x` | `-y -d -f -g -r -t -u -C -L -G -W` |
| `-X` | `-x` + `-P -Q -D -I -e -R -V --poly --aire --vm-trace --dsa` |

## Output / Format

| Flag | Description |
|------|-------------|
| `-a` | Show raw hex bytes alongside instructions |
| `-n` | No color (plain text, safe for pipes/grep) |
| `-v` | Verbose — extra counts and section info |
| `-d` | Demangle C++ Itanium ABI names |
| `-i` | Interactive shell (REPL) |
| `-o FILE` | Save `.daxc` AOT snapshot |
| `-c` | Convert `.daxc` → annotated `.S` assembly |

## Info / Meta

| Flag | Description |
|------|-------------|
| `--version` | Print version and exit |
| `--help` / `-h` | Help page |
| `--detail` | Host system info (CPU, OS, memory) |
| `--support` | Supported formats and architectures |

## Plugins

| Flag | Description |
|------|-------------|
| `-eox FOLDER` | Load plugins from folder (`.so` files) |
| `-eox-list` | List all loaded plugins |

## Interactive Shell Commands

| Command | Description |
|---------|-------------|
| `pd [func]` | Disassemble function |
| `fl` | List all functions |
| `sl` | List all symbols |
| `is` | Binary header + sections |
| `cfg [func]` | Control flow graph |
| `ssa [func]` | NR — NeoDAX Representation |
| `dsa [func\|all]` | DSA — Dynamic Single Assignment |
| `dec [func]` | Decompile to pseudo-C |
| `sym [func]` | Symbolic execution |
| `ivf` | Instruction validity filter |
| `poly` | Polymorphic obfuscation map |
| `aire` | AIRE synthesis |
| `run [func]` | Emulate function |
| `step init [f]` | Init step session |
| `step [n]` | Advance N instructions |
| `vt` | VM dispatch trace |
| `ent` | Entropy scan |
| `cg` | Call graph |
| `rda` | Recursive descent |
| `xr ADDR` | Cross-references |
| `seek ADDR` | Move cursor |
| `px [addr] [n]` | Hex dump |
| `reg [func]` | Register dump after emulation |
| `o PATH` | Open binary |
| `cc ADDR TEXT` | Add comment |
| `rename OLD NEW` | Rename function |
| `q` | Quit |

## Fault Recovery Output

When a pass encounters a structural error in the input binary (corrupt section, invalid counter, truncated data), it prints a recovery notice on stderr and continues:

```
  [!] pass 'cfg-build' recovered from fault — func index out of bounds
```

This is expected behavior on malformed binaries. All other passes continue normally. To suppress: pipe stderr to `/dev/null`. To capture: redirect `2>faults.log`.

See `77_fault_isolation.md` for the full explanation.
