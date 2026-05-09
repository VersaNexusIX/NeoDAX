# .daxc Snapshot Format

Specification for the NeoDAX snapshot format.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX
> **License:** Apache 2.0
> **Implementation:** `src/daxc.c` · `include/dax.h`

---

## Overview

`.daxc` is an **AOT C source format** - a self-contained, compilable C file that embeds a complete NeoDAX analysis snapshot. Unlike traditional binary formats, `.daxc` files are human-readable C source code that can be inspected, compiled, and executed directly.

**Use cases:**
- Save an expensive full analysis (`-x -o`) and reload it into NeoDAX
- Compile and run as a standalone binary viewer (`clang -O2 -o snap snap.daxc && ./snap`)
- Convert to annotated `.S` assembly (`neodax -c snap.daxc`)
- Share analysis results without sharing the original binary
- Diff analysis results across versions using standard text tools

---

## Format Identity

| Field | Value |
|-------|-------|
| Magic | `NEOX` (encoded as `#define DAXC_MAGIC "NEOX"` in the C source) |
| Version | `4` (encoded as `#define DAXC_VERSION 4`) |
| Extension | `.daxc` |
| Content | Valid C99 source code |
| Compiler | GCC or Clang, any version supporting C99 |

---

## File Structure

A `.daxc` file is a single C translation unit with this layout:

```
#include directives          stdio.h, stdint.h, string.h, stdlib.h
#define DAXC_*               identity and metadata macros
static const char *          filepath, sha256, arch, neodax version
typedef structs              daxc_insn_t, daxc_func_t, daxc_comment_t
static const daxc_func_t[]  function table
static const daxc_comment_t[] comment table
static const daxc_insn_t[]  instruction table
static void daxc_print_insn() rendering helper
static void daxc_header()   header/summary renderer
int main()                  standalone viewer entry point
```

---

## Metadata Macros

```c
#define DAXC_MAGIC     "NEOX"
#define DAXC_VERSION   4
#define DAXC_ARCH      <dax_arch_t int>
#define DAXC_FMT       <dax_fmt_t int>
#define DAXC_OS        <dax_os_t int>
#define DAXC_ENTRY     0x<hex>ULL
#define DAXC_BASE      0x<hex>ULL
#define DAXC_PIE       <0|1>
#define DAXC_STRIPPED  <0|1>
#define DAXC_NSYMS     <count>
#define DAXC_NFUNCS    <count>
#define DAXC_NINSNS    <count>
```

These macros are parsed by `dax_daxc_read()` when NeoDAX loads the file as input.

---

## Embedded Data Types

### Instruction Record

```c
typedef struct {
    uint64_t address;
    char     mnem[32];
    char     ops[128];
    uint8_t  bytes[16];
    uint8_t  len;
    uint8_t  grp;
} daxc_insn_t;
```

### Function Record

```c
typedef struct {
    char     name[512];
    uint64_t start;
    uint64_t end;
} daxc_func_t;
```

### Comment Record

```c
typedef struct {
    uint64_t addr;
    char     text[256];
} daxc_comment_t;
```

---

## Creating a Snapshot

```bash
neodax -x -o analysis.daxc ./binary
```

The generated file is valid C source. Inspect it with any text editor or `grep`.

---

## Running as Standalone Viewer

```bash
clang -O2 -o snap analysis.daxc
./snap              # color output
./snap -n           # no color (for piping)
./snap -f           # functions only
```

---

## Loading Back into NeoDAX

```bash
neodax analysis.daxc            # load + disassemble
neodax -l analysis.daxc         # list functions
neodax -c analysis.daxc         # convert to annotated .S
```

---

## Parsing by NeoDAX (`dax_daxc_read`)

`dax_daxc_read()` opens the file as text and scans for known patterns:

| Pattern | Extracted field |
|---------|----------------|
| `#define DAXC_ARCH N` | `bin->arch` |
| `#define DAXC_FMT N` | `bin->fmt` |
| `#define DAXC_OS N` | `bin->os` |
| `#define DAXC_ENTRY 0xHEX` | `bin->entry` |
| `#define DAXC_BASE 0xHEX` | `bin->base` |
| `#define DAXC_PIE N` | `bin->is_pie` |
| `#define DAXC_STRIPPED N` | `bin->is_stripped` |
| `#define DAXC_NSYMS N` | `bin->nsymbols` |
| `#define DAXC_NFUNCS N` | `bin->nfunctions` |
| `static const char daxc_filepath[]` | `bin->filepath` |
| `static const char daxc_sha256[]` | `bin->sha256` |
| `static const daxc_func_t daxc_functions[N]` | `bin->functions[]` |
| `static const daxc_comment_t daxc_comments[N]` | `bin->comments[]` |

The instruction table is scanned separately by `dax_daxc_to_asm()` when converting to `.S`.

---

## config.dax-ng Integration

The `[daxc]` section of `config.dax-ng` documents the format parameters in use:

```ini
[daxc]
format_version  = 4
magic           = NEOX
extension       = .daxc
compile_hint    = clang -O2 -o snapshot <file.daxc>
run_hint        = ./snapshot
load_hint       = neodax <file.daxc>
```

The `format_version` and `magic` values here must match `DAX_DAXC_VERSION` and `DAX_DAXC_MAGIC` in `include/dax.h`.

---

## Version History

| Version | Change |
|---------|--------|
| 4 | Current - AOT C source format. `NEOX` magic. Adds `daxc_header()`, `-f` flag, comment table, arch string, neodax version embedding. |
| 3 | Binary format - added CFG blocks and comments. |
| 2 | Binary format - added functions and xrefs. |
| 1 | Binary format - original `DAXC` magic, sections + symbols + insns only. |

> Versions 1-3 used a compact binary layout with a fixed-size header struct. Version 4 switched to AOT C source for portability, inspectability, and standalone execution.

---

## Compatibility

`.daxc` files produced by NeoDAX v1.0.8 and later use format version 4. They are not compatible with older binary-format `.daxc` files (versions 1-3). NeoDAX detects the format by checking whether the file begins with `#include` (C source) or the `NEOX` binary magic bytes and returns an error for the latter.
