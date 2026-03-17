# NeoDAX API Reference

Complete reference for the NeoDAX C API — all public functions, types, and constants declared in `include/dax.h`.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Table of Contents

- [Core Types](#core-types)
- [Binary Loader](#binary-loader)
- [Disassembly](#disassembly)
- [Symbols](#symbols)
- [Analysis & Xrefs](#analysis--xrefs)
- [CFG](#cfg)
- [Loops](#loops)
- [Call Graph](#call-graph)
- [Unicode Scanner](#unicode-scanner)
- [Symbolic Execution](#symbolic-execution)
- [SSA & Decompiler](#ssa--decompiler)
- [Emulator](#emulator)
- [Snapshot (.daxc)](#snapshot-daxc)
- [Utilities](#utilities)
- [Constants](#constants)
- [Color Macros](#color-macros)

---

## Core Types

### `dax_binary_t`

Central struct holding all parsed and analyzed state for a binary.

```c
typedef struct {
    uint8_t      *data;               // Raw file bytes
    size_t        size;               // File size in bytes
    char          filepath[512];      // Resolved absolute path

    dax_fmt_t     fmt;                // Binary format (ELF64, PE32, etc.)
    dax_arch_t    arch;               // Architecture
    dax_os_t      os;                 // OS/ABI

    uint64_t      entry;              // Entry point virtual address
    uint64_t      base;               // Image base address

    uint64_t      image_size;         // Total virtual image size
    uint64_t      code_size;          // Total size of executable sections
    uint64_t      data_size;          // Total size of data sections
    uint32_t      total_insns;        // Instruction count after disassembly

    char          sha256[65];         // Hex SHA-256 digest of the file
    char          build_id[64];       // GNU Build-ID hex string (ELF)

    int           is_pie;             // Position-independent executable
    int           is_stripped;        // No symbol table
    int           has_debug;          // DWARF debug sections present

    dax_section_t sections[DAX_MAX_SECTIONS];
    int           nsections;

    dax_symbol_t  *symbols;           // Heap-allocated
    int            nsymbols;

    dax_xref_t    *xrefs;
    int            nxrefs;

    dax_func_t    *functions;
    int            nfunctions;

    dax_block_t   *blocks;
    int            nblocks;

    dax_comment_t *comments;
    int            ncomments;

    dax_ustring_t *ustrings;
    int            nustrings;
} dax_binary_t;
```

### `dax_opts_t`

Analysis flags passed to most output functions.

```c
typedef struct {
    int      show_bytes;    // -a  show hex bytes
    int      show_addr;     // addresses (always on)
    int      color;         // ANSI color output
    int      verbose;       // -v  verbose mode
    int      symbols;       // -y  resolve symbols
    int      demangle;      // -d  demangle C++
    int      funcs;         // -f  detect functions
    int      groups;        // -g  instruction group coloring
    int      xrefs;         // -r  cross-reference annotations
    int      strings;       // -t  string reference annotations
    int      cfg;           // -C  control flow graphs
    int      loops;         // -L  loop detection
    int      callgraph;     // -G  call graph
    int      switches;      // -W  switch/jump table detection
    int      unicode;       // -u  unicode string scan
    int      symexec;       // -P  symbolic execution
    int      ssa;           // -Q  SSA lifting
    int      decompile;     // -D  decompile
    int      emulate;       // -I  emulate
    char     section[64];   // target section name
    char     output_daxc[512];
    uint64_t start_addr;
    uint64_t end_addr;
} dax_opts_t;
```

### `dax_section_t`

```c
typedef struct {
    char          name[64];
    dax_sec_type_t type;       // code / data / rodata / bss / plt / got / dynamic / debug / other
    uint64_t      vaddr;
    uint64_t      offset;      // file offset
    uint64_t      size;
    uint32_t      flags;       // ELF sh_flags or PE characteristics
    uint32_t      insn_count;  // populated after disassembly
} dax_section_t;
```

### `dax_symbol_t`

```c
typedef struct {
    char         name[128];
    char         demangled[256];
    uint64_t     address;
    uint64_t     size;
    dax_sym_type_t type;       // function / object / import / export / weak / local
    int          is_entry;     // true if this is the binary entry point
} dax_symbol_t;
```

### `dax_xref_t`

```c
typedef struct {
    uint64_t from;
    uint64_t to;
    int      is_call;   // 1 = call instruction, 0 = branch
} dax_xref_t;
```

### `dax_func_t`

```c
typedef struct {
    char     name[128];
    uint64_t start;
    uint64_t end;
    uint32_t insn_count;
    uint32_t block_count;
    int      has_loops;
    int      has_calls;
    int      sym_idx;    // index into bin->symbols, or -1
} dax_func_t;
```

### `dax_block_t`

```c
typedef struct {
    uint64_t       start;
    uint64_t       end;
    int            id;
    int            func_idx;
    int            is_entry;
    int            is_exit;
    int            succ[4];
    dax_edge_type_t edge_type[4];
    int            nsucc;
    int            pred[4];
    int            npred;
} dax_block_t;
```

### `dax_ustring_t`

```c
typedef struct {
    uint64_t      address;
    char          value_utf8[DAX_MAX_UNICODE_STR]; // UTF-8 encoded value
    uint16_t      byte_length;                      // byte length in original encoding
    dax_str_enc_t encoding;                         // STR_ENC_UTF8 / UTF16LE / UTF16BE / ASCII
} dax_ustring_t;
```

### Enumerations

```c
typedef enum { FMT_ELF32, FMT_ELF64, FMT_PE32, FMT_PE64, FMT_RAW, FMT_UNKNOWN } dax_fmt_t;
typedef enum { ARCH_X86_64, ARCH_ARM64, ARCH_RISCV64, ARCH_UNKNOWN } dax_arch_t;
typedef enum { OS_LINUX, OS_ANDROID, OS_BSD, OS_WINDOWS, OS_SYSV, OS_UNKNOWN } dax_os_t;

typedef enum {
    SEC_TYPE_CODE, SEC_TYPE_DATA, SEC_TYPE_RODATA, SEC_TYPE_BSS,
    SEC_TYPE_PLT,  SEC_TYPE_GOT,  SEC_TYPE_DYNAMIC, SEC_TYPE_DEBUG, SEC_TYPE_OTHER
} dax_sec_type_t;

typedef enum {
    SYM_FUNC, SYM_OBJECT, SYM_IMPORT, SYM_EXPORT, SYM_WEAK, SYM_LOCAL, SYM_UNKNOWN
} dax_sym_type_t;

typedef enum {
    EDGE_FALL, EDGE_JUMP, EDGE_COND_TRUE, EDGE_COND_FALSE, EDGE_CALL, EDGE_RET
} dax_edge_type_t;

typedef enum {
    IGRP_CALL, IGRP_BRANCH, IGRP_RET, IGRP_ARITHMETIC, IGRP_LOGIC,
    IGRP_DATA_MOVE, IGRP_COMPARE, IGRP_STACK, IGRP_STRING,
    IGRP_FLOAT, IGRP_SIMD, IGRP_SYSCALL, IGRP_NOP,
    IGRP_PRIVILEGED, IGRP_PROLOGUE, IGRP_EPILOGUE, IGRP_UNKNOWN
} dax_igrp_t;

typedef enum { STR_ENC_ASCII, STR_ENC_UTF8, STR_ENC_UTF16LE, STR_ENC_UTF16BE } dax_str_enc_t;
```

---

## Binary Loader

```c
int  dax_load_binary(const char *path, dax_binary_t *bin);
```
Load and parse a binary file. Populates all fields of `bin`. Returns `0` on success, `-1` on error.

```c
void dax_free_binary(dax_binary_t *bin);
```
Free all heap-allocated fields inside `bin`. Does not free `bin` itself.

```c
void dax_compute_sha256(dax_binary_t *bin);
```
Compute SHA-256 of the raw file bytes and store in `bin->sha256`.

---

## Disassembly

```c
int dax_disasm_x86_64(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
int dax_disasm_arm64(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
int dax_disasm_riscv64(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Disassemble the target section (from `opts->section`) to `out`. Returns instruction count.

```c
void dax_print_banner(dax_binary_t *bin, dax_opts_t *opts);
```
Print the full NeoDAX analysis banner to stdout.

```c
void dax_print_sections(dax_binary_t *bin, dax_opts_t *opts);
```
Print the section table (`-l` flag output) to stdout.

```c
const char *dax_fmt_str(dax_fmt_t fmt);
const char *dax_arch_str(dax_arch_t arch);
const char *dax_os_str(dax_os_t os);
const char *dax_igrp_str(dax_igrp_t grp);
```
Return human-readable strings for enum values.

---

## Symbols

```c
int           dax_sym_load(dax_binary_t *bin);
```
Load symbols from the binary's symbol tables. Populates `bin->symbols` and `bin->nsymbols`. Returns symbol count.

```c
dax_symbol_t *dax_sym_find(dax_binary_t *bin, uint64_t addr);
```
Find the symbol at exactly `addr`. Returns `NULL` if not found.

```c
const char   *dax_sym_name(dax_binary_t *bin, uint64_t addr);
```
Return the symbol name at `addr`, or `NULL`. Convenience wrapper over `dax_sym_find`.

```c
char         *dax_demangle(const char *name, char *buf, size_t bufsz);
```
Demangle a C++ Itanium ABI symbol name into `buf`. Returns `buf`. Falls back to the original name if demangling fails.

---

## Analysis & Xrefs

```c
int  dax_xref_build(dax_binary_t *bin);
```
Scan all executable sections and build the cross-reference table. Populates `bin->xrefs` and `bin->nxrefs`. Returns xref count.

```c
int  dax_xref_find_to(dax_binary_t *bin, uint64_t addr,
                       dax_xref_t *out, int max_out);
```
Find all xrefs targeting `addr`. Fills `out[0..n-1]`. Returns count found (capped at `max_out`).

```c
int  dax_func_detect(dax_binary_t *bin, uint8_t *code, size_t sz,
                     uint64_t base, dax_section_t *sec);
```
Detect function boundaries in `code[0..sz)`. Appends results to `bin->functions`. Returns functions found in this pass.

```c
dax_func_t *dax_func_find(dax_binary_t *bin, uint64_t addr);
```
Find the function containing `addr`. Returns `NULL` if not found.

```c
dax_igrp_t dax_classify_x86(const char *mnemonic);
dax_igrp_t dax_classify_arm64(const char *mnemonic);
dax_igrp_t dax_classify_riscv(const char *mnemonic);
```
Classify a mnemonic string into an instruction group.

```c
int  dax_classify_x86_branch_type(const char *mnem);
int  dax_classify_arm64_branch_type(const char *mnem);
```
Return 1 if the mnemonic is an unconditional branch, 0 if conditional, -1 if not a branch.

---

## CFG

```c
int dax_cfg_build(dax_binary_t *bin, uint8_t *code, size_t sz,
                  uint64_t base, int func_idx);
```
Build the CFG for function `func_idx`. Performs two passes:
1. Pre-pass: register all branch targets as block boundaries
2. Main pass: walk instructions, build edges, skip dead bytes after unconditional branches

Returns total block count across all functions.

```c
int dax_cfg_print(dax_binary_t *bin, int func_idx,
                  dax_opts_t *opts, FILE *out);
```
Print a tree-style CFG for function `func_idx` to `out`. Returns block count for this function.

---

## Loops

```c
int  dax_loop_detect(dax_binary_t *bin, int func_idx, FILE *out, int color);
```
Detect natural loops in function `func_idx` and print results to `out`.

```c
void dax_loop_print_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Run loop detection across all functions.

---

## Call Graph

```c
void dax_callgraph_print(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Print the call graph (who calls whom) to `out` in tree view.

---

## Unicode Scanner

```c
void dax_scan_unicode(dax_binary_t *bin);
```
Scan non-code sections for UTF-8 multi-byte and UTF-16LE strings. Populates `bin->ustrings` and `bin->nustrings`.

```c
void dax_print_unicode_strings(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Print the unicode string table to `out`.

```c
int dax_utf8_decode(const uint8_t *buf, size_t len,
                    uint32_t *codepoint, int *seq_len);
```
Decode one UTF-8 codepoint from `buf`. Returns `0` on success, `-1` on invalid sequence. Sets `*seq_len` to byte length consumed (1–4).

```c
int dax_utf16le_to_utf8(const uint8_t *src, size_t src_bytes,
                         char *dst, size_t dst_max);
```
Convert a UTF-16LE byte sequence to a NUL-terminated UTF-8 string in `dst`. Returns number of bytes written (excluding NUL).

---

## Symbolic Execution

```c
void dax_symexec_func(dax_binary_t *bin, int func_idx,
                      dax_opts_t *opts, FILE *out);
```
Run symbolic execution on function `func_idx`. Tracks register state as symbolic expressions or concrete values. Prints annotated trace to `out`.

```c
void dax_symexec_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Run symbolic execution across all detected functions.

---

## SSA & Decompiler

```c
void dax_ssa_lift_func(dax_binary_t *bin, int func_idx,
                       dax_opts_t *opts, FILE *out);
```
Lift function `func_idx` to Static Single Assignment form and print the IR to `out`.

```c
void dax_ssa_lift_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
SSA-lift all functions.

```c
void dax_decompile_func(dax_binary_t *bin, int func_idx,
                        dax_opts_t *opts, FILE *out);
```
Decompile function `func_idx` to pseudo-C and print to `out`.

```c
void dax_decompile_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Decompile all functions.

---

## Emulator

```c
void dax_emulate_func(dax_binary_t *bin, int func_idx,
                      uint64_t *init_regs, int nregs,
                      dax_opts_t *opts, FILE *out);
```
Concretely emulate function `func_idx`.

- `init_regs[0..nregs-1]` — initial register values for `x0`..`x(nregs-1)`. Pass `NULL` for all-zero.
- Emulation stops at: `ret` (prints return value), `bl` (external call), `blr` (indirect call), or `EMU_MAX_STEPS` (8192) steps.
- Prints step-by-step trace with register changes to `out`.

```c
void dax_emulate_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Emulate up to the first 4 functions with default register values `{0, 1, 2, 3}`.

---

## Entropy, Recursive Descent, Validity Filter

```c
void dax_entropy_scan(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Shannon entropy sliding window analysis of all sections. Flags HIGH (≥ 6.8 bits/byte) and PACKED/ENCRYPTED (≥ 7.0) regions. Window: 256 bytes, step: 64 bytes.

```c
void dax_rda_section(dax_binary_t *bin, dax_section_t *sec,
                     uint64_t start_addr, dax_opts_t *opts, FILE *out);
void dax_rda_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Recursive descent disassembly via BFS from `start_addr` and all symbols in `sec`. Dead byte ranges printed as `[DEAD: 0x... .. 0x...]`. `dax_rda_all` runs on all code sections.

```c
void dax_ivf_scan(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Instruction validity filter. Emits findings for: invalid opcodes (`??`), privileged instructions in userspace, NOP-runs ≥ 8, INT3-runs ≥ 3, dead bytes after unconditional branches.

---

## Snapshot (.daxc)

```c
int dax_daxc_write(dax_binary_t *bin, dax_opts_t *opts, const char *path);
```
Serialize full analysis state to a `.daxc` file at `path`. Returns `0` on success.

```c
int dax_daxc_read(const char *path, dax_binary_t *bin);
```
Deserialize a `.daxc` file into `bin`. Returns `0` on success.

```c
int dax_daxc_to_asm(const char *daxc_path, const char *asm_path, int color);
```
Convert a `.daxc` snapshot to a `.S` annotated assembly file.

---

## Utilities

```c
void dax_comment_add(dax_binary_t *bin, uint64_t addr, const char *text);
```
Attach a comment to a virtual address.

```c
const char *dax_comment_get(dax_binary_t *bin, uint64_t addr);
```
Retrieve comment text at `addr`, or `NULL`.

```c
void dax_print_correction(int argc, char **argv, FILE *out);
```
If the user mistyped a flag, suggest the correct one.

---

## Constants

```c
#define DAX_VERSION         "1.0.0"

/* entropy.c */
#define ENT_WINDOW    256    // sliding window size
#define ENT_STEP      64     // step between windows
#define ENT_HIGH      6.8    // high entropy threshold
#define ENT_PACK_MIN  7.0    // packed/encrypted threshold

#define RDA_MAX_QUEUE   16384
#define RDA_MAX_VISITED 65536

#define MAX_IVF_FINDINGS 4096

#define DAX_MAX_SECTIONS    128
#define DAX_MAX_SYMBOLS     8192
#define DAX_MAX_FUNCTIONS   4096
#define DAX_MAX_BLOCKS      8192
#define DAX_MAX_XREFS       65536
#define DAX_MAX_COMMENTS    2048
#define DAX_MAX_USTRINGS    4096
#define DAX_MAX_UNICODE_STR 512

#define DAXC_MAGIC          0x584F454E   // 'NEOX'
#define DAXC_VERSION        4
```

---

## Color Macros

ANSI escape sequences used throughout output functions. All respected by `opts->color`.

```c
#define COL_RESET     "\033[0m"
#define COL_ADDR      "\033[1;34m"    // bold blue
#define COL_MNEM      "\033[1;33m"    // bold yellow
#define COL_OPS       "\033[0;36m"    // cyan
#define COL_COMMENT   "\033[0;90m"    // dark grey
#define COL_BYTES     "\033[0;90m"    // dark grey
#define COL_FUNC      "\033[1;32m"    // bold green
#define COL_LABEL     "\033[1;33m"    // bold yellow
#define COL_SYM       "\033[1;35m"    // bold magenta
#define COL_XREF      "\033[0;33m"    // orange
#define COL_SECTION   "\033[0;32m"    // green
#define COL_ENTRY     "\033[1;31m"    // bold red
#define COL_GRP_CALL  "\033[0;31m"    // red
#define COL_GRP_RET   "\033[0;35m"    // magenta
#define COL_GRP_BRANCH "\033[0;33m"   // yellow
#define COL_UNICODE   "\033[0;35m"    // purple
#define COL_CFG_TRUE  "\033[0;32m"    // green
#define COL_CFG_FALSE "\033[0;31m"    // red
#define COL_CFG_CALL  "\033[0;36m"    // cyan
#define COL_CFG_FALL  "\033[0;90m"    // dim
```
