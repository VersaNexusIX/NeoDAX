# Porting Guide

How to add support for new CPU architectures and binary formats to NeoDAX.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Adding a New Architecture

### Step 1 — Decoder

Create `src/<arch>_decode.c` and `include/<arch>.h`:

```c
/* include/mips.h */
#ifndef DAX_MIPS_H
#define DAX_MIPS_H
#include <stdint.h>

typedef struct {
    uint32_t raw;
    uint64_t address;
    char     mnemonic[32];
    char     operands[256];
    int      length;     /* always 4 for MIPS32, variable for MIPS16 */
} mips_insn_t;

int  mips_decode(const uint8_t *buf, size_t len, uint64_t addr, mips_insn_t *insn);
void mips_reg_name(int r, char *out);

#endif
```

`mips_decode()` must:
- Populate all fields of `mips_insn_t`
- Return instruction byte length (> 0) on success, ≤ 0 on invalid
- Be safe on any input (no crashes on garbage bytes)

### Step 2 — Add to `dax_arch_t` enum (`include/dax.h`)

```c
typedef enum {
    ARCH_X86_64, ARCH_ARM64, ARCH_RISCV64,
    ARCH_MIPS32,    /* ← add here */
    ARCH_UNKNOWN
} dax_arch_t;
```

### Step 3 — Classification (`src/analysis.c`)

```c
dax_igrp_t dax_classify_mips(const char *mnem) {
    if (!strcmp(mnem,"jal")||!strcmp(mnem,"jalr")) return IGRP_CALL;
    if (!strcmp(mnem,"j")  ||!strcmp(mnem,"jr"))   return IGRP_BRANCH;
    if (!strcmp(mnem,"jr")  && /* ra */)            return IGRP_RET;
    /* ... */
    return IGRP_UNKNOWN;
}
```

### Step 4 — Disassembly output (`src/disasm.c`)

```c
int dax_disasm_mips(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    /* same structure as dax_disasm_arm64 */
}
```

### Step 5 — CFG builder (`src/cfg.c`)

Add branch/call/ret classification to the CFG pass. The two-pass algorithm works the same for all architectures.

### Step 6 — Function detection (`src/analysis.c`)

Add prologue detection in `dax_func_detect()`. Look for the architecture's function entry patterns (stack frame setup, callee-saved register saves).

### Step 7 — Wire up in `loader.c` and `main.c`

```c
/* loader.c — ELF machine type detection */
case EM_MIPS:   bin->arch = ARCH_MIPS32;  break;

/* main.c — dispatch to disassembler */
if (bin.arch == ARCH_MIPS32) dax_disasm_mips(&bin, &opts, stdout);
```

### Step 8 — Add to Makefile and `build_js.sh`

```makefile
SRCS = ... src/mips_decode.c
```

```bash
# build_js.sh LIB_SRCS
LIB_SRCS="... src/mips_decode.c"
```

### Step 9 — N-API `disasmJson` (`js/src/neodax_napi.c`)

Add a branch to `ndx_disasm_json()`:

```c
} else if (bin->arch == ARCH_MIPS32) {
    while (off < sz) {
        mips_insn_t insn;
        memset(&insn, 0, sizeof(insn));
        int len = mips_decode(code+off, sz-off, base+off, &insn);
        if (len <= 0) { off++; continue; }
        /* ... build napi object ... */
        off += (size_t)insn.length;
    }
}
```

### Step 10 — Tests and documentation

- Add test binary or pattern to `js/test/basic.js` if available
- Document in `ARCHITECTURE.md`
- Add to format/arch table in `README.md`

---

## Adding a New Binary Format

### Example: WASM support

### Step 1 — Header file (`include/wasm.h`)

Define the file magic and key structures:

```c
#define WASM_MAGIC    0x6D736100U  /* '\0asm' as LE uint32 */
#define WASM_VERSION  0x01000000U

typedef struct {
    uint32_t magic;
    uint32_t version;
} wasm_header_t;
```

### Step 2 — Parser (`src/wasm.c`)

```c
int dax_parse_wasm(dax_binary_t *bin) {
    /* populate bin->sections[], bin->arch, bin->fmt, etc. */
    bin->arch = ARCH_UNKNOWN;  /* or add ARCH_WASM */
    bin->os   = DAX_PLAT_UNKNOWN;
    return 0;
}
```

Must populate at minimum:
- `bin->sections[]` and `bin->nsections`
- `bin->arch`, `bin->fmt`, `bin->os`
- `bin->entry`, `bin->base`
- `bin->sha256` (call `dax_compute_sha256(bin)` early)

### Step 3 — Format enum (`include/dax.h`)

```c
typedef enum {
    FMT_ELF32, FMT_ELF64, FMT_PE32, FMT_PE64, FMT_RAW,
    FMT_WASM,  /* ← add here */
    FMT_UNKNOWN
} dax_fmt_t;
```

### Step 4 — Detection in `loader.c`

```c
uint32_t magic32 = *(uint32_t *)bin->data;

if      (magic32 == 0x464C457F)  return dax_parse_elf(bin);
else if (magic16 == PE_DOS_MAGIC) return dax_parse_pe(bin);
else if (magic32 == MACHO_MAGIC_64_LE || ...) {
    dax_compute_sha256(bin);
    return dax_parse_macho(bin);
}
else if (magic32 == WASM_MAGIC) {   /* ← add here */
    dax_compute_sha256(bin);
    return dax_parse_wasm(bin);
}
```

### Step 5 — String representation (`src/loader.c` or `src/main.c`)

```c
const char *dax_fmt_str(dax_fmt_t f) {
    switch (f) {
        case FMT_WASM:  return "WASM";
        /* ... */
    }
}
```

---

## Checklist

When opening a PR for a new arch or format:

- [ ] Decoder handles all byte sequences without crashing (fuzz with AFL++)
- [ ] `dax_arch_str()` / `dax_fmt_str()` updated
- [ ] `dax_classify_<arch>()` returns correct group for at least call/branch/ret
- [ ] `disasmJson` N-API path added (or returns empty array with comment)
- [ ] Makefile `SRCS` updated
- [ ] `build_js.sh` `LIB_SRCS` updated
- [ ] `README.md` format/arch table updated
- [ ] `ARCHITECTURE.md` module description added
- [ ] `CHANGELOG.md` entry added
- [ ] `js/test/basic.js` passes (all 27 existing tests unaffected)

---

## Key Invariants to Preserve

Any new code must not break:

1. **Zero external dependencies** — no new `#include` for non-standard libraries
2. **C99 strict** — compiles with `clang -std=c99 -Wno-unused` and GCC 7+
3. **No segfaults on malformed input** — all bounds checks before array/pointer access
4. **`sections().length > 0` on any recognized binary** — or return a clear error
5. **`functions().length >= 1`** on any binary with detectable code sections — use the section entry point as fallback
