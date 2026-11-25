# Contributing to NeoDAX

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Testing](#testing)
- [Adding New Features](#adding-new-features)

---

## Code of Conduct

All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Ways to Contribute

- **Report bugs** — [open a bug report](https://github.com/VersaNexusIX/NeoDAX/issues/new?template=bug_report.md)
- **Request features** — [GitHub Discussions](https://github.com/VersaNexusIX/NeoDAX/discussions) or [feature request](https://github.com/VersaNexusIX/NeoDAX/issues/new?template=feature_request.md)
- **Fix bugs** — check issues labelled `bug` or `good first issue`
- **Improve decode coverage** — add ARM64, x86-64, or RISC-V instructions to the decoders
- **Add architecture support** — MIPS, PowerPC, Thumb-2
- **Improve the decompiler / NR** — better lifting patterns, type inference, inter-function linkage
- **Write tests** — expand `js/test/basic.js`
- **Improve documentation** — fix inaccuracies, add examples

**Security vulnerabilities:** report privately — see [SECURITY.md](SECURITY.md).

---

## Development Setup

```bash
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX

# Build CLI and JS addon
make

# Verify
./neodax -h
node js/test/basic.js   # all 27 tests should pass
```

**Termux:**
```bash
pkg install nodejs clang make git
git clone https://github.com/VersaNexusIX/NeoDAX.git && cd NeoDAX && make
```

---

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b fix/cfg-dead-bytes
   ```
2. Make your changes, following the [Code Style](#code-style) guide.
3. Build cleanly: `make clean && make`
4. Run the test suite: `node js/test/basic.js`
5. Push and open a PR against `main`.
6. Fill in the PR template completely.

**PRs that fail CI or introduce compiler warnings will not be merged.**

---

## Code Style

### C (C99 strict)

```c
/* snake_case for functions and variables */
int dax_cfg_build(dax_binary_t *bin, uint8_t *code, size_t sz, uint64_t base, int func_idx);

/* _t suffix for types */
typedef struct { ... } dax_section_t;

/* ALL_CAPS for macros and enum values */
#define DAX_MAX_SECTIONS 128
typedef enum { SEC_TYPE_CODE, SEC_TYPE_DATA } dax_sec_type_t;

/* Explicit integer types */
uint32_t n;     /* not: unsigned int */
uint64_t addr;  /* not: unsigned long long */

/* Check all heap allocations */
bin->data = calloc(sz, 1);
if (!bin->data) return -1;

/* Return 0 on success, -1 on failure */
```

**Fault isolation — mandatory for every new module:**

Every public entry point must include `dax_guard.h` (after `dax.h`) and open with a guard:

```c
#include "dax.h"
#include "dax_guard.h"

void dax_mymodule(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    DAX_GUARD_BIN(bin);              /* returns void on bad bin */
    if (!opts || !out) return;
    /* ... */
}

int dax_mymodule_build(dax_binary_t *bin, int fi) {
    DAX_GUARD_BIN_RET(bin, -1);      /* returns -1 on bad bin */
    DAX_GUARD_FUNC_RET(bin, fi, -1); /* returns -1 on OOB fi */
    /* ... */
}
```

All loops over `dax_binary_t` counter fields must have a `DAX_MAX_*` upper bound:

```c
/* correct */
for (i = 0; i < bin->nfunctions && i < DAX_MAX_FUNCTIONS; i++) { ... }

/* wrong — missing DAX_MAX guard */
for (i = 0; i < bin->nfunctions; i++) { ... }
```

All section offset arithmetic must use the overflow-safe subtraction form:

```c
/* correct */
if (sec->size > bin->size - sec->offset) continue;

/* wrong — can overflow on large offset values */
if (sec->offset + sec->size > bin->size) continue;
```

Set the fault register when aborting early so `DAX_RUN_PASS` can emit a diagnostic:

```c
if (something_wrong) {
    dax_fault_set("brief reason string");
    return;
}
```

No inline comments. Code is self-documented through clear naming.

No external dependencies. Do not add any `#include` not already present in the codebase. No new npm packages.

No GCC extensions. All code must compile under `clang -std=c99 -Werror`. No `auto` nested functions, no `__builtin_*` without a fallback.

### JavaScript

```js
'use strict';           // always
const / let             // never var
camelCase               // functions and variables
#privateField           // class private fields
```

---

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

| Type | When |
|------|------|
| `feat` | New feature |
| `fix` | Bug fix |
| `perf` | Performance improvement |
| `refactor` | No behavior change |
| `docs` | Documentation only |
| `build` | Makefile, build_js.sh, workflows |
| `test` | Tests |
| `chore` | Version bumps, formatting |

**Examples:**
```
feat(cfg): two-pass builder pre-registers all branch targets
fix(unicode): reject UTF-16LE strings without codepoints > U+02FF
fix(decomp): replace GCC auto nested functions with static helpers
build: add -lm to LDFLAGS for entropy log2()
docs: update CLI_REFERENCE.md with -e -R -V flags
```

---

## Testing

NeoDAX uses a hand-written test suite in `js/test/basic.js` (27 tests).

```bash
# Full test run
node js/test/basic.js

# Test against a specific binary
NEODAX_TEST_BIN=/path/to/binary node js/test/basic.js

# Quick CLI smoke tests
./neodax -x /bin/ls > /dev/null && echo OK
./neodax -e -R -V /bin/ls > /dev/null && echo OK
```

When contributing:

- All 27 existing tests must still pass.
- Add new tests for any new JS API methods.
- For CFG changes: test against a binary with jump tricks.
- For Unicode changes: test against a Windows PE binary.

---

## Adding New Features

### New CLI analysis module

1. Create `src/mymodule.c` and implement the analysis function.
2. Add `#include "dax_guard.h"` after `#include "dax.h"` in the new file.
3. Open every public entry point with `DAX_GUARD_BIN(bin)` or `DAX_GUARD_BIN_RET(bin, retval)`.
4. Cap all loops over `bin->nfunctions`, `bin->nsections`, etc. with `&& i < DAX_MAX_*`.
5. Use overflow-safe `sec->size > bin->size - sec->offset` for all section bounds checks.
6. Declare in `include/dax.h`: `void dax_mymodule(dax_binary_t *bin, dax_opts_t *opts, FILE *out);`
7. Add a flag to `dax_opts_t`: `int mymodule;`
8. Wire up in `src/main.c` using `DAX_RUN_PASS("mymodule", opts.color, dax_mymodule(&bin, &opts, stdout));`
9. Add to `SRCS` in `Makefile` and `LIB_SRCS` in `build_js.sh`.
10. Add an N-API wrapper in `js/src/neodax_napi.c`.
11. Add the method to `js/index.js` and its type to `js/index.d.ts`.
12. Add an endpoint to `js/server/server.js`.
13. Add a panel to `js/server/ui.html`.
14. Add tests to `js/test/basic.js`.
15. Document the change in `CHANGELOG.md`, `API.md`, and `CLI_REFERENCE.md`.

### New architecture

1. Add `ARCH_NEWARCH` to `dax_arch_t` in `include/dax.h`.
2. Create `include/newarch.h` and `src/newarch_decode.c`.
3. Add `dax_disasm_newarch()` in `src/disasm.c`.
4. Add `dax_classify_newarch()` in `src/analysis.c`.
5. Wire up in `src/loader.c`, `src/main.c`, and `src/cfg.c`.
6. Add the new source file to the Makefile.

---

## License

By contributing, you agree that your changes will be licensed under the [Apache 2.0 License](LICENSE).
