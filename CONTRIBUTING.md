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

- Report bugs — [open an issue](https://github.com/VersaNexusIX/NeoDAX/issues/new?template=bug_report.md)
- Request features — [GitHub Discussions](https://github.com/VersaNexusIX/NeoDAX/discussions) or [feature request](https://github.com/VersaNexusIX/NeoDAX/issues/new?template=feature_request.md)
- Fix bugs — check issues labelled `bug` or `good first issue`
- Improve decode coverage — add ARM64/x86-64 instructions to the decoders
- Add architecture support — MIPS, PowerPC, Thumb-2
- Improve the decompiler / SSA — better IR patterns, type inference
- Write tests — expand `js/test/basic.js`
- Improve documentation — fix inaccuracies, add examples

**Security vulnerabilities:** report privately — see [SECURITY.md](SECURITY.md).

---

## Development Setup

```bash
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX

# Build CLI + JS addon
make

# Verify
./neodax -h
node js/test/basic.js   # 27 tests should pass
```

**Termux:**
```bash
pkg install nodejs clang make git
git clone https://github.com/VersaNexusIX/NeoDAX.git && cd NeoDAX && make
```

---

## Submitting a Pull Request

1. Fork the repo, create a branch from `main`:
   ```bash
   git checkout -b fix/cfg-dead-bytes
   ```
2. Make your changes — follow the [Code Style](#code-style) guide
3. Build cleanly: `make clean && make`
4. Run tests: `node js/test/basic.js`
5. Push and open a PR against `main`
6. Fill in the PR template

**PRs that fail CI or add compiler warnings will not be merged.**

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

**No inline comments.** Code is self-documented through clear naming.

**No external dependencies.** Do not add any `#include` not already in the codebase. No npm packages.

**No GCC extensions.** All code must compile under `clang -std=c99 -Werror`. No `auto` nested functions, no `__builtin_*` without fallback.

### JavaScript

```js
'use strict';           // always
const/let               // never var
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

# Quick CLI smoke test
./neodax -x /bin/ls > /dev/null && echo OK
./neodax -e -R -V /bin/ls > /dev/null && echo OK
```

When contributing:
- All 27 existing tests must still pass
- Add new tests for new JS APIs
- For CFG changes: test against a binary with jump tricks
- For Unicode changes: test against a Windows PE binary

---

## Adding New Features

### New CLI analysis module

1. Create `src/mymodule.c` — implement the analysis function
2. Declare in `include/dax.h`: `void dax_mymodule(dax_binary_t *bin, dax_opts_t *opts, FILE *out);`
3. Add a flag to `dax_opts_t`: `int mymodule;`
4. Wire up in `src/main.c`: case + call
5. Add to `SRCS` in `Makefile` and `LIB_SRCS` in `build_js.sh`
6. Add N-API wrapper in `js/src/neodax_napi.c`
7. Add method to `js/index.js` and type to `js/index.d.ts`
8. Add endpoint to `js/server/server.js`
9. Add panel to `js/server/ui.html`
10. Add tests to `js/test/basic.js`
11. Document in `CHANGELOG.md`, `API.md`, `CLI_REFERENCE.md`

### New architecture

1. Add `ARCH_NEWARCH` to `dax_arch_t` in `include/dax.h`
2. Create `include/newarch.h` + `src/newarch_decode.c`
3. Add `dax_disasm_newarch()` in `src/disasm.c`
4. Add `dax_classify_newarch()` in `src/analysis.c`
5. Wire up in `src/loader.c`, `src/main.c`, `src/cfg.c`
6. Add to Makefile

---

## License

By contributing, you agree your changes will be licensed under the [MIT License](LICENSE).
