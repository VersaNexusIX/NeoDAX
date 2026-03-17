# Troubleshooting

Common build and runtime issues with NeoDAX and their solutions.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Build Issues

### `log2` undefined / linker error

**Symptom:** `undefined reference to 'log2'` or similar during link.

**Cause:** The entropy module uses `log2()` from `<math.h>` which requires `-lm` on Linux.

**Fix:**
```bash
grep LDFLAGS Makefile   # should show: LDFLAGS = -lm
# If missing:
sed -i 's/^LDFLAGS.*/LDFLAGS = -lm/' Makefile
make clean && make
```

---

### `open_memstream` undeclared / not found

**Symptom:** `warning: implicit declaration of 'open_memstream'` or linker error.

**Cause:** `open_memstream` is a POSIX extension. It requires:
- Linux: `-D_GNU_SOURCE` (already set in Makefile)
- macOS: `-D_DARWIN_C_SOURCE` (set automatically in `build_js.sh` for macOS)
- Minimum versions: Linux glibc ≥ 2.10, macOS ≥ 10.13

**Fix (macOS):**
```bash
# Ensure you're on macOS 10.13+
sw_vers -productVersion
# If OK, try explicitly:
make CC=clang CFLAGS_EXTRA="-D_DARWIN_C_SOURCE"
```

---

### `node_api.h` not found

**Symptom:** `fatal error: node_api.h: No such file or directory`

**Fix:**
```bash
# Debian/Ubuntu
sudo apt install libnode-dev

# Fedora
sudo dnf install nodejs-devel

# Termux — headers bundled with nodejs
pkg install nodejs

# macOS with Homebrew
brew install node
# Headers at: $(brew --prefix)/include/node/

# Or find them manually
node -p "require('path').join(process.execPath,'../../include/node')"
```

---

### `isprint` / `stdbool` undeclared (Clang strict C99)

**Symptom:** `error: implicit declaration of function 'isprint'` or `error: unknown type name '_Bool'`

**Cause:** Old versions of `neodax_napi.c` were missing explicit includes.

**Fix:** Update to v1.0.0+ — `<ctype.h>` and `<stdbool.h>` are now explicitly included.

---

### `auto` nested functions (GCC extension rejected by Clang)

**Symptom:** `error: function definition is not allowed here` in `src/decomp.c`

**Cause:** Pre-v1.0.0 code used GCC `auto` nested functions, a non-standard extension.

**Fix:** Update to v1.0.0+ — these are replaced with `static` file-scope helpers.

---

### macOS assembler errors in `arch/arm64_bsd.S`

**Symptom:**
```
arch/arm64_bsd.S:1:19: error: unexpected token in '.section' directive
.section .note.GNU-stack,"",@progbits
```

**Cause:** `arm64_bsd.S` uses Linux ELF assembly syntax. macOS uses Mach-O.

**Fix:** v1.0.0+ uses `arch/arm64_macos.S` (Mach-O syntax) on macOS. Ensure you have the latest code:
```bash
git pull
make clean && make
```

---

### `--unresolved-symbols=ignore-all` not supported (LLD on Android)

**Symptom:** `ld: unknown argument '--unresolved-symbols=ignore-all'` on Termux.

**Cause:** Some LLD versions use different flags.

**Fix:** `build_js.sh` detects this and falls back automatically. You can also force:
```bash
# Try alternate flag
CC=clang LDFLAGS="-Wl,-z,nodefaultlib -lm" bash build_js.sh
```

---

### `make` says `gmake` not found on BSD

```bash
# FreeBSD/OpenBSD/NetBSD
pkg install gmake   # or pkg_add gmake
gmake clean && gmake
```

---

## Runtime Issues

### `neodax.node` not found after `npm install`

**Symptom:** `Error: NeoDAX native addon not found: .../js/neodax.node`

**Fix:**
```bash
# Trigger rebuild
npm run build
# or
npm rebuild
# or from repo root
bash build_js.sh
```

---

### `sections()` returns empty array on macOS binary

**Symptom:** `sections: 0` when analyzing a macOS `.app` binary or `/bin/ls`.

**Cause (fixed in v1.0.0):** Mach-O magic constants were inverted — `0xFEEDFACF` (ARM64 LE) was labeled as big-endian, causing `swap=1` and corrupting all struct reads.

**Fix:** Update to v1.0.0+. Verify with:
```bash
node -e "const n=require('neodax'); n.withBinary('/bin/ls', b => console.log('sections:', b.sections().length));"
# Should print: sections: 20+  (not 0)
```

---

### `functions()` returns empty on macOS stripped binary

**Symptom:** `functions: 0` on macOS ARM64 stripped binary.

**Cause (fixed in v1.0.0):** The function prologue detector only knew `stp x29,x30`, `paciasp`, `bti`. macOS ARM64 binaries often start functions with `sub sp, sp, #N`.

**Fix:** Update to v1.0.0+. The detector now recognises all macOS ARM64 prologues and always returns ≥1 function (via the section entry point fallback).

---

### `disasmJson()` segfaults (exit code 139)

**Symptom:** Node process exits with code 139 when calling `bin.disasmJson('.text')` on x86-64.

**Cause (fixed in v1.0.0):** `neodax_napi.c` had a local `typedef struct` for `x86_insn_t` with field order different from the real struct in `x86.h`. This caused OOB memory reads.

**Fix:** Update to v1.0.0+.

---

### `rda()` returns `object` instead of `string`

**Symptom:** `typeof bin.rda('.text') === 'object'` (should be `'string'`).

**Cause (fixed in v1.0.0):** `ndx_rda()` returned `null` when the section was not found. `typeof null === 'object'` in JavaScript.

**Fix:** Update to v1.0.0+. `rda()` now returns an empty string `""` when the section is not found.

---

### Analysis is slow on large binaries (> 10 MB)

The main bottlenecks are:
- `dax_xref_build()` — O(instructions), ~2–5 ms per 10K instructions
- `dax_rda_section()` — BFS with O(N) visited set lookup

For large binaries in a production service, cache parsed handles keyed by SHA-256:

```js
const cache = new Map();
function getCached(file) {
    const b = neodax.load(file);
    if (cache.has(b.sha256)) { b.close(); return cache.get(b.sha256); }
    cache.set(b.sha256, b);
    return b;
}
// Clean up on exit
process.on('exit', () => cache.forEach(b => b.close()));
```

---

### Valgrind reports memory errors

```bash
# Build with AddressSanitizer instead of valgrind (faster, more precise)
make clean
make CFLAGS_EXTRA="-fsanitize=address,undefined -g -O1"
./neodax -x ./binary
```

ASAN will print exact locations of any memory errors. Report findings via [SECURITY.md](SECURITY.md).

---

## Getting Help

If none of the above solves your issue:

1. Check [existing issues](https://github.com/VersaNexusIX/NeoDAX/issues)
2. Include: NeoDAX version, OS/arch, compiler version, exact error output
3. Open a [bug report](https://github.com/VersaNexusIX/NeoDAX/issues/new?template=bug_report.md)

For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not open public issues.
