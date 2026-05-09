# Building NeoDAX

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Requirements

| Component | Minimum |
|-----------|---------|
| C compiler | GCC >= 7 or Clang >= 6 |
| Build system | GNU make (or `gmake` on BSD) |
| External libraries | None |
| JS addon / npm | Node.js >= 16 with dev headers |

---

## Linux (Debian / Ubuntu)

```bash
sudo apt install build-essential nodejs libnode-dev
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && make
```

## Linux (Fedora / RHEL)

```bash
sudo dnf install gcc make nodejs nodejs-devel
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && make
```

## Linux (Arch)

```bash
sudo pacman -S base-devel nodejs
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && make
```

## Android / Termux

```bash
pkg update && pkg install nodejs clang make git
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && make
```

## macOS

```bash
xcode-select --install   # if not already installed
brew install node        # or download from nodejs.org

git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && make
```

NeoDAX uses `arch/arm64_macos.S` (Mach-O syntax) on Apple Silicon and `arch/x86_64_macos.S` on Intel Mac — both are selected automatically by the Makefile. macOS Mach-O binaries, including universal/FAT binaries, are fully supported.

## FreeBSD / OpenBSD

```bash
# FreeBSD
pkg install gmake node
# OpenBSD
pkg_add node

git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && gmake
```

## Windows (MSYS2 / MinGW)

```bash
# In MSYS2 terminal
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make

git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && make
# Produces neodax.exe
```

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make` | Build `neodax` CLI and `js/neodax.node` |
| JS mode in setup.sh | Build only the JS addon |
| `make install` | Install `neodax` to `/usr/local/bin` |
| `make clean` | Remove object files and binaries |
| `make info` | Print the detected platform and compiler |

---

## Building the JS Addon

`make` builds both the CLI and the JS addon automatically. To build the addon separately:

```bash
make
# or
bash build_js.sh
# or (from inside js/)
npm run build
```

`build_js.sh` auto-detects the platform, compiler, Node.js headers, and applies the correct linker flags per platform.

### Manual compile

```bash
NODE_INC=$(node -p "require('path').join(process.execPath,'../../include/node')")
clang -shared -fPIC -O2 -std=c99 -D_GNU_SOURCE \
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
    -I./include -I"$NODE_INC" \
    js/src/neodax_napi.c \
    src/loader.c src/disasm.c src/x86_decode.c src/arm64_decode.c \
    src/symbols.c src/demangle.c src/analysis.c src/cfg.c src/daxc.c \
    src/interactive.c src/loops.c src/callgraph.c src/correct.c \
    src/riscv_decode.c src/unicode.c src/sha256.c src/main.c \
    src/symexec.c src/decomp.c src/emulate.c src/entropy.c \
    -Wl,--unresolved-symbols=ignore-all -lm \
    -o js/neodax.node
```

---

## Compiler Flags Explained

| Flag | Reason |
|------|--------|
| `-std=c99` | Strict C99 — no GNU extensions; works on Clang 21+ |
| `-O2` | Optimise for speed |
| `-I./include` | Required for `dax.h`, `dax_guard.h`, architecture headers |
| `-D_GNU_SOURCE` | Enable `open_memstream` and `memmem` |
| `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0` | Disable glibc buffer wrappers that reject valid N-API patterns |
| `-lm` | Math library — required for `log2()` in the entropy module |

The `-I./include` flag picks up `dax_guard.h` — the microkernel fault isolation header introduced in v1.1.1. All source files include this header and it must be visible to the compiler. The flag is already present in `setup.sh`'s `BASE_CFLAGS`.

---

## Verification

```bash
./neodax -h           # print help
./neodax /bin/ls      # basic disassembly
./neodax -x /bin/ls   # full standard analysis
./neodax -X /bin/ls   # full analysis including all advanced modules

node js/test/basic.js # 27 tests — all should pass
```

---

## Troubleshooting

**`dax_guard.h` not found:**
```bash
# Ensure -I./include is in CFLAGS. setup.sh adds this automatically.
grep "Iinclude\|I./include" setup.sh   # should match BASE_CFLAGS line
```
If building manually, add `-I./include` to your compile command.

**`isprint` undeclared (Clang strict C99):**
Fixed in v1.0.8. `<ctype.h>` and `<stdbool.h>` are now explicitly included in `js/src/neodax_napi.c`. Update to v1.1.1.

**`log2` undefined / linker error:**
```bash
grep LDFLAGS Makefile   # must contain: LDFLAGS = -lm
```

**`node_api.h` not found:**
```bash
# Check where Node.js headers are installed
node -p "require('path').join(process.execPath,'../../include/node')"
# On Debian/Ubuntu: sudo apt install libnode-dev
```

**`--unresolved-symbols=ignore-all` not supported (some LLD versions):**
`build_js.sh` detects this and falls back automatically. On macOS, `-undefined dynamic_lookup` is used instead.

**`open_memstream` not available:**
Requires Linux glibc >= 2.10 or macOS >= 10.13. On older systems, upgrade the OS or use Termux.

---

## npm Install (No Git Clone Required)

```bash
npm install neodax
```

The postinstall script compiles the native addon automatically:

1. Checks for a prebuilt binary in `js/prebuilds/neodax-<platform>-<arch>.node` — copies it if found.
2. Falls back to running `build_js.sh`.
3. Falls back to an inline `clang`/`gcc` compile using the detected Node.js headers.

```js
const neodax = require('neodax');
neodax.withBinary('/bin/ls', bin => console.log(bin.arch));
```

See [NPM_USAGE.md](NPM_USAGE.md) for full examples.
