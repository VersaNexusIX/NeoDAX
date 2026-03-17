# Building NeoDAX

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Requirements

| Component | Minimum |
|---|---|
| C compiler | GCC ≥ 7 or Clang ≥ 6 |
| Build system | GNU make (or `gmake` on BSD) |
| External libs | **None** |
| JS addon | Node.js ≥ 16 with dev headers |

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
brew install node        # or: download from nodejs.org

git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX && make
```

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
# → neodax.exe
```

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make` | Build `neodax` CLI + `js/neodax.node` |
| `make js` | Build only the JS addon |
| `make install` | Install `neodax` to `/usr/local/bin` |
| `make clean` | Remove objects and binaries |
| `make info` | Print detected platform/compiler |

---

## Building the JS Addon

`make` builds both the CLI and JS addon automatically. To build the addon separately:

```bash
make js
# or
bash build_js.sh
# or (inside js/)
npm run build
```

`build_js.sh` auto-detects platform, compiler, Node headers, and applies correct linker flags per platform.

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
| `-std=c99` | Strict C99 — no GNU extensions, works on Clang 21+ |
| `-O2` | Optimise for speed |
| `-D_GNU_SOURCE` | Enable `open_memstream`, `memmem` |
| `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0` | Disable glibc buffer wrappers that reject legal N-API patterns |
| `-lm` | Math library — required for `log2()` in entropy module |

---

## Verification

```bash
./neodax -h           # print help
./neodax /bin/ls      # basic disassembly
./neodax -x /bin/ls   # full standard analysis
./neodax -X /bin/ls   # full analysis + advanced modules

node js/test/basic.js # 27 tests — all should pass
```

---

## Troubleshooting

**`isprint` undeclared (Clang strict C99):**
Fixed in v1.0.0 — `<ctype.h>` and `<stdbool.h>` are now explicitly included in `js/src/neodax_napi.c`.

**`log2` undefined / linker error:**
```bash
grep LDFLAGS Makefile   # must contain: LDFLAGS = -lm
```

**`node_api.h` not found:**
```bash
# Check where Node headers are
node -p "require('path').join(process.execPath,'../../include/node')"
# On Debian: sudo apt install libnode-dev
```

**`--unresolved-symbols=ignore-all` not supported (some LLD):**
`build_js.sh` detects this and falls back automatically. You can also use `-undefined dynamic_lookup` on macOS.

**`open_memstream` not available:**
Requires Linux glibc ≥ 2.10 or macOS ≥ 10.13. On older systems, upgrade or use Linux/Termux.
