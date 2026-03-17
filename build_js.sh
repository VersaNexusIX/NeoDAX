#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
CYN='\033[1;36m'
DIM='\033[0;90m'
RST='\033[0m'

log()  { echo -e "  ${DIM}$*${RST}"; }
ok()   { echo -e "  ${GRN}✓ $*${RST}"; }
warn() { echo -e "  ${YLW}⚠ $*${RST}"; }
die()  { echo -e "  ${RED}✗ $*${RST}"; exit 1; }

echo -e "\n  ${CYN}NeoDAX — JS Native Addon Builder${RST}\n"

NODE_BIN="$(command -v node 2>/dev/null || command -v nodejs 2>/dev/null || true)"
[ -z "$NODE_BIN" ] && die "node not found — install Node.js first"
NODE_VER="$("$NODE_BIN" --version)"
log "Node: $NODE_VER  ($NODE_BIN)"

NODE_ARCH="$("$NODE_BIN" -p 'process.arch' 2>/dev/null)"
NODE_PLATFORM="$("$NODE_BIN" -p 'process.platform' 2>/dev/null)"
log "Platform: $NODE_PLATFORM / $NODE_ARCH"

find_node_headers() {
    local candidates=(
        "/usr/include/node"
        "/usr/local/include/node"
        "$PREFIX/include/node"
        "$("$NODE_BIN" -p "require('path').join(process.execPath,'../../include/node')" 2>/dev/null || true)"
        "$("$NODE_BIN" -p "require('path').join(process.execPath,'../../../include/node')" 2>/dev/null || true)"
    )
    for d in "${candidates[@]}"; do
        [ -f "$d/node_api.h" ] && echo "$d" && return
    done
    return 1
}

# Allow CI/users to pre-set NODE_INC via environment variable
if [ -n "${NODE_INC:-}" ] && [ -f "${NODE_INC}/node_api.h" ]; then
    ok "Node headers from environment: $NODE_INC"
fi

if [ -z "${NODE_INC:-}" ] || [ ! -f "${NODE_INC}/node_api.h" ]; then

NODE_INC="$(find_node_headers 2>/dev/null || true)"

# Also search node-gyp header cache (installed by CI via: node-gyp install)
if [ -z "$NODE_INC" ]; then
    NODE_VER="$(node --version 2>/dev/null | sed 's/v//' || true)"
    for gyp_root in \
        "$HOME/.cache/node-gyp/$NODE_VER/include/node" \
        "$HOME/.node-gyp/$NODE_VER/include/node" \
        "/root/.cache/node-gyp/$NODE_VER/include/node" \
        "/root/.node-gyp/$NODE_VER/include/node"; do
        if [ -f "$gyp_root/node_api.h" ]; then
            NODE_INC="$gyp_root"
            break
        fi
    done
fi

if [ -z "$NODE_INC" ]; then
    warn "node headers not found — trying to locate via npm..."
    NPM_BIN="$(command -v npm 2>/dev/null || true)"
    if [ -n "$NPM_BIN" ]; then
        NPM_PREFIX="$("$NPM_BIN" prefix -g 2>/dev/null || true)"
        NODE_INC="$NPM_PREFIX/include/node"
        [ -f "$NODE_INC/node_api.h" ] || NODE_INC=""
    fi
fi

if [ -z "$NODE_INC" ]; then
    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists nodejs 2>/dev/null; then
        NODE_INC="$(pkg-config --variable=includedir nodejs)/node"
    fi
fi

[ -z "$NODE_INC" ] && die "Cannot find node headers (node_api.h).\n  On Termux: pkg install nodejs\n  On Debian/Ubuntu: apt install nodejs libnode-dev\n  On macOS: brew install node"

fi  # end: if NODE_INC not already set

ok "Node headers: $NODE_INC"

CC_BIN=""
for try_cc in clang gcc cc; do
    if command -v "$try_cc" >/dev/null 2>&1; then
        CC_BIN="$try_cc"
        break
    fi
done
[ -z "$CC_BIN" ] && die "No C compiler found — install gcc or clang"
CC_VER="$("$CC_BIN" --version 2>/dev/null | head -1)"
log "Compiler: $CC_VER"

LIB_SRCS="src/loader.c src/disasm.c src/x86_decode.c src/arm64_decode.c \
    src/symbols.c src/demangle.c src/analysis.c src/cfg.c src/daxc.c \
    src/interactive.c src/loops.c src/callgraph.c src/correct.c \
    src/riscv_decode.c src/unicode.c src/sha256.c src/main.c \
    src/symexec.c src/decomp.c src/emulate.c src/entropy.c src/macho.c"

CFLAGS="-shared -fPIC -O2 \
    -I./include \
    -I${NODE_INC} \
    -std=c99 \
    -D_GNU_SOURCE \
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
    -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function"

OS="$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')"

case "$OS" in
    linux)
        LDFLAGS="-Wl,--unresolved-symbols=ignore-all"
        ;;
    darwin)
        LDFLAGS="-undefined dynamic_lookup"
        # macOS: use _DARWIN_C_SOURCE for open_memstream + POSIX extensions
        # Remove -fPIC (not needed on macOS with dylib/shared)
        CFLAGS="$(echo "$CFLAGS" | sed 's/-fPIC//')"
        CFLAGS="$CFLAGS -D_DARWIN_C_SOURCE -DBUILD_OS_DARWIN"
        ;;
    freebsd|openbsd|netbsd)
        LDFLAGS="-Wl,--unresolved-symbols=ignore-all"
        ;;
    *)
        LDFLAGS="-Wl,--unresolved-symbols=ignore-all"
        ;;
esac

is_termux() {
    [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ] && echo "$PREFIX" | grep -q "com.termux"
}

if is_termux; then
    log "Detected Termux — applying Android/Termux flags"
    CFLAGS="$CFLAGS -DBUILD_OS_ANDROID -DBUILD_OS_LINUX"
    # LLD on Android: use -z nodefaultlib instead of --unresolved-symbols
    LDFLAGS="-Wl,--unresolved-symbols=ignore-all -lm"
    # Test if --unresolved-symbols is supported (some LLD versions differ)
    if ! echo "int main(){}" | $CC_BIN -x c - -Wl,--unresolved-symbols=ignore-all -o /dev/null 2>/dev/null; then
        LDFLAGS="-Wl,-z,nodefaultlib -lm"
    fi
fi

OUT="js/neodax.node"
CMD="$CC_BIN $CFLAGS js/src/neodax_napi.c $LIB_SRCS $LDFLAGS -lm -o $OUT"

log "Compiling js/neodax.node ..."
if eval "$CMD" 2>&1; then
    ok "Built: $OUT"
    SIZE="$(du -sh "$OUT" 2>/dev/null | cut -f1)"
    log "Size: $SIZE"
else
    die "Build failed — check error output above"
fi

echo ""
echo -e "  ${GRN}Done! Run:${RST}"
echo -e "  ${CYN}  node js/server/server.js${RST}           # start API server"
echo -e "  ${CYN}  node js/examples/01_binary_info.js /bin/ls${RST}"
echo ""
