#!/usr/bin/env bash
set -e

ESC=$(printf '\033')
BOLD="${ESC}[1m"
DIM="${ESC}[2m"
RESET="${ESC}[0m"
RED="${ESC}[1;31m"
GREEN="${ESC}[1;32m"
YELLOW="${ESC}[1;33m"
BLUE="${ESC}[1;34m"
MAGENTA="${ESC}[1;35m"
CYAN="${ESC}[1;36m"
WHITE="${ESC}[1;37m"
GREY="${ESC}[0;90m"

ok()    { printf "  ${GREEN}+${RESET}  %s\n"  "$*"; }
err()   { printf "  ${RED}x${RESET}  %s\n"    "$*" >&2; }
warn()  { printf "  ${YELLOW}!${RESET}  %s\n" "$*"; }
info()  { printf "  ${CYAN}>${RESET}  %s\n"   "$*"; }
label() { printf "  ${WHITE}%-10s${RESET}  ${CYAN}%s${RESET}\n" "$1" "$2"; }
sep()   { printf "${GREY}  ─────────────────────────────────────────────────${RESET}\n"; }
blank() { printf "\n"; }

print_banner() {
    printf "${YELLOW}${BOLD}\n"
    printf '   ███╗   ██╗███████╗ ██████╗ \n'
    printf '   ████╗  ██║██╔════╝██╔═══██╗\n'
    printf '   ██╔██╗ ██║█████╗  ██║   ██║\n'
    printf '   ██║╚██╗██║██╔══╝  ██║   ██║\n'
    printf '   ██║ ╚████║███████╗╚██████╔╝\n'
    printf '   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ %s\n' "${RESET}"
    blank
    sep
    label "Setup"   "Interactive Launcher"
    label "Version" "v1.1.1"
    sep
    blank
}

detect_platform() {
    UNAME_S="$(uname -s 2>/dev/null || echo Unknown)"
    UNAME_M="$(uname -m 2>/dev/null || echo unknown)"
    IS_TERMUX=no
    IS_ANDROID=no
    COMPAT_OK=yes
    COMPAT_NOTES=()

    if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ]; then
        echo "$PREFIX" | grep -q "com.termux" && IS_TERMUX=yes
    fi
    { [ -f /system/build.prop ] || [ "$IS_TERMUX" = yes ]; } && IS_ANDROID=yes

    case "$UNAME_S" in
        Linux)
            if   [ "$IS_TERMUX"  = yes ]; then OS_KIND=android
            elif [ "$IS_ANDROID" = yes ]; then OS_KIND=android
            else                               OS_KIND=linux
            fi ;;
        Darwin)       OS_KIND=darwin  ;;
        FreeBSD)      OS_KIND=freebsd ;;
        OpenBSD)      OS_KIND=openbsd ;;
        NetBSD)       OS_KIND=netbsd  ;;
        MINGW*|MSYS*|CYGWIN*) OS_KIND=windows ;;
        *)            OS_KIND=unknown ;;
    esac

    case "$UNAME_M" in
        x86_64|amd64)       ARCH_KIND=x86_64  ;;
        aarch64|arm64)      ARCH_KIND=arm64   ;;
        riscv64)            ARCH_KIND=riscv64 ;;
        armv7*|armv6*|arm*) ARCH_KIND=arm32   ;;
        i386|i486|i686)     ARCH_KIND=x86_32  ;;
        *)                  ARCH_KIND=unknown  ;;
    esac

    case "$OS_KIND" in
        android)
            [ "$IS_TERMUX" = yes ] && PLAT_LABEL="Android / Termux" || PLAT_LABEL="Android" ;;
        linux)
            _n="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-$NAME}" || true)"
            [ -n "$_n" ] && PLAT_LABEL="$_n" || PLAT_LABEL="Linux" ;;
        darwin)
            _sw="$(sw_vers -productVersion 2>/dev/null || true)"
            [ -n "$_sw" ] && PLAT_LABEL="macOS $_sw" || PLAT_LABEL="macOS / Darwin" ;;
        freebsd) PLAT_LABEL="FreeBSD"         ;;
        openbsd) PLAT_LABEL="OpenBSD"         ;;
        netbsd)  PLAT_LABEL="NetBSD"          ;;
        windows) PLAT_LABEL="Windows / MinGW" ;;
        *)       PLAT_LABEL="Unknown ($UNAME_S)" ;;
    esac

    ASM_FILE=""
    case "${ARCH_KIND}:${OS_KIND}" in
        arm64:android|arm64:linux)                ASM_FILE="arch/arm64_linux.S"      ;;
        arm64:darwin)                             ASM_FILE="arch/arm64_macos.S"      ;;
        arm64:freebsd|arm64:openbsd|arm64:netbsd) ASM_FILE="arch/arm64_bsd.S"        ;;
        arm64:windows)                            ASM_FILE="arch/arm64_windows.asm"  ;;
        x86_64:android|x86_64:linux)              ASM_FILE="arch/x86_64_linux.S"     ;;
        x86_64:darwin)                            ASM_FILE="arch/x86_64_macos.S"     ;;
        x86_64:freebsd|x86_64:openbsd|x86_64:netbsd) ASM_FILE="arch/x86_64_bsd.S"  ;;
        x86_64:windows)                           ASM_FILE="arch/x86_64_windows.asm" ;;
        riscv64:android|riscv64:linux)            ASM_FILE="arch/riscv64_linux.S"    ;;
    esac

    if [ -n "$ASM_FILE" ] && [ ! -f "$ASM_FILE" ]; then
        COMPAT_NOTES+=("arch stub '$ASM_FILE' listed but not found on disk")
        ASM_FILE=""
    fi

    case "$OS_KIND" in
        unknown)
            COMPAT_OK=no
            COMPAT_NOTES+=("unrecognised kernel: $UNAME_S") ;;
    esac

    case "$ARCH_KIND" in
        arm32)
            COMPAT_OK=no
            COMPAT_NOTES+=("32-bit ARM is not supported  (aarch64 required)") ;;
        x86_32)
            COMPAT_OK=no
            COMPAT_NOTES+=("32-bit x86 is not supported  (x86_64 required)") ;;
        unknown)
            COMPAT_OK=no
            COMPAT_NOTES+=("unrecognised CPU architecture: $UNAME_M") ;;
    esac

    if [ "$ARCH_KIND" = riscv64 ] && \
       [ "$OS_KIND" != linux ] && [ "$OS_KIND" != android ]; then
        COMPAT_OK=no
        COMPAT_NOTES+=("riscv64 is only supported on Linux/Android (no $OS_KIND asm stub)")
    fi

    if [ "$COMPAT_OK" = yes ] && [ -z "$ASM_FILE" ]; then
        COMPAT_NOTES+=("no arch/ asm stub for ${ARCH_KIND}/${OS_KIND} -- C-only build, platform stubs skipped")
    fi
}

detect_compiler() {
    CC=""
    for try in clang gcc cc; do
        if command -v "$try" >/dev/null 2>&1; then CC="$try"; break; fi
    done
    [ -z "$CC" ] && { err "No C compiler found. Install gcc or clang."; exit 1; }
    CC_VER="$($CC --version 2>/dev/null | head -1)"

    IS_CLANG=0
    echo "$CC_VER" | grep -qi clang && IS_CLANG=1

    BASE_CFLAGS="-O2 -Wall -Wextra \
        -Wno-unused-variable \
        -Wno-unused-parameter \
        -Wno-unused-function \
        -Wno-format-truncation \
        -I./include \
        -std=c99 \
        -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"

    if [ "$IS_CLANG" = 1 ]; then
        EXTRA="-Wno-format-truncation -Wno-format-extra-args \
               -Wno-tautological-compare \
               -Wno-gnu-variable-sized-type-not-at-end"
    else
        EXTRA="-Wno-stringop-truncation -Wno-format-truncation \
               -Wno-format-extra-args -Wno-tautological-compare"
    fi

    CFLAGS="$BASE_CFLAGS $EXTRA"
    LDFLAGS="-lm -ldl -rdynamic"

    case "$OS_KIND" in
        android)
            CFLAGS="$CFLAGS -DBUILD_OS_ANDROID -DBUILD_OS_LINUX -D_GNU_SOURCE"
            # clang 21 on Android crashes linker with tagged-pointer truncation.
            # Drop -rdynamic and add --no-rosegment to avoid the MTE/HWASan crash.
            LDFLAGS="-lm -ldl -Wl,--no-rosegment" ;;
        linux)
            CFLAGS="$CFLAGS -DBUILD_OS_LINUX -D_GNU_SOURCE" ;;
        darwin)
            CFLAGS="$CFLAGS -DBUILD_OS_BSD -DBUILD_OS_DARWIN"
            LDFLAGS="-lm" ;;
        freebsd|openbsd|netbsd)
            CFLAGS="$CFLAGS -DBUILD_OS_BSD" ;;
        windows)
            CFLAGS="$CFLAGS -DBUILD_OS_WINDOWS"
            TARGET_BIN="neodax.exe" ;;
        *)
            CFLAGS="$CFLAGS -DBUILD_OS_UNIX" ;;
    esac

    TARGET_BIN="${TARGET_BIN:-neodax}"
}

SRCS="src/main.c src/loader.c src/disasm.c src/x86_decode.c \
      src/arm64_decode.c src/symbols.c src/demangle.c src/analysis.c \
      src/cfg.c src/daxc.c src/plugin.c src/interactive.c src/loops.c \
      src/callgraph.c src/correct.c src/riscv_decode.c src/unicode.c \
      src/sha256.c src/symexec.c src/decomp.c src/emulate.c \
      src/entropy.c src/dsa.c src/macho.c src/hardening.c src/config.c"

do_compile() {
    detect_compiler

    blank
    sep
    label "Platform" "$PLAT_LABEL"
    label "Arch"     "$UNAME_M"
    label "Compiler" "$CC_VER"
    label "Target"   "$TARGET_BIN"
    [ -n "$ASM_FILE" ] && label "Asm stub" "$ASM_FILE"
    sep
    blank

    TOTAL=$(echo $SRCS | wc -w)
    printf "${GREY}  Compiling %d source files ...${RESET}\n\n" "$TOTAL"

    OBJS=""
    for src in $SRCS; do
        obj="${src%.c}.o"
        printf "  ${BLUE}Compiling${RESET} ${GREY}->${RESET} ${WHITE}%-32s${RESET}\n" "$src"
        $CC $CFLAGS -c "$src" -o "$obj"
        OBJS="$OBJS $obj"
    done

    if [ -n "$ASM_FILE" ]; then
        asm_obj="${ASM_FILE%.S}.o"
        asm_obj="${asm_obj%.asm}.o"
        printf "  ${MAGENTA}Assembling${RESET} ${GREY}->${RESET} ${WHITE}%-32s${RESET}\n" "$ASM_FILE"
        $CC $CFLAGS -c "$ASM_FILE" -o "$asm_obj"
        OBJS="$OBJS $asm_obj"
    fi

    sep
    printf "  ${YELLOW}Linking${RESET}   ${GREY}->${RESET} ${WHITE}%s${RESET}\n" "$TARGET_BIN"
    $CC $OBJS -o "$TARGET_BIN" $LDFLAGS
}

do_compile_js() {
    blank
    printf "  ${WHITE}Building JS bindings ...${RESET}\n\n"
    bash build_js.sh
}

print_compat_report() {
    blank
    sep
    printf "  ${WHITE}${BOLD}System Check${RESET}\n"
    sep
    blank
    label "OS"       "$PLAT_LABEL"
    label "Kernel"   "$UNAME_S"
    label "Arch"     "$UNAME_M ($ARCH_KIND)"
    [ -n "$ASM_FILE" ] && label "Asm stub" "$ASM_FILE" || label "Asm stub" "none"
    blank

    if [ "$COMPAT_OK" = yes ]; then
        ok "Platform is compatible with NeoDAX"
        if [ "${#COMPAT_NOTES[@]}" -gt 0 ]; then
            blank
            for note in "${COMPAT_NOTES[@]}"; do warn "$note"; done
        fi
    else
        printf "  ${RED}${BOLD}x  This platform is not supported${RESET}\n"
        blank
        for note in "${COMPAT_NOTES[@]}"; do
            printf "  ${GREY}    %s${RESET}\n" "$note"
        done
        blank
        sep
        printf "  ${WHITE}Supported configurations:${RESET}\n"
        blank
        printf "${GREY}"
        printf "    Arch       OS\n"
        printf "    ─────────  ──────────────────────────────────────────\n"
        printf "    x86_64     Linux, macOS, FreeBSD, OpenBSD, NetBSD, Windows\n"
        printf "    arm64      Linux, macOS, FreeBSD, OpenBSD, NetBSD, Windows, Android\n"
        printf "    riscv64    Linux, Android\n"
        printf "${RESET}"
        blank
        sep
        blank
        printf "  ${GREY}If your platform should be supported, please open an issue:${RESET}\n"
        printf "  ${CYAN}  https://github.com/VersaNexusIX/NeoDAX/issues${RESET}\n"
        blank
        exit 1
    fi

    blank
    sep
    blank
}

pick_option() {
    local prompt="$1"; shift
    local opts=("$@")
    local n="${#opts[@]}"

    blank; sep
    printf "  ${BOLD}${WHITE}%s${RESET}\n" "$prompt"
    sep; blank

    local i=1
    for opt in "${opts[@]}"; do
        printf "    ${CYAN}[%d]${RESET}  %s\n" "$i" "$opt"
        i=$(( i + 1 ))
    done

    blank
    while true; do
        printf "  ${GREY}Enter number (1-%d):${RESET} " "$n"
        read -r PICKED
        case "$PICKED" in
            ''|*[!0-9]*) printf "  ${RED}Invalid. Enter a number.${RESET}\n"; continue ;;
        esac
        if [ "$PICKED" -ge 1 ] && [ "$PICKED" -le "$n" ]; then break
        else printf "  ${RED}Out of range. Choose 1 to %d.${RESET}\n" "$n"
        fi
    done
}

mode_js() {
    blank; sep
    printf "  ${YELLOW}${BOLD}JS Framework Build${RESET}\n"
    sep

    if [ ! -f "./$TARGET_BIN" ]; then
        printf "\n  ${WHITE}Building native core first ...${RESET}\n"
        do_compile
        blank
        sep
        ok "Native core built"
        sep
    else
        blank; ok "Native binary already built"
    fi

    do_compile_js

    blank; sep
    printf "${GREEN}${BOLD}\n"
    printf '  ╔══════════════════════════════════════════════╗\n'
    printf '  ║  JS Framework ready                          ║\n'
    printf '  ║                                              ║\n'
    printf '  ║  node js/server/server.js      API server    ║\n'
    printf '  ║  node js/examples/01_binary_info.js          ║\n'
    printf '  ╚══════════════════════════════════════════════╝\n'
    printf '%s\n' "${RESET}"

    if [ -f js/package.json ] && command -v npm >/dev/null 2>&1; then
        info "Installing npm dependencies ..."
        ( cd js && npm install --silent ) && ok "npm install done"
    fi
}

mode_code() {
    blank; sep
    printf "  ${YELLOW}${BOLD}Full Compile${RESET}\n"
    sep

    do_compile

    blank; sep
    printf "${GREEN}${BOLD}\n"
    printf '  ╔══════════════════════════════════════════════╗\n'
    printf '  ║  NeoDAX compiled successfully                ║\n'
    printf '  ║                                              ║\n'
    printf '  ║  ./neodax <binary>             run           ║\n'
    printf '  ║  ./neodax -h                   help          ║\n'
    printf '  ║  ./neodax -x -u <binary>       full RE       ║\n'
    printf '  ╚══════════════════════════════════════════════╝\n'
    printf '%s\n' "${RESET}"
}

mode_learn() {
    blank; sep
    printf "  ${YELLOW}${BOLD}Learn NeoDAX${RESET}\n"
    sep; blank

    pick_option "Select interface" \
        "GUI  --  Open web browser  (served from ./web/)" \
        "CLI  --  Terminal lessons  (markdown in ./learn/)"

    case "$PICKED" in
        1) learn_gui ;;
        2) learn_cli ;;
    esac
}

learn_gui() {
    blank; sep
    printf "  ${YELLOW}${BOLD}Learn / GUI Mode${RESET}\n"
    sep; blank

    if ! command -v node >/dev/null 2>&1; then
        err "node not found. Install Node.js first."
        case "$OS_KIND" in
            android) info "On Termux:  pkg install nodejs" ;;
            linux)   info "On Debian/Ubuntu:  apt install nodejs" ;;
            darwin)  info "On macOS:  brew install node" ;;
        esac
        exit 1
    fi

    PORT="${NEODAX_PORT:-7474}"
    if command -v ss >/dev/null 2>&1; then
        while ss -tlnp 2>/dev/null | grep -q ":${PORT} "; do PORT=$(( PORT + 1 )); done
    elif command -v lsof >/dev/null 2>&1; then
        while lsof -i ":${PORT}" >/dev/null 2>&1; do PORT=$(( PORT + 1 )); done
    fi

    # Resolve a writable directory that works on Android/Termux (no /tmp/ write access on non-root)
    NEODAX_CACHE_DIR="$(pwd)/.neodax_cache"
    mkdir -p "$NEODAX_CACHE_DIR" 2>/dev/null || NEODAX_CACHE_DIR="$HOME/.cache/neodax" && mkdir -p "$NEODAX_CACHE_DIR" 2>/dev/null
    SRV_SCRIPT="$NEODAX_CACHE_DIR/_learn_srv.js"

    cat > "$SRV_SCRIPT" << 'JSEOF'
const http = require('http');
const fs   = require('fs');
const path = require('path');
const WEB_DIR = process.argv[2] || './web';
const PORT    = parseInt(process.argv[3] || '7474', 10);
const MIME = {
    '.html': 'text/html; charset=utf-8', '.js': 'application/javascript',
    '.css': 'text/css', '.json': 'application/json', '.png': 'image/png',
    '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.svg': 'image/svg+xml',
};
const server = http.createServer((req, res) => {
    let url = req.url.split('?')[0];
    if (url === '/' || url === '') url = '/learn.html';
    const filepath = path.join(WEB_DIR, url);
    fs.readFile(filepath, (err, data) => {
        if (err) {
            fs.readFile(path.join(WEB_DIR, 'learn.html'), (e2, d2) => {
                if (e2) { res.writeHead(404); res.end('Not found'); return; }
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(d2);
            });
            return;
        }
        const ext = path.extname(filepath).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
        res.end(data);
    });
});
server.listen(PORT, '127.0.0.1', () => {
    process.stdout.write('NEODAX_SERVER_READY ' + PORT + '\n');
});
process.on('SIGINT',  () => { server.close(); process.exit(0); });
process.on('SIGTERM', () => { server.close(); process.exit(0); });
JSEOF

    info "Starting learn server on port ${PORT} ..."
    node "$SRV_SCRIPT" "$(pwd)/web" "$PORT" &
    SRV_PID=$!

    READY=no
    for _ in 1 2 3 4 5; do
        sleep 1
        if kill -0 "$SRV_PID" 2>/dev/null; then READY=yes; break; fi
    done
    if [ "$READY" = no ]; then err "Server failed to start."; exit 1; fi

    URL="http://127.0.0.1:${PORT}/learn.html"
    blank; sep
    printf "${GREEN}${BOLD}\n"
    printf '  ╔══════════════════════════════════════════════╗\n'
    printf '  ║  Learn server running                        ║\n'
    printf '  ║                                              ║\n'
    printf "  ║  %-44s║\n" "$URL"
    printf '  ║                                              ║\n'
    printf '  ║  Open the URL above in your browser.         ║\n'
    printf '  ║  Press Ctrl+C to stop the server.            ║\n'
    printf '  ╚══════════════════════════════════════════════╝\n'
    printf '%s\n' "${RESET}"

    if command -v xdg-open    >/dev/null 2>&1; then xdg-open    "$URL" 2>/dev/null & fi
    if command -v termux-open >/dev/null 2>&1; then termux-open "$URL" 2>/dev/null & fi

    wait "$SRV_PID" 2>/dev/null || true
    blank; ok "Server stopped."
}

learn_cli() {
    blank; sep
    printf "  ${YELLOW}${BOLD}Learn / CLI Mode${RESET}\n"
    sep; blank

    LEARN_DIR="$(pwd)/learn"
    if [ ! -d "$LEARN_DIR" ]; then err "learn/ directory not found."; exit 1; fi

    printf "${GREY}  Lessons in:${RESET}  ${CYAN}%s${RESET}\n\n" "$LEARN_DIR"
    printf "  ${WHITE}${BOLD}Available lessons:${RESET}\n\n"
    while IFS= read -r f; do
        printf "  ${GREY}  %s${RESET}\n" "$(basename "$f" .md)"
    done < <(find "$LEARN_DIR" -maxdepth 1 -name '*.md' | sort)

    blank; sep; blank
    printf "${GREEN}${BOLD}\n"
    printf '  ╔══════════════════════════════════════════════╗\n'
    printf '  ║  Entering learn/  directory                  ║\n'
    printf '  ║                                              ║\n'
    printf '  ║  Tips:                                       ║\n'
    printf '  ║    cat 01_what_is_binary_analysis.md         ║\n'
    printf '  ║    less INDEX.md                             ║\n'
    printf '  ║    grep -l "disasm" *.md                     ║\n'
    printf '  ║                                              ║\n'
    printf '  ║  Type  exit  to leave.                       ║\n'
    printf '  ╚══════════════════════════════════════════════╝\n'
    printf '%s\n' "${RESET}"

    SHELL_CMD="${SHELL:-/bin/bash}"
    case "$(basename "$SHELL_CMD")" in
        bash)
            _P='PS1="\[\033[1;33m\][NeoDAX learn]\[\033[0m\] \[\033[0;90m\]\W\[\033[0m\] \$ "'
            exec bash --rcfile <(printf '%s\ncd "%s"\n' "$_P" "$LEARN_DIR") ;;
        zsh)
            _Z="$(mktemp -d)"
            printf 'PROMPT="%%F{yellow}[NeoDAX learn]%%f %%F{8}%%1~%%f %% "\ncd "%s"\n' \
                "$LEARN_DIR" > "$_Z/.zshrc"
            ZDOTDIR="$_Z" exec zsh ;;
        *)
            cd "$LEARN_DIR" && exec "$SHELL_CMD" ;;
    esac
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_banner
detect_platform
print_compat_report

pick_option "What do you want to do?" \
    "JS      --  Build JS Framework and native addon" \
    "Code    --  Compile everything" \
    "Learn   --  Browse lessons  (GUI or CLI)"

case "$PICKED" in
    1) mode_js    ;;
    2) mode_code  ;;
    3) mode_learn ;;
esac
