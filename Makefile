SRCS = src/main.c          \
       src/loader.c        \
       src/disasm.c        \
       src/x86_decode.c    \
       src/arm64_decode.c  \
       src/symbols.c       \
       src/demangle.c      \
       src/analysis.c      \
       src/cfg.c           \
       src/daxc.c          \
       src/interactive.c   \
       src/loops.c         \
       src/callgraph.c     \
       src/correct.c       \
       src/riscv_decode.c  \
       src/unicode.c       \
       src/sha256.c        \
       src/symexec.c       \
       src/decomp.c        \
       src/emulate.c       \
       src/entropy.c

TARGET  = neodax
ASM_SRC =
LDFLAGS = -lm

UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
UNAME_M := $(shell uname -m 2>/dev/null || echo unknown)

IS_TERMUX  := $(shell test -n "$$PREFIX" && test -d "$$PREFIX/bin" && echo yes || echo no)
IS_ANDROID := $(shell test -f /system/build.prop && echo yes || echo no)
IS_LINUX   := $(shell test "$(UNAME_S)" = "Linux"   && echo yes || echo no)
IS_DARWIN  := $(shell test "$(UNAME_S)" = "Darwin"  && echo yes || echo no)
IS_FREEBSD := $(shell test "$(UNAME_S)" = "FreeBSD" && echo yes || echo no)
IS_OPENBSD := $(shell test "$(UNAME_S)" = "OpenBSD" && echo yes || echo no)
IS_NETBSD  := $(shell test "$(UNAME_S)" = "NetBSD"  && echo yes || echo no)
IS_WINDOWS := $(shell uname -s 2>/dev/null | grep -qi mingw && echo yes || echo no)

HAS_GCC   := $(shell command -v gcc   2>/dev/null && echo yes || echo no)
HAS_CLANG := $(shell command -v clang 2>/dev/null && echo yes || echo no)

ifeq ($(IS_TERMUX), yes)
    IS_ANDROID := yes
    IS_LINUX   := no
endif

ifeq ($(IS_ANDROID), yes)
    ifeq ($(HAS_CLANG), yes)
        CC = clang
    else ifeq ($(HAS_GCC), yes)
        CC = gcc
    else
        CC = cc
    endif
else ifeq ($(IS_LINUX), yes)
    ifeq ($(HAS_GCC), yes)
        CC = gcc
    else ifeq ($(HAS_CLANG), yes)
        CC = clang
    else
        CC = cc
    endif
else ifeq ($(IS_DARWIN), yes)
    ifeq ($(HAS_CLANG), yes)
        CC = clang
    else
        CC = gcc
    endif
else ifeq ($(IS_FREEBSD), yes)
    ifeq ($(HAS_CLANG), yes)
        CC = clang
    else
        CC = gcc
    endif
else ifeq ($(IS_OPENBSD), yes)
    CC = clang
else ifeq ($(IS_NETBSD), yes)
    ifeq ($(HAS_GCC), yes)
        CC = gcc
    else
        CC = clang
    endif
else ifeq ($(IS_WINDOWS), yes)
    ifeq ($(HAS_GCC), yes)
        CC = gcc
    else ifeq ($(HAS_CLANG), yes)
        CC = clang
    else
        CC = cc
    endif
else
    CC = cc
endif

IS_CLANG := $(shell $(CC) --version 2>/dev/null | grep -i clang | head -1 | grep -c clang || echo 0)

BASE_CFLAGS = -O2 -Wall -Wextra          \
              -Wno-unused-variable        \
              -Wno-unused-parameter       \
              -Wno-unused-function        \
              -I./include                 \
              -std=c99                    \
              -U_FORTIFY_SOURCE           \
              -D_FORTIFY_SOURCE=0

GCC_EXTRA   = -Wno-stringop-truncation   \
              -Wno-format-truncation      \
              -Wno-format-extra-args      \
              -Wno-tautological-compare

CLANG_EXTRA = -Wno-format-truncation     \
              -Wno-format-extra-args      \
              -Wno-tautological-compare   \
              -Wno-gnu-variable-sized-type-not-at-end

ifeq ($(IS_CLANG), 1)
    CFLAGS = $(BASE_CFLAGS) $(CLANG_EXTRA)
else
    CFLAGS = $(BASE_CFLAGS) $(GCC_EXTRA)
endif

ifeq ($(IS_ANDROID), yes)
    CFLAGS     += -DBUILD_OS_ANDROID -DBUILD_OS_LINUX -D_GNU_SOURCE
    PREFIX_INST ?= $(if $(filter yes,$(IS_TERMUX)),$(PREFIX),/system/xbin)
    ifeq ($(UNAME_M), aarch64)
        ASM_SRC = arch/arm64_linux.S
    else ifeq ($(UNAME_M), x86_64)
        ASM_SRC = arch/x86_64_linux.S
    endif

else ifeq ($(IS_LINUX), yes)
    CFLAGS     += -DBUILD_OS_LINUX -D_GNU_SOURCE
    PREFIX_INST ?= /usr/local
    ifeq ($(UNAME_M), x86_64)
        ASM_SRC = arch/x86_64_linux.S
    else ifeq ($(UNAME_M), aarch64)
        ASM_SRC = arch/arm64_linux.S
    endif

else ifeq ($(IS_DARWIN), yes)
    CFLAGS     += -DBUILD_OS_BSD
    PREFIX_INST ?= /usr/local
    ifeq ($(UNAME_M), arm64)
        ASM_SRC = arch/arm64_bsd.S
    else
        ASM_SRC = arch/x86_64_bsd.S
    endif

else ifeq ($(IS_FREEBSD), yes)
    CFLAGS     += -DBUILD_OS_BSD
    PREFIX_INST ?= /usr/local
    ifeq ($(UNAME_M), x86_64)
        ASM_SRC = arch/x86_64_bsd.S
    else ifeq ($(UNAME_M), aarch64)
        ASM_SRC = arch/arm64_bsd.S
    endif

else ifeq ($(IS_OPENBSD), yes)
    CFLAGS     += -DBUILD_OS_BSD
    PREFIX_INST ?= /usr/local
    ifeq ($(UNAME_M), x86_64)
        ASM_SRC = arch/x86_64_bsd.S
    else ifeq ($(UNAME_M), aarch64)
        ASM_SRC = arch/arm64_bsd.S
    endif

else ifeq ($(IS_NETBSD), yes)
    CFLAGS     += -DBUILD_OS_BSD
    PREFIX_INST ?= /usr/pkg
    ifeq ($(UNAME_M), x86_64)
        ASM_SRC = arch/x86_64_bsd.S
    else ifeq ($(UNAME_M), aarch64)
        ASM_SRC = arch/arm64_bsd.S
    endif

else ifeq ($(IS_WINDOWS), yes)
    TARGET     = neodax.exe
    CFLAGS    += -DBUILD_OS_WINDOWS
    PREFIX_INST ?= C:/Windows/System32

else
    CFLAGS     += -DBUILD_OS_UNIX
    PREFIX_INST ?= /usr/local
endif

OBJS = $(SRCS:.c=.o)
ifneq ($(ASM_SRC),)
    ASM_OBJ = $(ASM_SRC:.S=.o)
    OBJS   += $(ASM_OBJ)
endif

TOTAL_SRCS := $(words $(SRCS))

ESC     := $(shell printf '\033')
BOLD    := $(ESC)[1m
DIM     := $(ESC)[2m
RESET   := $(ESC)[0m
RED     := $(ESC)[1;31m
GREEN   := $(ESC)[1;32m
YELLOW  := $(ESC)[1;33m
BLUE    := $(ESC)[1;34m
MAGENTA := $(ESC)[1;35m
CYAN    := $(ESC)[1;36m
WHITE   := $(ESC)[1;37m
GREY    := $(ESC)[0;90m

ifeq ($(IS_ANDROID), yes)
    PLAT_LABEL := $(if $(filter yes,$(IS_TERMUX)),Android · Termux,Android)
else ifeq ($(IS_LINUX), yes)
    PLAT_LABEL := $(shell . /etc/os-release 2>/dev/null && echo "Linux · $$NAME" || echo Linux)
else ifeq ($(IS_DARWIN), yes)
    PLAT_LABEL := macOS · Darwin
else ifeq ($(IS_FREEBSD), yes)
    PLAT_LABEL := FreeBSD
else ifeq ($(IS_OPENBSD), yes)
    PLAT_LABEL := OpenBSD
else ifeq ($(IS_NETBSD), yes)
    PLAT_LABEL := NetBSD
else ifeq ($(IS_WINDOWS), yes)
    PLAT_LABEL := Windows · MinGW
else
    PLAT_LABEL := Unknown UNIX
endif

COMPILER_VER := $(shell $(CC) --version 2>/dev/null | head -1)

.PHONY: all clean install info _banner js

all: _banner $(TARGET) js
	@printf '$(GREEN)$(BOLD)\n'
	@printf '  ╔══════════════════════════════════════════════╗\n'
	@printf '  ║  ✓  NeoDAX v1.0.0  built successfully       ║\n'
	@printf '  ║                                              ║\n'
	@printf '  ║  $(CYAN)./$(TARGET)$(GREEN) $(GREY)<binary>$(GREEN)                run      ║\n'
	@printf '  ║  $(CYAN)./$(TARGET)$(GREEN) $(GREY)-h$(GREEN)                      help     ║\n'
	@printf '  ║  $(CYAN)./$(TARGET)$(GREEN) $(GREY)-x -u <binary>$(GREEN)          full RE  ║\n'
	@printf '  ╚══════════════════════════════════════════════╝\n'
	@printf '$(RESET)\n'

_banner:
	@printf '$(YELLOW)$(BOLD)\n'
	@printf '   ███╗   ██╗███████╗ ██████╗ \n'
	@printf '   ████╗  ██║██╔════╝██╔═══██╗\n'
	@printf '   ██╔██╗ ██║█████╗  ██║   ██║\n'
	@printf '   ██║╚██╗██║██╔══╝  ██║   ██║\n'
	@printf '   ██║ ╚████║███████╗╚██████╔╝\n'
	@printf '   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ $(RESET)\n'
	@printf '\n'
	@printf '$(GREY)  ─────────────────────────────────────────────────$(RESET)\n'
	@printf '  $(WHITE)Platform$(RESET)  $(CYAN)$(PLAT_LABEL)$(RESET)\n'
	@printf '  $(WHITE)Arch    $(RESET)  $(CYAN)$(UNAME_M)$(RESET)\n'
	@printf '  $(WHITE)Compiler$(RESET)  $(CYAN)$(COMPILER_VER)$(RESET)\n'
	@printf '  $(WHITE)Target  $(RESET)  $(CYAN)$(TARGET)$(RESET)\n'
	@printf '$(GREY)  ─────────────────────────────────────────────────$(RESET)\n'
	@printf '\n'
	@printf '$(GREY)  Building $(TOTAL_SRCS) source files ...$(RESET)\n\n'

$(TARGET): $(OBJS)
	@printf '$(GREY)  ─────────────────────────────────────────────────$(RESET)\n'
	@printf '  $(YELLOW)Linking$(RESET)   $(GREY)→$(RESET) $(WHITE)$(TARGET)$(RESET)\n'
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)

src/%.o: src/%.c
	@printf '  $(BLUE)Compiling$(RESET) $(GREY)→$(RESET) $(WHITE)%-32s$(RESET)\n' '$<'
	@$(CC) $(CFLAGS) -c $< -o $@

arch/%.o: arch/%.S
	@printf '  $(MAGENTA)Assembling$(RESET)$(GREY)→$(RESET) $(WHITE)%-32s$(RESET)\n' '$<'
	@$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	@printf '\n$(CYAN)  Installing$(RESET) → $(WHITE)$(PREFIX_INST)/bin/$(TARGET)$(RESET)\n'
	@install -d $(PREFIX_INST)/bin
	@install -m 0755 $(TARGET) $(PREFIX_INST)/bin/$(TARGET)
	@printf '$(GREEN)  ✓ Done$(RESET)\n\n'

js:
	@printf '\n  $(CYAN)Building JS bindings ...$(RESET)\n'
	@bash build_js.sh
	@printf '  $(GREEN)✓ js/neodax.node built$(RESET)\n\n'

clean:
	@printf '\n$(GREY)  Cleaning build artifacts ...$(RESET)\n'
	@rm -f src/*.o arch/*.o $(TARGET) neodax.exe js/neodax.node
	@printf '$(GREEN)  ✓ Clean$(RESET)\n\n'

info:
	@printf '\n'
	@printf '$(GREY)  ─────────────────────────────────────────────────$(RESET)\n'
	@printf '  $(WHITE)OS        $(RESET)  $(CYAN)$(UNAME_S)$(RESET)\n'
	@printf '  $(WHITE)Arch      $(RESET)  $(CYAN)$(UNAME_M)$(RESET)\n'
	@printf '  $(WHITE)Compiler  $(RESET)  $(CYAN)$(CC)$(RESET)\n'
	@printf '  $(WHITE)IsClang   $(RESET)  $(CYAN)$(IS_CLANG)$(RESET)\n'
	@printf '  $(WHITE)CFLAGS    $(RESET)  $(DIM)$(CFLAGS)$(RESET)\n'
	@printf '  $(WHITE)ASM stub  $(RESET)  $(CYAN)$(if $(ASM_SRC),$(ASM_SRC),none)$(RESET)\n'
	@printf '  $(WHITE)Target    $(RESET)  $(CYAN)$(TARGET)$(RESET)\n'
	@printf '  $(WHITE)Install   $(RESET)  $(CYAN)$(PREFIX_INST)/bin/$(RESET)\n'
	@printf '$(GREY)  ─────────────────────────────────────────────────$(RESET)\n'
	@printf '\n'
