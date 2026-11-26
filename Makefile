.PHONY: all setup build js test clean install

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wformat-security -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-format-truncation -Wno-stringop-truncation -Wno-misleading-indentation -I./include -std=c99 -DBUILD_OS_LINUX -D_GNU_SOURCE
LDFLAGS ?= -lm -ldl -rdynamic
SRCS     = $(wildcard src/*.c)
UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
  ifeq ($(UNAME_M),x86_64)
    ASM = arch/x86_64_linux.S
  else ifeq ($(UNAME_M),aarch64)
    ASM = arch/arm64_linux.S
  else ifeq ($(UNAME_M),riscv64)
    ASM = arch/riscv64_linux.S
  endif
else ifeq ($(UNAME_S),Darwin)
  CFLAGS  := -O2 -Wall -Wextra -Wformat-security -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -I./include -std=c99 -DBUILD_OS_BSD -DBUILD_OS_DARWIN
  LDFLAGS := -lm
  ifeq ($(UNAME_M),arm64)
    ASM = arch/arm64_macos.S
  else ifeq ($(UNAME_M),x86_64)
    ASM = arch/x86_64_macos.S
  endif
endif

all: setup

setup:
	@chmod +x setup.sh
	@bash setup.sh

build:
	$(CC) $(CFLAGS) $(SRCS) $(ASM) $(LDFLAGS) -o neodax

js:
	@bash build_js.sh

test: js
	@node js/test/basic.js && node js/test/security.js

clean:
	@rm -f src/*.o arch/*.o neodax neodax.exe js/neodax.node

install:
	@echo "Run 'make build' first, then copy ./neodax to your PATH."
