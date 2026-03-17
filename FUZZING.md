# Fuzzing and Robustness Testing

NeoDAX processes untrusted binary files from potentially hostile sources. This guide explains how to fuzz the parser and analysis engine.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Why Fuzz NeoDAX?

NeoDAX is often used to analyze malware and obfuscated binaries. A malicious analyst might feed crafted binaries to crash the tool or trigger unexpected behavior. The parser handles arbitrary byte sequences as ELF/PE structures — integer overflows in size calculations or OOB reads are the primary risk class.

---

## Quick Robustness Check

Before fuzzing, verify NeoDAX handles obviously malformed input:

```bash
# Empty file
touch /tmp/empty && ./neodax /tmp/empty

# Random bytes (not a valid ELF/PE)
dd if=/dev/urandom bs=4096 count=1 of=/tmp/random.bin 2>/dev/null
./neodax /tmp/random.bin

# Truncated ELF header
echo -n $'\x7fELF' > /tmp/bad_elf
./neodax /tmp/bad_elf

# All zeros
dd if=/dev/zero bs=4096 count=1 of=/tmp/zeros.bin 2>/dev/null
./neodax /tmp/zeros.bin

# ELF magic + garbage section headers
python3 -c "
import struct
# ELF magic + class=64 + LE + version + OS=Linux
hdr  = b'\x7fELF\x02\x01\x01\x00' + b'\x00'*8
# e_type=DYN, e_machine=x86_64, e_version=1
hdr += struct.pack('<HHI', 3, 62, 1)
# Garbage for everything else
hdr += b'\xff'*(64-len(hdr))
open('/tmp/elf_garbage.bin','wb').write(hdr)
"
./neodax /tmp/elf_garbage.bin
```

All of these should print an error message and exit cleanly — no segfault, no hang.

---

## AFL++ Fuzzing

```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make -j$(nproc) && sudo make install

# Build NeoDAX with AFL++ instrumentation
cd /path/to/NeoDAX
make clean
CC=afl-clang-fast make CFLAGS_EXTRA="-fsanitize=address,undefined"

# Create seed corpus
mkdir -p fuzz/corpus fuzz/findings
cp /bin/ls       fuzz/corpus/ls_elf
cp /usr/bin/file fuzz/corpus/file_elf
# Add a small PE if available:
# cp /path/to/small.exe fuzz/corpus/small_pe

# Create AFL wrapper — analyze without output
cat > fuzz/fuzz_target.sh << 'EOF'
#!/bin/bash
./neodax -x -n "$1" > /dev/null 2>&1
EOF
chmod +x fuzz/fuzz_target.sh

# Run AFL++
afl-fuzz -i fuzz/corpus -o fuzz/findings \
    -t 5000 -m 512 \
    -- ./neodax -x -n @@
```

---

## libFuzzer Integration

Build a dedicated fuzz target:

```bash
cat > fuzz/fuzz_neodax.c << 'EOF'
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "dax.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    // Write to temp file (dax_load_binary takes a path)
    char tmpname[] = "/tmp/neodax_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd < 0) return 0;
    write(fd, data, size);
    close(fd);

    dax_binary_t bin;
    memset(&bin, 0, sizeof(bin));

    if (dax_load_binary(tmpname, &bin) == 0) {
        dax_opts_t opts;
        memset(&opts, 0, sizeof(opts));
        opts.color = 0;

        // Exercise core analysis
        dax_sym_load(&bin);
        dax_xref_build(&bin);

        // Exercise CFG builder
        for (int i = 0; i < bin.nsections; i++) {
            dax_section_t *sec = &bin.sections[i];
            if (sec->type == SEC_TYPE_CODE &&
                sec->size > 0 &&
                sec->offset + sec->size <= bin.size) {
                dax_cfg_build(&bin,
                    bin.data + sec->offset,
                    (size_t)sec->size,
                    sec->vaddr, -1);
            }
        }

        // Exercise unicode scanner
        dax_scan_unicode(&bin);

        // Exercise entropy
        dax_entropy_scan(&bin, &opts, fopen("/dev/null","w"));

        // Exercise IVF
        dax_ivf_scan(&bin, &opts, fopen("/dev/null","w"));

        dax_free_binary(&bin);
    }

    unlink(tmpname);
    return 0;
}
EOF

# Compile with libFuzzer
clang -fsanitize=fuzzer,address,undefined \
    -std=c99 -D_GNU_SOURCE \
    -I./include \
    fuzz/fuzz_neodax.c \
    src/loader.c src/disasm.c src/x86_decode.c src/arm64_decode.c \
    src/symbols.c src/demangle.c src/analysis.c src/cfg.c \
    src/loops.c src/callgraph.c src/correct.c \
    src/riscv_decode.c src/unicode.c src/sha256.c src/main.c \
    src/symexec.c src/decomp.c src/emulate.c src/entropy.c \
    src/daxc.c src/interactive.c \
    -lm \
    -o fuzz/fuzz_neodax

# Run libFuzzer
./fuzz/fuzz_neodax fuzz/corpus/ \
    -max_total_time=3600 \
    -max_len=65536 \
    -jobs=4 -workers=4
```

---

## AddressSanitizer Build

For catching memory errors during normal testing:

```bash
make clean
make CFLAGS_EXTRA="-fsanitize=address,undefined -g -O1"
./neodax -X ./binary   # run normally — ASAN reports any issues
```

---

## What to Fuzz

Priority targets based on attack surface:

1. **`dax_load_binary()`** — parses ELF/PE headers; integer overflows in e_phoff, sh_offset, sh_size
2. **`dax_cfg_build()`** — decodes arbitrary byte sequences as instructions
3. **`dax_scan_unicode()`** — scans non-code sections byte by byte
4. **`dax_ivf_scan()`** — linear scan of code sections
5. **`dax_rda_section()`** — BFS with queue; queue overflow potential

---

## Reporting Crashes

If fuzzing finds a crash, follow [SECURITY.md](SECURITY.md) for private reporting. Include:
- The crashing input (minimized with `afl-tmin` or `llvm-reduce`)
- The ASAN/UBSAN output
- The command that triggered it
