#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include "dax.h"

#define DAX_MAX_SANE_FILESIZE   (512UL * 1024UL * 1024UL)
#define DAX_MIN_SANE_FILESIZE   4
#define DAX_MAX_SANE_SECTIONS   128
#define DAX_MAX_SANE_SYMBOLS    131072
#define DAX_MAX_SANE_XREFS      524288
#define DAX_MAX_SANE_FUNCTIONS  65536
#define DAX_MAX_SANE_BLOCKS     262144
#define DAX_CANARY_VALUE        0xDEADC0DE1337CAFEU
#define DAX_NOP_RUN_THRESHOLD   4096
#define DAX_FLAT_ENTROPY_WARN   0.10
#define DAX_NULL_RATIO_WARN     0.70

typedef struct {
    uint64_t canary_head;
    uint64_t canary_tail;
} dax_canary_t;

static dax_canary_t g_canary = {DAX_CANARY_VALUE, DAX_CANARY_VALUE};

static int dax_canary_check(void) {
    return (g_canary.canary_head == DAX_CANARY_VALUE &&
            g_canary.canary_tail == DAX_CANARY_VALUE);
}

static void dax_hardening_fatal(const char *reason, int color) {
    const char *RD = color ? "\033[1;31m" : "";
    const char *YL = color ? "\033[1;33m" : "";
    const char *DG = color ? "\033[0;90m" : "";
    const char *W  = color ? "\033[1;37m" : "";
    const char *R  = color ? "\033[0m"    : "";
    fprintf(stderr, "\n");
    fprintf(stderr, "%s  ╔══════════════════════════════════════════════════════════╗%s\n", RD, R);
    fprintf(stderr, "%s  ║             NEODAX INTEGRITY VIOLATION                   ║%s\n", RD, R);
    fprintf(stderr, "%s  ╚══════════════════════════════════════════════════════════╝%s\n", RD, R);
    fprintf(stderr, "\n");
    fprintf(stderr, "  %sReason%s   : %s%s%s\n", W, R, YL, reason, R);
    fprintf(stderr, "  %sAction%s   : %sAborting immediately. This input is unsafe or malformed.%s\n", W, R, DG, R);
    fprintf(stderr, "\n");
    exit(1);
}

int dax_harden_filesize(size_t sz, int color) {
    if (sz < DAX_MIN_SANE_FILESIZE)
        dax_hardening_fatal("File is too small to be a valid binary (< 4 bytes).", color);
    if (sz > DAX_MAX_SANE_FILESIZE)
        dax_hardening_fatal("File exceeds maximum safe size (512 MiB). Possible decompression bomb or fuzzing artifact.", color);
    return 0;
}

int dax_harden_section_bounds(dax_binary_t *bin, int color) {
    int i;
    if (bin->nsections < 0 || bin->nsections > DAX_MAX_SANE_SECTIONS) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Implausible section count: %d. Parser attack or corrupt header.", bin->nsections);
        dax_hardening_fatal(msg, color);
    }
    for (i = 0; i < bin->nsections; i++) {
        dax_section_t *s = &bin->sections[i];
        if (s->offset > bin->size) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                "Section '%s' offset 0x%llx exceeds file size 0x%llx. Truncated or forged.",
                s->name, (unsigned long long)s->offset, (unsigned long long)bin->size);
            dax_hardening_fatal(msg, color);
        }
        /* BSS (SHT_NOBITS) has no file data — offset+size exceeding file_size is by design */
        if (s->type != SEC_TYPE_BSS && s->size > 0 && s->offset + s->size > bin->size) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                "Section '%s' extends past EOF (off=0x%llx size=0x%llx file=0x%llx). Forged section header.",
                s->name,
                (unsigned long long)s->offset,
                (unsigned long long)s->size,
                (unsigned long long)bin->size);
            dax_hardening_fatal(msg, color);
        }
        if (s->size > DAX_MAX_SANE_FILESIZE) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                "Section '%s' has pathological size 0x%llx. Possible integer overflow in size field.",
                s->name, (unsigned long long)s->size);
            dax_hardening_fatal(msg, color);
        }
    }
    return 0;
}

int dax_harden_symcount(int n, int color) {
    if (n < 0 || n > DAX_MAX_SANE_SYMBOLS) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Symbol count %d is outside safe range [0, %d]. Possible heap overflow setup.",
            n, DAX_MAX_SANE_SYMBOLS);
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_funccount(int n, int color) {
    if (n < 0 || n > DAX_MAX_SANE_FUNCTIONS) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Function count %d exceeds hard limit %d. Possible allocation amplification attack.",
            n, DAX_MAX_SANE_FUNCTIONS);
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_blockcount(int n, int color) {
    if (n < 0 || n > DAX_MAX_SANE_BLOCKS) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "CFG block count %d exceeds hard limit %d. Possible infinite loop in CFG builder.",
            n, DAX_MAX_SANE_BLOCKS);
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_xrefcount(int n, int color) {
    if (n < 0 || n > DAX_MAX_SANE_XREFS) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Xref count %d exceeds safe limit %d.",
            n, DAX_MAX_SANE_XREFS);
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_flat_binary(dax_binary_t *bin, int color) {
    size_t  i;
    size_t  null_count = 0;
    size_t  nop_run    = 0;
    size_t  max_nop    = 0;
    uint8_t prev       = 0xFF;
    size_t  sample     = bin->size < 65536 ? bin->size : 65536;
    double  null_ratio;

    if (bin->fmt != FMT_RAW) return 0;

    for (i = 0; i < sample; i++) {
        uint8_t b = bin->data[i];
        if (b == 0x00) null_count++;
        if (b == prev) {
            nop_run++;
            if (nop_run > max_nop) max_nop = nop_run;
        } else {
            nop_run = 0;
        }
        prev = b;
    }

    null_ratio = (double)null_count / (double)sample;

    if (null_ratio > DAX_NULL_RATIO_WARN && sample >= 256) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Raw binary is %.0f%% null bytes. Possible padding bomb, sparse file, or zero-fill attack.",
            null_ratio * 100.0);
        dax_hardening_fatal(msg, color);
    }
    if (max_nop > DAX_NOP_RUN_THRESHOLD) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Raw binary contains a monotone byte run of %zu bytes. Likely synthetic fuzz input.",
            max_nop);
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_daxc_magic(uint32_t magic, uint32_t version, int color) {
    if (magic != DAX_DAXC_MAGIC) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            ".daxc magic mismatch: expected 0x%08X, got 0x%08X. File is corrupt or forged.",
            DAX_DAXC_MAGIC, magic);
        dax_hardening_fatal(msg, color);
    }
    if (version == 0 || version > DAX_DAXC_VERSION + 2) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            ".daxc version %u is outside accepted range [1, %u]. Incompatible or tampered snapshot.",
            version, DAX_DAXC_VERSION + 2);
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_string_field(const char *s, size_t maxlen, const char *field_name, int color) {
    size_t i;
    size_t len;
    if (!s) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Null pointer in required string field '%s'.", field_name);
        dax_hardening_fatal(msg, color);
    }
    len = strnlen(s, maxlen + 1);
    if (len > maxlen) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "String field '%s' is not NUL-terminated within %zu bytes. Possible buffer overread.",
            field_name, maxlen);
        dax_hardening_fatal(msg, color);
    }
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c > 0 && c < 0x09) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                "String field '%s' contains control character 0x%02X at offset %zu. Possible injection.",
                field_name, c, i);
            dax_hardening_fatal(msg, color);
        }
    }
    return 0;
}

int dax_harden_address_range(uint64_t start, uint64_t end, const char *context, int color) {
    if (end < start) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Address range inversion in '%s': start=0x%llx > end=0x%llx. Possible wrap-around exploit.",
            context,
            (unsigned long long)start,
            (unsigned long long)end);
        dax_hardening_fatal(msg, color);
    }
    if (end - start > DAX_MAX_SANE_FILESIZE) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Address range in '%s' spans 0x%llx bytes. Too large to be a real code region.",
            context,
            (unsigned long long)(end - start));
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_insn_length(uint8_t len, uint64_t addr, int color) {
    if (len == 0 || len > DAX_MAX_INSN_LEN) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Decoder returned illegal instruction length %u at 0x%llx. "
            "Decode loop divergence — possible parser manipulation.",
            (unsigned)len, (unsigned long long)addr);
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_canary(int color) {
    if (!dax_canary_check()) {
        dax_hardening_fatal(
            "Global memory canary corrupted. Possible stack/heap overflow during analysis. "
            "This is a critical internal integrity failure.",
            color);
    }
    return 0;
}

int dax_harden_alloc_size(size_t n, size_t elemsize, const char *what, int color) {
    size_t total;
    if (n == 0) return 0;
    if (elemsize == 0 || n > (SIZE_MAX / elemsize)) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Allocation size overflow for '%s': %zu × %zu bytes wraps size_t. "
            "Possible integer overflow exploit.",
            what, n, elemsize);
        dax_hardening_fatal(msg, color);
    }
    total = n * elemsize;
    if (total > DAX_MAX_SANE_FILESIZE * 4) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Requested allocation of %zu bytes for '%s' exceeds 2 GiB. Refusing.",
            total, what);
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_elf_header(const uint8_t *data, size_t size, int color) {
    if (size < 16) {
        dax_hardening_fatal("File too small to contain ELF e_ident (need ≥ 16 bytes).", color);
    }
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        dax_hardening_fatal(
            "ELF magic bytes invalid. File may have been modified or is not an ELF binary.", color);
    }
    if (data[4] != 1 && data[4] != 2) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "ELF class byte is 0x%02X — must be ELFCLASS32 (1) or ELFCLASS64 (2). "
            "Possibly a truncated upload or fuzzer-generated header.",
            data[4]);
        dax_hardening_fatal(msg, color);
    }
    if (data[5] != 1 && data[5] != 2) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "ELF data encoding byte is 0x%02X — must be ELFDATA2LSB (1) or ELFDATA2MSB (2).",
            data[5]);
        dax_hardening_fatal(msg, color);
    }
    return 0;
}

int dax_harden_pe_header(const uint8_t *data, size_t size, int color) {
    uint32_t nt_off;
    if (size < 64) {
        dax_hardening_fatal("File too small to contain DOS stub (need ≥ 64 bytes).", color);
    }
    if (data[0] != 'M' || data[1] != 'Z') {
        dax_hardening_fatal(
            "DOS magic bytes 'MZ' not found. Not a valid PE file.", color);
    }
    nt_off = (uint32_t)(data[0x3C]) | ((uint32_t)(data[0x3D]) << 8)
           | ((uint32_t)(data[0x3E]) << 16) | ((uint32_t)(data[0x3F]) << 24);
    if ((size_t)nt_off + 4 > size) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "PE NT headers offset 0x%X points outside file (size=0x%zX). "
            "Forged DOS stub or truncated binary.",
            nt_off, size);
        dax_hardening_fatal(msg, color);
    }
    if (data[nt_off] != 'P' || data[nt_off+1] != 'E' ||
        data[nt_off+2] != 0  || data[nt_off+3] != 0) {
        dax_hardening_fatal(
            "PE signature 'PE\\0\\0' not found at expected offset. "
            "Possibly a PE with overwritten NT headers.",
            color);
    }
    return 0;
}

void dax_harden_all(dax_binary_t *bin, int color) {
    dax_harden_canary(color);
    dax_harden_filesize(bin->size, color);
    dax_harden_section_bounds(bin, color);
    dax_harden_symcount(bin->nsymbols, color);
    dax_harden_funccount(bin->nfunctions, color);
    dax_harden_blockcount(bin->nblocks, color);
    dax_harden_xrefcount(bin->nxrefs, color);
    dax_harden_string_field(bin->filepath,  sizeof(bin->filepath) - 1, "filepath",  color);
    dax_harden_string_field(bin->sha256,    sizeof(bin->sha256) - 1,   "sha256",    color);
    dax_harden_string_field(bin->build_id,  sizeof(bin->build_id) - 1, "build_id",  color);
    if (bin->fmt == FMT_RAW)
        dax_harden_flat_binary(bin, color);
    if (bin->entry && bin->base && bin->image_size)
        dax_harden_address_range(bin->base, bin->base + bin->image_size, "image", color);
}

