#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "dax.h"

int dax_utf8_decode(const uint8_t *buf, size_t len, uint32_t *codepoint, int *seq_len) {
    uint8_t b0;
    if (!buf || len == 0) return -1;
    b0 = buf[0];
    if (b0 < 0x80) { *codepoint = b0; *seq_len = 1; return 0; }
    if ((b0 & 0xE0) == 0xC0 && len >= 2 && (buf[1] & 0xC0) == 0x80) {
        *codepoint = ((uint32_t)(b0 & 0x1F) << 6) | (buf[1] & 0x3F);
        *seq_len = 2;
        return (*codepoint >= 0x80) ? 0 : -1;
    }
    if ((b0 & 0xF0) == 0xE0 && len >= 3 &&
        (buf[1] & 0xC0) == 0x80 && (buf[2] & 0xC0) == 0x80) {
        *codepoint = ((uint32_t)(b0 & 0x0F) << 12) |
                     ((uint32_t)(buf[1] & 0x3F) << 6) | (buf[2] & 0x3F);
        *seq_len = 3;
        return (*codepoint >= 0x800 &&
                !(*codepoint >= 0xD800 && *codepoint <= 0xDFFF)) ? 0 : -1;
    }
    if ((b0 & 0xF8) == 0xF0 && len >= 4 &&
        (buf[1] & 0xC0) == 0x80 && (buf[2] & 0xC0) == 0x80 &&
        (buf[3] & 0xC0) == 0x80) {
        *codepoint = ((uint32_t)(b0 & 0x07) << 18) |
                     ((uint32_t)(buf[1] & 0x3F) << 12) |
                     ((uint32_t)(buf[2] & 0x3F) << 6) | (buf[3] & 0x3F);
        *seq_len = 4;
        return (*codepoint >= 0x10000 && *codepoint <= 0x10FFFF) ? 0 : -1;
    }
    return -1;
}

static uint32_t encode_utf8_cp(uint32_t cp, char *out) {
    if (cp < 0x80)    { out[0]=(char)cp; return 1; }
    if (cp < 0x800)   { out[0]=(char)(0xC0|(cp>>6)); out[1]=(char)(0x80|(cp&0x3F)); return 2; }
    if (cp < 0x10000) { out[0]=(char)(0xE0|(cp>>12)); out[1]=(char)(0x80|((cp>>6)&0x3F)); out[2]=(char)(0x80|(cp&0x3F)); return 3; }
    out[0]=(char)(0xF0|(cp>>18)); out[1]=(char)(0x80|((cp>>12)&0x3F));
    out[2]=(char)(0x80|((cp>>6)&0x3F)); out[3]=(char)(0x80|(cp&0x3F)); return 4;
}

int dax_utf16le_to_utf8(const uint8_t *src, size_t src_bytes, char *dst, size_t dst_max) {
    size_t si = 0, di = 0;
    while (si + 2 <= src_bytes && di + 6 < dst_max) {
        uint16_t unit = (uint16_t)(src[si]) | ((uint16_t)(src[si+1]) << 8);
        uint32_t cp;
        si += 2;
        if (unit == 0) break;
        if (unit >= 0xD800 && unit <= 0xDBFF) {
            if (si + 2 <= src_bytes) {
                uint16_t lo = (uint16_t)(src[si]) | ((uint16_t)(src[si+1]) << 8);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((uint32_t)(unit - 0xD800) << 10) + (lo - 0xDC00);
                    si += 2;
                } else { continue; }
            } else { break; }
        } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
            continue;
        } else {
            cp = unit;
        }
        if (cp < 0x20 && cp != 0x09 && cp != 0x0A && cp != 0x0D) continue;
        char tmp[5] = {0};
        uint32_t n = encode_utf8_cp(cp, tmp);
        if (di + n >= dst_max) break;
        memcpy(dst + di, tmp, n);
        di += n;
    }
    dst[di] = '\0';
    return (int)di;
}

static int section_skip_utf16(const char *name) {
    if (!name) return 1;
    if (strcmp(name, ".dynstr")   == 0) return 1;
    if (strcmp(name, ".dynsym")   == 0) return 1;
    if (strcmp(name, ".symtab")   == 0) return 1;
    if (strcmp(name, ".strtab")   == 0) return 1;
    if (strcmp(name, ".shstrtab") == 0) return 1;
    if (strcmp(name, ".gnu.hash") == 0) return 1;
    if (strcmp(name, ".gnu.version") == 0) return 1;
    if (strcmp(name, ".gnu.version_r") == 0) return 1;
    if (strncmp(name, ".note",   5) == 0) return 1;
    if (strncmp(name, ".debug",  6) == 0) return 1;
    if (strncmp(name, ".rela.",  6) == 0) return 1;
    if (strcmp(name, ".plt")     == 0) return 1;
    if (strcmp(name, ".got")     == 0) return 1;
    if (strcmp(name, ".got.plt") == 0) return 1;
    return 0;
}

static int cp_is_printable(uint32_t cp) {
    if (cp < 0x20 && cp != 0x09 && cp != 0x0A && cp != 0x0D) return 0;
    if (cp >= 0xFFF0) return 0;
    return 1;
}

/*
 * UTF-8 multibyte scanner:
 * Returns 1 if buf[0..] starts a valid multi-byte UTF-8 string.
 * The string must contain at least one codepoint >= 0x0080.
 */
static int scan_utf8_string(const uint8_t *buf, size_t len,
                             size_t *out_byte_len) {
    size_t i = 0;
    int count = 0, mb = 0;
    *out_byte_len = 0;

    while (i < len) {
        if (buf[i] == 0) break;
        uint32_t cp = 0; int sl = 0;
        if (dax_utf8_decode(buf + i, len - i, &cp, &sl) != 0) return 0;
        if (sl < 1 || sl > 4) return 0;
        if (!cp_is_printable(cp)) return 0;
        if (sl > 1) mb = 1;
        count++;
        i += (size_t)sl;
    }

    if (count < 2 || !mb) return 0;
    if (i >= len || buf[i] != 0) return 0;

    *out_byte_len = i;
    return 1;
}

/*
 * UTF-16LE scanner — strict version.
 *
 * Conditions for a REAL UTF-16LE string:
 *  1. Must begin at an even offset with a plausible first unit.
 *  2. The byte BEFORE position i (if any) must be 0x00 — meaning we are
 *     at a clean string start, not mid-way through null-separated ASCII.
 *  3. Must contain >= 2 code units where the HIGH BYTE is in a
 *     non-ASCII BMP language range OR is a surrogate pair (emoji/SMP).
 *  4. "High byte in language range" means >= 0x01 AND NOT in
 *     the 0x00xx range (which would just be null-padded ASCII).
 *  5. Must end with a 0x0000 null terminator.
 *
 * This eliminates the main false-positive class: null-separated ASCII
 * symbol names from .dynstr where "n\0__cxa\0" looks like UTF-16LE.
 */
static int scan_utf16le_string(const uint8_t *buf, size_t buf_len, size_t buf_off,
                                size_t *out_byte_len) {
    size_t i = 0;
    int count = 0, wide = 0, surrogate = 0;

    *out_byte_len = 0;

    if (buf_len < 4) return 0;

    /*
     * Guard against false starts: the byte immediately before this position
     * in the buffer (buf_off - 1) must be 0x00 or we must be at offset 0,
     * i.e., this is the start of a null-terminated string, not mid-ASCII.
     * Actually we check: the UNIT at i=0 must have hi=0x00 (BMP ASCII range)
     * or hi != 0x00 (real wide char), but the PRECEDING byte must be 0x00.
     * We pass buf_off so we can check buf[buf_off - 1].
     */
    if (buf_off > 0 && buf[buf_off - 1] != 0x00) return 0;

    while (i + 2 <= buf_len) {
        uint16_t unit = (uint16_t)(buf[i]) | ((uint16_t)(buf[i+1]) << 8);
        if (unit == 0) break;

        if (unit >= 0xD800 && unit <= 0xDBFF) {
            if (i + 4 > buf_len) break;
            uint16_t lo = (uint16_t)(buf[i+2]) | ((uint16_t)(buf[i+3]) << 8);
            if (lo < 0xDC00 || lo > 0xDFFF) break;
            uint32_t cp = 0x10000 + ((uint32_t)(unit - 0xD800) << 10) + (lo - 0xDC00);
            if (!cp_is_printable(cp)) break;
            surrogate++;
            wide++;
            count++;
            i += 4;
        } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
            break;
        } else {
            if (unit < 0x20 && unit != 0x09 && unit != 0x0A && unit != 0x0D) break;
            /*
             * A unit is "wide" if its HIGH byte is non-zero
             * AND it falls outside the ASCII/Latin-1 range.
             * We require hi >= 0x01 but also avoid the 0x00xx range entirely.
             * Emoji supplementary planes are already caught by the surrogate case.
             */
            uint8_t hi = (uint8_t)(unit >> 8);
            if (hi >= 0x01) wide++;
            count++;
            i += 2;
        }
    }

    if (count < 6) return 0;  /* require at least 6 units to reduce false positives */

    /* Need null terminator */
    if (i + 2 > buf_len) return 0;
    if (buf[i] != 0x00 || buf[i+1] != 0x00) return 0;

    /* Require genuine wide content: at least 2 units with hi != 0,
     * OR at least 1 surrogate pair (emoji/SMP). */
    if (wide < 3 && surrogate == 0) return 0;

    /* If all wide units are in the ASCII range but just null-padded (hi==0),
     * reject — these are just null-padded ASCII strings, not interesting. */
    if (wide == 0) return 0;

    /* Reject if the string looks like null-separated ASCII pairs.
     * Check: if EVERY OTHER BYTE starting at buf[1] is 0x00,
     * it is pure null-padded ASCII → reject as uninteresting. */
    {
        int all_hi_zero = 1;
        for (size_t k = 1; k < i && k + 1 < buf_len; k += 2) {
            if (buf[k] != 0x00) { all_hi_zero = 0; break; }
        }
        if (all_hi_zero) return 0;
    }

    /*
     * Require at least one truly non-Latin codepoint (> U+02FF).
     * This rejects ELF/DWARF binary data that accidentally has
     * a few non-zero high bytes (e.g., Android section header strings
     * where pairs like [6E 00][64 72] = 'n' + 'dr' look like UTF-16LE
     * yielding CJK characters, but NO code point exceeds U+02FF for
     * typical ASCII-derived symbol tables).
     * Exceptions: surrogate pairs (emoji) are already accepted above.
     */
    if (surrogate == 0) {
        int has_beyond_latin = 0;
        size_t k;
        for (k = 0; k + 2 <= i; k += 2) {
            uint16_t u = (uint16_t)(buf[k]) | ((uint16_t)(buf[k+1]) << 8);
            if (u > 0x02FF && u < 0xD800) { has_beyond_latin = 1; break; }
        }
        if (!has_beyond_latin) return 0;
    }

    *out_byte_len = i;
    return 1;
}

void dax_scan_unicode(dax_binary_t *bin) {
    int    si;
    size_t i;

    if (!bin->ustrings) {
        bin->ustrings = (dax_ustring_t *)calloc(DAX_MAX_USTRINGS, sizeof(dax_ustring_t));
        if (!bin->ustrings) return;
    }
    bin->nustrings = 0;

    for (si = 0; si < bin->nsections; si++) {
        dax_section_t *sec   = &bin->sections[si];
        uint8_t       *base;
        size_t         slen;
        int            skip_utf16;

        if (sec->type == SEC_TYPE_CODE) continue;
        if (sec->offset + sec->size > bin->size) continue;
        if (sec->size == 0) continue;

        base       = bin->data + sec->offset;
        slen       = (size_t)sec->size;
        skip_utf16 = section_skip_utf16(sec->name);
        /* skip sections at vaddr 0 (file header region) */
        if (sec->vaddr == 0 && sec->type != SEC_TYPE_DATA && sec->type != SEC_TYPE_RODATA) continue;

        for (i = 0; i + 2 < slen && bin->nustrings < DAX_MAX_USTRINGS; i++) {
            size_t byte_len = 0;

            /* ── Try UTF-8 first ── */
            if (scan_utf8_string(base + i, slen - i, &byte_len)) {
                dax_ustring_t *us = &bin->ustrings[bin->nustrings];
                us->address     = sec->vaddr + i;
                us->byte_length = (uint16_t)(byte_len < 65535 ? byte_len : 65535);
                us->encoding    = STR_ENC_UTF8;
                {
                    size_t copy = byte_len < (size_t)(DAX_MAX_UNICODE_STR - 1)
                                  ? byte_len : (size_t)(DAX_MAX_UNICODE_STR - 1);
                    memcpy(us->value_utf8, base + i, copy);
                    us->value_utf8[copy] = '\0';
                }
                bin->nustrings++;
                i += byte_len > 0 ? byte_len - 1 : 0;
                continue;
            }

            /* ── Try UTF-16LE (skip unsafe sections) ── */
            if (!skip_utf16 && (i % 2) == 0 && i + 4 <= slen) {
                /*
                 * Pass the full section base + offset so we can check
                 * the preceding byte inside the scanner.
                 */
                if (scan_utf16le_string(base, slen, i, &byte_len)) {
                    dax_ustring_t *us = &bin->ustrings[bin->nustrings];
                    us->address     = sec->vaddr + i;
                    us->byte_length = (uint16_t)(byte_len < 65534 ? byte_len : 65534);
                    us->encoding    = STR_ENC_UTF16LE;
                    dax_utf16le_to_utf8(base + i, byte_len,
                                        us->value_utf8, DAX_MAX_UNICODE_STR - 1);
                    bin->nustrings++;
                    i += byte_len > 0 ? byte_len - 1 : 0;
                    continue;
                }
            }
        }
    }
}

void dax_print_unicode_strings(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i;
    int c = opts ? opts->color : 1;
    const char *CU = c ? COL_UNICODE : "";
    const char *CA = c ? COL_ADDR    : "";
    const char *CM = c ? COL_COMMENT : "";
    const char *CW = c ? COL_MNEM    : "";
    const char *CR = c ? COL_RESET   : "";

    if (!bin->ustrings || bin->nustrings == 0) {
        fprintf(out, "\n%s  (no Unicode strings found)%s\n", CM, CR);
        return;
    }

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  ════════════════ UNICODE STRINGS (%d) ════════════════\n",
                 bin->nustrings);
    if (c) fprintf(out, "%s", COL_RESET);

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", CW);
    fprintf(out, "  %-18s %-10s %-8s  %s\n", "Address", "Encoding", "Bytes", "Value");
    if (c) fprintf(out, "%s", CR);
    if (c) fprintf(out, "%s", CM);
    { int j; for (j=0;j<80;j++) fprintf(out,"─"); }
    if (c) fprintf(out, "%s", CR);
    fprintf(out, "\n");

    for (i = 0; i < bin->nustrings; i++) {
        dax_ustring_t *us  = &bin->ustrings[i];
        const char    *enc = (us->encoding == STR_ENC_UTF16LE) ? "UTF-16LE"
                           : (us->encoding == STR_ENC_UTF16BE) ? "UTF-16BE"
                           : (us->encoding == STR_ENC_UTF8)    ? "UTF-8"
                           :                                      "ASCII";
        size_t vlen = strlen(us->value_utf8);
        char   preview[256];
        size_t pi = 0, vi = 0;

        while (vi < vlen && pi < 200) {
            unsigned char ch = (unsigned char)us->value_utf8[vi];
            if      (ch == '\n') { preview[pi++]='\\'; if(pi<200) preview[pi++]='n'; vi++; }
            else if (ch == '\t') { preview[pi++]='\\'; if(pi<200) preview[pi++]='t'; vi++; }
            else if (ch == '\r') { preview[pi++]='\\'; if(pi<200) preview[pi++]='r'; vi++; }
            else if (ch < 0x20)  { vi++; }
            else                 { preview[pi++]=(char)ch; vi++; }
        }
        if (vi < vlen && pi + 3 <= 200) {
            preview[pi++]='.'; preview[pi++]='.'; preview[pi++]='.';
        }
        preview[pi] = '\0';

        fprintf(out, "  %s0x%016llx%s  %s%-10s%s %-8u  %s%s%s\n",
                CA, (unsigned long long)us->address, CR,
                CM, enc, CR,
                (unsigned)us->byte_length,
                CU, preview, CR);
    }
    fprintf(out, "\n");
}
