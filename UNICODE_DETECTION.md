# Unicode String Detection

How NeoDAX detects genuine Unicode strings in binary files and avoids false positives.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX  
> **Implementation:** `src/unicode.c`

---

## Overview

Many binaries contain Unicode strings — internationalized UI text, error messages, log strings, or embedded Unicode data. NeoDAX scans non-code sections for UTF-8 multi-byte sequences and UTF-16LE strings, using a set of heuristics to eliminate false positives that plague naive scanners.

---

## UTF-8 Detection

### Algorithm

For each byte position `i` in a non-code section:

1. Call `dax_utf8_decode()` to attempt decoding a codepoint starting at `buf[i]`
2. If the sequence is valid and the codepoint is printable, continue to the next sequence
3. If the string terminates with a NUL byte, has ≥ 2 characters, and contains at least one multi-byte sequence (codepoint ≥ U+0080), emit the string

### Why "at least one multi-byte sequence"?

Pure ASCII NUL-terminated strings are already reported by the ASCII string scanner (`-t` flag, `bin.strings()`). The Unicode scanner only reports strings that contain actual multi-byte encoded characters — Cyrillic, Arabic, CJK, emoji, etc.

### Codepoint validation

`dax_utf8_decode()` rejects:
- Overlong sequences (e.g. 2-byte encoding of a character that fits in 1 byte)
- Sequences that decode to surrogate code points (U+D800–U+DFFF)
- Sequences above U+10FFFF

---

## UTF-16LE Detection

UTF-16LE is common in Windows PE files and some Android resources. It is also the encoding that produces the most false positives in naive scanners.

### The False Positive Problem

Consider the symbol name string table (`.dynstr`) in a Linux ELF:

```
n\0__cxa_finalize\0__cxa_atexit\0strcmp\0...
```

A naive scanner reads this two bytes at a time:
- `[0x6E, 0x00]` = U+006E = `'n'` (ASCII 'n' in wide encoding)
- `[0x5F, 0x5F]` = U+5F5F = `'彟'` (CJK unified ideograph)
- `[0x63, 0x78]` = U+7863 = `'硣'` (CJK)

Result: garbage CJK characters from perfectly normal ASCII symbol names. Before the v1.0.0 fix, NeoDAX produced 85 false positives on a simple `/bin/ls` analysis.

### v1.0.0 Fixes — Seven Layers of Defense

**Layer 1 — Section blacklist:**  
Skip the following sections entirely for UTF-16LE scanning:
`.dynstr`, `.dynsym`, `.symtab`, `.strtab`, `.shstrtab`, `.gnu.hash`, `.gnu.version`, `.gnu.version_r`, `.note.*`, `.debug*`, `.rela.*`, `.plt`, `.got`, `.got.plt`

These sections contain binary data and symbol names that structurally look like UTF-16LE but never are.

**Layer 2 — Preceding byte guard:**  
A valid UTF-16LE string must start at a clean string boundary. The byte immediately before the candidate position must be `0x00` (end of a previous NUL-terminated string), or we must be at position 0. This prevents starting mid-way through a null-separated ASCII list like `.dynstr`.

**Layer 3 — Pure null-padded ASCII rejection:**  
If all high bytes (odd-indexed bytes) are `0x00`, the string is just ASCII with null padding — e.g. `H\0e\0l\0l\0o\0`. This is valid UTF-16LE but uninteresting (the ASCII scanner already reports it). Rejected.

**Layer 4 — Beyond-Latin codepoint requirement:**  
Require at least one codepoint > U+02FF. Codepoints U+0000–U+02FF cover Basic Latin, Latin-1, Latin Extended-A/B — these appear in binary data by accident far too often. Codepoints from U+0300 upward (Greek, Cyrillic, Arabic, CJK, emoji, etc.) are very unlikely to appear by chance.

**Layer 5 — Minimum width threshold:**  
Require ≥ 3 "wide" code units (units where the high byte ≠ 0x00) to avoid accepting very short accidental matches.

**Layer 6 — Minimum length:**  
Require ≥ 6 total code units (12 bytes). This rejects single-character wide matches and very short fragments.

**Layer 7 — Surrogate pair acceptance:**  
Surrogate pairs (emoji and Supplementary Multilingual Plane characters) are always accepted when found, overriding the minimum length/width requirements. An emoji is always genuine.

### Result

| Binary | False positives (before) | False positives (after) |
|--------|--------------------------|-------------------------|
| `/bin/ls` (x86-64 ELF) | 59 | 0–1 |
| `nightmare4` (ARM64 ELF with jump tricks) | 85 | ~1 |
| Windows PE with actual UTF-16 strings | n/a | Reports genuine strings |

---

## section_skip_utf16 — Sections Always Skipped

```
.dynstr       dynamic linker string table — null-separated ASCII
.dynsym       dynamic symbol table — binary struct data
.symtab       symbol table
.strtab       string table — null-separated ASCII
.shstrtab     section header string table
.gnu.hash     hash table — binary data
.gnu.version  version table — binary data
.gnu.version_r  version requirement table
.note.*       note sections — binary data
.debug*       DWARF debug info — complex binary format
.rela.*       relocation tables — binary data
.plt          procedure linkage table — code stubs
.got          global offset table — pointers
.got.plt      GOT for PLT entries
```

---

## Encoding Identification

| Encoding | Detection | Typical source |
|----------|-----------|----------------|
| `utf-8` | Valid UTF-8 sequence, at least one codepoint ≥ U+0080 | Linux .rodata, Android logs, modern apps |
| `utf-16le` | All 7 guards pass | Windows PE strings, Android res, wchar_t |
| `utf-16be` | Same as UTF-16LE with byte order reversed | Big-endian systems, some older formats |

---

## API

```c
// Scan all non-code sections
void dax_scan_unicode(dax_binary_t *bin);

// UTF-8 decoder (exposed for use in disasm.c string annotation)
int dax_utf8_decode(const uint8_t *buf, size_t len,
                    uint32_t *codepoint, int *seq_len);

// Convert UTF-16LE bytes to UTF-8 string
int dax_utf16le_to_utf8(const uint8_t *src, size_t src_bytes,
                         char *dst, size_t dst_max);
```

JS API: `bin.unicodeStrings()` — returns array of `{ address, value, byteLength, encoding }`.
