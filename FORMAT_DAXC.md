# .daxc Snapshot Format

Specification for the NeoDAX binary snapshot format.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX  
> **Implementation:** `src/daxc.c` · `include/dax.h`

---

## Overview

`.daxc` is a compact binary format for saving and reloading a full NeoDAX analysis result. It serializes all parsed and analyzed data so that a binary does not need to be re-analyzed from scratch.

**Use cases:**
- Save an expensive full analysis (`-X`) and reload it later
- Share analysis results without sharing the original binary
- Convert to annotated `.S` assembly for diffing or archiving

---

## Format Identity

| Field | Value |
|-------|-------|
| Magic | `0x584F454E` = `NEOX` (little-endian) |
| Version | `4` |
| Extension | `.daxc` |
| Endianness | Little-endian |

---

## File Structure

```
┌──────────────────────────────────────────────────────────┐
│  daxc_header_t         fixed-size header (256 bytes)     │
├──────────────────────────────────────────────────────────┤
│  sections[]            dax_section_t × nsections         │
├──────────────────────────────────────────────────────────┤
│  symbols[]             dax_symbol_t  × nsymbols          │
├──────────────────────────────────────────────────────────┤
│  xrefs[]               dax_xref_t    × nxrefs            │
├──────────────────────────────────────────────────────────┤
│  functions[]           dax_func_t    × nfunctions        │
├──────────────────────────────────────────────────────────┤
│  blocks[]              dax_block_t   × nblocks           │
├──────────────────────────────────────────────────────────┤
│  comments[]            dax_comment_t × ncomments         │
├──────────────────────────────────────────────────────────┤
│  insns[]               daxc_insn_t   × ninsns            │
├──────────────────────────────────────────────────────────┤
│  ustrings[]            dax_ustring_t × nustrings         │
└──────────────────────────────────────────────────────────┘
```

---

## Header Layout (`daxc_header_t`)

```c
#pragma pack(push,1)
typedef struct {
    uint32_t  magic;            // 0x584F454E ('NEOX')
    uint32_t  version;          // 4
    char      filepath[512];    // original binary path
    uint64_t  entry;
    uint64_t  base;
    uint64_t  image_size;
    uint64_t  code_size;
    uint64_t  data_size;
    uint32_t  total_insns;
    uint8_t   fmt;              // dax_fmt_t
    uint8_t   arch;             // dax_arch_t
    uint8_t   os;               // dax_os_t
    uint8_t   is_pie;
    uint8_t   is_stripped;
    uint8_t   has_debug;
    uint8_t   _pad[2];
    char      sha256[65];
    char      build_id[64];
    uint32_t  nsections;
    uint32_t  nsymbols;
    uint32_t  nxrefs;
    uint32_t  nfunctions;
    uint32_t  nblocks;
    uint32_t  ncomments;
    uint32_t  ninsns;
    uint32_t  nustrings;
} daxc_header_t;
#pragma pack(pop)
```

---

## Instruction Record (`daxc_insn_t`)

```c
typedef struct {
    uint64_t addr;
    uint8_t  bytes[15];
    uint8_t  length;
    char     mnemonic[32];
    char     operands[128];
    uint8_t  group;    // dax_igrp_t
    uint8_t  _pad[3];
} daxc_insn_t;
```

---

## Creating a Snapshot

```bash
# Save
./neodax -x -o analysis.daxc ./binary

# Reload and print
./neodax -n analysis.daxc

# Convert to annotated assembly
./neodax -c analysis.daxc > annotated.S
```

Via JS:
```js
// (daxc write is CLI-only — not exposed in N-API)
// Use the CLI to create snapshots, then load them with the normal loader
```

---

## Version History

| Version | Change |
|---------|--------|
| 4 | Current — added `image_size`, `code_size`, `data_size`, `total_insns`, `is_pie`, `is_stripped`, `has_debug`, `nustrings`, `build_id`; renamed magic to `NEOX` |
| 3 | Added `blocks[]` (CFG basic blocks), `comments[]` |
| 2 | Added `functions[]`, `xrefs[]` |
| 1 | Original DAX format — sections + symbols + insns only |

---

## Compatibility

`.daxc` files are specific to the NeoDAX version that created them. The magic (`NEOX`) and version field (`4`) must match. Older `.daxc` files (magic `DAXC`, versions 1–3) are not compatible with v1.0.0.
