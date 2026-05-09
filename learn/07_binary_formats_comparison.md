# Binary Formats Comparison

**Level:** 0 - Foundation
**Prerequisites:** 06_understanding_macho_format.md
**What You Will Learn:** Side-by-side comparison of ELF, PE, and Mach-O to solidify your understanding.

## At a Glance

| Feature | ELF | PE | Mach-O |
|---------|-----|----|--------|
| Platform | Linux, Android, BSD | Windows | macOS, iOS |
| Magic bytes | 7F 45 4C 46 | 4D 5A | CF FA ED FE (and others) |
| Multi-arch | No | No | Yes (FAT) |
| Entry point | e_entry field | AddressOfEntryPoint | LC_MAIN offset |
| Code section | .text | .text | __TEXT,__text |
| Imports | PLT/GOT via .dynsym | Import table (.idata) | LC_DYLD_INFO |
| Exports | .dynsym | Export table (.edata) | LC_SYMTAB / exports trie |
| Symbols | .symtab / .dynsym | Export directory | LC_SYMTAB |
| Debug info | DWARF (.debug_*) | PDB (separate file) | DWARF (.dSYM bundle) |
| Stripping | Remove .symtab | Remove exports | Remove LC_SYMTAB |

## Address Space

Each format has a different convention for addresses:

**ELF:** Addresses in the file are absolute virtual addresses. For PIE executables, the actual runtime addresses are randomized, but the analysis addresses are file-relative.

**PE:** Addresses are relative to the image base (a preferred load address, typically 0x400000 for x86 or 0x140000000 for x86-64). The actual runtime address is image_base + rva (relative virtual address).

**Mach-O:** For 64-bit executables, the `__TEXT` segment is typically loaded at address 0x100000000. Addresses in the file are absolute and the OS maps the binary at that address unless ASLR shifts it.

When NeoDAX reports addresses, it uses the in-file virtual addresses. On PIE or ASLR-enabled binaries, runtime addresses differ.

## Section Names Across Formats

NeoDAX normalizes section names across formats. When you see `.text`, it refers to the code section regardless of whether the file is ELF, PE, or Mach-O (where it is actually `__TEXT,__text`).

This normalization means analysis scripts and habits transfer across platforms.

## How Detection Works

NeoDAX reads the first 4 bytes of any file and compares them against known magic values:

1. `7F 45 4C 46` -> ELF
2. `4D 5A` (as first 2 bytes) -> PE
3. `CF FA ED FE`, `CE FA ED FE`, `FE ED FA CF`, `FE ED FA CE`, `CA FE BA BE` -> Mach-O

If none match, the file is treated as a raw binary. You can still disassemble raw binaries by specifying a start address and architecture.

## Common Confusion Points

**"Where does execution start?"**
- ELF: the `e_entry` field in the ELF header
- PE: `AddressOfEntryPoint` in the optional header (plus image base)
- Mach-O: `LC_MAIN` load command's `entryoff` field plus the `__TEXT` segment base

**"What are these symbols?"**
- ELF: `.symtab` for internal symbols, `.dynsym` for shared library symbols
- PE: the export directory for exported symbols, no internal symbol table in stripped binaries
- Mach-O: `LC_SYMTAB` for all symbols, with underscore prefix convention

**"Why are addresses different on different machines?"**
PIE executables are relocated by the OS at load time. The addresses NeoDAX shows are the pre-relocation addresses from the file.

## Practice

Analyze the same binary on different platforms if possible, or compare two binaries of different formats:

1. Run `./neodax -l` on an ELF file and a PE file.
2. Note the section names and whether they follow the same pattern.
3. Find the entry point in both and compare the addresses.

## Next

You have completed Level 0 - Foundation. Continue to `10_cli_basics.md` to begin Level 1.
