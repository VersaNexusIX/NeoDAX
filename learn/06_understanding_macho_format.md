# Understanding Mach-O Format

**Level:** 0 - Foundation
**Prerequisites:** 05_understanding_pe_format.md
**What You Will Learn:** The structure of macOS Mach-O files, including FAT universal binaries.

## What Mach-O Is

Mach-O stands for Mach Object. It is the binary format used on macOS, iOS, iPadOS, and other Apple platforms. Mach-O evolved from the original Mach microkernel developed at Carnegie Mellon University.

Mach-O files are identified by a 4-byte magic number at the start. The magic value depends on the file's architecture and endianness.

## Magic Numbers

| Magic (hex) | Bytes on disk | Meaning |
|-------------|--------------|---------|
| 0xFEEDFACF | CF FA ED FE | 64-bit little-endian (ARM64, x86-64) |
| 0xFEEDFACE | CE FA ED FE | 32-bit little-endian |
| 0xCFFAEDFE | FE ED FA CF | 64-bit big-endian (rare) |
| 0xBEBAFECA | CA FE BA BE | FAT/Universal binary |

The most common magic on modern Apple hardware is 0xFEEDFACF for ARM64 (Apple Silicon) and x86-64 (Intel Mac).

An important detail: the magic value is what a little-endian CPU reads from the raw bytes. This is why 0xFEEDFACF corresponds to the bytes CF FA ED FE on disk.

## FAT Universal Binaries

macOS ships most system binaries as FAT (universal) files. A FAT file contains multiple Mach-O slices, one for each CPU architecture. When you run the program, the OS picks the slice that matches your CPU.

The FAT header uses big-endian byte order regardless of the host architecture. It contains a list of architecture entries, each specifying the CPU type, offset within the file, and size of that slice.

NeoDAX automatically selects the best slice when loading a FAT binary. It prefers ARM64 and falls back to x86-64.

## Mach-O Structure

A Mach-O file consists of:

**Mach-O header:** Contains magic, CPU type, CPU subtype, file type (executable, dylib, bundle), number of load commands, and flags.

**Load commands:** A sequence of variable-length structures that describe how to map the file into memory. Each load command has a type identifier and a size.

**Segments and sections:** Load commands of type LC_SEGMENT_64 describe segments. Each segment contains zero or more sections.

## Key Segments and Sections

Mach-O uses double-underscore prefixes for segment and section names:

`__TEXT` is the read-execute segment. It contains:
- `__TEXT,__text`: Compiled machine code
- `__TEXT,__stubs`: PLT-equivalent stubs for external functions
- `__TEXT,__cstring`: String literals

`__DATA` is the read-write segment. It contains:
- `__DATA,__data`: Initialized global variables
- `__DATA,__bss`: Uninitialized global variables
- `__DATA,__got`: Global offset table
- `__DATA,__la_symbol_ptr`: Lazy symbol pointers

NeoDAX strips the double underscores and reports sections as `.text`, `.data`, `.cstring`, and so on, making them consistent with ELF naming.

## Load Commands Relevant to Analysis

`LC_MAIN` specifies the entry point as an offset from the start of the `__TEXT` segment. NeoDAX reads this to determine the entry point address.

`LC_SYMTAB` points to the symbol table. NeoDAX reads `nlist_64` entries from this table to get function names. macOS follows a convention where C symbol names have a leading underscore: `_main`, `_printf`. NeoDAX strips this underscore automatically.

`LC_DYLD_INFO` and `LC_DYLD_EXPORTS_TRIE` describe imports and exports for shared libraries. NeoDAX does not currently parse these, but they are relevant for advanced analysis.

## Practice

On macOS:

```bash
./neodax -l /bin/ls
```

Look for the `__text` section (displayed as `.text`) and note its address. On Apple Silicon, addresses typically start around `0x100000000` for executables.

Try the debug endpoint to see how NeoDAX resolves a FAT binary:

```bash
./neodax -l /usr/bin/file
```

Note whether the binary is reported as PIE. Most modern macOS executables are PIE.

## Next

Continue to `07_binary_formats_comparison.md`.
