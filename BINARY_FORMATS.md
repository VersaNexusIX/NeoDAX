# Binary Format Support

Detailed reference for all binary formats supported by NeoDAX.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Format Detection

NeoDAX detects the file format by reading the first 4 bytes as a little-endian `uint32_t`:

| Magic value | Bytes on disk | Format |
|-------------|---------------|--------|
| `0x464C457F` | `7F 45 4C 46` | ELF (any) |
| `0x00005A4D` | `4D 5A xx xx` | PE (DOS MZ header) |
| `0xFEEDFACF` | `CF FA ED FE` | Mach-O 64-bit LE |
| `0xFEEDFACE` | `CE FA ED FE` | Mach-O 32-bit LE |
| `0xCFFAEDFE` | `FE ED FA CF` | Mach-O 64-bit BE |
| `0xCEFAEDFE` | `FE ED FA CE` | Mach-O 32-bit BE |
| `0xBEBAFECA` | `CA FE BA BE` | FAT/Universal |
| `0xCAFEBABE` | `BE BA FE CA` | FAT (alternate) |
| *(anything else)* | - | Raw binary |

---

## ELF

**Parser:** `src/loader.c` -> `dax_parse_elf()`
**Header:** `include/elf.h`

### Supported variants

| Variant | Architecture | Status |
|---------|-------------|--------|
| ELF64 LE | x86-64, AArch64, RISC-V | Full |
| ELF32 LE | x86, ARM, RISC-V | Full |
| ELF64 BE | SPARC, MIPS64 | Parsed (no decoder) |
| ELF32 BE | MIPS32, PowerPC | Parsed (no decoder) |

### Extracted metadata

- Class (32/64-bit), endianness, OS/ABI
- Architecture (`e_machine`)
- Entry point (`e_entry`)
- Section headers: name, type (`SHT_*`), flags (`SHF_*`), vaddr, offset, size
- Symbol table from `.symtab` and `.dynsym`
- SHA-256 hash
- GNU Build-ID from `.note.gnu.build-id`
- PIE detection (`ET_DYN` with dynamic interpreter)
- Stripped detection (no `.symtab`)
- Debug info detection (`.debug_*` sections present)

### OS/ABI detection

| EI_OSABI | Detected as |
|----------|-------------|
| `0x00` SYSV | Linux (heuristic: interpreter path) |
| `0x03` GNU/Linux | Linux |
| `0x61` ARM | Android (heuristic) |
| `0x09` FreeBSD | BSD |
| `0x0C` OpenBSD | BSD |

---

## PE / COFF

**Parser:** `src/loader.c` -> `dax_parse_pe()`
**Header:** `include/pe.h`

### Supported variants

| Variant | Architecture | Status |
|---------|-------------|--------|
| PE64+ (x86-64) | x86-64 | Full |
| PE64+ (ARM64) | AArch64 | Full |
| PE32 (x86) | x86 | Full |
| PE32 (ARM) | ARM32 | Parsed (no decoder) |

### Extracted metadata

- DOS stub and PE signature
- Machine type (`IMAGE_FILE_MACHINE_*`)
- Optional header: ImageBase, SizeOfImage, AddressOfEntryPoint
- Section table: Name, VirtualAddress, VirtualSize, PointerToRawData, Characteristics
- Export directory: exported symbol names and addresses
- PIE detection (DLL characteristic flag)
- Image size, code size (`SizeOfCode`), initialized data size

---

## Mach-O

**Parser:** `src/macho.c` -> `dax_parse_macho()`
**Header:** `include/macho.h`
**Full docs:** [MACHO_SUPPORT.md](MACHO_SUPPORT.md)

### Supported variants

| Variant | Architecture | Status |
|---------|-------------|--------|
| Mach-O 64-bit LE | ARM64, x86-64, RISC-V | Full |
| FAT/Universal | ARM64 + x86-64 | Full (auto-selects ARM64 slice) |
| Mach-O 64-bit BE | - | Parsed |
| Mach-O 32-bit | x86, ARM | Parsed |

### Load commands parsed

`LC_SEGMENT_64`, `LC_MAIN`, `LC_SYMTAB`. All others are safely skipped.

---

## Raw Binary

When no recognized format is detected, NeoDAX treats the file as a raw binary:

- `fmt = FMT_RAW`, `arch = ARCH_UNKNOWN`
- No sections are created — the entire file is treated as one implicit code region.
- Disassembly requires the architecture to be specified (raw mode currently returns no output).

---

## Format x Feature Matrix

| Feature | ELF | PE | Mach-O | Raw |
|---------|:---:|:--:|:------:|:---:|
| Sections | Y | Y | Y | - |
| Symbols | Y | Y (exports) | Y (nlist_64) | - |
| Entry point | Y | Y | Y (LC_MAIN) | - |
| SHA-256 | Y | Y | Y | Y |
| Build-ID | Y (GNU) | - | - | - |
| PIE flag | Y | Y | Y | - |
| Stripped flag | Y | Y | Y | - |
| Debug flag | Y | - | - | - |
| Disassembly | Y | Y | Y | - |
| CFG | Y | Y | Y | - |
| Function detect | Y | Y | Y | - |
| Xrefs | Y | Y | Y | - |
| Entropy | Y | Y | Y | Y |
| Unicode scan | Y | Y | Y | - |
| Symexec | Y (ARM64) | Y (ARM64) | Y (ARM64) | - |
| Decompile | Y (ARM64) | Y (ARM64) | Y (ARM64) | - |
| Emulate | Y (ARM64) | Y (ARM64) | Y (ARM64) | - |
