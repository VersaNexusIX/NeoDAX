# Understanding PE Format

**Level:** 0 - Foundation
**Prerequisites:** 04_understanding_elf_format.md
**What You Will Learn:** The structure of Windows PE files and how they differ from ELF.

## What PE Is

PE stands for Portable Executable. It is the binary format used on Windows for executables (.exe) and dynamic libraries (.dll). PE is based on the older COFF format from the DEC VAX era.

PE files are identified by the bytes `4d 5a` at the start, which spells "MZ" in ASCII. These are the initials of Mark Zbykowski, who designed the original DOS EXE format that PE extends.

## PE Structure

A PE file has several layers:

**DOS header:** The first 64 bytes, starting with MZ. Contains a pointer to the PE header. Also contains a tiny DOS stub program that prints "This program cannot be run in DOS mode" if someone tries to run the program under DOS.

**PE header:** Contains the PE signature `50 45 00 00` (PE followed by two null bytes), the machine type, number of sections, and timestamps.

**Optional header:** Despite the name, this is required for executables. Contains the image base (preferred load address), entry point, section alignment, and size of code and data.

**Section table:** A list of section headers describing each section.

**Sections:** The actual content.

## PE Sections vs ELF Sections

PE and ELF use different naming conventions:

| PE Name | ELF Name | Contents |
|---------|----------|----------|
| .text | .text | Executable code |
| .rdata | .rodata | Read-only data |
| .data | .data | Writable data |
| .bss | .bss | Uninitialized data |
| .idata | (various) | Import table |
| .edata | (various) | Export table |
| .rsrc | (none) | Resources (icons, strings, manifests) |
| .reloc | .rel | Relocation entries |

Section names in PE are not enforced. Malware often uses non-standard section names or no names at all.

## Imports and Exports

PE files use an import table to declare which functions they need from DLLs. For example, a program calling `MessageBoxA` from `user32.dll` has an import entry for it.

The import table is one of the first places to look when analyzing malware. The imported functions reveal what system capabilities the program uses: file I/O, networking, cryptography, process injection, and so on.

Exports are functions that a DLL makes available to other modules. Analyzing exports tells you what a library does.

NeoDAX reads PE exports and presents them as symbols.

## PE vs ELF Differences

The key conceptual differences:

- PE uses "virtual address" as address relative to the image base. ELF uses absolute addresses after loading.
- PE has a rich resource section for embedded assets. ELF has no equivalent.
- PE imports are resolved at load time through the import address table. ELF uses the PLT/GOT mechanism.
- PE sections have explicit alignment requirements.

## Practice

If you have a Windows binary available (a .exe or .dll file), analyze it:

```bash
./neodax -l yourfile.exe
./neodax -y yourfile.dll
```

If not, look at the PE import table of any Windows executable using NeoDAX. Notice which DLL names appear and what functions are imported.

## Next

Continue to `06_understanding_macho_format.md`.
