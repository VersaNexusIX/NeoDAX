# Understanding ELF Format

**Level:** 0 - Foundation
**Prerequisites:** 03_your_first_binary.md
**What You Will Learn:** The structure of ELF files and what NeoDAX extracts from them.

## What ELF Is

ELF stands for Executable and Linkable Format. It is the standard binary format on Linux, Android, and most Unix-like systems. When you compile a C program on Linux, the result is an ELF file.

ELF files come in several types:

- **Executable:** A program you can run directly, like `/bin/ls`.
- **Shared object:** A library with a `.so` extension, like `libc.so`.
- **Relocatable object:** An intermediate `.o` file produced by the compiler.
- **Core dump:** A snapshot of a crashed process's memory.

NeoDAX handles executables and shared objects.

## ELF Header

Every ELF file starts with a header that contains:

- A magic number: the bytes `7f 45 4c 46` (7F followed by ELF in ASCII)
- Class: 32-bit or 64-bit
- Data encoding: little-endian or big-endian
- OS/ABI: identifies the target operating system
- File type: executable, shared object, etc.
- Machine type: the target CPU architecture
- Entry point address: where execution begins

NeoDAX reads all of this and reports it in the overview output.

## Program Headers and Section Headers

ELF files have two views of their contents:

**Program headers** describe segments: contiguous regions of memory that the loader maps into the process. Each segment has a virtual address, a file offset, a size, and permissions (read, write, execute).

**Section headers** describe sections: logical units like code, read-only data, symbol tables, and debug information. Sections are for the linker and debugger, not the loader.

NeoDAX primarily works with sections because they provide finer-grained information. When you run `./neodax -l`, you see section names, types, addresses, sizes, and offsets.

## Key Sections

The most important sections in a typical ELF executable:

`.text` contains executable machine code. This is where you spend most of your analysis time.

`.rodata` contains read-only data: string literals, constant tables, and jump tables.

`.data` contains initialized writable data: global variables with non-zero initial values.

`.bss` contains uninitialized writable data. It takes no space in the file but is zeroed in memory at load time.

`.symtab` contains the full symbol table with all function and variable names. Stripped binaries do not have this section.

`.dynsym` contains the dynamic symbol table for shared library functions. Even stripped binaries usually have this.

`.plt` and `.got` handle calls to shared library functions through indirection.

## PIE and ASLR

A Position Independent Executable (PIE) can be loaded at any address in memory. The OS chooses a random base address each time the program runs. This is called ASLR (Address Space Layout Randomization) and makes exploitation harder.

NeoDAX detects and reports whether a binary is PIE.

When a binary is PIE, the addresses in the disassembly output are the file-relative (pre-ASLR) addresses, not runtime addresses.

## Stripped vs Unstripped

An unstripped binary has a `.symtab` section containing the names of all functions and variables. This makes analysis much easier because you can see `malloc`, `encrypt_key`, or `check_password` instead of `sub_401234`.

A stripped binary has had its symbol table removed with the `strip` command. You still have the dynamic symbols (functions called from shared libraries) but lose all internal function names.

NeoDAX reports whether a binary is stripped and uses whatever symbols are available.

## Practice

```bash
./neodax -l /bin/ls
```

Identify:
1. Which section contains the executable code (.text).
2. Which section is largest.
3. Whether the binary is PIE (look for "PIE" in the output header).
4. Whether the binary is stripped.

## Next

Continue to `05_understanding_pe_format.md`.
