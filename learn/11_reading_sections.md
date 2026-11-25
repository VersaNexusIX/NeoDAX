# Reading Sections

**Level:** 1 - Basic Analysis
**Prerequisites:** 10_cli_basics.md
**What You Will Learn:** How to read and interpret section listing output in detail.

## The Section Listing

Run:

```bash
./neodax -l /bin/ls
```

Each line in the output represents one section. A typical ELF output looks like:

```
.text      code    0x401000  size 0x1234  offset 0x1000  insns 892
.rodata    rodata  0x402234  size 0x0200  offset 0x2234
.data      data    0x404000  size 0x0050  offset 0x4000
.bss       bss     0x404050  size 0x0100  offset 0x0000
.plt       plt     0x400800  size 0x00a0  offset 0x0800
.got       got     0x403000  size 0x0030  offset 0x3000
```

## Section Fields

**Name:** The section identifier. Standard names follow conventions but custom sections can have any name.

**Type:** NeoDAX classifies each section:
- `code`: executable machine code
- `data`: readable and writable data
- `rodata`: read-only data
- `bss`: uninitialized data (zero-filled at load time)
- `plt`: procedure linkage table (code stubs for external calls)
- `got`: global offset table (pointers resolved at load time)
- `other`: anything that does not fit a known category

**Virtual address:** Where the section is mapped in memory. This is what you see in disassembly output.

**Size:** How many bytes the section occupies. BSS sections have a size but no file content because they are zero-initialized.

**Offset:** Where the section's data starts in the file. For BSS, this is 0 because there is no data in the file.

**Insns:** For code sections, NeoDAX counts the number of instructions during parsing.

## What Section Layout Tells You

A normal Linux executable typically has:

- One `.text` section with the bulk of the code
- One `.plt` section for external function calls
- One `.rodata` section with string literals and constants
- One `.data` section with initialized globals
- One `.bss` section with uninitialized globals

When a binary deviates from this pattern, it is worth investigating why.

A binary with many unusually named sections may be packed or have custom build tooling.

A binary with a very large `.text` section relative to its apparent functionality may have inlined a lot of library code or be statically linked.

A binary with a large `.rodata` section may contain embedded data files, certificates, or resource tables.

## Identifying Code vs Data

NeoDAX marks sections as `code` based on the executable flag in the section header. Only sections marked executable should contain instructions. If you see disassembly output in a section marked `data`, that is suspicious and may indicate obfuscation or position-independent shellcode.

## Section Sizes and Entropy

High-entropy sections are often compressed or encrypted. A `.text` section with entropy close to 8.0 (the maximum for random data) is likely packed. You will learn how to measure entropy in Level 4.

For now, pay attention to section sizes relative to what you expect. A 50KB executable that claims to have a 40KB `.text` section but a 5KB `.rodata` is normal. But a 50KB executable with a 48KB section of unknown type and no visible strings is suspicious.

## Practice

1. List sections of several binaries on your system.
2. Find a binary with a `.plt` section. Note its size relative to `.text`.
3. Find a binary that is statically linked (no `.plt` section). Try `/bin/busybox` if available.
4. Look at the offset column and verify that sections appear in the order they are listed.

## Next

Continue to `12_symbols_and_names.md`.
