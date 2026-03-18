const lessons = [
  {
    id: "00_introduction",
    num: 0,
    level: 0,
    title: "NeoDAX Learning Path",
    prereq: "",
    learn: "",
    level_label: "",
    content: `# NeoDAX Learning Path

## Welcome

This learning path teaches you how to use NeoDAX from the ground up. Each file in this series builds on the previous one. You do not need prior experience with binary analysis, reverse engineering, or assembly language to start here.

By the time you finish, you will be able to analyze real-world binaries, extract meaningful information from executables, automate analysis with JavaScript, and build tools on top of NeoDAX.

## How This Path is Structured

The path is divided into eight levels:

**Level 0 - Foundation**
What binary analysis is, how to install NeoDAX, and what binary formats exist.

**Level 1 - Basic Analysis**
Using the command line, reading sections, symbols, and disassembly output.

**Level 2 - Intermediate Analysis**
Functions, cross-references, control flow graphs, loops, and call graphs.

**Level 3 - JavaScript API**
Loading binaries programmatically, querying data, and building scripts.

**Level 4 - Advanced Analysis**
Entropy scanning, recursive descent, instruction validity, obfuscation detection.

**Level 5 - Symbolic Execution and Decompilation**
SSA lifting, the decompiler, reading pseudo-C output, and the ARM64 emulator.

**Level 6 - Real World Reverse Engineering**
Practical walkthroughs, malware analysis basics, and vulnerability discovery.

**Level 7 - Integration and Automation**
REST API, batch analysis, CI/CD integration, and building custom tools.

**Appendix**
Quick reference sheets, cheatsheets, and a glossary.

## Prerequisites

You need:

- A computer running Linux, macOS, or Android with Termux
- A C99 compiler (GCC or Clang)
- Node.js version 16 or later (for Level 3 and above)
- Basic familiarity with the terminal

You do not need:

- Prior knowledge of assembly language
- Prior experience with reverse engineering tools
- A paid license or account

## How to Read Each File

Every file follows the same structure:

- **Level** tells you where this topic sits in the curriculum
- **Prerequisites** lists which files you should have read first
- **What You Will Learn** states the goals up front
- **Content** explains the topic with examples
- **Practice** gives you something to try yourself
- **Next** points to the next file in sequence

Start with file \`00\` and work forward. Do not skip levels unless you already have the background knowledge.

## Getting the Most from Practice Exercises

Each file has a practice section. These exercises use real binaries you already have on your system such as \`/bin/ls\` on Linux, \`/usr/bin/file\` on macOS, or compiled programs from the NeoDAX repository itself.

Do not rush through the practice sections. Understanding why an output looks the way it does is more valuable than moving to the next topic quickly.

## Next

Continue to \`01_what_is_binary_analysis.md\`.
`
  },
  {
    id: "01_what_is_binary_analysis",
    num: 1,
    level: 0,
    title: "What is Binary Analysis",
    prereq: "00_introduction.md",
    learn: "What a binary file is, why we analyze them, and what kinds of questions binary analysis answers.",
    level_label: "0 - Foundation",
    content: `# What is Binary Analysis

**Level:** 0 - Foundation
**Prerequisites:** 00_introduction.md
**What You Will Learn:** What a binary file is, why we analyze them, and what kinds of questions binary analysis answers.

## What a Binary File Is

When you compile a C program, the compiler turns your source code into machine instructions that the CPU understands. The result is a binary file: a sequence of bytes encoding instructions, data, and metadata.

Unlike a text file, you cannot open a binary in a text editor and read it. The bytes represent encoded integers, addresses, opcodes, and structures that have meaning only when interpreted according to a specific format.

Every executable you run on your computer, every shared library, every kernel module is a binary file.

## Why Analyze Binaries

There are several legitimate reasons to analyze a binary:

**Security research.** Finding vulnerabilities in software before attackers do. Understanding how malware works. Verifying that a binary does what its documentation claims.

**Compatibility work.** Understanding an old program with no source code so you can recreate it, port it, or interface with it.

**Performance analysis.** Looking at what the compiler actually produced to understand why a program is slow or behaves unexpectedly.

**Learning.** Understanding how software works at the lowest level is one of the most effective ways to become a better programmer.

## What Binary Analysis Answers

Given a binary file, analysis can answer questions like:

- What functions does this program contain?
- What strings are embedded in it?
- Does this code decrypt something before running it?
- What other functions does a given function call?
- What memory addresses does this code access?
- Is this code packed or obfuscated?
- What would happen if we trace symbolic values through this function?

NeoDAX answers all of these questions and more.

## Static vs Dynamic Analysis

There are two broad approaches to binary analysis:

**Static analysis** examines the binary without running it. You read the instructions, map the data, trace control flow, and reason about behavior from the code alone. NeoDAX is a static analysis tool.

**Dynamic analysis** runs the binary and observes what it does. Tools like debuggers, tracers, and emulators belong here. NeoDAX includes a concrete emulator for ARM64, which bridges static and dynamic approaches.

Both approaches have strengths and weaknesses. Static analysis is safe because you never execute potentially malicious code. Dynamic analysis is more precise because it sees actual runtime values. In practice, skilled analysts use both.

## The Analysis Pipeline

A typical static analysis session looks like this:

1. Load the binary and identify its format (ELF, PE, Mach-O, raw).
2. Read the section layout to understand what is where.
3. Extract symbols to get function names if they exist.
4. Disassemble code sections to read instructions.
5. Build a control flow graph to understand execution paths.
6. Extract strings to find clues about behavior.
7. Scan for suspicious patterns like high entropy or invalid instructions.

NeoDAX automates all of these steps. You can run them individually or all at once.

## Practice

Look at a binary file in raw hex to see what you are working with:

\`\`\`bash
xxd /bin/ls | head -20
\`\`\`

You should see the first bytes are \`7f 45 4c 46\` which spells out "ELF" in ASCII preceded by a non-printable byte. This is the magic number that identifies ELF files.

On macOS, the first bytes of \`/bin/ls\` are \`ca fe ba be\` which is the FAT (universal binary) magic number.

Now look at the same file as NeoDAX sees it:

\`\`\`bash
./neodax -l /bin/ls
\`\`\`

This lists all the sections. Notice how the raw bytes you saw in hex have been interpreted into a structured view.

## Next

Continue to \`02_setting_up_neodax.md\`.
`
  },
  {
    id: "02_setting_up_neodax",
    num: 2,
    level: 0,
    title: "Setting Up NeoDAX",
    prereq: "01_what_is_binary_analysis.md",
    learn: "How to install NeoDAX on Linux, macOS, and Android.",
    level_label: "0 - Foundation",
    content: `# Setting Up NeoDAX

**Level:** 0 - Foundation
**Prerequisites:** 01_what_is_binary_analysis.md
**What You Will Learn:** How to install NeoDAX on Linux, macOS, and Android.

## Installation Overview

NeoDAX has zero external dependencies. You only need a C compiler and GNU make. The build compiles all source files and produces a single executable called \`neodax\`.

## Linux

\`\`\`bash
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX
make
\`\`\`

The build takes under a minute. When it finishes you will see the NeoDAX banner and a message confirming the build succeeded. The \`neodax\` binary is in the current directory.

Add it to your path for convenience:

\`\`\`bash
sudo cp neodax /usr/local/bin/
\`\`\`

Or keep it in the NeoDAX directory and call it as \`./neodax\`.

## macOS

Install the Xcode command line tools if you have not already:

\`\`\`bash
xcode-select --install
\`\`\`

Then build exactly as on Linux:

\`\`\`bash
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX
make
\`\`\`

NeoDAX uses \`arch/arm64_macos.S\` on Apple Silicon and \`arch/x86_64_macos.S\` on Intel Mac. The Makefile selects the correct file automatically.

## Android with Termux

Termux provides a Linux-like environment on Android without root. Install the required packages first:

\`\`\`bash
pkg install nodejs clang make git
\`\`\`

Then clone and build:

\`\`\`bash
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX
make
\`\`\`

The build works the same way as on Linux. The resulting \`neodax\` binary runs natively on ARM64 Android.

## Verifying the Installation

Run the help flag to confirm everything is working:

\`\`\`bash
./neodax -h
\`\`\`

You should see a list of all available flags. If you see this, the installation succeeded.

Try analyzing a system binary:

\`\`\`bash
./neodax -l /bin/ls
\`\`\`

On Linux this lists the ELF sections of \`/bin/ls\`. On macOS it lists the Mach-O sections.

## Building the JavaScript Addon

If you want to use the JavaScript API (covered in Level 3), you also need to build the native Node.js addon:

\`\`\`bash
make js
\`\`\`

This produces \`js/neodax.node\`. You can also install from npm directly, which builds the addon automatically:

\`\`\`bash
npm install neodax
\`\`\`

## Directory Layout After Building

\`\`\`
NeoDAX/
  neodax          the CLI binary
  src/            C source files
  include/        header files
  arch/           platform assembly stubs
  js/
    neodax.node   the Node.js native addon (after make js)
    index.js      the JavaScript API wrapper
    server/       the REST API server
\`\`\`

## Practice

1. Build NeoDAX and confirm it runs.
2. Run \`./neodax -h\` and read through the available flags.
3. Run \`./neodax -l /bin/ls\` (Linux) or \`./neodax -l /bin/ls\` (macOS).
4. Note how many sections are listed.

## Next

Continue to \`03_your_first_binary.md\`.
`
  },
  {
    id: "03_your_first_binary",
    num: 3,
    level: 0,
    title: "Your First Binary Analysis",
    prereq: "02_setting_up_neodax.md",
    learn: "How to run a complete analysis on a binary and understand the output at a high level.",
    level_label: "0 - Foundation",
    content: `# Your First Binary Analysis

**Level:** 0 - Foundation
**Prerequisites:** 02_setting_up_neodax.md
**What You Will Learn:** How to run a complete analysis on a binary and understand the output at a high level.

## The -x Flag

The \`-x\` flag runs all standard analysis in one command. It is the best starting point when you encounter a new binary:

\`\`\`bash
./neodax -x /bin/ls
\`\`\`

This runs: disassembly, section listing, symbol resolution, cross-references, string extraction, function detection, instruction groups, CFG building, loop detection, call graph, switch table detection, and unicode string scanning.

The output is long. Do not try to read all of it in one go. The goal for now is to see what kinds of information NeoDAX extracts.

## Reading the Output Structure

The output has several clearly labeled sections. Each section begins with a header line.

The disassembly section shows lines like:

\`\`\`
0x401000  55              push   rbp
0x401001  48 89 e5        mov    rbp, rsp
0x401004  48 83 ec 20     sub    rsp, 0x20
\`\`\`

The first column is the virtual address. The second column is the raw bytes. The third and fourth columns are the mnemonic and operands.

The sections listing shows entries like:

\`\`\`
.text      code    0x401000  size 0x1234  offset 0x1000
.rodata    rodata  0x402234  size 0x0200  offset 0x2234
.data      data    0x403000  size 0x0050  offset 0x3000
\`\`\`

The strings section shows printable strings found in the binary.

## A Targeted First Look

Rather than running \`-x\` immediately, a useful habit is to start with the sections:

\`\`\`bash
./neodax -l /bin/ls
\`\`\`

Then look at symbols:

\`\`\`bash
./neodax -y /bin/ls
\`\`\`

Then disassemble:

\`\`\`bash
./neodax /bin/ls
\`\`\`

This builds up your understanding layer by layer instead of flooding you with all information at once.

## What to Look For

When approaching an unknown binary for the first time, ask:

- How many sections are there? A stripped binary with unusual sections is suspicious.
- Are there symbols? Stripped binaries have no symbol names.
- What strings are present? Strings often reveal what a program does.
- What functions are detected? A binary with only a few functions or thousands of small ones is unusual.

## Practice

1. Run \`./neodax -x /bin/ls\` and scroll through the output.
2. Count how many sections \`/bin/ls\` has on your system.
3. Find one string in the output that tells you something about what \`ls\` does.
4. Run \`./neodax -f /bin/ls\` to list only the detected functions. Note how many there are.

## Next

Continue to \`04_understanding_elf_format.md\`.
`
  },
  {
    id: "04_understanding_elf_format",
    num: 4,
    level: 0,
    title: "Understanding ELF Format",
    prereq: "03_your_first_binary.md",
    learn: "The structure of ELF files and what NeoDAX extracts from them.",
    level_label: "0 - Foundation",
    content: `# Understanding ELF Format

**Level:** 0 - Foundation
**Prerequisites:** 03_your_first_binary.md
**What You Will Learn:** The structure of ELF files and what NeoDAX extracts from them.

## What ELF Is

ELF stands for Executable and Linkable Format. It is the standard binary format on Linux, Android, and most Unix-like systems. When you compile a C program on Linux, the result is an ELF file.

ELF files come in several types:

- **Executable:** A program you can run directly, like \`/bin/ls\`.
- **Shared object:** A library with a \`.so\` extension, like \`libc.so\`.
- **Relocatable object:** An intermediate \`.o\` file produced by the compiler.
- **Core dump:** A snapshot of a crashed process's memory.

NeoDAX handles executables and shared objects.

## ELF Header

Every ELF file starts with a header that contains:

- A magic number: the bytes \`7f 45 4c 46\` (7F followed by ELF in ASCII)
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

NeoDAX primarily works with sections because they provide finer-grained information. When you run \`./neodax -l\`, you see section names, types, addresses, sizes, and offsets.

## Key Sections

The most important sections in a typical ELF executable:

\`.text\` contains executable machine code. This is where you spend most of your analysis time.

\`.rodata\` contains read-only data: string literals, constant tables, and jump tables.

\`.data\` contains initialized writable data: global variables with non-zero initial values.

\`.bss\` contains uninitialized writable data. It takes no space in the file but is zeroed in memory at load time.

\`.symtab\` contains the full symbol table with all function and variable names. Stripped binaries do not have this section.

\`.dynsym\` contains the dynamic symbol table for shared library functions. Even stripped binaries usually have this.

\`.plt\` and \`.got\` handle calls to shared library functions through indirection.

## PIE and ASLR

A Position Independent Executable (PIE) can be loaded at any address in memory. The OS chooses a random base address each time the program runs. This is called ASLR (Address Space Layout Randomization) and makes exploitation harder.

NeoDAX detects and reports whether a binary is PIE.

When a binary is PIE, the addresses in the disassembly output are the file-relative (pre-ASLR) addresses, not runtime addresses.

## Stripped vs Unstripped

An unstripped binary has a \`.symtab\` section containing the names of all functions and variables. This makes analysis much easier because you can see \`malloc\`, \`encrypt_key\`, or \`check_password\` instead of \`sub_401234\`.

A stripped binary has had its symbol table removed with the \`strip\` command. You still have the dynamic symbols (functions called from shared libraries) but lose all internal function names.

NeoDAX reports whether a binary is stripped and uses whatever symbols are available.

## Practice

\`\`\`bash
./neodax -l /bin/ls
\`\`\`

Identify:
1. Which section contains the executable code (.text).
2. Which section is largest.
3. Whether the binary is PIE (look for "PIE" in the output header).
4. Whether the binary is stripped.

## Next

Continue to \`05_understanding_pe_format.md\`.
`
  },
  {
    id: "05_understanding_pe_format",
    num: 5,
    level: 0,
    title: "Understanding PE Format",
    prereq: "04_understanding_elf_format.md",
    learn: "The structure of Windows PE files and how they differ from ELF.",
    level_label: "0 - Foundation",
    content: `# Understanding PE Format

**Level:** 0 - Foundation
**Prerequisites:** 04_understanding_elf_format.md
**What You Will Learn:** The structure of Windows PE files and how they differ from ELF.

## What PE Is

PE stands for Portable Executable. It is the binary format used on Windows for executables (.exe) and dynamic libraries (.dll). PE is based on the older COFF format from the DEC VAX era.

PE files are identified by the bytes \`4d 5a\` at the start, which spells "MZ" in ASCII. These are the initials of Mark Zbykowski, who designed the original DOS EXE format that PE extends.

## PE Structure

A PE file has several layers:

**DOS header:** The first 64 bytes, starting with MZ. Contains a pointer to the PE header. Also contains a tiny DOS stub program that prints "This program cannot be run in DOS mode" if someone tries to run the program under DOS.

**PE header:** Contains the PE signature \`50 45 00 00\` (PE followed by two null bytes), the machine type, number of sections, and timestamps.

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

PE files use an import table to declare which functions they need from DLLs. For example, a program calling \`MessageBoxA\` from \`user32.dll\` has an import entry for it.

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

\`\`\`bash
./neodax -l yourfile.exe
./neodax -y yourfile.dll
\`\`\`

If not, look at the PE import table of any Windows executable using NeoDAX. Notice which DLL names appear and what functions are imported.

## Next

Continue to \`06_understanding_macho_format.md\`.
`
  },
  {
    id: "06_understanding_macho_format",
    num: 6,
    level: 0,
    title: "Understanding Mach-O Format",
    prereq: "05_understanding_pe_format.md",
    learn: "The structure of macOS Mach-O files, including FAT universal binaries.",
    level_label: "0 - Foundation",
    content: `# Understanding Mach-O Format

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

\`__TEXT\` is the read-execute segment. It contains:
- \`__TEXT,__text\`: Compiled machine code
- \`__TEXT,__stubs\`: PLT-equivalent stubs for external functions
- \`__TEXT,__cstring\`: String literals

\`__DATA\` is the read-write segment. It contains:
- \`__DATA,__data\`: Initialized global variables
- \`__DATA,__bss\`: Uninitialized global variables
- \`__DATA,__got\`: Global offset table
- \`__DATA,__la_symbol_ptr\`: Lazy symbol pointers

NeoDAX strips the double underscores and reports sections as \`.text\`, \`.data\`, \`.cstring\`, and so on, making them consistent with ELF naming.

## Load Commands Relevant to Analysis

\`LC_MAIN\` specifies the entry point as an offset from the start of the \`__TEXT\` segment. NeoDAX reads this to determine the entry point address.

\`LC_SYMTAB\` points to the symbol table. NeoDAX reads \`nlist_64\` entries from this table to get function names. macOS follows a convention where C symbol names have a leading underscore: \`_main\`, \`_printf\`. NeoDAX strips this underscore automatically.

\`LC_DYLD_INFO\` and \`LC_DYLD_EXPORTS_TRIE\` describe imports and exports for shared libraries. NeoDAX does not currently parse these, but they are relevant for advanced analysis.

## Practice

On macOS:

\`\`\`bash
./neodax -l /bin/ls
\`\`\`

Look for the \`__text\` section (displayed as \`.text\`) and note its address. On Apple Silicon, addresses typically start around \`0x100000000\` for executables.

Try the debug endpoint to see how NeoDAX resolves a FAT binary:

\`\`\`bash
./neodax -l /usr/bin/file
\`\`\`

Note whether the binary is reported as PIE. Most modern macOS executables are PIE.

## Next

Continue to \`07_binary_formats_comparison.md\`.
`
  },
  {
    id: "07_binary_formats_comparison",
    num: 7,
    level: 0,
    title: "Binary Formats Comparison",
    prereq: "06_understanding_macho_format.md",
    learn: "Side-by-side comparison of ELF, PE, and Mach-O to solidify your understanding.",
    level_label: "0 - Foundation",
    content: `# Binary Formats Comparison

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

**Mach-O:** For 64-bit executables, the \`__TEXT\` segment is typically loaded at address 0x100000000. Addresses in the file are absolute and the OS maps the binary at that address unless ASLR shifts it.

When NeoDAX reports addresses, it uses the in-file virtual addresses. On PIE or ASLR-enabled binaries, runtime addresses differ.

## Section Names Across Formats

NeoDAX normalizes section names across formats. When you see \`.text\`, it refers to the code section regardless of whether the file is ELF, PE, or Mach-O (where it is actually \`__TEXT,__text\`).

This normalization means analysis scripts and habits transfer across platforms.

## How Detection Works

NeoDAX reads the first 4 bytes of any file and compares them against known magic values:

1. \`7F 45 4C 46\` -> ELF
2. \`4D 5A\` (as first 2 bytes) -> PE
3. \`CF FA ED FE\`, \`CE FA ED FE\`, \`FE ED FA CF\`, \`FE ED FA CE\`, \`CA FE BA BE\` -> Mach-O

If none match, the file is treated as a raw binary. You can still disassemble raw binaries by specifying a start address and architecture.

## Common Confusion Points

**"Where does execution start?"**
- ELF: the \`e_entry\` field in the ELF header
- PE: \`AddressOfEntryPoint\` in the optional header (plus image base)
- Mach-O: \`LC_MAIN\` load command's \`entryoff\` field plus the \`__TEXT\` segment base

**"What are these symbols?"**
- ELF: \`.symtab\` for internal symbols, \`.dynsym\` for shared library symbols
- PE: the export directory for exported symbols, no internal symbol table in stripped binaries
- Mach-O: \`LC_SYMTAB\` for all symbols, with underscore prefix convention

**"Why are addresses different on different machines?"**
PIE executables are relocated by the OS at load time. The addresses NeoDAX shows are the pre-relocation addresses from the file.

## Practice

Analyze the same binary on different platforms if possible, or compare two binaries of different formats:

1. Run \`./neodax -l\` on an ELF file and a PE file.
2. Note the section names and whether they follow the same pattern.
3. Find the entry point in both and compare the addresses.

## Next

You have completed Level 0 - Foundation. Continue to \`10_cli_basics.md\` to begin Level 1.
`
  },
  {
    id: "10_cli_basics",
    num: 10,
    level: 1,
    title: "CLI Basics",
    prereq: "07_binary_formats_comparison.md",
    learn: "The complete set of NeoDAX command-line flags and how to combine them.",
    level_label: "1 - Basic Analysis",
    content: `# CLI Basics

**Level:** 1 - Basic Analysis
**Prerequisites:** 07_binary_formats_comparison.md
**What You Will Learn:** The complete set of NeoDAX command-line flags and how to combine them.

## Running NeoDAX

The basic syntax is:

\`\`\`
./neodax [flags] <binary>
\`\`\`

Without flags, NeoDAX disassembles the \`.text\` section of the binary.

## Essential Flags

### -l: List Sections

\`\`\`bash
./neodax -l /bin/ls
\`\`\`

Shows all sections with name, type, virtual address, size, and file offset. Always start here to understand the binary's layout.

### -y: Show Symbols

\`\`\`bash
./neodax -y /bin/ls
\`\`\`

Lists all symbols with their addresses. On stripped binaries, only dynamic symbols (imported functions) appear.

### -f: Detect Functions

\`\`\`bash
./neodax -f /bin/ls
\`\`\`

Runs the function detector and lists detected functions with start address, end address, size, and instruction count.

### -t: Extract Strings

\`\`\`bash
./neodax -t /bin/ls
\`\`\`

Extracts printable ASCII strings and annotates them inline in the disassembly.

### -r: Cross-References

\`\`\`bash
./neodax -r /bin/ls
\`\`\`

Builds a cross-reference table showing which addresses call or branch to which targets.

### -C: Control Flow Graph

\`\`\`bash
./neodax -C /bin/ls
\`\`\`

Builds and prints the CFG for each detected function.

## Targeting Specific Areas

### -s: Target a Specific Section

\`\`\`bash
./neodax -s .rodata /bin/ls
\`\`\`

Disassembles only the specified section instead of the default \`.text\`.

### -A and -E: Address Range

\`\`\`bash
./neodax -A 0x401000 -E 0x401200 /bin/ls
\`\`\`

Disassembles only the bytes between two virtual addresses. Useful when you know which function you want to examine.

### -S: All Sections

\`\`\`bash
./neodax -S /bin/ls
\`\`\`

Disassembles all executable sections, not just \`.text\`. Useful when code is spread across multiple sections.

## Output Modifiers

### -n: No Color

\`\`\`bash
./neodax -n /bin/ls
\`\`\`

Disables ANSI color codes. Use this when piping output to a file or another tool.

### -a: Show Raw Bytes

\`\`\`bash
./neodax -a /bin/ls
\`\`\`

Shows the hex bytes alongside the disassembly.

### -v: Verbose

\`\`\`bash
./neodax -v /bin/ls
\`\`\`

Shows additional information about the analysis process.

### -d: Demangle C++ Names

\`\`\`bash
./neodax -d /path/to/cpp_binary
\`\`\`

Runs Itanium ABI demangling on C++ symbol names, turning \`_ZN3foo3barEv\` into \`foo::bar()\`.

## Combining Flags

Flags can be combined freely:

\`\`\`bash
./neodax -f -r -t /bin/ls
\`\`\`

This detects functions, builds xrefs, and extracts strings in one pass.

The \`-x\` flag is a shorthand for all standard analysis flags combined:

\`\`\`bash
./neodax -x /bin/ls
\`\`\`

The \`-X\` flag includes everything, including the advanced analysis features:

\`\`\`bash
./neodax -X /bin/ls
\`\`\`

## Saving Output

Pipe the output to a file for later reading:

\`\`\`bash
./neodax -n -x /bin/ls > analysis.txt
\`\`\`

Use \`-n\` (no color) when saving to a file to avoid embedding ANSI escape codes.

## DAXC Snapshots

You can save an analysis snapshot to a \`.daxc\` file and reload it later:

\`\`\`bash
./neodax -x -o snapshot.daxc /bin/ls
./neodax -c snapshot.daxc
\`\`\`

The snapshot preserves all analysis results so you do not need to reanalyze the binary each time.

## Practice

1. Run \`./neodax -h\` and read every flag description.
2. Run \`./neodax -l -y /bin/ls\` to see sections and symbols together.
3. Run \`./neodax -f /bin/ls\` and count the detected functions.
4. Run \`./neodax -n -x /bin/ls > /tmp/ls_analysis.txt\` and open the file.

## Next

Continue to \`11_reading_sections.md\`.
`
  },
  {
    id: "11_reading_sections",
    num: 11,
    level: 1,
    title: "Reading Sections",
    prereq: "10_cli_basics.md",
    learn: "How to read and interpret section listing output in detail.",
    level_label: "1 - Basic Analysis",
    content: `# Reading Sections

**Level:** 1 - Basic Analysis
**Prerequisites:** 10_cli_basics.md
**What You Will Learn:** How to read and interpret section listing output in detail.

## The Section Listing

Run:

\`\`\`bash
./neodax -l /bin/ls
\`\`\`

Each line in the output represents one section. A typical ELF output looks like:

\`\`\`
.text      code    0x401000  size 0x1234  offset 0x1000  insns 892
.rodata    rodata  0x402234  size 0x0200  offset 0x2234
.data      data    0x404000  size 0x0050  offset 0x4000
.bss       bss     0x404050  size 0x0100  offset 0x0000
.plt       plt     0x400800  size 0x00a0  offset 0x0800
.got       got     0x403000  size 0x0030  offset 0x3000
\`\`\`

## Section Fields

**Name:** The section identifier. Standard names follow conventions but custom sections can have any name.

**Type:** NeoDAX classifies each section:
- \`code\`: executable machine code
- \`data\`: readable and writable data
- \`rodata\`: read-only data
- \`bss\`: uninitialized data (zero-filled at load time)
- \`plt\`: procedure linkage table (code stubs for external calls)
- \`got\`: global offset table (pointers resolved at load time)
- \`other\`: anything that does not fit a known category

**Virtual address:** Where the section is mapped in memory. This is what you see in disassembly output.

**Size:** How many bytes the section occupies. BSS sections have a size but no file content because they are zero-initialized.

**Offset:** Where the section's data starts in the file. For BSS, this is 0 because there is no data in the file.

**Insns:** For code sections, NeoDAX counts the number of instructions during parsing.

## What Section Layout Tells You

A normal Linux executable typically has:

- One \`.text\` section with the bulk of the code
- One \`.plt\` section for external function calls
- One \`.rodata\` section with string literals and constants
- One \`.data\` section with initialized globals
- One \`.bss\` section with uninitialized globals

When a binary deviates from this pattern, it is worth investigating why.

A binary with many unusually named sections may be packed or have custom build tooling.

A binary with a very large \`.text\` section relative to its apparent functionality may have inlined a lot of library code or be statically linked.

A binary with a large \`.rodata\` section may contain embedded data files, certificates, or resource tables.

## Identifying Code vs Data

NeoDAX marks sections as \`code\` based on the executable flag in the section header. Only sections marked executable should contain instructions. If you see disassembly output in a section marked \`data\`, that is suspicious and may indicate obfuscation or position-independent shellcode.

## Section Sizes and Entropy

High-entropy sections are often compressed or encrypted. A \`.text\` section with entropy close to 8.0 (the maximum for random data) is likely packed. You will learn how to measure entropy in Level 4.

For now, pay attention to section sizes relative to what you expect. A 50KB executable that claims to have a 40KB \`.text\` section but a 5KB \`.rodata\` is normal. But a 50KB executable with a 48KB section of unknown type and no visible strings is suspicious.

## Practice

1. List sections of several binaries on your system.
2. Find a binary with a \`.plt\` section. Note its size relative to \`.text\`.
3. Find a binary that is statically linked (no \`.plt\` section). Try \`/bin/busybox\` if available.
4. Look at the offset column and verify that sections appear in the order they are listed.

## Next

Continue to \`12_symbols_and_names.md\`.
`
  },
  {
    id: "12_symbols_and_names",
    num: 12,
    level: 1,
    title: "Symbols and Names",
    prereq: "11_reading_sections.md",
    learn: "What symbols are, how to read them, and what to do when they are absent.",
    level_label: "1 - Basic Analysis",
    content: `# Symbols and Names

**Level:** 1 - Basic Analysis
**Prerequisites:** 11_reading_sections.md
**What You Will Learn:** What symbols are, how to read them, and what to do when they are absent.

## What Symbols Are

A symbol is a named address. Every function and global variable in a compiled program has a symbol: a name associated with its starting address.

Symbols are stored in symbol tables within the binary. Two tables are relevant:

\`.symtab\` contains all symbols: internal functions, local variables, static functions, and global functions. This table exists in development builds but is usually removed when shipping software.

\`.dynsym\` contains only the symbols needed for dynamic linking: functions the binary imports from shared libraries and functions it exports for others to use. This table cannot be fully removed without breaking the binary, so it survives stripping.

## Reading Symbol Output

\`\`\`bash
./neodax -y /bin/ls
\`\`\`

Output looks like:

\`\`\`
0x401234  func    main
0x401300  func    process_file
0x401500  func    printf@plt
0x401510  func    malloc@plt
0x404020  object  optarg
\`\`\`

Each line shows the address, type, and name.

The \`@plt\` suffix means the symbol is a PLT stub for an imported function. When the binary calls \`printf\`, it actually calls the PLT stub, which in turn calls the real \`printf\` from libc.

## Symbol Types

NeoDAX reports two main symbol types:

\`func\`: A function symbol. Points to the start of executable code.

\`object\`: A data symbol. Points to a variable or data structure.

## Working with Stripped Binaries

When a binary is stripped, \`.symtab\` is gone. You lose all internal function names. What remains:

1. PLT stubs for imported functions (these have names).
2. Exported symbols if the binary is a shared library.
3. Names that NeoDAX reconstructs from heuristics, labeled \`sub_<address>\`.

For a stripped binary, \`./neodax -y /bin/ls\` may show only a few dozen PLT entries while reporting hundreds of detected functions.

## Using Symbol Context During Analysis

Even partial symbols provide useful context. If you see:

\`\`\`
call   0x401510  ; malloc@plt
\`\`\`

You know that this call allocates memory. If you then see:

\`\`\`
call   0x401560  ; memcpy@plt
\`\`\`

You can infer data is being copied into the newly allocated buffer. Following the PLT names gives you a rough narrative even without internal names.

## C++ Symbols

C++ compilers mangle symbol names to encode type information. A function like \`MyClass::process(int, char*)\` becomes something like \`_ZN7MyClass7processEic\`.

Use the \`-d\` flag to demangle these names:

\`\`\`bash
./neodax -d -y /path/to/cpp_binary
\`\`\`

NeoDAX implements the Itanium ABI demangling algorithm and expands mangled names into readable forms.

## Practice

1. Run \`./neodax -y /bin/ls\` and count the PLT symbols.
2. Find at least three PLT symbols that give you clues about what \`ls\` does (hint: look for \`opendir\`, \`readdir\`, \`stat\`).
3. If you have an unstripped binary available (compile a simple C program without \`-s\`), compare the symbol count before and after stripping.
4. Run \`./neodax -d -y /path/to/a/cpp_binary\` if you have one available.

## Next

Continue to \`13_reading_disassembly.md\`.
`
  },
  {
    id: "13_reading_disassembly",
    num: 13,
    level: 1,
    title: "Reading Disassembly",
    prereq: "12_symbols_and_names.md",
    learn: "How to read NeoDAX disassembly output and understand instruction-level information.",
    level_label: "1 - Basic Analysis",
    content: `# Reading Disassembly

**Level:** 1 - Basic Analysis
**Prerequisites:** 12_symbols_and_names.md
**What You Will Learn:** How to read NeoDAX disassembly output and understand instruction-level information.

## Basic Disassembly Output

Running NeoDAX without flags disassembles the \`.text\` section:

\`\`\`bash
./neodax /bin/ls
\`\`\`

Each line of disassembly shows:

\`\`\`
0x401000  push   rbp
0x401001  mov    rbp, rsp
0x401004  sub    rsp, 0x40
0x401008  mov    QWORD PTR [rbp-0x8], rdi
\`\`\`

The address column shows the virtual address where this instruction lives in memory.

The mnemonic is the instruction name: \`push\`, \`mov\`, \`sub\`, \`call\`, \`ret\`.

The operands describe what the instruction operates on.

## Adding Context with Flags

### Bytes

\`\`\`bash
./neodax -a /bin/ls
\`\`\`

Adds the raw hex bytes:

\`\`\`
0x401000  55              push   rbp
0x401001  48 89 e5        mov    rbp, rsp
0x401004  48 83 ec 40     sub    rsp, 0x40
\`\`\`

This is useful when you need to verify encoding or identify specific byte patterns.

### Symbols and Strings

\`\`\`bash
./neodax -y -t /bin/ls
\`\`\`

Annotates call targets with symbol names and string references:

\`\`\`
0x40120a  call   0x401510  ; malloc@plt
0x401230  lea    rdi, [0x402100]  ; "Hello, World"
0x401237  call   0x401520  ; printf@plt
\`\`\`

This makes the disassembly much more readable.

## Instruction Groups

\`\`\`bash
./neodax -g /bin/ls
\`\`\`

Instruction groups color-code instructions by category:

- **call**: Function calls
- **branch**: Conditional and unconditional jumps
- **ret**: Return instructions
- **stack**: Push, pop, and stack pointer manipulation
- **syscall**: System call instructions
- **arithmetic**: Math operations
- **data-move**: Data movement instructions

When output is in color, each group has a different color. In text mode, the group names appear as annotations.

## Finding Specific Addresses

Use \`-A\` and \`-E\` to focus on a known address range:

\`\`\`bash
./neodax -A 0x401000 -E 0x4010f0 /bin/ls
\`\`\`

Use \`-A\` alone to start at a specific address and disassemble until the end of the section:

\`\`\`bash
./neodax -A 0x401234 /bin/ls
\`\`\`

## Reading the Instruction Stream

When reading disassembly, pay attention to patterns:

A function prologue (setup) typically begins with saving registers and allocating stack space:
\`\`\`
push   rbp
mov    rbp, rsp
sub    rsp, 0x40
\`\`\`

A function epilogue (teardown) restores registers and returns:
\`\`\`
mov    rsp, rbp
pop    rbp
ret
\`\`\`

Calls to external functions appear as \`call <address>\` with the PLT symbol annotated.

Branches change the flow of execution. An unconditional \`jmp\` always transfers control. A conditional \`je\` (jump if equal) only transfers control if the zero flag is set.

## Practice

1. Disassemble \`/bin/ls\` and find the first \`call\` instruction.
2. What function is being called? Use \`-y\` flag to get symbol annotations.
3. Find a \`ret\` instruction. What is the address of the instruction immediately before it?
4. Use \`-g\` to enable instruction groups and identify a block of arithmetic instructions.

## Next

Continue to \`14_x86_64_primer.md\`.
`
  },
  {
    id: "14_x86_64_primer",
    num: 14,
    level: 1,
    title: "x86-64 Primer",
    prereq: "13_reading_disassembly.md",
    learn: "Enough x86-64 assembly to read NeoDAX disassembly output for common programs.",
    level_label: "1 - Basic Analysis",
    content: `# x86-64 Primer

**Level:** 1 - Basic Analysis
**Prerequisites:** 13_reading_disassembly.md
**What You Will Learn:** Enough x86-64 assembly to read NeoDAX disassembly output for common programs.

## Registers

x86-64 has 16 general-purpose 64-bit registers:

\`\`\`
rax  rbx  rcx  rdx
rsi  rdi  rbp  rsp
r8   r9   r10  r11
r12  r13  r14  r15
\`\`\`

Each register can be accessed at different widths:
- \`rax\`: 64-bit
- \`eax\`: lower 32 bits
- \`ax\`: lower 16 bits
- \`al\`: lower 8 bits, \`ah\`: bits 8-15

## Calling Conventions

On Linux (System V AMD64 ABI), function arguments are passed in registers in this order:

\`\`\`
rdi  rsi  rdx  rcx  r8  r9
\`\`\`

Additional arguments go on the stack. The return value goes in \`rax\`.

On Windows (Microsoft x64), the order is:

\`\`\`
rcx  rdx  r8  r9
\`\`\`

When you see \`mov rdi, <value>\` followed by \`call <function>\`, that value is the first argument to the function.

## Common Instructions

**Data movement:**
\`\`\`
mov  rax, rbx        ; copy rbx into rax
mov  rax, [rbp-8]    ; load 8 bytes from memory at rbp-8
mov  [rbp-8], rax    ; store rax to memory at rbp-8
lea  rax, [rbp-8]    ; load the address rbp-8 (not the value)
push rbx             ; push rbx onto stack, decrement rsp by 8
pop  rbx             ; pop from stack into rbx, increment rsp by 8
\`\`\`

**Arithmetic:**
\`\`\`
add  rax, rbx        ; rax = rax + rbx
sub  rax, 8          ; rax = rax - 8
imul rax, rbx        ; rax = rax * rbx (signed)
xor  rax, rax        ; rax = 0 (common idiom to zero a register)
and  rax, 0xff       ; isolate lower 8 bits
or   rax, rbx        ; bitwise or
shl  rax, 2          ; shift left by 2 (multiply by 4)
shr  rax, 1          ; shift right by 1 (divide by 2)
\`\`\`

**Comparison and branching:**
\`\`\`
cmp  rax, 0         ; set flags based on rax - 0
test rax, rax       ; set flags based on rax & rax (checks if zero)
je   0x401200       ; jump if equal (zero flag set)
jne  0x401200       ; jump if not equal
jg   0x401200       ; jump if greater (signed)
jl   0x401200       ; jump if less (signed)
ja   0x401200       ; jump if above (unsigned)
jmp  0x401200       ; unconditional jump
\`\`\`

**Function calls:**
\`\`\`
call 0x401234       ; push rip, jump to 0x401234
ret                 ; pop rip and jump to it
\`\`\`

## Reading a Simple Function

Given this disassembly:

\`\`\`
0x401000  push   rbp
0x401001  mov    rbp, rsp
0x401004  mov    DWORD PTR [rbp-4], edi   ; save first arg (int)
0x401007  cmp    DWORD PTR [rbp-4], 0     ; compare arg to 0
0x40100b  jle    0x401015                  ; jump if <= 0
0x40100d  mov    eax, 1                    ; return 1
0x401012  pop    rbp
0x401013  ret
0x401015  mov    eax, 0                    ; return 0
0x40101a  pop    rbp
0x40101b  ret
\`\`\`

This function takes one integer argument, returns 1 if it is positive, and 0 otherwise.

## Stack Frame Layout

The stack grows downward. \`rsp\` points to the top of the stack (lowest address). Local variables live below \`rbp\`:

\`\`\`
[rbp-4]   : 4-byte local variable
[rbp-8]   : another 4-byte local variable
[rbp-16]  : 8-byte local variable or pointer
[rbp+8]   : return address (caller pushed it with call)
[rbp+16]  : first argument if passed on stack
\`\`\`

## Practice

1. Disassemble \`/bin/ls\` and find a function that calls \`malloc\`.
2. What argument is passed to \`malloc\` (look at \`rdi\` value before the call)?
3. Find a conditional jump. What is the comparison being made?
4. Identify the prologue and epilogue of any function.

## Next

Continue to \`15_arm64_primer.md\`.
`
  },
  {
    id: "15_arm64_primer",
    num: 15,
    level: 1,
    title: "ARM64 Primer",
    prereq: "14_x86_64_primer.md",
    learn: "Enough ARM64 assembly to read NeoDAX disassembly for Android and Apple Silicon binaries.",
    level_label: "1 - Basic Analysis",
    content: `# ARM64 Primer

**Level:** 1 - Basic Analysis
**Prerequisites:** 14_x86_64_primer.md
**What You Will Learn:** Enough ARM64 assembly to read NeoDAX disassembly for Android and Apple Silicon binaries.

## Overview

ARM64 (also called AArch64) is the instruction set used by Apple Silicon Macs, iPhones, Android phones, and many embedded systems. It is a RISC architecture: instructions are fixed-width (4 bytes each) and have a more regular structure than x86-64.

## Registers

ARM64 has 31 general-purpose 64-bit registers named x0 through x30, plus a zero register:

\`\`\`
x0  - x7  : function arguments and return values
x8        : indirect result location / syscall number
x9  - x15 : temporary (caller-saved)
x16 - x17 : intra-procedure call scratch
x18       : platform register (do not use on iOS)
x19 - x28 : callee-saved registers
x29 (fp)  : frame pointer
x30 (lr)  : link register (return address)
sp        : stack pointer
xzr       : zero register (reads as 0, writes discarded)
\`\`\`

Each 64-bit x register has a 32-bit alias: \`x0\` contains the full 64 bits, \`w0\` refers to the lower 32 bits.

## Calling Convention

Function arguments go in x0 through x7 in order. The return value goes in x0. If a function returns a 128-bit value, x1 holds the upper 64 bits.

## Common Instructions

**Data movement:**
\`\`\`
mov  x0, x1          ; copy x1 into x0
ldr  x0, [x1]        ; load 8 bytes from memory at x1
ldr  w0, [x1, #4]    ; load 4 bytes from x1+4 into w0
str  x0, [x1]        ; store x0 to memory at x1
adr  x0, label       ; load PC-relative address of label into x0
adrp x0, label@PAGE  ; load page-aligned PC-relative address
add  x0, x0, label@PAGEOFF  ; add page offset (often follows adrp)
\`\`\`

**Arithmetic:**
\`\`\`
add  x0, x1, x2      ; x0 = x1 + x2
sub  x0, x1, x2      ; x0 = x1 - x2
mul  x0, x1, x2      ; x0 = x1 * x2
and  x0, x1, x2      ; x0 = x1 & x2
orr  x0, x1, x2      ; x0 = x1 | x2
eor  x0, x1, x2      ; x0 = x1 ^ x2
lsl  x0, x1, #2      ; x0 = x1 << 2
lsr  x0, x1, #1      ; x0 = x1 >> 1 (logical)
asr  x0, x1, #1      ; x0 = x1 >> 1 (arithmetic)
\`\`\`

**Stack operations:**
\`\`\`
stp  x29, x30, [sp, #-16]!  ; save frame pointer and link register
ldp  x29, x30, [sp], #16    ; restore frame pointer and link register
\`\`\`

The \`!\` means write-back: the address is computed and then written back to the base register. This is the standard ARM64 function prologue.

**Branches:**
\`\`\`
b    label            ; unconditional branch
bl   label            ; branch with link (call: saves return address in x30/lr)
br   x0               ; branch to address in x0
blr  x0               ; branch with link to address in x0 (indirect call)
ret                   ; return: branch to x30 (lr)
cbz  x0, label        ; branch if x0 == 0
cbnz x0, label        ; branch if x0 != 0
\`\`\`

**Comparison:**
\`\`\`
cmp  x0, x1           ; set flags based on x0 - x1
tst  x0, x1           ; set flags based on x0 & x1
b.eq label            ; branch if equal
b.ne label            ; branch if not equal
b.gt label            ; branch if greater (signed)
b.lt label            ; branch if less (signed)
\`\`\`

## Function Prologue and Epilogue

A typical ARM64 function begins with:

\`\`\`
stp  x29, x30, [sp, #-32]!   ; allocate 32 bytes, save fp and lr
mov  x29, sp                  ; set frame pointer
\`\`\`

And ends with:

\`\`\`
ldp  x29, x30, [sp], #32     ; restore fp and lr, deallocate
ret                            ; return to caller
\`\`\`

NeoDAX detects these patterns when identifying function boundaries.

## Pointer Authentication

macOS and iOS use pointer authentication (PA) instructions. You may see:

\`\`\`
paciasp    ; authenticate x30 (lr) using sp
autiasp    ; verify x30 authentication
retaa      ; authenticated return
\`\`\`

These are security features that make it harder to corrupt return addresses. NeoDAX recognizes them during function detection.

## Practice

On an ARM64 system (Apple Silicon Mac or Android with Termux):

1. Disassemble \`/bin/ls\` with NeoDAX.
2. Find the function prologue \`stp x29, x30, [sp, ...]\`.
3. Count how many bytes are allocated on the stack by the first function you see.
4. Find a \`bl\` instruction and identify the callee from symbol annotations.

## Next

Continue to \`16_riscv_primer.md\`.
`
  },
  {
    id: "16_riscv_primer",
    num: 16,
    level: 1,
    title: "RISC-V Primer",
    prereq: "15_arm64_primer.md",
    learn: "Enough RISC-V RV64 assembly to understand NeoDAX output for RISC-V binaries.",
    level_label: "1 - Basic Analysis",
    content: `# RISC-V Primer

**Level:** 1 - Basic Analysis
**Prerequisites:** 15_arm64_primer.md
**What You Will Learn:** Enough RISC-V RV64 assembly to understand NeoDAX output for RISC-V binaries.

## Overview

RISC-V is an open-source instruction set architecture. NeoDAX supports the RV64GC variant: the 64-bit base ISA with standard extensions G (general) and C (compressed 16-bit instructions).

RISC-V is increasingly common in embedded systems, research platforms, and some single-board computers. While you may not encounter it as often as x86-64 or ARM64, understanding its basics rounds out your analysis knowledge.

## Registers

RISC-V has 32 registers named x0 through x31 with conventional aliases:

\`\`\`
x0  (zero) : always reads as 0, writes discarded
x1  (ra)   : return address
x2  (sp)   : stack pointer
x3  (gp)   : global pointer
x4  (tp)   : thread pointer
x5  (t0)   : temporary
x6  (t1)   : temporary
x7  (t2)   : temporary
x8  (s0/fp): saved register / frame pointer
x9  (s1)   : saved register
x10 (a0)   : argument / return value
x11 (a1)   : argument / return value
x12 (a2)   : argument
...
x17 (a7)   : argument / syscall number
x18 (s2) - x27 (s11): saved registers
x28 (t3) - x31 (t6): temporaries
\`\`\`

## Calling Convention

Arguments go in a0 through a7. Return values go in a0 (and a1 for 128-bit returns). The ra register holds the return address.

## Common Instructions

**Data movement:**
\`\`\`
mv   a0, a1           ; copy a1 into a0 (pseudo-instruction for add a0, a1, zero)
li   a0, 42           ; load immediate 42 into a0
la   a0, symbol       ; load address of symbol into a0
lw   a0, 4(a1)        ; load 32-bit word from a1+4
ld   a0, 8(a1)        ; load 64-bit doubleword from a1+8
sw   a0, 4(a1)        ; store 32-bit word to a1+4
sd   a0, 8(a1)        ; store 64-bit doubleword to a1+8
\`\`\`

**Arithmetic:**
\`\`\`
add  a0, a1, a2       ; a0 = a1 + a2
sub  a0, a1, a2       ; a0 = a1 - a2
addi a0, a1, 4        ; a0 = a1 + 4 (immediate add)
mul  a0, a1, a2       ; a0 = a1 * a2
and  a0, a1, a2       ; a0 = a1 & a2
or   a0, a1, a2       ; a0 = a1 | a2
xor  a0, a1, a2       ; a0 = a1 ^ a2
sll  a0, a1, a2       ; a0 = a1 << a2
srl  a0, a1, a2       ; a0 = a1 >> a2 (logical)
sra  a0, a1, a2       ; a0 = a1 >> a2 (arithmetic)
\`\`\`

**Branches:**
\`\`\`
j    label            ; unconditional jump (pseudo for jal zero, label)
jal  ra, label        ; jump and link (call: saves return to ra)
jalr zero, ra, 0      ; return (jump to ra)
beq  a0, a1, label    ; branch if a0 == a1
bne  a0, a1, label    ; branch if a0 != a1
blt  a0, a1, label    ; branch if a0 < a1 (signed)
bge  a0, a1, label    ; branch if a0 >= a1 (signed)
\`\`\`

## Differences from x86-64 and ARM64

RISC-V has no dedicated push/pop instructions. Stack manipulation is done with explicit \`addi sp, sp, -N\` and store/load instructions.

There is no dedicated return instruction. The idiom \`jalr zero, ra, 0\` (sometimes written as \`ret\` by disassemblers) jumps to the address in ra.

RISC-V has no flags register. Comparisons are done with conditional branch instructions directly.

## Practice

If you have a RISC-V binary:

\`\`\`bash
./neodax -l myriscvbinary
./neodax myriscvbinary
\`\`\`

If not, you can cross-compile a small C program using a RISC-V toolchain and analyze the result. The key thing to practice is tracing the calling convention: finding \`li a0, X\` before a \`jal ra, function\` and understanding that X is the first argument.

## Next

Continue to \`17_string_extraction.md\`.
`
  },
  {
    id: "17_string_extraction",
    num: 17,
    level: 1,
    title: "String Extraction",
    prereq: "16_riscv_primer.md",
    learn: "How to extract strings from binaries and use them to understand program behavior.",
    level_label: "1 - Basic Analysis",
    content: `# String Extraction

**Level:** 1 - Basic Analysis
**Prerequisites:** 16_riscv_primer.md
**What You Will Learn:** How to extract strings from binaries and use them to understand program behavior.

## Why Strings Matter

Strings embedded in a binary reveal a lot about what a program does. Error messages, file paths, URLs, command names, cryptographic algorithm names, registry keys, and user-facing text all appear as strings in the binary.

Analyzing strings is often the quickest way to form a hypothesis about a program's purpose before diving into disassembly.

## ASCII String Extraction

\`\`\`bash
./neodax -t /bin/ls
\`\`\`

NeoDAX extracts printable ASCII strings from all sections (not just .rodata). Strings appear as annotations in the disassembly output next to the instructions that reference them.

A string is printed when a \`lea\` or \`mov\` instruction loads its address.

## Unicode String Extraction

\`\`\`bash
./neodax -u /bin/ls
\`\`\`

Modern software often uses UTF-16 (Windows) or UTF-8 (everywhere else) for internationalized strings. NeoDAX's unicode scanner applies a multi-layer filter to reduce false positives:

- Requires at least 4 characters
- Skips code points below U+02FF (avoids treating binary data as text)
- Rejects strings composed entirely of ASCII characters in UTF-16 encoding (these are typically not human-readable text)
- Handles surrogate pairs for characters outside the Basic Multilingual Plane

Run both flags together for complete coverage:

\`\`\`bash
./neodax -t -u /bin/ls
\`\`\`

## Interpreting String Results

When you see a string like \`/etc/passwd\`, you know the program accesses that file. When you see \`OPENSSL_init_ssl\`, you know it uses TLS. When you see \`SELECT * FROM\`, you know it queries a database.

Some strings are less obvious. A long string of random-looking characters might be a base64-encoded payload. A string like \`TVqQAAMAAAA...\` is almost certainly a base64-encoded PE file (the MZ header in base64 starts with "TVq").

## False Positives in Raw Sections

String extraction from \`.text\` (code section) produces false positives. Some byte sequences in code happen to look like printable characters. NeoDAX reports them anyway because a human can filter them.

The most reliable strings come from \`.rodata\` and \`.data\` sections. If a string appears in one of these sections, it is almost certainly intentional.

## Using Strings to Navigate

Strings give you entry points for analysis. Once you find an interesting string, note its address. Then search for code that references that address:

\`\`\`bash
./neodax -r /bin/ls
\`\`\`

The cross-reference output shows which code addresses load each data address. Find the address of your string in the xref table to discover which functions use it.

## Practice

1. Run \`./neodax -t /bin/ls\` and find three strings that tell you something about what \`ls\` does.
2. Find the address of one of those strings in the output.
3. Run \`./neodax -u /bin/ls\` and note how many unicode strings are found (likely zero for \`ls\`).
4. Find a binary with unicode strings on your system (Windows binaries, or macOS system frameworks).

## Next

Continue to \`18_entry_points_and_flow.md\`.
`
  },
  {
    id: "18_entry_points_and_flow",
    num: 18,
    level: 1,
    title: "Entry Points and Execution Flow",
    prereq: "17_string_extraction.md",
    learn: "How to find where a program starts executing and trace its initial flow.",
    level_label: "1 - Basic Analysis",
    content: `# Entry Points and Execution Flow

**Level:** 1 - Basic Analysis
**Prerequisites:** 17_string_extraction.md
**What You Will Learn:** How to find where a program starts executing and trace its initial flow.

## The Entry Point

Every executable has an entry point: the address where execution begins when the OS loads the program.

For ELF executables, the entry point is the \`e_entry\` field in the ELF header. For C programs, this is not \`main\` but rather \`_start\`, a small stub in the C runtime that sets up the environment and then calls \`main\`.

NeoDAX reports the entry point in its analysis overview and you can disassemble from it directly:

\`\`\`bash
./neodax -A 0x401040 /bin/ls   # use the reported entry point address
\`\`\`

## The C Runtime Startup

On Linux with glibc, the execution flow from entry point to \`main\` looks like:

1. \`_start\`: Receives argc, argv, and envp from the OS. Calls \`__libc_start_main\`.
2. \`__libc_start_main\`: Initializes glibc, calls constructors, then calls \`main\`.
3. \`main\`: Your program's entry point.

On stripped binaries you will not see these names, but you can identify \`_start\` by its characteristic pattern: loading argc and argv from the stack, then calling an external function (which is \`__libc_start_main\`).

## Finding main on Stripped Binaries

On x86-64 Linux, \`_start\` passes the address of \`main\` as the first argument to \`__libc_start_main\`. Look for:

\`\`\`
lea    rdi, [0x401234]    ; address of main
...
call   __libc_start_main@plt
\`\`\`

The address loaded into \`rdi\` is \`main\`. On ARM64 the same pattern uses \`x0\` instead of \`rdi\`.

## Constructors and Destructors

ELF binaries can have constructor functions that run before \`main\` and destructor functions that run after \`main\` returns. These are listed in the \`.init_array\` and \`.fini_array\` sections.

Malware sometimes hides initialization code in constructors to complicate analysis.

## Tracing from Entry to main

A useful exercise is to trace execution from the entry point to \`main\` manually:

1. Start at the entry point.
2. Follow the first \`call\` instruction.
3. In the called function, look for another function address being loaded.
4. That address is likely \`main\`.

This teaches you to read execution flow even when symbol names are absent.

## Practice

1. Find the entry point of \`/bin/ls\` from NeoDAX output.
2. Disassemble from the entry point with \`./neodax -A <entry_point> /bin/ls\`.
3. Trace the first few calls manually.
4. Identify which address represents \`main\` (the function that actually implements the program logic).

## Next

You have completed Level 1 - Basic Analysis. Continue to \`20_functions_detection.md\` to begin Level 2.
`
  },
  {
    id: "20_functions_detection",
    num: 20,
    level: 2,
    title: "Function Detection",
    prereq: "18_entry_points_and_flow.md",
    learn: "How NeoDAX detects functions and what the results tell you.",
    level_label: "2 - Intermediate Analysis",
    content: `# Function Detection

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 18_entry_points_and_flow.md
**What You Will Learn:** How NeoDAX detects functions and what the results tell you.

## Why Function Detection Matters

Functions are the unit of analysis in reverse engineering. When you understand what each function does, you understand the program. Everything else: CFGs, xrefs, decompilation, is built on top of function boundaries.

## How NeoDAX Detects Functions

NeoDAX uses two strategies in combination:

**Symbol-guided detection:** If the binary has symbols, every symbol of type \`func\` becomes a known function boundary. This is reliable and gives function names.

**Heuristic detection:** For stripped binaries, NeoDAX scans the code sections looking for function prologue patterns:

For x86-64:
- \`push rbp\` followed by \`mov rbp, rsp\`
- \`sub rsp, N\` (stack allocation)
- \`endbr64\` (Intel CET)

For ARM64:
- \`stp x29, x30, [sp, #-N]!\` (frame pointer and link register save)
- \`sub sp, sp, #N\` (stack allocation without frame pointer)
- \`paciasp\` (pointer authentication)
- \`bti c\` or \`bti j\` (branch target identification)

Both strategies run together. On unstripped binaries, symbols give names and heuristics catch any functions that lack symbols.

## Running Function Detection

\`\`\`bash
./neodax -f /bin/ls
\`\`\`

Output looks like:

\`\`\`
sub_401000  [0x401000 .. 0x40106c]  108 bytes  27 insns
main        [0x401070 .. 0x401200]  400 bytes  95 insns  [calls] [loops]
sub_401210  [0x401210 .. 0x401240]  48 bytes   12 insns
\`\`\`

Each line shows:
- Function name (or \`sub_<address>\` for unnamed functions)
- Address range
- Size in bytes
- Instruction count
- Flags: \`[calls]\` if the function calls other functions, \`[loops]\` if loops are detected

## Function Boundaries

A function boundary has a start address and an end address. The end is where execution leaves the function.

NeoDAX sets the end address at the last \`ret\` (or equivalent) instruction. If a function uses tail calls (\`jmp\` to another function), the end is set at the tail call.

For functions where the end cannot be determined (some compiler-generated stubs or obfuscated code), the end address equals the start address, indicating an unknown boundary.

## Hottest Functions

\`\`\`bash
./neodax -f -r /bin/ls
\`\`\`

After building cross-references, NeoDAX can identify the most-called functions:

\`\`\`bash
./neodax -f -r -v /bin/ls
\`\`\`

Functions that are called many times are candidates for performance-critical routines, common utilities, or important dispatch points.

## Practice

1. Run \`./neodax -f /bin/ls\` and count the total number of detected functions.
2. Find the largest function by byte count.
3. Find a function with both \`[calls]\` and \`[loops]\` flags.
4. Compile a small C program with two or three functions and verify that NeoDAX detects them all.

## Next

Continue to \`21_cross_references.md\`.
`
  },
  {
    id: "21_cross_references",
    num: 21,
    level: 2,
    title: "Cross References",
    prereq: "20_functions_detection.md",
    learn: "How to build and interpret cross-references to understand program structure.",
    level_label: "2 - Intermediate Analysis",
    content: `# Cross References

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 20_functions_detection.md
**What You Will Learn:** How to build and interpret cross-references to understand program structure.

## What Cross References Are

A cross-reference (xref) records a relationship between two addresses: from where a reference is made and to where it points.

There are two types:

**Call xrefs:** One function calls another. \`0x401200 calls 0x401500\` means there is a \`call 0x401500\` instruction at address \`0x401200\`.

**Branch xrefs:** A conditional or unconditional jump. \`0x401234 branches to 0x401260\` means a \`jmp\` or \`je\` instruction at \`0x401234\` targets \`0x401260\`.

## Building Cross References

\`\`\`bash
./neodax -r /bin/ls
\`\`\`

The output lists all detected xrefs. The list can be long for a real binary.

## What Cross References Tell You

**Who calls a function?** If you find a function that does something interesting, the call xrefs to it tell you which other functions invoke it. This reveals how the interesting function fits into the larger program.

**What does a function call?** The call xrefs from a function tell you what it depends on. A function that calls \`malloc\`, \`memcpy\`, and \`free\` is probably managing a buffer.

**Data references:** Xrefs to data addresses (strings, tables, constants) show you which functions use specific data.

## Xref Depth

The xref graph has depth. If function A calls function B which calls function C, then A indirectly depends on C. Tracing these chains reveals the call hierarchy of the program.

At the top of the hierarchy are high-level operations. At the bottom are primitive operations like memory allocation, string operations, and system calls.

## Cross References and Strings

A particularly useful technique: find an interesting string, note its address, then look up which functions reference that address in the xref table.

For example, if a binary contains the string \`"password incorrect"\` at address \`0x402100\`, searching the xrefs for references to \`0x402100\` tells you which function handles password checking.

## Practice

1. Run \`./neodax -r /bin/ls\` and find a function that is called by many others.
2. Find the function that calls the most other functions.
3. Identify at least one string reference xref (a branch or load that targets a data address rather than a code address).

## Next

Continue to \`22_control_flow_graphs.md\`.
`
  },
  {
    id: "22_control_flow_graphs",
    num: 22,
    level: 2,
    title: "Control Flow Graphs",
    prereq: "21_cross_references.md",
    learn: "What CFGs are, how NeoDAX builds them, and how to read them.",
    level_label: "2 - Intermediate Analysis",
    content: `# Control Flow Graphs

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 21_cross_references.md
**What You Will Learn:** What CFGs are, how NeoDAX builds them, and how to read them.

## What a Control Flow Graph Is

A control flow graph (CFG) represents all possible execution paths through a function. Each node in the graph is a basic block: a sequence of instructions with one entry point and one exit point. Edges connect blocks according to possible control transfers.

A basic block ends when execution must leave it:
- A conditional branch creates two edges (taken and not taken)
- An unconditional jump creates one edge
- A \`ret\` creates no outgoing edges (function exit)

## Why CFGs Matter

Reading code linearly as a sequence of instructions gives you a flat view. The CFG gives you the structure. You can see:

- Which conditions lead to which code paths
- Which code is unreachable
- How loops are formed (back edges that go to an earlier block)
- How switch statements fan out

Understanding the CFG of a function is often required before you can reliably understand what the function does.

## Building CFGs in NeoDAX

\`\`\`bash
./neodax -C /bin/ls
\`\`\`

NeoDAX builds and prints the CFG for each detected function.

Output looks like:

\`\`\`
Function main [0x401070 .. 0x401200]

Block 0x401070 [entry]
  0x401070  push   rbp
  0x401071  mov    rbp, rsp
  0x401074  sub    rsp, 0x40
  -> block 0x401078

Block 0x401078
  0x401078  cmp    edi, 1
  0x40107b  jle    0x4010c0
  -> block 0x40107f (fall-through)
  -> block 0x4010c0 (conditional)

Block 0x40107f
  ...
\`\`\`

Each block shows its start address, the instructions it contains, and the outgoing edges.

## The Two-Pass Algorithm

NeoDAX builds CFGs using a two-pass algorithm that correctly handles a challenge called the "jump trick."

In some binaries (especially obfuscated ones), unconditional jumps are used to mislead disassemblers. For example:

\`\`\`
jmp  0x401010
db   0xff      ; dead byte that looks like an instruction prefix
0x401010:
mov  eax, 0
\`\`\`

A naive disassembler would try to decode the \`0xff\` byte as an instruction. NeoDAX's first pass registers all branch targets. In the second pass, it skips dead bytes after unconditional branches and resumes at the next known target.

This means NeoDAX's CFGs are more accurate than single-pass disassemblers.

## Reading a CFG

When looking at a function's CFG:

1. Find the entry block (marked \`[entry]\`).
2. Trace each path forward.
3. When you encounter a conditional branch, trace both paths.
4. Note where paths rejoin (a block with multiple incoming edges is a join point).
5. Note where back edges create loops.

The structure of the CFG often reveals the algorithm more clearly than reading the linear instruction sequence.

## Practice

1. Run \`./neodax -C /bin/ls\` and find a function with more than 5 basic blocks.
2. Trace through the CFG of that function and count the number of conditional branches.
3. Identify whether any function has a back edge (a loop).

## Next

Continue to \`23_cfg_in_practice.md\`.
`
  },
  {
    id: "23_cfg_in_practice",
    num: 23,
    level: 2,
    title: "CFGs in Practice",
    prereq: "22_control_flow_graphs.md",
    learn: "Practical techniques for using CFGs to understand function logic.",
    level_label: "2 - Intermediate Analysis",
    content: `# CFGs in Practice

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 22_control_flow_graphs.md
**What You Will Learn:** Practical techniques for using CFGs to understand function logic.

## Classifying Function Shapes

CFG shape gives you a quick read of a function's complexity before you read a single instruction.

**Linear function:** One block from entry to return. No branches. Simple operation.

**Diamond shape:** Entry block branches into two paths that rejoin at a merge block before returning. Typical of a simple if-else.

**If without else:** Entry block branches. One path goes directly to the return block. Other path does some work then reaches the same return block.

**Loop body:** A back edge exists. The CFG has a block that branches back to an earlier block. At least one exit condition eventually breaks out of the loop.

**Switch statement:** One block with many outgoing edges, one per case. Each case has its own subgraph that merges back at the end.

## Reading Conditionals

When you see a conditional branch, ask:

1. What is being compared?
2. Which path is taken on success?
3. Which path is the "error" or "cleanup" path?

The fall-through path (the block immediately after the branch in memory) is often the normal success path. The taken branch target is often the error handler or early return.

This is a convention, not a rule. Some compilers invert this. You learn the convention by reading a lot of code.

## Identifying Loops

A loop has three parts:

**Initialization:** Done once before the loop starts (may be in the entry block or the first loop block).

**Condition check:** Decides whether to continue or exit. The block with the back edge usually contains this check.

**Body:** The work done each iteration.

In NeoDAX output, identify the loop by finding the back edge. The source of the back edge is the block that increments the counter or updates the loop variable.

## Unreachable Code

After an unconditional jump or a \`ret\`, code that follows is unreachable if there is no other way to reach it. NeoDAX's two-pass CFG builder marks such bytes as dead.

Dead bytes between legitimate instructions are sometimes an obfuscation technique or a compiler artifact.

## Connecting CFG to Semantics

The CFG is purely structural. To understand semantics, you combine CFG structure with instruction reading:

1. Read the entry block to understand initialization.
2. For each conditional, determine what condition is being checked.
3. For each path, trace what the code computes.
4. At the return block, determine what is being returned.

This process is essentially manual decompilation. The NeoDAX decompiler (Level 5) automates it for ARM64.

## Practice

1. Pick a function with at least 3 basic blocks from \`/bin/ls\`.
2. Draw the CFG on paper (boxes for blocks, arrows for edges).
3. Write in each box what the block appears to do.
4. Write a one-sentence description of what the function does.

## Next

Continue to \`24_loop_detection.md\`.
`
  },
  {
    id: "24_loop_detection",
    num: 24,
    level: 2,
    title: "Loop Detection",
    prereq: "23_cfg_in_practice.md",
    learn: "How NeoDAX detects loops and what that tells you about a function's complexity.",
    level_label: "2 - Intermediate Analysis",
    content: `# Loop Detection

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 23_cfg_in_practice.md
**What You Will Learn:** How NeoDAX detects loops and what that tells you about a function's complexity.

## What Loop Detection Does

NeoDAX uses dominator analysis to find natural loops in the CFG. A natural loop has a single entry point and at least one back edge.

The dominator analysis works as follows: block A dominates block B if every path from the entry to B passes through A. A back edge is an edge from block B to block A where A dominates B. Such an edge always creates a loop.

## Running Loop Detection

\`\`\`bash
./neodax -L /bin/ls
\`\`\`

Output shows functions with detected loops:

\`\`\`
Function sub_401300: 2 loops detected
  Loop 1: header 0x401320, body blocks: 0x401320, 0x401340
  Loop 2: header 0x401380, body blocks: 0x401380, 0x4013a0, 0x4013c0
\`\`\`

Functions with the \`[loops]\` flag in the \`-f\` output also have loops.

## What Loops Indicate

**A function with no loops** is simple and bounded. It does a fixed amount of work.

**A function with one loop** iterates over something: an array, a list, a string. The number of iterations depends on input.

**A function with nested loops** is more complex. Nested loops often indicate O(n^2) algorithms: comparing all pairs, building a matrix, parsing structured data.

**A function with many loops** is a processing engine: a parser, a serializer, a cryptographic algorithm, a state machine.

Loop count is a proxy for complexity. Functions with many loops deserve more attention.

## Loop Identification vs Loop Unrolling

Compilers sometimes unroll loops: replicate the loop body multiple times to reduce branch overhead. An unrolled loop may appear as a long linear block with no back edge. NeoDAX cannot detect unrolled loops through dominator analysis alone.

Entropy analysis (Level 4) sometimes catches unrolled loops because the repeated instruction pattern produces characteristic entropy signatures.

## Nested Loops

When one loop contains another, the inner loop's header block is inside the outer loop's body. You can identify nesting by looking at the loop header addresses: if loop B's header is within the block range of loop A, then B is nested inside A.

## Practice

1. Run \`./neodax -f -L /bin/ls\` to see function listing with loop annotations.
2. Find the function with the most loops.
3. Disassemble that function and identify which part of the code corresponds to the loop body.

## Next

Continue to \`25_call_graphs.md\`.
`
  },
  {
    id: "25_call_graphs",
    num: 25,
    level: 2,
    title: "Call Graphs",
    prereq: "24_loop_detection.md",
    learn: "How to generate and use call graphs to understand program architecture.",
    level_label: "2 - Intermediate Analysis",
    content: `# Call Graphs

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 24_loop_detection.md
**What You Will Learn:** How to generate and use call graphs to understand program architecture.

## What a Call Graph Is

A call graph is a directed graph where nodes are functions and edges connect callers to callees. If function A calls function B, there is an edge from A to B.

The call graph shows the program's high-level architecture: which functions depend on which, which functions are utility functions called by many others, and which functions are top-level operations called rarely.

## Generating a Call Graph

\`\`\`bash
./neodax -G /bin/ls
\`\`\`

Output lists each function and its callees:

\`\`\`
main -> process_args, print_files, sort_entries
process_args -> getopt, strcmp, malloc
print_files -> format_entry, printf, stat
\`\`\`

The function at the top of the call graph (called by no other function) is an entry point or a constructor.

The functions at the bottom (calling no other functions in the binary) are either leaf functions that do simple computations or wrappers around system calls.

## Call Graph Layers

You can think of the call graph as having layers:

**Layer 0 (root):** Entry points like \`main\` or constructors. Called by nothing within the binary.

**Layer 1:** Functions called directly from entry points. Often high-level orchestration functions.

**Layer N:** Functions called from layer N-1. Each layer is more specialized and lower-level.

**Leaf layer:** Functions that make only external calls (to libraries, system calls) or no calls at all.

Understanding which layer a function lives in helps you understand what it does. A leaf function does a specific primitive operation. A root function orchestrates the whole program.

## Indirect Calls

Some calls go through function pointers: \`call [rax]\` or \`blr x1\`. These are indirect calls. NeoDAX records them in the call graph but cannot statically determine the target. They appear as edges to an unknown target.

A high number of indirect calls suggests the binary uses callbacks, virtual dispatch, or a function table.

## Recursive Functions

A function is recursive if it appears in its own call subgraph: it calls itself directly or calls another function that eventually calls it back.

Direct recursion appears as a self-loop in the call graph. Mutual recursion appears as a cycle between two or more functions.

Recursive functions often implement tree traversal, divide-and-conquer algorithms, or parsers.

## Practice

1. Run \`./neodax -G /bin/ls\` and find the function that calls the most other functions.
2. Find a leaf function (calls nothing else).
3. Trace the call path from \`main\` down to a leaf function through at least 3 levels.

## Next

Continue to \`26_switch_tables.md\`.
`
  },
  {
    id: "26_switch_tables",
    num: 26,
    level: 2,
    title: "Switch Tables",
    prereq: "25_call_graphs.md",
    learn: "How compilers implement switch statements and how NeoDAX detects them.",
    level_label: "2 - Intermediate Analysis",
    content: `# Switch Tables

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 25_call_graphs.md
**What You Will Learn:** How compilers implement switch statements and how NeoDAX detects them.

## How Compilers Implement Switch

A switch statement with many cases is too inefficient to compile as a series of if-else comparisons. Instead, compilers generate a jump table: an array of addresses, one per case. The switch expression is used as an index into the table to load the target address, then execution jumps to that address.

In x86-64, this typically looks like:

\`\`\`
cmp    eax, 10            ; check if index is within bounds
ja     default_case       ; if > 10, go to default
mov    rax, [table + rax*8]  ; load target from table
jmp    rax               ; jump to case handler
\`\`\`

In ARM64:

\`\`\`
cmp    w0, #10
b.hi   default_case
adr    x1, table
ldr    x0, [x1, x0, lsl #3]
br     x0
\`\`\`

## Switch Table Detection

\`\`\`bash
./neodax -W /bin/ls
\`\`\`

NeoDAX scans for the pattern of a bounds check followed by a computed indirect jump. When found, it reports the switch table:

\`\`\`
Switch table at 0x402100:
  case 0: 0x401234
  case 1: 0x401280
  case 2: 0x4012c0
  default: 0x401200
\`\`\`

## Why This Matters

Switch tables appear in:

- Command dispatchers that handle different opcodes or commands
- State machines that transition based on current state
- Protocol parsers that handle different message types
- Interpreters that dispatch based on instruction type

Finding a switch table in a binary immediately tells you that the function is a dispatcher. The cases correspond to the dispatched operations.

## Obfuscated Switch Tables

Obfuscated binaries sometimes disguise switch tables by encrypting the addresses or using a different indirection scheme. NeoDAX's detection heuristic catches standard compiler patterns but may miss heavily obfuscated dispatch.

In such cases, the indirect \`jmp\` instruction still appears in the disassembly. Looking for unconditional indirect jumps (\`jmp [rax]\`, \`br x0\`) and the code that sets up the target register is a manual approach.

## Practice

1. Run \`./neodax -W /bin/ls\` and note how many switch tables are found.
2. Find the function containing a switch table and look at the cases.
3. Can you determine what values are being dispatched?

## Next

Continue to \`27_unicode_strings.md\`.
`
  },
  {
    id: "27_unicode_strings",
    num: 27,
    level: 2,
    title: "Unicode Strings",
    prereq: "26_switch_tables.md",
    learn: "How NeoDAX scans for unicode strings and why this matters for modern software analysis.",
    level_label: "2 - Intermediate Analysis",
    content: `# Unicode Strings

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 26_switch_tables.md
**What You Will Learn:** How NeoDAX scans for unicode strings and why this matters for modern software analysis.

## Unicode in Binaries

Modern software increasingly uses unicode strings for user-facing text. On Windows, most system APIs accept UTF-16LE strings (two bytes per character for the Basic Multilingual Plane). On Linux and macOS, UTF-8 is dominant.

When analyzing malware or Windows software, unicode strings often contain important clues that a pure ASCII scan misses.

## Running the Unicode Scanner

\`\`\`bash
./neodax -u /path/to/binary
\`\`\`

The scanner searches all sections for UTF-16LE encoded strings.

## The False Positive Problem

A naive unicode scanner produces enormous amounts of noise. Any two-byte sequence can look like a UTF-16LE character. Binary data is full of short sequences that accidentally appear as plausible characters.

NeoDAX applies a seven-layer filter to reduce false positives:

1. Skips strings found in \`.dynstr\` and \`.dynsym\` sections (these are ELF internal names, not user strings).
2. Requires at least 6 code units (3 characters minimum).
3. Rejects strings where all characters are in the ASCII range and could be a null-padded ASCII string.
4. Rejects code points below U+02FF (avoids treating binary patterns as text).
5. Checks the bytes preceding the string to verify they are not part of another string.
6. Handles surrogate pairs correctly for characters outside the Basic Multilingual Plane (code points above U+FFFF).
7. Requires that each code unit forms a valid unicode code point.

## What Unicode Strings Reveal

On Windows binaries, unicode strings commonly include:

- File paths and registry keys
- Error messages and dialog text
- URL patterns and hostnames
- Command names and configuration keys

In malware analysis, finding a unicode string like \`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\` immediately tells you the binary modifies the Windows autorun registry key.

## Comparing ASCII and Unicode Results

Run both scanners and compare:

\`\`\`bash
./neodax -t -u /path/to/binary
\`\`\`

If the ASCII scanner finds few strings but the unicode scanner finds many, the binary likely targets Windows or stores its strings in UTF-16 to complicate analysis.

## Practice

1. Run \`./neodax -u /bin/ls\` on a Linux binary. How many unicode strings are found?
2. If you have a Windows PE binary, run the unicode scanner and compare results with the ASCII scanner.
3. Find a unicode string that reveals something about the binary's functionality.

## Next

Continue to \`28_instruction_groups.md\`.
`
  },
  {
    id: "28_instruction_groups",
    num: 28,
    level: 2,
    title: "Instruction Groups",
    prereq: "27_unicode_strings.md",
    learn: "How NeoDAX classifies instructions and how this aids analysis.",
    level_label: "2 - Intermediate Analysis",
    content: `# Instruction Groups

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 27_unicode_strings.md
**What You Will Learn:** How NeoDAX classifies instructions and how this aids analysis.

## What Instruction Groups Are

NeoDAX classifies every disassembled instruction into one of several groups based on its type and function:

- **call**: Function calls (x86 \`call\`, ARM64 \`bl\`/\`blr\`)
- **branch**: Conditional and unconditional jumps that stay within the function
- **ret**: Return instructions
- **stack**: Stack manipulation (push, pop, frame setup)
- **syscall**: System call instructions
- **arithmetic**: Mathematical operations (add, sub, mul, div, shift)
- **data-move**: Data transfer between registers and memory
- **nop**: No-operation instructions

## Using Instruction Groups

Enable groups with the \`-g\` flag:

\`\`\`bash
./neodax -g /bin/ls
\`\`\`

In color-enabled terminals, each group has a distinct color. When output is plain text, the group name appears as an annotation.

## Reading Group Distribution

The distribution of instruction groups in a function tells you about its character.

A function with many \`call\` instructions is an orchestrator: it coordinates work done by other functions.

A function with many \`arithmetic\` instructions and few \`call\` instructions is a computational kernel: it does math or bit manipulation.

A function with many \`data-move\` instructions copies data between memory and registers, suggesting buffer processing or struct manipulation.

A function with a \`syscall\` instruction directly invokes the OS kernel.

## Detecting Suspicious Patterns

Instruction groups help identify unusual code:

**No \`ret\` instruction:** The function exits through an indirect jump or never returns (an infinite loop or a function that exits the process).

**Many \`nop\` instructions:** Padding between functions (normal) or part of a NOP sled used in exploitation (suspicious if appearing before a specific address).

**\`syscall\` in unexpected places:** Direct system calls are normal in libc but unusual in application code. A binary making direct syscalls is trying to bypass library-level monitoring.

**Arithmetic on seemingly random data:** Combined with high entropy, heavy arithmetic may indicate decryption or decompression.

## Groups in CFG Analysis

When building CFGs manually, knowing which instructions are branches (\`branch\` group) tells you where basic block boundaries are. The CFG builder uses this same classification internally.

## Practice

1. Run \`./neodax -g /bin/ls\` and identify a function where most instructions are \`arithmetic\`.
2. Find a function that calls many external functions (many \`call\` instructions to PLT stubs).
3. Find at least one \`syscall\` instruction if your binary has any direct system calls.

## Next

You have completed Level 2 - Intermediate Analysis. Continue to \`30_js_api_introduction.md\` to begin Level 3.
`
  },
  {
    id: "30_js_api_introduction",
    num: 30,
    level: 3,
    title: "JavaScript API Introduction",
    prereq: "28_instruction_groups.md",
    learn: "What the NeoDAX JavaScript API is, when to use it, and how it relates to the CLI.",
    level_label: "3 - JavaScript API",
    content: `# JavaScript API Introduction

**Level:** 3 - JavaScript API
**Prerequisites:** 28_instruction_groups.md
**What You Will Learn:** What the NeoDAX JavaScript API is, when to use it, and how it relates to the CLI.

## Why a JavaScript API

The CLI is excellent for interactive analysis. But when you need to analyze many binaries programmatically, integrate analysis into a larger tool, or build a web-based interface, the CLI becomes inconvenient.

The JavaScript API exposes all NeoDAX analysis capabilities through a native Node.js addon. You call Node.js functions that run the same C analysis engine under the hood, no separate process needed.

## What the API Provides

The same features available through the CLI are available through the API:

- Load and parse any supported binary format
- List sections, symbols, and functions
- Disassemble to structured JSON
- Build CFGs and detect loops
- Extract strings and unicode strings
- Build cross-references
- Run entropy analysis
- Run symbolic execution and decompilation (ARM64)

Additional capabilities only in the API:

- Binary SHA-256 and metadata access
- Programmatic filtering and processing of results
- Integration with web servers and databases
- Batch processing of many files
- TypeScript type declarations for IDE support

## Installation

Via npm (builds the native addon automatically):

\`\`\`bash
npm install neodax
\`\`\`

Or build from source after cloning the repository:

\`\`\`bash
make js
\`\`\`

This produces \`js/neodax.node\`.

## A Minimal Example

\`\`\`javascript
const neodax = require('neodax')

neodax.withBinary('/bin/ls', bin => {
    console.log('Architecture:', bin.arch)
    console.log('Format:', bin.format)
    console.log('SHA-256:', bin.sha256)
    console.log('Sections:', bin.sections().length)
    console.log('Functions:', bin.functions().length)
})
\`\`\`

Save this as \`analyze.js\` and run:

\`\`\`bash
node analyze.js
\`\`\`

## The withBinary Pattern

The \`withBinary\` function handles opening and closing the binary handle automatically. The callback receives the binary object and the handle is closed when the callback returns.

This is the recommended pattern for simple scripts. For long-running programs that analyze many files, use \`neodax.load()\` directly and manage the lifecycle manually.

## BigInt Addresses

All memory addresses in the NeoDAX API are JavaScript BigInt values. This is because 64-bit addresses can exceed the safe integer range of regular JavaScript numbers.

When printing addresses, use \`.toString(16)\` to get hex:

\`\`\`javascript
const sections = bin.sections()
sections.forEach(s => {
    console.log(s.name, '0x' + s.vaddr.toString(16))
})
\`\`\`

## Practice

1. Install NeoDAX via npm or build from source.
2. Run the minimal example above against \`/bin/ls\`.
3. Modify it to also print the entry point address.

## Next

Continue to \`31_loading_binaries_in_js.md\`.
`
  },
  {
    id: "31_loading_binaries_in_js",
    num: 31,
    level: 3,
    title: "Loading Binaries in JavaScript",
    prereq: "30_js_api_introduction.md",
    learn: "The different ways to load and manage binary handles in the NeoDAX API.",
    level_label: "3 - JavaScript API",
    content: `# Loading Binaries in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 30_js_api_introduction.md
**What You Will Learn:** The different ways to load and manage binary handles in the NeoDAX API.

## Three Loading Patterns

NeoDAX provides three functions for loading binaries:

\`\`\`javascript
const neodax = require('neodax')
\`\`\`

### neodax.load(path)

Loads a binary and returns a handle. You are responsible for calling \`.close()\` when done.

\`\`\`javascript
const bin = neodax.load('/bin/ls')
try {
    console.log(bin.arch)
    // ... analysis ...
} finally {
    bin.close()
}
\`\`\`

### neodax.withBinary(path, callback)

Loads a binary, passes it to your callback, and closes it automatically when the callback returns or throws.

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    console.log(bin.arch)
})
\`\`\`

### neodax.withBinaryAsync(path, asyncCallback)

Same as \`withBinary\` but supports async callbacks.

\`\`\`javascript
await neodax.withBinaryAsync('/bin/ls', async bin => {
    const result = await someAsyncOperation(bin.sha256)
    console.log(result)
})
\`\`\`

## Binary Metadata Properties

Once loaded, the binary object exposes these properties directly (no function call needed):

\`\`\`javascript
bin.arch        // 'x86_64', 'AArch64 (ARM64)', 'RISC-V RV64'
bin.format      // 'ELF64', 'ELF32', 'PE64', 'PE32', 'Mach-O 64'
bin.os          // 'Linux', 'BSD', 'Windows', 'Android'
bin.entry       // BigInt: entry point virtual address
bin.sha256      // string: hex SHA-256 hash
bin.buildId     // string: GNU build ID if present
bin.isPie       // boolean: Position Independent Executable
bin.isStripped  // boolean: symbol table was stripped
bin.hasDebug    // boolean: debug sections present
bin.file        // string: absolute path to the binary
\`\`\`

## Handle Lifecycle

Binary handles hold the loaded binary in memory and maintain analysis state. They should be closed when no longer needed.

For short-lived analysis scripts, \`withBinary\` handles this for you.

For servers that analyze many binaries, consider caching handles by SHA-256:

\`\`\`javascript
const cache = new Map()

function getOrLoad(filePath) {
    const bin = neodax.load(filePath)
    const key = bin.sha256
    if (cache.has(key)) {
        bin.close()  // discard duplicate
        return cache.get(key)
    }
    cache.set(key, bin)
    return bin
}

// Clean up on exit
process.on('exit', () => cache.forEach(b => b.close()))
\`\`\`

## Error Handling

\`neodax.load()\` throws if:
- The file does not exist
- The file is not a supported format
- Memory allocation fails

Always use try-catch or withBinary which handles errors for you:

\`\`\`javascript
try {
    neodax.withBinary(path, bin => {
        // ...
    })
} catch (e) {
    console.error('Failed to analyze:', e.message)
}
\`\`\`

## Practice

1. Load \`/bin/ls\` and print all metadata properties.
2. Load a non-existent file and observe the error message.
3. Load three different binaries and compare their architectures and formats.
4. Implement the cache pattern above and verify it works by loading the same binary twice.

## Next

Continue to \`32_working_with_sections.md\`.
`
  },
  {
    id: "32_working_with_sections",
    num: 32,
    level: 3,
    title: "Working with Sections in JavaScript",
    prereq: "31_loading_binaries_in_js.md",
    learn: "How to query and process section data programmatically.",
    level_label: "3 - JavaScript API",
    content: `# Working with Sections in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 31_loading_binaries_in_js.md
**What You Will Learn:** How to query and process section data programmatically.

## Listing Sections

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const sections = bin.sections()
    sections.forEach(s => {
        console.log(s.name, s.type, '0x' + s.vaddr.toString(16), s.size.toString())
    })
})
\`\`\`

## Section Object Properties

Each section object has:

\`\`\`javascript
s.name      // string: '.text', '.data', etc.
s.type      // string: 'code', 'data', 'rodata', 'bss', 'plt', 'got', 'other'
s.vaddr     // BigInt: virtual address
s.size      // BigInt: size in bytes
s.offset    // BigInt: offset in file
s.flags     // number: raw section flags
s.insnCount // number: instruction count (for code sections)
\`\`\`

## Filtering Sections

Filter to only code sections:

\`\`\`javascript
const codeSections = bin.sections().filter(s => s.type === 'code')
\`\`\`

Find a section by name:

\`\`\`javascript
const textSection = bin.sectionByName('.text')
if (textSection) {
    console.log('.text size:', textSection.size.toString())
}
\`\`\`

Find which section contains an address:

\`\`\`javascript
const section = bin.sectionAt(bin.entry)
console.log('Entry point is in:', section?.name)
\`\`\`

## Reading Raw Bytes

\`\`\`javascript
const bytes = bin.readBytes(bin.entry, 16)
// Returns Uint8Array or null if address out of range

if (bytes) {
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ')
    console.log('First 16 bytes at entry:', hex)
}
\`\`\`

This is useful for extracting shellcode, reading embedded data, or verifying specific byte patterns.

## Computing Section Statistics

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const sections = bin.sections()

    const totalCode = sections
        .filter(s => s.type === 'code')
        .reduce((sum, s) => sum + Number(s.size), 0)

    const totalData = sections
        .filter(s => s.type === 'data' || s.type === 'rodata')
        .reduce((sum, s) => sum + Number(s.size), 0)

    console.log('Total code bytes:', totalCode)
    console.log('Total data bytes:', totalData)
    console.log('Code to data ratio:', (totalCode / totalData).toFixed(2))
})
\`\`\`

Note: convert BigInt to Number with \`Number()\` for arithmetic. For very large files this may lose precision, but for section sizes it is safe.

## Practice

1. List all sections of a binary and print only the ones with size greater than 1000 bytes.
2. Find the section with the largest size.
3. Read the first 8 bytes of the entry point and print them as hex.
4. Calculate what percentage of the file is executable code.

## Next

Continue to \`33_working_with_functions.md\`.
`
  },
  {
    id: "33_working_with_functions",
    num: 33,
    level: 3,
    title: "Working with Functions in JavaScript",
    prereq: "32_working_with_sections.md",
    learn: "How to query function data and use it in analysis scripts.",
    level_label: "3 - JavaScript API",
    content: `# Working with Functions in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 32_working_with_sections.md
**What You Will Learn:** How to query function data and use it in analysis scripts.

## Listing Functions

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const functions = bin.functions()
    console.log('Total functions:', functions.length)

    functions.forEach(fn => {
        const size = Number(fn.end - fn.start)
        console.log(fn.name, '0x' + fn.start.toString(16), size + ' bytes')
    })
})
\`\`\`

## Function Object Properties

\`\`\`javascript
fn.name       // string: function name or 'sub_<hex>' for unnamed
fn.start      // BigInt: start address
fn.end        // BigInt: end address (equals start if unknown)
fn.size       // BigInt: end - start (0 if unknown)
fn.insnCount  // number: instruction count
fn.blockCount // number: number of basic blocks
fn.hasLoops   // boolean: loops detected
fn.hasCalls   // boolean: function makes calls
fn.symIndex   // number: index into symbol table (-1 if no symbol)
\`\`\`

## Finding a Specific Function

By address:

\`\`\`javascript
const fn = bin.funcAt(0x401234n)  // note BigInt literal with n suffix
if (fn) {
    console.log('Function at that address:', fn.name)
}
\`\`\`

By name (search manually):

\`\`\`javascript
function findByName(bin, name) {
    return bin.functions().find(fn => fn.name === name)
}

const main = findByName(bin, 'main')
\`\`\`

## Hottest Functions

\`\`\`javascript
const hottest = bin.hottestFunctions(10)
hottest.forEach((entry, i) => {
    const fn = entry.function
    console.log(\`\${i+1}. \${fn.name} called \${entry.callCount} times\`)
})
\`\`\`

The hottest functions are those most frequently called by other functions in the binary. This helps identify utility functions and central dispatch points.

## Filtering Functions

Find all functions containing loops:

\`\`\`javascript
const loopFunctions = bin.functions().filter(fn => fn.hasLoops)
console.log('Functions with loops:', loopFunctions.length)
\`\`\`

Find large functions:

\`\`\`javascript
const largeFunctions = bin.functions()
    .filter(fn => Number(fn.size) > 500)
    .sort((a, b) => Number(b.size - a.size))

largeFunctions.forEach(fn => {
    console.log(fn.name, Number(fn.size) + ' bytes')
})
\`\`\`

## Functions and Analysis

The full analysis pipeline runs all analysis in one call:

\`\`\`javascript
const result = bin.analyze()
// result.functions contains the full function list
// result.xrefs contains cross-references
// result.sections, result.symbols, etc.
\`\`\`

This is equivalent to running the CLI with \`-x\` but returns structured JavaScript objects instead of text output.

## Practice

1. List the 5 largest functions in \`/bin/ls\`.
2. Count how many functions have loops.
3. Find the function with the highest instruction count.
4. Use \`hottestFunctions\` to find the most-called function and print its name.

## Next

Continue to \`34_disasm_json.md\`.
`
  },
  {
    id: "34_disasm_json",
    num: 34,
    level: 3,
    title: "Structured Disassembly in JavaScript",
    prereq: "33_working_with_functions.md",
    learn: "How to get disassembly as structured JSON and process it programmatically.",
    level_label: "3 - JavaScript API",
    content: `# Structured Disassembly in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 33_working_with_functions.md
**What You Will Learn:** How to get disassembly as structured JSON and process it programmatically.

## disasmJson

The \`disasmJson\` method returns disassembly as an array of instruction objects instead of formatted text:

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const instructions = bin.disasmJson('.text', { limit: 100, offset: 0 })

    instructions.forEach(insn => {
        const addr = '0x' + insn.address.toString(16)
        console.log(addr, insn.mnemonic, insn.operands)
    })
})
\`\`\`

## Instruction Object Properties

\`\`\`javascript
insn.address    // BigInt: virtual address
insn.mnemonic   // string: 'mov', 'call', 'ret', etc.
insn.operands   // string: 'rax, rbx' or 'rdi, [rbp-8]'
insn.length     // number: instruction length in bytes
insn.group      // string: 'call', 'branch', 'ret', 'stack', 'arithmetic', etc.
insn.bytes      // Uint8Array: raw instruction bytes
insn.symbol     // string or null: symbol annotation if available
\`\`\`

## Using Offset and Limit

The \`offset\` parameter skips the first N instructions. The \`limit\` parameter caps the total returned. Use them together for pagination:

\`\`\`javascript
function getPage(bin, section, pageNum, pageSize) {
    return bin.disasmJson(section, {
        offset: pageNum * pageSize,
        limit: pageSize
    })
}
\`\`\`

## Counting by Group

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const insns = bin.disasmJson('.text', { limit: 10000 })

    const groupCounts = {}
    insns.forEach(insn => {
        groupCounts[insn.group] = (groupCounts[insn.group] || 0) + 1
    })

    console.log('Instruction group distribution:')
    Object.entries(groupCounts)
        .sort((a, b) => b[1] - a[1])
        .forEach(([group, count]) => {
            const pct = ((count / insns.length) * 100).toFixed(1)
            console.log(\`  \${group}: \${count} (\${pct}%)\`)
        })
})
\`\`\`

## Finding Specific Patterns

Find all call instructions:

\`\`\`javascript
const calls = insns.filter(i => i.group === 'call')
calls.forEach(i => {
    console.log('0x' + i.address.toString(16), 'calls', i.operands)
})
\`\`\`

Find instructions referencing a specific address:

\`\`\`javascript
const targetAddr = '0x401234'
const refs = insns.filter(i => i.operands.includes(targetAddr))
\`\`\`

## Building a Simple Disassembler Script

\`\`\`javascript
const neodax = require('neodax')
const path = process.argv[2]
if (!path) { console.error('Usage: node disasm.js <binary>'); process.exit(1) }

neodax.withBinary(path, bin => {
    const sections = bin.sections().filter(s => s.type === 'code')
    sections.forEach(section => {
        console.log(\`\\n=== \${section.name} ===\`)
        const insns = bin.disasmJson(section.name, { limit: 500 })
        insns.forEach(i => {
            const addr = '0x' + i.address.toString(16).padStart(16, '0')
            const bytes = Array.from(i.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ')
            console.log(addr, bytes.padEnd(20), i.mnemonic, i.operands)
        })
    })
})
\`\`\`

## Practice

1. Use \`disasmJson\` on \`/bin/ls\` and print all \`call\` instructions with their target operands.
2. Count the total number of instructions in \`.text\`.
3. Find the instruction group that appears most frequently.
4. Build the simple disassembler script above and test it.

## Next

Continue to \`35_xrefs_in_js.md\`.
`
  },
  {
    id: "35_xrefs_in_js",
    num: 35,
    level: 3,
    title: "Cross References in JavaScript",
    prereq: "34_disasm_json.md",
    learn: "How to query cross-references programmatically and build analysis tools from them.",
    level_label: "3 - JavaScript API",
    content: `# Cross References in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 34_disasm_json.md
**What You Will Learn:** How to query cross-references programmatically and build analysis tools from them.

## Getting All Cross References

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const xrefs = bin.xrefs()
    console.log('Total xrefs:', xrefs.length)

    const calls = xrefs.filter(x => x.isCall)
    const branches = xrefs.filter(x => !x.isCall)
    console.log('Calls:', calls.length)
    console.log('Branches:', branches.length)
})
\`\`\`

## Xref Object Properties

\`\`\`javascript
x.from      // BigInt: address of the instruction making the reference
x.to        // BigInt: address being referenced
x.isCall    // boolean: true for calls, false for branches
\`\`\`

## Querying by Target

Find all callers of a specific function:

\`\`\`javascript
function callers(bin, targetAddr) {
    return bin.xrefs()
        .filter(x => x.isCall && x.to === targetAddr)
        .map(x => x.from)
}

neodax.withBinary('/bin/ls', bin => {
    const fns = bin.functions()
    const mainFn = fns.find(f => f.name === 'main')
    if (mainFn) {
        const mainCallers = callers(bin, mainFn.start)
        console.log('main is called from:', mainCallers.length, 'places')
    }
})
\`\`\`

## Targeted Queries

Use the targeted methods for better performance than filtering all xrefs:

\`\`\`javascript
// All xrefs that point TO a given address
const incoming = bin.xrefsTo(0x401234n)

// All xrefs FROM a given address
const outgoing = bin.xrefsFrom(0x401234n)
\`\`\`

## Building a Call Graph Programmatically

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const functions = bin.functions()
    const xrefs = bin.xrefs().filter(x => x.isCall)

    // Build a map from start address to function name
    const fnMap = new Map()
    functions.forEach(fn => fnMap.set(fn.start, fn.name))

    // Build adjacency list
    const callGraph = new Map()
    functions.forEach(fn => callGraph.set(fn.name, new Set()))

    xrefs.forEach(x => {
        const callerFn = bin.funcAt(x.from)
        const calleeName = fnMap.get(x.to) || 'unknown'
        if (callerFn) {
            callGraph.get(callerFn.name)?.add(calleeName)
        }
    })

    // Print top-level entries
    callGraph.forEach((callees, caller) => {
        if (callees.size > 0) {
            console.log(caller, '->', [...callees].join(', '))
        }
    })
})
\`\`\`

## Finding Unused Functions

Functions that are never called (no incoming xrefs) are potential dead code, constructors, or entry points:

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const xrefs = bin.xrefs().filter(x => x.isCall)
    const calledAddrs = new Set(xrefs.map(x => x.to))

    const unused = bin.functions().filter(fn => !calledAddrs.has(fn.start))
    console.log('Uncalled functions:', unused.map(f => f.name))
})
\`\`\`

## Practice

1. Count how many unique functions are called by \`main\` directly.
2. Find the function that has the most incoming call xrefs.
3. List all functions that are never called by other functions in the binary.

## Next

Continue to \`36_analyze_pipeline.md\`.
`
  },
  {
    id: "36_analyze_pipeline",
    num: 36,
    level: 3,
    title: "The Analyze Pipeline",
    prereq: "35_xrefs_in_js.md",
    learn: "How to use the full analysis pipeline and process the combined result object.",
    level_label: "3 - JavaScript API",
    content: `# The Analyze Pipeline

**Level:** 3 - JavaScript API
**Prerequisites:** 35_xrefs_in_js.md
**What You Will Learn:** How to use the full analysis pipeline and process the combined result object.

## Running Full Analysis

The \`analyze()\` method runs the complete analysis pipeline in one call:

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const result = bin.analyze()
})
\`\`\`

This is equivalent to the CLI's \`-x\` flag.

## Result Object Structure

\`\`\`javascript
result.info         // binary metadata (same as bin.arch, bin.format, etc.)
result.sections     // array of section objects
result.symbols      // array of symbol objects
result.functions    // array of function objects
result.xrefs        // array of xref objects
result.blocks       // array of CFG block objects
result.loadTimeMs   // number: time to load in milliseconds
result.analysisTimeMs // number: time to analyze in milliseconds
\`\`\`

## The info Object

\`\`\`javascript
result.info.arch        // architecture string
result.info.format      // format string
result.info.os          // OS string
result.info.entry       // BigInt: entry point
result.info.sha256      // SHA-256 hash
result.info.isPie       // boolean
result.info.isStripped  // boolean
result.info.hasDebug    // boolean
result.info.codeSize    // BigInt: total code bytes
result.info.imageSize   // BigInt: total image size
\`\`\`

## Building a Summary Report

\`\`\`javascript
const neodax = require('neodax')

function summarize(filePath) {
    neodax.withBinary(filePath, bin => {
        const r = bin.analyze()
        const i = r.info

        const codeSecs = r.sections.filter(s => s.type === 'code')
        const loopFns  = r.functions.filter(f => f.hasLoops)
        const calls    = r.xrefs.filter(x => x.isCall)

        console.log('File:', filePath)
        console.log('Format:', i.format, '|', i.arch)
        console.log('SHA-256:', i.sha256)
        console.log('PIE:', i.isPie, '| Stripped:', i.isStripped)
        console.log('Code sections:', codeSecs.length)
        console.log('Functions:', r.functions.length, '(', loopFns.length, 'with loops)')
        console.log('Symbols:', r.symbols.length)
        console.log('Xrefs:', r.xrefs.length, '(', calls.length, 'calls)')
        console.log('Load time:', r.loadTimeMs, 'ms')
        console.log()
    })
}

// Analyze all arguments
process.argv.slice(2).forEach(summarize)
\`\`\`

## Timing Considerations

The \`analyze()\` method does all work synchronously. For large binaries, it may take several seconds.

For a web server, run analysis in a worker thread or offload it to avoid blocking the event loop:

\`\`\`javascript
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads')

if (!isMainThread) {
    const neodax = require('neodax')
    neodax.withBinary(workerData.path, bin => {
        const result = bin.analyze()
        parentPort.postMessage(result)
    })
}
\`\`\`

## Practice

1. Use \`analyze()\` on three different binaries and compare their stats.
2. Build the summary report script above and run it on five different system binaries.
3. Identify which binary has the highest ratio of functions to symbols (indicating how stripped it is).

## Next

Continue to \`37_typescript_usage.md\`.
`
  },
  {
    id: "37_typescript_usage",
    num: 37,
    level: 3,
    title: "TypeScript Usage",
    prereq: "36_analyze_pipeline.md",
    learn: "How to use NeoDAX with TypeScript for type-safe analysis scripts.",
    level_label: "3 - JavaScript API",
    content: `# TypeScript Usage

**Level:** 3 - JavaScript API
**Prerequisites:** 36_analyze_pipeline.md
**What You Will Learn:** How to use NeoDAX with TypeScript for type-safe analysis scripts.

## TypeScript Declarations

NeoDAX ships with full TypeScript declarations in \`js/index.d.ts\`. These are automatically used when you install via npm.

## Basic TypeScript Setup

Create a \`tsconfig.json\`:

\`\`\`json
{
    "compilerOptions": {
        "target": "ES2020",
        "module": "commonjs",
        "strict": true,
        "esModuleInterop": true
    }
}
\`\`\`

Install TypeScript if needed:

\`\`\`bash
npm install -D typescript ts-node
\`\`\`

## A Typed Analysis Script

\`\`\`typescript
import neodax, { NeoDAXBinary, Section, DaxFunction } from 'neodax'

function analyzeCodeSections(bin: NeoDAXBinary): void {
    const codeSections: Section[] = bin.sections()
        .filter(s => s.type === 'code')

    codeSections.forEach(section => {
        console.log(section.name, 'size:', section.size.toString())
    })
}

function findComplexFunctions(bin: NeoDAXBinary, minLoops: number = 1): DaxFunction[] {
    return bin.functions()
        .filter(fn => fn.hasLoops && fn.hasCalls)
        .sort((a, b) => b.insnCount - a.insnCount)
}

neodax.withBinary(process.argv[2], (bin: NeoDAXBinary) => {
    console.log('Analyzing:', bin.file)
    analyzeCodeSections(bin)

    const complex = findComplexFunctions(bin)
    console.log('Complex functions:', complex.length)
    complex.slice(0, 5).forEach(fn => {
        console.log(' ', fn.name, fn.insnCount, 'insns')
    })
})
\`\`\`

Run with ts-node:

\`\`\`bash
npx ts-node analyze.ts /bin/ls
\`\`\`

## Key Types

The main types from the declarations:

\`\`\`typescript
interface NeoDAXBinary {
    arch: string
    format: string
    os: string
    entry: bigint
    sha256: string
    isPie: boolean
    isStripped: boolean
    hasDebug: boolean
    sections(): Section[]
    symbols(): Symbol[]
    functions(): DaxFunction[]
    xrefs(): Xref[]
    disasmJson(section: string, opts?: DisasmOptions): Instruction[]
    analyze(): AnalyzeResult
    close(): void
}

interface Section {
    name: string
    type: string
    vaddr: bigint
    size: bigint
    offset: bigint
    insnCount: number
}

interface DaxFunction {
    name: string
    start: bigint
    end: bigint
    size: bigint
    insnCount: number
    hasLoops: boolean
    hasCalls: boolean
}

interface Instruction {
    address: bigint
    mnemonic: string
    operands: string
    length: number
    group: string
    bytes: Uint8Array
    symbol: string | null
}
\`\`\`

## Type Narrowing with Addresses

Since addresses are BigInt, comparisons require BigInt literals:

\`\`\`typescript
const mainFn = bin.functions().find(fn => fn.start === 0x401234n)
//                                                             ^ BigInt literal
\`\`\`

## Practice

1. Convert one of the JavaScript examples from previous files to TypeScript.
2. Add a type annotation to a function that returns \`DaxFunction[]\`.
3. Use the TypeScript compiler to catch a type error (try passing a string where BigInt is expected).

## Next

Continue to \`38_async_patterns.md\`.
`
  },
  {
    id: "38_async_patterns",
    num: 38,
    level: 3,
    title: "Async Patterns",
    prereq: "37_typescript_usage.md",
    learn: "How to structure async analysis code and handle multiple binaries concurrently.",
    level_label: "3 - JavaScript API",
    content: `# Async Patterns

**Level:** 3 - JavaScript API
**Prerequisites:** 37_typescript_usage.md
**What You Will Learn:** How to structure async analysis code and handle multiple binaries concurrently.

## Synchronous Nature of Analysis

NeoDAX analysis is CPU-bound and synchronous. The \`analyze()\`, \`functions()\`, \`disasmJson()\`, and similar methods run synchronously and block until complete.

This is not a problem for command-line scripts. It becomes important in web servers and multi-file batch processing.

## withBinaryAsync

For cases where your callback contains async operations, use \`withBinaryAsync\`:

\`\`\`javascript
const neodax = require('neodax')
const fs = require('fs/promises')

async function analyzeAndSave(filePath, outputPath) {
    await neodax.withBinaryAsync(filePath, async bin => {
        const result = bin.analyze()
        const summary = {
            sha256: result.info.sha256,
            arch: result.info.arch,
            functions: result.functions.length,
        }
        await fs.writeFile(outputPath, JSON.stringify(summary, null, 2))
    })
}
\`\`\`

Note: the analysis itself still runs synchronously within the callback. The \`async\` allows you to use \`await\` for I/O operations around the analysis.

## Processing Multiple Files

To analyze multiple files concurrently, use \`Promise.all\`:

\`\`\`javascript
async function analyzeAll(filePaths) {
    const results = await Promise.all(
        filePaths.map(filePath =>
            new Promise((resolve, reject) => {
                try {
                    neodax.withBinary(filePath, bin => {
                        resolve({
                            path: filePath,
                            sha256: bin.sha256,
                            functions: bin.functions().length,
                        })
                    })
                } catch (e) {
                    reject({ path: filePath, error: e.message })
                }
            })
        )
    )
    return results
}
\`\`\`

Be cautious: loading many large binaries simultaneously consumes significant memory. Consider batching:

\`\`\`javascript
async function analyzeBatch(filePaths, batchSize = 4) {
    const results = []
    for (let i = 0; i < filePaths.length; i += batchSize) {
        const batch = filePaths.slice(i, i + batchSize)
        const batchResults = await analyzeAll(batch)
        results.push(...batchResults)
        console.log(\`Processed \${Math.min(i + batchSize, filePaths.length)} / \${filePaths.length}\`)
    }
    return results
}
\`\`\`

## Worker Threads

For true parallelism, run analysis in worker threads. Each worker has its own event loop and can run NeoDAX synchronously without blocking the main thread:

\`\`\`javascript
// worker.js
const { workerData, parentPort } = require('worker_threads')
const neodax = require('neodax')

neodax.withBinary(workerData.path, bin => {
    const result = bin.analyze()
    parentPort.postMessage({
        path: workerData.path,
        sha256: result.info.sha256,
        functions: result.functions.length,
        sections: result.sections.length,
    })
})
\`\`\`

\`\`\`javascript
// main.js
const { Worker } = require('worker_threads')

function analyzeInWorker(filePath) {
    return new Promise((resolve, reject) => {
        const worker = new Worker('./worker.js', { workerData: { path: filePath } })
        worker.on('message', resolve)
        worker.on('error', reject)
    })
}
\`\`\`

## Practice

1. Write a script that analyzes all executables in \`/usr/bin\` (or a subset) and prints a summary table.
2. Use batching to keep memory usage bounded.
3. Handle errors gracefully so one failed binary does not stop the entire batch.

## Next

You have completed Level 3 - JavaScript API. Continue to \`40_entropy_analysis.md\` to begin Level 4.
`
  },
  {
    id: "40_entropy_analysis",
    num: 40,
    level: 4,
    title: "Entropy Analysis",
    prereq: "38_async_patterns.md",
    learn: "What entropy is, how NeoDAX measures it, and how to use it to detect packed and encrypted sections.",
    level_label: "4 - Advanced Analysis",
    content: `# Entropy Analysis

**Level:** 4 - Advanced Analysis
**Prerequisites:** 38_async_patterns.md
**What You Will Learn:** What entropy is, how NeoDAX measures it, and how to use it to detect packed and encrypted sections.

## What Entropy Measures

Shannon entropy measures the information density of a byte sequence. High entropy means the bytes are close to random. Low entropy means there is significant repetition or structure.

For binary analysis, entropy is measured in bits per byte on a scale from 0 to 8:

- **0 to 3**: Highly structured data. Executable code with many zeros, sparse arrays, or ASCII text.
- **4 to 6**: Normal range for compiled code and data.
- **6.8 to 7.0 (HIGH)**: Compressed data, encrypted data, or packed code.
- **7.0 to 8.0 (PACKED)**: Almost certainly compressed or encrypted. Random data approaches 8.0.

NeoDAX uses these thresholds: HIGH at 6.8 bits/byte and PACKED at 7.0 bits/byte.

## Running Entropy Analysis

\`\`\`bash
./neodax -e /bin/ls
\`\`\`

The output shows entropy for the entire file using a sliding window of 256 bytes with a 64-byte step size:

\`\`\`
Entropy scan: /bin/ls
  .text      avg 5.82 bits/byte  max 6.41
  .rodata    avg 4.21 bits/byte  max 5.89
  .data      avg 2.15 bits/byte  max 3.44

  No HIGH entropy regions detected.
\`\`\`

If packed sections exist:

\`\`\`
  .text      avg 7.81 bits/byte  max 7.95  [PACKED]
  HIGH: 0x401000 - 0x410000 (entropy 7.81)
\`\`\`

## In JavaScript

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const report = bin.entropy()
    console.log(report)
})
\`\`\`

## Interpreting Results

A normal unobfuscated binary has low to medium entropy throughout. The \`.text\` section typically sits between 5.0 and 6.5. The \`.rodata\` section is lower because strings have significant ASCII structure.

When a section has entropy above 7.0, the data inside is likely:

- Compressed with zlib, lz4, or similar
- Encrypted with AES, RC4, or XOR
- A native code stub that decrypts something into memory before running it

## UPX and Other Packers

UPX is a common binary packer. It compresses the original binary and adds a small unpacking stub. The packed binary has very high entropy in its main section and a small low-entropy \`.text\` stub.

NeoDAX detects the high entropy but cannot unpack the binary. If you suspect packing:

1. Check the entropy with \`-e\`.
2. Look for a small code section (the unpacker stub) alongside a large high-entropy section.
3. Use a dynamic analysis tool or unpacker to extract the original code.

## Entropy and Encryption

Malware often stores encrypted payloads. A \`.data\` or custom section with very high entropy combined with code that reads and processes that section is a strong indicator of encryption.

The recursive descent analysis (\`-R\`) combined with entropy can help: if the code reads from a high-entropy section and passes the result to a function full of XOR operations, that function is likely a decryptor.

## Practice

1. Run \`./neodax -e /bin/ls\` and note the entropy of each section.
2. If available, run entropy analysis on a UPX-packed binary and compare.
3. Find the section with the highest entropy in three different binaries.

## Next

Continue to \`41_packed_binary_detection.md\`.
`
  },
  {
    id: "41_packed_binary_detection",
    num: 41,
    level: 4,
    title: "Packed Binary Detection",
    prereq: "40_entropy_analysis.md",
    learn: "How to identify packed, obfuscated, or encrypted binaries using multiple NeoDAX features.",
    level_label: "4 - Advanced Analysis",
    content: `# Packed Binary Detection

**Level:** 4 - Advanced Analysis
**Prerequisites:** 40_entropy_analysis.md
**What You Will Learn:** How to identify packed, obfuscated, or encrypted binaries using multiple NeoDAX features.

## Signs of Packing

No single indicator confirms packing. Use multiple signals together:

**High entropy sections:** The clearest indicator. Legitimate code rarely exceeds 7.0 bits/byte.

**Few imports:** A packed binary often imports only the functions needed for the unpacker stub. The real import table is inside the packed payload.

**Suspicious section names:** Non-standard names like \`.UPX0\`, \`_RDATA\`, or random strings where \`.text\` should be.

**Small code section with large data section:** The unpacker stub is small; the compressed payload is large.

**No readable strings:** If a binary has almost no ASCII strings, its data is likely encrypted.

**No recognizable functions:** Few detected functions with no identifiable names suggests the analysis-visible code is minimal.

## Combining Signals in NeoDAX

\`\`\`bash
./neodax -l -y -t -e /bin/suspicious
\`\`\`

This runs sections, symbols, strings, and entropy together. Look for:

1. Section count: typical packed binary has 2-4 sections
2. Symbol count: stripped and few PLT symbols
3. Strings: almost none
4. Entropy: at least one section above 7.0

## In JavaScript

\`\`\`javascript
function isProbablyPacked(bin) {
    const sections = bin.sections()
    const symbols  = bin.symbols()
    const result   = bin.analyze()
    const entropy  = bin.entropy()

    const signals = {
        highEntropy:    entropy.includes('PACKED') || entropy.includes('HIGH'),
        fewImports:     symbols.filter(s => s.name.includes('@plt')).length < 5,
        fewSections:    sections.length < 4,
        fewFunctions:   result.functions.length < 10,
        fewStrings:     result.strings?.length < 5,
    }

    const score = Object.values(signals).filter(Boolean).length
    return { signals, score, likelyPacked: score >= 3 }
}
\`\`\`

## Identifying the Unpacker Stub

If you have identified a likely packed binary, find the unpacker stub:

1. Run \`./neodax -e binary\` to find the low-entropy section (the stub).
2. Disassemble the stub section.
3. Look for a loop that reads from the high-entropy section and writes to an executable region.
4. The loop contains the decryption or decompression logic.

## Common Packer Signatures

While NeoDAX does not include a packer signature database, the entropy patterns are distinctive:

**UPX:** Two sections, both nearly 8.0 entropy. Very few imports.

**MPRESS:** One section with 7.5+ entropy, very small stub.

**Enigma Protector:** Multiple sections, some high entropy, code section is virtualized.

**Custom XOR stub:** Single high-entropy data section, small code section with arithmetic-heavy loop.

## Practice

1. Download a UPX binary (or pack one yourself with \`upx myprog\`) and run the full detection analysis.
2. Compare the import count before and after packing.
3. Write a JavaScript function that scores a binary on the packing indicators.

## Next

Continue to \`42_recursive_descent.md\`.
`
  },
  {
    id: "42_recursive_descent",
    num: 42,
    level: 4,
    title: "Recursive Descent Disassembly",
    prereq: "41_packed_binary_detection.md",
    learn: "What recursive descent is, how it differs from linear sweep, and when to use it.",
    level_label: "4 - Advanced Analysis",
    content: `# Recursive Descent Disassembly

**Level:** 4 - Advanced Analysis
**Prerequisites:** 41_packed_binary_detection.md
**What You Will Learn:** What recursive descent is, how it differs from linear sweep, and when to use it.

## Two Disassembly Strategies

There are two main approaches to disassembling a binary:

**Linear sweep** reads the code section byte by byte from start to finish, decoding each instruction in sequence. It is simple and fast but can be confused by data embedded within code or by jump tricks.

**Recursive descent** starts at a known entry point and follows control flow. When it encounters a conditional branch, it queues both targets. When it encounters an unconditional jump, it follows it. When it reaches a return, it backtracks. Code that is not reachable from any known entry point is not disassembled.

NeoDAX uses a combination: the primary disassembler uses linear sweep with the two-pass jump trick fix, and the recursive descent module is available as a separate analysis.

## Running Recursive Descent

\`\`\`bash
./neodax -R /bin/ls
\`\`\`

Or for a specific section:

\`\`\`bash
./neodax -R -s .text /bin/ls
\`\`\`

The output marks bytes that are not reachable from any known entry point as dead bytes.

## In JavaScript

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const report = bin.rda('.text')
    console.log(report)
})
\`\`\`

## What Recursive Descent Reveals

**Dead bytes:** Bytes between function boundaries, alignment padding, or data embedded in code sections that is never executed.

**Unreachable code:** Functions that exist in the binary but are never called. These may be dead code left by the compiler, debugging remnants, or code that is only reachable dynamically.

**Jump tricks:** Code where a disassembler would be confused by data after an unconditional jump. Recursive descent naturally skips these bytes.

**Coverage gaps:** If a significant portion of the code section is marked dead, the binary may have self-modifying code or dynamic code generation that RDA cannot follow.

## Limitations

Recursive descent cannot follow indirect branches (\`call rax\`, \`jmp [rax]\`) without knowing the target value. These appear as unresolved edges. If many indirect branches exist, the coverage will be lower than the actual executed code.

For binaries with many indirect calls (virtual dispatch in C++, function tables, callbacks), recursive descent misses significant portions of the reachable code.

## Combining with Entropy

A section with high entropy that also has many unreachable bytes according to RDA is a strong indicator of packed or encrypted code. The unreachable bytes are the encrypted payload; the small amount of reachable code is the decryptor stub.

## Practice

1. Run \`./neodax -R /bin/ls\` and note how many dead bytes are reported.
2. Find the largest gap (sequence of unreachable bytes) in the code section.
3. Compare RDA coverage on a stripped binary vs an unstripped binary of the same program.

## Next

Continue to \`43_instruction_validity_filter.md\`.
`
  },
  {
    id: "43_instruction_validity_filter",
    num: 43,
    level: 4,
    title: "Instruction Validity Filter",
    prereq: "42_recursive_descent.md",
    learn: "How the instruction validity filter works and what it tells you about code quality and obfuscation.",
    level_label: "4 - Advanced Analysis",
    content: `# Instruction Validity Filter

**Level:** 4 - Advanced Analysis
**Prerequisites:** 42_recursive_descent.md
**What You Will Learn:** How the instruction validity filter works and what it tells you about code quality and obfuscation.

## What the IVF Does

The instruction validity filter scans code sections and flags instructions or byte sequences that are unlikely to be legitimate compiled code:

- **Invalid opcodes:** Byte sequences that do not decode to any valid instruction for the target architecture.
- **Privileged instructions:** Instructions that only make sense in kernel mode (like \`wrmsr\`, \`invlpg\`, \`lgdt\`). These appearing in userspace code is suspicious.
- **NOP runs:** Long sequences of NOP instructions (8 or more consecutive). A few NOPs are normal padding; long NOP sleds suggest exploitation artifacts or obfuscation.
- **INT3 runs:** Multiple consecutive breakpoint instructions suggest debugging artifacts left in the binary.
- **Dead bytes after unconditional branches:** Code that follows a \`jmp\` and is never targeted by any other branch. These are often fake instructions injected to confuse disassemblers.

## Running the IVF

\`\`\`bash
./neodax -V /bin/ls
\`\`\`

The output reports any flagged regions:

\`\`\`
Instruction Validity Filter: /bin/ls

No suspicious patterns detected.
\`\`\`

Or for a suspicious binary:

\`\`\`
Instruction Validity Filter: suspicious_binary

0x401234: Invalid opcode (0xFF 0xFF)
0x401300: NOP run (12 consecutive NOPs)
0x4014a0: Privileged instruction: wrmsr
0x401500: Dead bytes after unconditional branch (14 bytes)
\`\`\`

## In JavaScript

\`\`\`javascript
neodax.withBinary('/path/to/binary', bin => {
    const report = bin.ivf()
    if (report.includes('No suspicious')) {
        console.log('Binary appears clean')
    } else {
        console.log('Suspicious patterns found:')
        console.log(report)
    }
})
\`\`\`

## Interpreting Results

A clean binary with no IVF flags is expected for normally compiled code. One or two flags may be noise or compiler artifacts.

Multiple flags, especially invalid opcodes or privileged instructions in user code, strongly suggest either:

- Deliberate obfuscation (fake instructions injected to mislead disassemblers)
- Anti-analysis techniques (code that detects being analyzed and behaves differently)
- Corrupted binary
- Code that is not meant to be directly executed (it is decrypted first)

## NOP Sleds

A NOP sled is a long sequence of NOP instructions placed before shellcode. It was historically used in heap and stack overflows to ensure the instruction pointer lands somewhere in the NOP sled and slides down to the shellcode.

Finding a NOP sled in a binary's normal code section is very unusual and worth investigating.

## Combining with Other Analysis

The IVF works best as part of a multi-signal analysis:

1. High entropy section + dead bytes after jumps + invalid opcodes = packed binary with anti-disassembly
2. Privileged instructions in user code + no kernel symbols = rootkit or ring-0 exploit payload
3. Long NOP sled in non-code section + executable section at that address = shellcode

## Practice

1. Run \`./neodax -V /bin/ls\` on a clean system binary and verify no flags.
2. If you have any suspicious binary samples, run the IVF and note the results.
3. Combine with entropy: \`./neodax -e -V /path/to/binary\` to see both signals at once.

## Next

Continue to \`44_hottest_functions.md\`.
`
  },
  {
    id: "44_hottest_functions",
    num: 44,
    level: 4,
    title: "Hottest Functions",
    prereq: "43_instruction_validity_filter.md",
    learn: "How to identify the most-called functions and why they matter.",
    level_label: "4 - Advanced Analysis",
    content: `# Hottest Functions

**Level:** 4 - Advanced Analysis
**Prerequisites:** 43_instruction_validity_filter.md
**What You Will Learn:** How to identify the most-called functions and why they matter.

## What "Hottest" Means

In NeoDAX, the hottest functions are those with the most incoming call xrefs. A function called 50 times by other functions is hotter than one called twice.

This is a static measure, not a dynamic profiling result. It counts how many times the function is called in the code, not how many times it actually runs at runtime.

## Running Hottest Functions

CLI:

\`\`\`bash
./neodax -f -r -v /bin/ls
\`\`\`

JavaScript:

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const hottest = bin.hottestFunctions(10)
    hottest.forEach((entry, i) => {
        console.log(i+1, entry.function.name, entry.callCount + ' calls')
    })
})
\`\`\`

## What Hottest Functions Tell You

The most-called functions in a program are typically:

- **Utility functions:** Memory allocation, string manipulation, error handling.
- **Logging functions:** Debug or error output called throughout the code.
- **Initialization routines:** Setup functions called at many startup paths.
- **Critical dispatch points:** Functions that route execution to different handlers.

If you need to understand a codebase quickly, the hottest functions are often the best starting point. Understanding what the most-called function does tells you about the program's core patterns.

## Hottest Functions in Malware Analysis

In malware, the hottest functions may be:

- **Decryption helpers:** Called each time an encrypted string or payload needs to be decrypted.
- **Anti-analysis checks:** Called before each significant operation to verify the environment.
- **Communication wrappers:** Called whenever data is sent or received.

Identifying these functions and understanding them reveals the malware's core techniques.

## Ranking by Size vs Call Count

Two different ranking strategies give different insights:

By call count (hottest): Find utility and infrastructure functions.
By size (largest): Find complex algorithms and core logic.

Neither is strictly better. Use both to triangulate the important parts of a binary.

## Practice

1. Run hottest functions on \`/bin/ls\` and identify the top 5.
2. Disassemble the hottest function and determine what it does.
3. Compare the hottest function list to the largest function list. Are they the same functions?

## Next

Continue to \`45_obfuscation_detection.md\`.
`
  },
  {
    id: "45_obfuscation_detection",
    num: 45,
    level: 4,
    title: "Obfuscation Detection",
    prereq: "44_hottest_functions.md",
    learn: "How to detect common obfuscation techniques using NeoDAX's combined analysis tools.",
    level_label: "4 - Advanced Analysis",
    content: `# Obfuscation Detection

**Level:** 4 - Advanced Analysis
**Prerequisites:** 44_hottest_functions.md
**What You Will Learn:** How to detect common obfuscation techniques using NeoDAX's combined analysis tools.

## What Obfuscation Is

Obfuscation deliberately makes code harder to analyze without changing its functional behavior. Unlike packing (which compresses code), obfuscation transforms the code itself.

Common techniques include:

- **Control flow flattening:** Replaces structured control flow (if-else, loops) with a state machine dispatch loop.
- **Opaque predicates:** Conditional branches whose outcome is always the same (always taken or never taken) but appears to depend on runtime values.
- **Instruction substitution:** Replaces simple instructions with equivalent sequences of more complex ones.
- **String encryption:** Strings are stored encrypted and decrypted at runtime just before use.
- **Dead code insertion:** Fake instructions or unreachable code blocks mixed into the real code.

## Detecting Control Flow Flattening

Control flow flattening produces a characteristic CFG shape: one large dispatcher block with many incoming edges, and many small case blocks each returning to the dispatcher.

Signs in NeoDAX output:

- Functions with very high block count relative to instruction count
- Many back edges all targeting the same block (the dispatcher)
- Many short basic blocks (2-4 instructions) that all end with the same jump

\`\`\`bash
./neodax -C /bin/suspicious
\`\`\`

Look for a function where nearly every block has an edge back to a single block.

## Detecting Opaque Predicates

Opaque predicates add fake conditional branches that always resolve the same way. They appear as dead code blocks: blocks that are syntactically reachable but practically unreachable.

NeoDAX's recursive descent can expose these: if RDA finds that a significant portion of the code after conditional branches is never actually reached in the control flow from any known entry, those branches may be opaque.

## Detecting String Encryption

Signs:

- Very few readable strings despite apparent complexity
- A function that is called many times with a small integer argument (string index)
- The function returns different values each time based on the argument
- The returned value, when printed as ASCII, forms readable text

The hottest functions analysis often identifies string decryptors: they are called frequently and appear simple (short with arithmetic).

## Detecting Dead Code

The IVF combined with RDA catches dead code injection:

\`\`\`bash
./neodax -V -R /bin/suspicious
\`\`\`

Dead bytes after unconditional branches, unreachable blocks reported by RDA, and invalid opcodes together suggest systematic dead code injection.

## Building an Obfuscation Score

\`\`\`javascript
function obfuscationScore(bin) {
    const result = bin.analyze()
    const entropy = bin.entropy()
    const ivf     = bin.ivf()
    const rda     = bin.rda('.text')

    let score = 0
    const reasons = []

    if (entropy.includes('PACKED')) { score += 3; reasons.push('high entropy') }
    if (!ivf.includes('No suspicious')) { score += 2; reasons.push('IVF flags') }
    if (result.strings?.length < 5) { score += 2; reasons.push('few strings') }

    const avgBlocksPerFn = result.blocks.length / Math.max(result.functions.length, 1)
    if (avgBlocksPerFn > 20) { score += 2; reasons.push('high block count per function') }

    return { score, reasons, likely: score >= 4 }
}
\`\`\`

## Practice

1. Run the combined analysis (\`./neodax -e -V -R -C\`) on a normal binary and on any binary you suspect is obfuscated.
2. Compare the CFG shapes of functions in both.
3. Look for the pattern of a large dispatcher block in any function.

## Next

Continue to \`46_symbol_demangling.md\`.
`
  },
  {
    id: "46_symbol_demangling",
    num: 46,
    level: 4,
    title: "Symbol Demangling",
    prereq: "45_obfuscation_detection.md",
    learn: "How C++ name mangling works and how NeoDAX demangles names for readability.",
    level_label: "4 - Advanced Analysis",
    content: `# Symbol Demangling

**Level:** 4 - Advanced Analysis
**Prerequisites:** 45_obfuscation_detection.md
**What You Will Learn:** How C++ name mangling works and how NeoDAX demangles names for readability.

## Why C++ Names Are Mangled

C++ supports function overloading (multiple functions with the same name but different argument types) and namespaces. The linker, which works with flat name spaces, cannot distinguish \`void foo(int)\` from \`void foo(double)\`.

The solution is name mangling: the compiler encodes type information into the symbol name. The function \`MyClass::process(int, const char*)\` becomes \`_ZN7MyClass7processEiPKc\` in the symbol table.

## The Itanium ABI

The Itanium C++ ABI defines the mangling scheme used by GCC, Clang, and most compilers on Linux and macOS. NeoDAX implements full Itanium ABI demangling.

The \`_Z\` prefix identifies a mangled name. The encoding that follows describes the class name, function name, and parameter types using a compact notation.

## Demangling in the CLI

\`\`\`bash
./neodax -d -y /path/to/cpp_binary
\`\`\`

The \`-d\` flag enables demangling. All symbol names are demangled in the output.

Before demangling:

\`\`\`
0x401234  func  _ZN7MyClass7processEiPKc
0x401290  func  _ZN7MyClass11handleErrorERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
\`\`\`

After demangling with \`-d\`:

\`\`\`
0x401234  func  MyClass::process(int, char const*)
0x401290  func  MyClass::handleError(std::string const&)
\`\`\`

## In JavaScript

\`\`\`javascript
neodax.withBinary('/path/to/cpp_binary', bin => {
    const symbols = bin.symbols()
    symbols.filter(s => s.name.startsWith('_Z')).forEach(s => {
        console.log(s.demangled || s.name)
    })
})
\`\`\`

The symbol object has both \`name\` (mangled) and \`demangled\` (demangled) fields. If demangling fails, \`demangled\` is an empty string.

## Reading Mangled Names

Even without demangling, you can extract some information from mangled names manually:

- \`_ZN\` prefix: nested name (a method in a class or namespace)
- The numbers encode string lengths: \`_ZN7MyClass7process\` has class name length 7 (\`MyClass\`) and method name length 7 (\`process\`)
- \`E\` ends the nested name
- Type letters: \`i\` = int, \`c\` = char, \`d\` = double, \`v\` = void, \`b\` = bool
- \`P\` prefix = pointer, \`R\` prefix = reference, \`K\` modifier = const

## Windows (MSVC) Mangling

The Microsoft Visual C++ compiler uses a different mangling scheme. NeoDAX implements the Itanium scheme. MSVC-mangled names start with \`?\` instead of \`_Z\`.

For Windows binaries, NeoDAX's demangler may not decode MSVC names. You can identify MSVC names by the \`?\` prefix.

## Practice

1. Find a C++ binary on your system (look in \`/usr/lib\` or \`/usr/bin\` for anything with \`++\` in its name or try \`ls /usr/bin/*++\`).
2. Run \`./neodax -d -y <binary>\` and read the demangled names.
3. Identify the class hierarchy from the method names.

## Next

You have completed Level 4 - Advanced Analysis. Continue to \`50_symbolic_execution_intro.md\` to begin Level 5.
`
  },
  {
    id: "50_symbolic_execution_intro",
    num: 50,
    level: 5,
    title: "Symbolic Execution Introduction",
    prereq: "46_symbol_demangling.md",
    learn: "What symbolic execution is, how NeoDAX implements it, and when it is useful.",
    level_label: "5 - Symbolic Execution and Decompilation",
    content: `# Symbolic Execution Introduction

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 46_symbol_demangling.md
**What You Will Learn:** What symbolic execution is, how NeoDAX implements it, and when it is useful.

## What Symbolic Execution Is

Symbolic execution runs code with symbolic values instead of concrete values. Instead of tracking that register \`x0\` contains the value \`42\`, symbolic execution tracks that \`x0\` contains the symbolic expression \`arg0 + 8\`.

As execution proceeds, symbolic expressions accumulate. When a branch condition depends on a symbolic value, symbolic execution notes both possible outcomes without committing to either.

The result is a mapping from function inputs to observable behavior: what does this function return given symbolic inputs? What expressions reach which code paths?

## NeoDAX's Symbolic Execution

NeoDAX implements symbolic execution for ARM64 functions. It builds an expression tree that tracks how register values change throughout a function.

The engine:

- Tracks all 32 ARM64 registers as symbolic expressions
- Evaluates expressions concretely when possible (constant folding)
- Records the symbolic state at each basic block
- Reports the final state of return registers

## Running Symbolic Execution

CLI:

\`\`\`bash
./neodax -P /bin/ls
\`\`\`

This runs symbolic execution on all detected functions and prints the results.

JavaScript:

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const result = bin.symexec(0)  // analyze function at index 0
    console.log(result)
})
\`\`\`

## Reading Symbolic Execution Output

The output for a simple function looks like:

\`\`\`
Function sub_401000 symbolic execution:

  Entry state:
    x0 = arg0
    x1 = arg1

  Block 0x401000:
    x0 = arg0 + 1
    x2 = arg0 * 2

  Exit state:
    x0 = arg0 + 1     (return value)
\`\`\`

This tells you the function takes one argument and returns \`argument + 1\`.

For a more complex function with conditionals:

\`\`\`
  Path 1 (condition: arg0 > 0):
    x0 = arg0 * 2

  Path 2 (condition: arg0 <= 0):
    x0 = 0
\`\`\`

## Limitations

NeoDAX's symbolic execution is intentionally limited for performance:

- ARM64 only (not x86-64 or RISC-V)
- Does not track memory state (only registers)
- Limited to a single function (no interprocedural analysis)
- Does not handle indirect branches to unknown targets

These limitations mean symbolic execution is most useful for small, self-contained functions that manipulate values arithmetically.

## When to Use It

Symbolic execution is most valuable for:

- Understanding what a mathematical transformation function computes
- Identifying the formula used to check a license key or password
- Understanding how values are encoded or decoded
- Identifying constant folding opportunities

It is less useful for functions that depend heavily on memory state or make many function calls.

## Practice

1. Run \`./neodax -P /bin/ls\` and find a function where symbolic execution produces a readable expression.
2. In JavaScript, call \`bin.symexec(0)\` on the first function and print the result.
3. Find a function that takes one integer argument and determine what it returns.

## Next

Continue to \`51_ssa_lifting.md\`.
`
  },
  {
    id: "51_ssa_lifting",
    num: 51,
    level: 5,
    title: "SSA Lifting",
    prereq: "50_symbolic_execution_intro.md",
    learn: "What Static Single Assignment form is and how NeoDAX uses it as an intermediate representation.",
    level_label: "5 - Symbolic Execution and Decompilation",
    content: `# SSA Lifting

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 50_symbolic_execution_intro.md
**What You Will Learn:** What Static Single Assignment form is and how NeoDAX uses it as an intermediate representation.

## What SSA Is

Static Single Assignment (SSA) is a program representation where each variable is assigned exactly once. When a variable is used in multiple code paths, a special phi function merges the different values at the join point.

SSA form makes data flow analysis easier because each use of a variable has exactly one definition. You can trace any value back to its origin without complex aliasing analysis.

## From Assembly to SSA

NeoDAX lifts ARM64 instructions to SSA IR in several steps:

1. Assign unique versions to each register write: \`x0\` becomes \`x0_1\` on the first write, \`x0_2\` on the second, and so on.
2. Insert phi nodes at control flow join points.
3. Replace all register reads with references to the appropriate versioned value.

The result is an IR where data flow is explicit.

## Running SSA Lifting

CLI:

\`\`\`bash
./neodax -Q /bin/ls
\`\`\`

JavaScript:

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const ssa = bin.ssa(0)  // SSA for function at index 0
    console.log(ssa)
})
\`\`\`

## Reading SSA Output

A simple loop in assembly:

\`\`\`
mov  x0, #0          ; counter = 0
loop:
add  x0, x0, #1      ; counter++
cmp  x0, #10
b.lt loop            ; if counter < 10, continue
ret
\`\`\`

In SSA form:

\`\`\`
x0_1 = 0
loop_header:
  x0_2 = phi(x0_1, x0_3)  ; x0 at loop top is either initial or from prev iteration
  x0_3 = x0_2 + 1
  if x0_3 < 10 goto loop_header
  return
\`\`\`

The phi node at the loop header makes explicit that \`x0\` at that point can come from two places: the initial value or the result of the previous iteration.

## SSA and the Decompiler

NeoDAX's decompiler uses SSA as its intermediate representation. After lifting to SSA, it applies transformations to reconstruct higher-level constructs:

- Recognizes loop patterns (a phi node at a block with a back edge)
- Recognizes if-else patterns (phi nodes at merge points with condition context)
- Eliminates redundant phi nodes (phi with all same value)
- Propagates constants

The output of this process is the pseudo-C decompiler output.

## Limitations

SSA lifting in NeoDAX is designed for ARM64 only. It handles straightforward functions well but may struggle with:

- Functions using advanced SIMD or floating-point registers
- Functions with complex memory aliasing
- Heavily optimized or obfuscated code

## Practice

1. Run \`./neodax -Q /bin/ls\` on an ARM64 binary and examine the SSA output.
2. Find a phi node in the output and identify which control flow merge it corresponds to.
3. Compare the SSA output of a simple loop function with its assembly.

## Next

Continue to \`52_decompiler_output.md\`.
`
  },
  {
    id: "52_decompiler_output",
    num: 52,
    level: 5,
    title: "Decompiler Output",
    prereq: "51_ssa_lifting.md",
    learn: "How to use the NeoDAX decompiler and interpret its pseudo-C output.",
    level_label: "5 - Symbolic Execution and Decompilation",
    content: `# Decompiler Output

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 51_ssa_lifting.md
**What You Will Learn:** How to use the NeoDAX decompiler and interpret its pseudo-C output.

## The Decompiler

NeoDAX includes a decompiler that converts ARM64 assembly to pseudo-C. It works by lifting assembly to SSA IR and then applying structural analysis to recover C-like constructs.

The output is pseudo-C: it resembles C but may not compile directly. It is intended as a human-readable approximation of the original code.

## Running the Decompiler

CLI:

\`\`\`bash
./neodax -D /bin/ls
\`\`\`

This decompiles all detected functions.

To decompile a specific function by address range:

\`\`\`bash
./neodax -D -A 0x401000 -E 0x401200 /bin/ls
\`\`\`

JavaScript:

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const fns = bin.functions()
    fns.forEach((fn, i) => {
        const code = bin.decompile(i)
        if (code.trim()) {
            console.log('// Function:', fn.name)
            console.log(code)
            console.log()
        }
    })
})
\`\`\`

## Reading Pseudo-C Output

A simple function that counts the length of an array:

Assembly:

\`\`\`
sub_401000:
  mov  x2, #0
loop:
  ldr  x3, [x0, x2, lsl #3]
  cbz  x3, done
  add  x2, x2, #1
  b    loop
done:
  mov  x0, x2
  ret
\`\`\`

Pseudo-C output:

\`\`\`c
uint64_t sub_401000(uint64_t *x0) {
    uint64_t x2 = 0;
    while (1) {
        uint64_t x3 = x0[x2];
        if (x3 == 0) break;
        x2 = x2 + 1;
    }
    return x2;
}
\`\`\`

The decompiler correctly identifies the loop structure and the break condition.

## When Decompiler Output Is Imperfect

The decompiler produces less readable output for:

- Heavily optimized code with register reuse
- Functions using indirect calls or virtual dispatch
- Code with complex memory operations
- SIMD or floating-point operations (not fully supported)

In these cases, the output may look like:

\`\`\`c
uint64_t sub_401234(uint64_t x0, uint64_t x1) {
    x0 = x0 + x1;
    x0 = x0 << 2;
    // ... many register operations ...
    return x0;
}
\`\`\`

This is still useful as a starting point for manual analysis.

## Combining with Symbolic Execution

For small functions, symbolic execution (Level 5, file 50) may give you a cleaner view of what the function computes. The decompiler gives you structure; symbolic execution gives you the formula.

Use both:

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    const i = 5  // function index
    console.log('=== Decompiled ===')
    console.log(bin.decompile(i))
    console.log('=== Symbolic ===')
    console.log(bin.symexec(i))
})
\`\`\`

## Practice

1. Run \`./neodax -D /bin/ls\` on an ARM64 binary.
2. Find a function where the decompiled output clearly shows a loop.
3. Identify the loop variable and the termination condition.
4. Compare the pseudo-C to the assembly for the same function.

## Next

Continue to \`53_reading_pseudo_c.md\`.
`
  },
  {
    id: "53_reading_pseudo_c",
    num: 53,
    level: 5,
    title: "Reading Pseudo-C Output",
    prereq: "52_decompiler_output.md",
    learn: "Techniques for reading and understanding decompiler output, including handling imperfect output.",
    level_label: "5 - Symbolic Execution and Decompilation",
    content: `# Reading Pseudo-C Output

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 52_decompiler_output.md
**What You Will Learn:** Techniques for reading and understanding decompiler output, including handling imperfect output.

## The Goal of Pseudo-C

The decompiler does not need to produce compilable C. It needs to produce something a human can read faster than raw assembly. Even imperfect pseudo-C is valuable if it conveys the structure.

## Simplifying the Output Mentally

When reading pseudo-C, apply these mental transformations:

**Rename variables based on context.** The decompiler uses generic names like \`x0\`, \`x1\`, \`var_8\`. When you understand what a variable represents, rename it mentally.

If you see:

\`\`\`c
uint64_t x0 = strlen(x1);
\`\`\`

Rename: \`x1\` is a string pointer, \`x0\` is the string length.

**Recognize patterns.** Common code patterns appear in predictable pseudo-C forms:

A length-bounded copy:

\`\`\`c
uint64_t i = 0;
while (i < length) {
    dest[i] = src[i];
    i = i + 1;
}
\`\`\`

A null-terminated string scan:

\`\`\`c
uint64_t p = str;
while (*p != 0) {
    p = p + 1;
}
return p - str;
\`\`\`

**Ignore register artifact noise.** Sometimes the decompiler produces:

\`\`\`c
x3 = x0;
x0 = x3 + 1;
\`\`\`

This is really just \`x0 = x0 + 1\`. The extra assignment is an artifact of the register versioning.

## Handling Unknown Functions

When the decompiler shows a call to an unknown function address:

\`\`\`c
x0 = sub_401234(x0, x1);
\`\`\`

Cross-reference it with the symbol table. The address \`0x401234\` may correspond to a known PLT symbol, making the call:

\`\`\`c
x0 = malloc(x0);
\`\`\`

Use the \`-y\` flag or the JavaScript \`symAt()\` method to look up addresses.

## Data Type Inference

The decompiler uses \`uint64_t\` for most values because ARM64 registers are 64-bit. When you know a value is actually a 32-bit int, a pointer, or a boolean, you can mentally substitute the correct type.

Clues:
- A value passed to \`strlen\` is a \`char*\`
- A value compared with small constants (0, 1, -1) is probably an \`int\` or \`bool\`
- A value used with array indexing is a pointer
- A value that only appears in comparisons and branches is likely a status code

## Iterative Refinement

Understanding complex decompiler output is iterative:

1. Read the whole function once to get the big picture.
2. Identify the most important variables.
3. Rename them.
4. Re-read with the new names.
5. Identify any sub-functions that are called and understand what they do.
6. Re-read with that knowledge.

After a few iterations, most functions become clear.

## Practice

1. Decompile a function that has at least two nested loops.
2. Rename all variables to meaningful names based on context.
3. Write a one-paragraph description of what the function does.
4. Verify your understanding by checking against any available documentation or source code.

## Next

Continue to \`54_arm64_emulator.md\`.
`
  },
  {
    id: "54_arm64_emulator",
    num: 54,
    level: 5,
    title: "ARM64 Emulator",
    prereq: "53_reading_pseudo_c.md",
    learn: "How the NeoDAX ARM64 emulator works and when concrete emulation is useful.",
    level_label: "5 - Symbolic Execution and Decompilation",
    content: `# ARM64 Emulator

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 53_reading_pseudo_c.md
**What You Will Learn:** How the NeoDAX ARM64 emulator works and when concrete emulation is useful.

## Concrete vs Symbolic Execution

Symbolic execution (file 50) tracks values as symbolic expressions. Concrete emulation runs the code with actual values, just like the real CPU would, but inside a controlled environment.

NeoDAX includes a concrete ARM64 emulator that:

- Maintains a full 32-register file
- Simulates a page-based memory model (64 pages of 4KB each)
- Tracks CPSR (condition flags)
- Stops at \`ret\`, \`bl\`/\`blr\` (to prevent running into called functions), or after a maximum step count

## Running the Emulator

CLI:

\`\`\`bash
./neodax -I /bin/ls
\`\`\`

JavaScript:

\`\`\`javascript
neodax.withBinary('/bin/ls', bin => {
    // Emulate function 0 with x0=42
    const result = bin.emulate(0, { '0': 42n })
    console.log(result)
})
\`\`\`

The second argument is a map of register index (as string) to BigInt initial value. Register indices: 0=x0, 1=x1, ..., 30=x30.

## Reading Emulator Output

The emulator prints a trace of register state changes:

\`\`\`
Emulating function sub_401000 (x0=42)

Step 1: 0x401000  mov x2, #0
  x2: 0 -> 0

Step 2: 0x401004  add x2, x2, #1
  x2: 0 -> 1

...

Emulation complete: 15 steps
  Final x0: 5 (return value)
  Halt reason: ret
\`\`\`

## What Concrete Emulation Shows

Unlike symbolic execution, concrete emulation produces actual values. This is useful when:

**Testing decryption functions:** Set x0 to the address of an encrypted buffer and x1 to the key, then run the emulator to see what the output would be.

**Tracing initialization routines:** Run the initializer with specific inputs to see what state it produces.

**Understanding arithmetic transformations:** For a function that transforms a value through complex bit manipulation, emulation immediately shows you the input-output relationship for specific values.

## Limitations

The emulator stops at function calls (\`bl\`/\`blr\`) because it cannot emulate external functions like \`malloc\` or \`printf\`. If the function under analysis calls other functions early on, the trace will be short.

The page-based memory model is simplified. Complex memory operations that span page boundaries or rely on specific memory layouts may not work correctly.

The emulator does not handle SIMD instructions, system registers, or privileged instructions.

## Combining with Symbolic Execution

Use symbolic execution to understand the general formula, and concrete emulation to verify specific inputs:

1. Symbolic execution: "This function computes \`arg0 * 2 + arg1\`"
2. Concrete emulation with \`{0: 5n, 1: 3n}\`: "Returns 13, which confirms \`5*2+3=13\`"

## Practice

1. Run \`./neodax -I /bin/ls\` on an ARM64 binary.
2. Using JavaScript, emulate function index 0 with different initial register values.
3. Find a function that takes one argument and determine its return value for inputs 0, 1, and 2.

## Next

Continue to \`55_emulator_use_cases.md\`.
`
  },
  {
    id: "55_emulator_use_cases",
    num: 55,
    level: 5,
    title: "Emulator Use Cases",
    prereq: "54_arm64_emulator.md",
    learn: "Practical ways to apply the ARM64 emulator in real analysis scenarios.",
    level_label: "5 - Symbolic Execution and Decompilation",
    content: `# Emulator Use Cases

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 54_arm64_emulator.md
**What You Will Learn:** Practical ways to apply the ARM64 emulator in real analysis scenarios.

## Use Case 1: Decrypting Strings

Many malware samples encrypt their strings at compile time and decrypt them at runtime. The decryption function is called with an index or a pointer to encrypted data.

To use the emulator to decrypt strings:

1. Identify the string decryption function using hottest functions analysis (it is called many times) and decompiler output (it has XOR or arithmetic operations).
2. Find the encrypted string data in the binary using \`readBytes\`.
3. Set up the emulator with the appropriate arguments.
4. Read the output buffer from the emulator trace.

\`\`\`javascript
neodax.withBinary('/path/to/malware', bin => {
    const fnIndex = 5  // index of suspected string decryptor
    const encryptedAddr = 0x401234n

    // Emulate with pointer to encrypted string as argument
    const result = bin.emulate(fnIndex, { '0': encryptedAddr })
    console.log(result)
})
\`\`\`

## Use Case 2: Understanding Hash Functions

Security-critical code sometimes includes custom hash or checksum functions for integrity verification. The emulator reveals what the function computes:

\`\`\`javascript
neodax.withBinary('/path/to/binary', bin => {
    // Try several inputs to understand the hash function
    [0n, 1n, 255n, 65536n].forEach(input => {
        const result = bin.emulate(fnIndex, { '0': input })
        console.log(\`hash(\${input}) = ...\`)  // read from result
    })
})
\`\`\`

## Use Case 3: Identifying Key Derivation

If a binary derives encryption keys from some input, the key derivation function takes a password or seed and produces key material. Emulating with known inputs lets you verify the key derivation algorithm.

## Use Case 4: Verification Functions

License check functions, serial number validators, and crackme challenges typically take a string or number as input and return a boolean. The emulator can quickly test whether specific inputs pass the check.

## Use Case 5: Understanding State Machines

Binaries that implement protocol parsers or command processors often have state machine functions. Emulating with specific state inputs shows you the transitions.

## Limitations to Keep in Mind

The emulator stops at external function calls. If the function you want to emulate calls \`malloc\` early on, the trace will stop before the interesting part.

Workaround: if the function only calls internal helper functions, and you know the indices of those helpers, you can emulate the helper first and then continue from where it left off.

## Extending with JavaScript

The emulator output is a string report. For automated analysis, you may want to parse the final register state from the output:

\`\`\`javascript
function getReturnValue(emulateOutput) {
    const match = emulateOutput.match(/Final x0:\\s*(0x[0-9a-f]+|\\d+)/)
    if (match) return BigInt(match[1])
    return null
}
\`\`\`

## Practice

1. Find a function in any ARM64 binary that takes one integer argument.
2. Emulate it with 5 different inputs.
3. Determine the relationship between input and output (linear, lookup table, etc.).

## Next

You have completed Level 5. Continue to \`60_analyzing_malware_basics.md\` to begin Level 6.
`
  },
  {
    id: "60_analyzing_malware_basics",
    num: 60,
    level: 6,
    title: "Analyzing Malware Basics",
    prereq: "55_emulator_use_cases.md",
    learn: "A safe, systematic approach to analyzing suspicious binaries using NeoDAX.",
    level_label: "6 - Real World Reverse Engineering",
    content: `# Analyzing Malware Basics

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 55_emulator_use_cases.md
**What You Will Learn:** A safe, systematic approach to analyzing suspicious binaries using NeoDAX.

## Safety First

Never run malware on your analysis machine without appropriate isolation. Use a virtual machine or a dedicated analysis device that you can restore to a clean state.

NeoDAX is a static analysis tool. It never executes the binary. This makes it safe to use on malware: you are reading the binary file, not running it.

## Initial Triage

When you receive a suspicious binary, run a quick triage before deep analysis:

\`\`\`bash
./neodax -l -y -t -e /path/to/suspicious
\`\`\`

This gives you:
1. Section layout (are the section names normal?)
2. Import symbols (what capabilities does it use?)
3. Strings (what does it talk about?)
4. Entropy (is it packed?)

From these four pieces of information, you can form a first hypothesis about what the binary does.

## Reading the Import Table

The most revealing quick analysis for malware is the import table. The functions a binary imports from system libraries directly reveal its capabilities.

Look for these categories of imports:

**File operations:** \`CreateFile\`, \`ReadFile\`, \`WriteFile\`, \`DeleteFile\`, \`CopyFile\` (Windows) or \`open\`, \`read\`, \`write\`, \`unlink\` (Linux/macOS)

**Network operations:** \`connect\`, \`send\`, \`recv\`, \`gethostbyname\`, \`WSAStartup\`, \`socket\`

**Process operations:** \`CreateProcess\`, \`OpenProcess\`, \`VirtualAlloc\`, \`WriteProcessMemory\`

**Registry operations (Windows):** \`RegOpenKey\`, \`RegSetValue\`, \`RegDeleteKey\`

**Cryptography:** \`CryptEncrypt\`, \`CryptDecrypt\`, \`MD5Update\`, \`SHA1Final\`

**Anti-analysis:** \`IsDebuggerPresent\`, \`CheckRemoteDebuggerPresent\`, \`GetTickCount\` (timing check), \`VirtualQueryEx\` (checking for analysis tools)

## The Analysis Workflow

A structured approach:

1. **Triage:** Section layout, imports, strings, entropy.
2. **Identify the entry point behavior:** What does the startup code do? Does it check for debuggers? Set up persistence?
3. **Find communication:** Look for network-related imports and the functions that use them.
4. **Find payload execution:** If the binary downloads or decrypts code, find where that code is executed.
5. **Understand the purpose:** Combine all findings into a description.

## Common Patterns in Malware

**Dropper:** Downloads or extracts a second payload and executes it. Look for file write operations followed by process creation.

**Loader:** Decrypts a payload in memory and executes it without writing to disk. High entropy data section, VirtualAlloc with execute permission, function pointer call.

**RAT (Remote Access Tool):** Connects to a C2 server, receives commands, executes them. Network operations combined with command dispatch (switch table) and system operations.

**Ransomware:** Enumerates files, encrypts them, writes ransom note. File enumeration operations, crypto functions, file write operations.

## Practice

1. If you have a safe, known malware sample (from a CTF or an analysis sandbox), run the initial triage.
2. List the imported functions and categorize them.
3. Find the most-called internal function and determine what it does.

## Next

Continue to \`61_crackme_walkthrough.md\`.
`
  },
  {
    id: "61_crackme_walkthrough",
    num: 61,
    level: 6,
    title: "Crackme Walkthrough",
    prereq: "60_analyzing_malware_basics.md",
    learn: "A complete walkthrough of analyzing a crackme challenge using NeoDAX techniques.",
    level_label: "6 - Real World Reverse Engineering",
    content: `# Crackme Walkthrough

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 60_analyzing_malware_basics.md
**What You Will Learn:** A complete walkthrough of analyzing a crackme challenge using NeoDAX techniques.

## What is a Crackme

A crackme is a program designed for reverse engineering practice. It typically asks for a password, serial number, or key, and your goal is to find the correct input through analysis rather than guessing.

Crackmes are ideal for practice because they are intentionally solvable and you can verify your answer.

## Step 1: Initial Recon

Start with triage:

\`\`\`bash
./neodax -l -y -t /crackme
\`\`\`

Key questions:
- Is there a string like "Correct!" or "Wrong password"?
- Are there imported functions suggesting how input is processed?
- Is the binary stripped?

## Step 2: Find the Check Function

Look for the function that prints "Correct!" or "Wrong". Use cross-references:

\`\`\`bash
./neodax -r -t /crackme
\`\`\`

Find the address of the "Correct!" string in the output. Then find which code address references that string. That code is in the check function.

## Step 3: Analyze the Check

Disassemble the check function:

\`\`\`bash
./neodax -A <check_function_start> -E <check_function_end> /crackme
\`\`\`

Look for:
- How is the input read? (via \`read\`, \`scanf\`, \`gets\`, \`fgets\`)
- What transformations are applied to the input?
- What is the input compared against?

## Step 4: Use the Decompiler (ARM64)

On ARM64 crackmes, the decompiler gives you pseudo-C:

\`\`\`bash
./neodax -D -A <start> -E <end> /crackme
\`\`\`

Read the pseudo-C to understand the algorithm directly.

## Step 5: Use Symbolic Execution

Run symbolic execution on the check function:

\`\`\`bash
./neodax -P /crackme
\`\`\`

This may directly tell you the relationship between input and the expected value.

## Step 6: Verify

Once you have determined the expected input:

1. Run the crackme with your answer.
2. If you see "Correct!", you have solved it.

## Common Crackme Patterns

**Direct comparison:** The input is compared byte-by-byte or as a whole against a hardcoded string. Read the string from the binary.

**Transformed comparison:** The input is transformed (hashed, encrypted, XOR'd) before comparison. Use symbolic execution or the decompiler to understand the transform.

**Checksum-based:** The sum, product, or XOR of the input's characters must equal a specific value. Multiple inputs satisfy the condition.

**Time-based:** The check uses the current time. Understand the expected state.

## Practice

1. Find a crackme challenge online (crackmes.one is a common resource).
2. Apply the full NeoDAX analysis pipeline.
3. Write notes at each step documenting your findings.
4. Solve the crackme and verify your solution.

## Next

Continue to \`62_finding_vulnerabilities.md\`.
`
  },
  {
    id: "62_finding_vulnerabilities",
    num: 62,
    level: 6,
    title: "Finding Vulnerabilities",
    prereq: "61_crackme_walkthrough.md",
    learn: "How to use NeoDAX to identify common vulnerability patterns in binary code.",
    level_label: "6 - Real World Reverse Engineering",
    content: `# Finding Vulnerabilities

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 61_crackme_walkthrough.md
**What You Will Learn:** How to use NeoDAX to identify common vulnerability patterns in binary code.

## What NeoDAX Can Help With

NeoDAX is a static analysis tool. It excels at finding patterns in code that suggest vulnerabilities. It does not automatically discover exploitable vulnerabilities, but it helps you find areas worth investigating more closely.

## Buffer Overflow Patterns

A classic buffer overflow occurs when code copies data into a fixed-size buffer without checking the length.

Look for:
- Calls to \`strcpy\`, \`gets\`, \`sprintf\` (unsafe string functions)
- A \`malloc\` or stack allocation followed by a \`memcpy\` or loop that writes without bounds checking

In NeoDAX:

\`\`\`bash
./neodax -y -r /binary
\`\`\`

Look in the xref table for calls to \`strcpy@plt\` or \`gets@plt\`. Each call site is a potential overflow location.

## Use-After-Free Patterns

Use-after-free bugs occur when memory is freed but then accessed again. In static analysis, look for:

- A \`free\` call followed by a use of the same pointer
- A pointer stored in a structure that is freed while the pointer is still accessible

Trace the lifetime of pointers from \`malloc\` through \`free\` and any subsequent uses.

## Format String Vulnerabilities

Format string bugs occur when user-controlled input is passed as the format argument to \`printf\`-family functions.

Search for:

\`\`\`bash
./neodax -y -t /binary | grep "printf@plt"
\`\`\`

Then examine the call sites. If \`rdi\` (the first argument, the format string) is loaded from user input rather than a constant string, it is a format string vulnerability.

## Integer Overflow Patterns

Integer overflow occurs when arithmetic wraps around the integer size boundary. Common patterns:

- A length value is computed with arithmetic on user input, then used as a \`malloc\` size
- A multiplication \`size * count\` without overflow checking
- A subtraction that can produce a negative result used as an unsigned size

Look for arithmetic instructions before \`malloc\` calls.

## NeoDAX Analysis for Vulnerabilities

A practical workflow:

1. Find all calls to unsafe functions:
   \`\`\`bash
   ./neodax -y /binary | grep -E "strcpy|gets|sprintf|scanf"
   \`\`\`

2. For each dangerous call, disassemble around it to understand the context:
   \`\`\`bash
   ./neodax -A <call_address - 50> -E <call_address + 50> /binary
   \`\`\`

3. Identify whether input validation happens before the dangerous call.

4. If no validation: potential vulnerability. Note the location.

## Practice

1. Write a small C program with a known buffer overflow (\`strcpy\` without length check).
2. Compile it and analyze it with NeoDAX.
3. Find the call to \`strcpy@plt\` in the output.
4. Verify that no length check exists before the call.

## Next

Continue to \`63_reverse_engineering_protocols.md\`.
`
  },
  {
    id: "63_reverse_engineering_protocols",
    num: 63,
    level: 6,
    title: "Reverse Engineering Protocols",
    prereq: "62_finding_vulnerabilities.md",
    learn: "How to use NeoDAX to understand custom network protocols and data formats.",
    level_label: "6 - Real World Reverse Engineering",
    content: `# Reverse Engineering Protocols

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 62_finding_vulnerabilities.md
**What You Will Learn:** How to use NeoDAX to understand custom network protocols and data formats.

## Why Protocol RE Is Valuable

Many applications communicate using undocumented protocols. Understanding these protocols is necessary for:

- Building compatible clients or servers
- Security testing of the protocol
- Analyzing malware command-and-control communication
- Interoperability projects

## Finding Network Code

Start by looking for network-related imports:

\`\`\`bash
./neodax -y /binary | grep -E "socket|connect|send|recv|htons|htonl"
\`\`\`

The functions that call these imports are the network I/O functions. They are your starting point.

## Tracing Data Flow

Once you have the send/receive functions, trace the data flow:

1. Find where received data is stored (what buffer does \`recv\` write into?).
2. Find what code reads from that buffer.
3. That code is the protocol parser.

Work from the receive call outward through cross-references:

\`\`\`bash
./neodax -r /binary
\`\`\`

Find xrefs from the address where \`recv@plt\` is called. The function containing that call is the receive handler.

## Identifying Protocol Structure

Look for patterns in the parsing code:

**Fixed header:** Code reads a fixed number of bytes first, then uses values in those bytes to determine what follows. The header size and field offsets are visible as constants.

**Length-prefixed fields:** A field read pattern where the length is read first, then that many bytes are read. The length field offset is a constant.

**Magic numbers:** Values compared with specific constants at the start of messages. These are message type codes or protocol magic.

**State machine dispatch:** A switch statement that dispatches based on a message type field. The switch table contains one case per message type.

## Extracting Protocol Definitions

As you identify fields, build a protocol definition:

\`\`\`
Packet header (16 bytes):
  offset 0: uint32 magic (0xDEADBEEF)
  offset 4: uint16 message_type
  offset 6: uint16 flags
  offset 8: uint32 sequence_number
  offset 12: uint32 payload_length

Payload: payload_length bytes
\`\`\`

## Documenting as You Go

Create a markdown file documenting what you find. Use NeoDAX's string extraction to find error messages that confirm your understanding:

\`\`\`bash
./neodax -t /binary | grep -i "invalid\\|unknown\\|error\\|bad"
\`\`\`

Error message strings often name protocol concepts: "invalid magic", "unknown message type", "bad length".

## Practice

1. Find a binary that makes network connections.
2. Identify the send and receive functions.
3. Trace what happens to received data.
4. Document at least the first 8 bytes of the protocol header.

## Next

Continue to \`64_android_binary_analysis.md\`.
`
  },
  {
    id: "64_android_binary_analysis",
    num: 64,
    level: 6,
    title: "Android Binary Analysis",
    prereq: "63_reverse_engineering_protocols.md",
    learn: "How to analyze Android native libraries and binaries with NeoDAX on Termux.",
    level_label: "6 - Real World Reverse Engineering",
    content: `# Android Binary Analysis

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 63_reverse_engineering_protocols.md
**What You Will Learn:** How to analyze Android native libraries and binaries with NeoDAX on Termux.

## Android Binary Formats

Android applications (APKs) contain several types of code:

**Dalvik bytecode (.dex files):** Java/Kotlin code compiled to Dalvik bytecode. NeoDAX does not analyze .dex files.

**Native libraries (.so files):** C/C++ code compiled as ELF shared objects for ARM64 or x86-64. NeoDAX analyzes these fully.

**Executable binaries:** Some apps ship standalone executable binaries in their \`assets\` or \`lib\` directories. These are ELF files.

## Extracting Native Libraries

APK files are ZIP archives. Extract them to access the native libraries:

\`\`\`bash
cd /sdcard/Download
unzip myapp.apk -d myapp_extracted
ls myapp_extracted/lib/
# arm64-v8a/   armeabi-v7a/   x86/   x86_64/
\`\`\`

The \`arm64-v8a\` directory contains ARM64 \`.so\` files, which are the most relevant on modern Android devices.

## Analyzing with NeoDAX on Termux

NeoDAX runs natively on Android with Termux. After extraction:

\`\`\`bash
./neodax -l myapp_extracted/lib/arm64-v8a/libnative.so
./neodax -y myapp_extracted/lib/arm64-v8a/libnative.so
./neodax -x myapp_extracted/lib/arm64-v8a/libnative.so
\`\`\`

## JNI Functions

Native libraries that interface with Java use JNI (Java Native Interface). JNI functions have names starting with \`Java_\`:

\`\`\`
Java_com_example_app_MainActivity_checkLicense
Java_com_example_app_NativeLib_processData
\`\`\`

These are the entry points where Java code calls into native code. They are excellent starting points for analysis because they represent the native library's public API.

\`\`\`bash
./neodax -y mylib.so | grep "^Java_"
\`\`\`

## Understanding JNI Signatures

JNI functions always receive two parameters before the user parameters:

- \`x0/rdi\`: JNI environment pointer
- \`x1/rsi\`: Java object (the \`this\` reference or class reference)
- \`x2/rdx\` onwards: actual parameters

A Java method \`boolean checkLicense(String key)\` corresponds to a C function:

\`\`\`c
jboolean Java_com_example_app_MainActivity_checkLicense(
    JNIEnv *env,
    jobject thiz,
    jstring key
);
\`\`\`

In the disassembly, the first two arguments are the JNI internals. The third is your actual parameter.

## Common Analysis Targets

**License checks:** Functions like \`checkLicense\`, \`validateKey\`, \`verifyPurchase\`. These are common targets for cracking.

**Anti-tampering:** Functions that verify APK integrity, check for root, or detect analysis tools.

**Cryptographic operations:** Functions that encrypt or decrypt data.

**C2 communication:** Functions that connect to remote servers.

## Practice

1. Install an APK on your Android device.
2. Extract it and find the native libraries.
3. List the JNI function names.
4. Pick one JNI function and analyze what it does.

## Next

Continue to \`65_stripping_and_obfuscation.md\`.
`
  },
  {
    id: "65_stripping_and_obfuscation",
    num: 65,
    level: 6,
    title: "Stripping and Obfuscation in Practice",
    prereq: "64_android_binary_analysis.md",
    learn: "Practical strategies for analyzing stripped and lightly obfuscated binaries.",
    level_label: "6 - Real World Reverse Engineering",
    content: `# Stripping and Obfuscation in Practice

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 64_android_binary_analysis.md
**What You Will Learn:** Practical strategies for analyzing stripped and lightly obfuscated binaries.

## The Reality of Stripped Binaries

Most released software is stripped. You will rarely have symbol names for internal functions. The question is not "how do I avoid stripped binaries" but "how do I work effectively with them."

## Rebuilding Semantic Understanding

When working with a stripped binary, rebuild understanding from context:

**Behavior clues:** What does the function do to its inputs? Does it return 0 or 1? Does it modify a buffer? Does it call specific external functions?

**Call context:** If \`sub_401234\` is always called with a pointer and a length, and always precedes a network send, it is probably a serialization function.

**String context:** If a function prints a specific string, you know something about its purpose.

**Naming strategy:** Give functions names as you understand them. \`sub_401234\` becomes \`check_license\` once you understand it. Document your names alongside the addresses.

## Working with Function Lists

Build your own symbol table as you analyze:

\`\`\`javascript
const mySymbols = {
    0x401234n: 'check_license',
    0x401500n: 'decrypt_string',
    0x401800n: 'send_request',
}

neodax.withBinary('/binary', bin => {
    const fns = bin.functions()
    fns.forEach(fn => {
        const name = mySymbols[fn.start] || fn.name
        console.log('0x' + fn.start.toString(16), name)
    })
})
\`\`\`

## Light Obfuscation Patterns

Some binaries use light obfuscation that NeoDAX's standard analysis handles:

**Jump tables used as dispatch:** Covered by switch table detection.

**Dead code insertion:** Covered by IVF and RDA.

**Instruction substitution (e.g., \`xor eax, eax\` instead of \`mov eax, 0\`):** Recognized by the assembler; the decompiler normalizes these.

**String obfuscation:** Covered by the emulator and symbolic execution.

## When Standard Analysis Fails

For heavily obfuscated code:

1. Identify the obfuscation technique from the patterns (high block count, switch-heavy dispatch, etc.).
2. Look for the deobfuscator: the function that transforms obfuscated code to runnable form.
3. Analyze the deobfuscator, not the obfuscated code.
4. Use dynamic analysis tools to observe the deobfuscated code at runtime.

## Documentation Habits

Good reverse engineering requires good notes:

- Record your hypotheses and the evidence for them
- Record addresses alongside your interpretations
- Record what you have ruled out as well as what you have confirmed

A well-maintained notes file is more valuable than hours of undocumented analysis.

## Practice

1. Take a stripped binary and list all functions.
2. Without any symbol names, identify at least 3 functions based on behavior analysis.
3. Document your reasoning for each identification.

## Next

Continue to \`66_daxc_snapshots.md\`.
`
  },
  {
    id: "66_daxc_snapshots",
    num: 66,
    level: 6,
    title: "DAXC Snapshots",
    prereq: "65_stripping_and_obfuscation.md",
    learn: "How to use DAXC snapshots to save and reload analysis state.",
    level_label: "6 - Real World Reverse Engineering",
    content: `# DAXC Snapshots

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 65_stripping_and_obfuscation.md
**What You Will Learn:** How to use DAXC snapshots to save and reload analysis state.

## What DAXC Is

DAXC (NeoDAX Compiled) is NeoDAX's binary snapshot format. It saves the results of a complete analysis to a file that can be reloaded instantly without re-analyzing the original binary.

This is useful when:
- The original binary is large and analysis is slow
- You want to share analysis results without sharing the binary
- You want to resume analysis later from a saved state

## Creating a Snapshot

\`\`\`bash
./neodax -x -o snapshot.daxc /path/to/binary
\`\`\`

The \`-o\` flag specifies the output file. The snapshot includes:

- Binary metadata (arch, format, SHA-256, etc.)
- Section layout
- Symbols
- Detected functions
- Cross-references
- CFG blocks
- Extracted strings

## Loading a Snapshot

\`\`\`bash
./neodax -c snapshot.daxc
\`\`\`

The \`-c\` flag loads a DAXC snapshot. The output is the same as running the full analysis on the original binary, but much faster because everything was precomputed.

## DAXC Format Details

The DAXC format uses the magic bytes \`NEOX\` followed by a version number. The current version is 4.

The format is compact and binary, not human-readable. It is designed for fast loading, not inspection. See \`FORMAT_DAXC.md\` for the complete specification.

## Sharing Analysis

You can share a DAXC snapshot with a colleague who also has NeoDAX installed. They can load the snapshot and see your analysis results without needing the original binary.

This is useful for:
- Team analysis workflows
- Sharing malware analysis results (without sharing the malware)
- Archiving analysis of specific binary versions

## Limitations

A DAXC snapshot captures the analysis state at the time of creation. If you discover new information later (a renamed function, new cross-references), you need to re-run the analysis and create a new snapshot.

The snapshot does not include the original binary's bytes. Disassembly can be re-run from the snapshot because the relevant bytes are stored, but you cannot extract arbitrary sections of the original binary from a snapshot.

## Practice

1. Run \`./neodax -x -o test.daxc /bin/ls\`.
2. Load it with \`./neodax -c test.daxc\` and verify the output matches.
3. Compare the load times between analyzing from the original binary and loading the snapshot.

## Next

You have completed Level 6 - Real World RE. Continue to \`70_rest_api_automation.md\` to begin Level 7.
`
  },
  {
    id: "70_rest_api_automation",
    num: 70,
    level: 7,
    title: "REST API Automation",
    prereq: "66_daxc_snapshots.md",
    learn: "How to use the NeoDAX REST API to integrate binary analysis into other tools.",
    level_label: "7 - Integration and Automation",
    content: `# REST API Automation

**Level:** 7 - Integration and Automation
**Prerequisites:** 66_daxc_snapshots.md
**What You Will Learn:** How to use the NeoDAX REST API to integrate binary analysis into other tools.

## The REST API Server

NeoDAX ships with a Node.js REST API server:

\`\`\`bash
node js/server/server.js
\`\`\`

By default it listens on port 7070. Access the web UI at \`http://localhost:7070/ui\`.

## API Endpoints

All endpoints accept POST requests with JSON bodies:

| Endpoint | Body | Returns |
|----------|------|---------|
| /api/info | { file } | Binary metadata |
| /api/sections | { file } | Section list |
| /api/symbols | { file } | Symbol list |
| /api/functions | { file } | Function list |
| /api/xrefs | { file } | Xref list |
| /api/disasm | { file, section, limit } | Disassembly |
| /api/analyze | { file } | Full analysis |
| /api/entropy | { file } | Entropy report |
| /api/decompile | { file, funcIdx } | Pseudo-C |
| /api/symexec | { file, funcIdx } | Symbolic execution |
| /api/ivf | { file } | Validity filter |
| /api/strings | { file } | String extraction |
| /api/hottest | { file, n } | Hottest functions |

## Making API Calls

From any HTTP client:

\`\`\`bash
curl -X POST http://localhost:7070/api/sections      -H "Content-Type: application/json"      -d '{"file": "/bin/ls"}'
\`\`\`

From Python:

\`\`\`python
import requests, json

def analyze(binary_path):
    base = "http://localhost:7070"
    payload = {"file": binary_path}

    r = requests.post(f"{base}/api/analyze", json=payload)
    result = r.json()

    print(f"Arch: {result['info']['arch']}")
    print(f"Functions: {len(result['functions'])}")
    return result
\`\`\`

From JavaScript (client-side or Node.js):

\`\`\`javascript
async function getDisassembly(file, section = '.text', limit = 100) {
    const res = await fetch('http://localhost:7070/api/disasm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file, section, limit })
    })
    return res.json()
}
\`\`\`

## Building a Simple Analysis Pipeline

A Python script that analyzes a directory of binaries:

\`\`\`python
import requests
import os
import json

BASE = "http://localhost:7070"

def quick_scan(directory):
    results = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        try:
            r = requests.post(f"{BASE}/api/analyze", json={"file": path}, timeout=30)
            if r.status_code == 200:
                data = r.json()
                results.append({
                    "name": name,
                    "arch": data["info"]["arch"],
                    "functions": len(data["functions"]),
                    "stripped": data["info"]["isStripped"],
                })
        except Exception as e:
            results.append({"name": name, "error": str(e)})
    return results

results = quick_scan("/usr/bin")
for r in sorted(results, key=lambda x: x.get("functions", 0), reverse=True)[:10]:
    print(r)
\`\`\`

## Practice

1. Start the NeoDAX REST API server.
2. Make a curl request to \`/api/sections\` for \`/bin/ls\`.
3. Write a Python or shell script that prints the function count for each binary in a directory.

## Next

Continue to \`71_building_analysis_scripts.md\`.
`
  },
  {
    id: "71_building_analysis_scripts",
    num: 71,
    level: 7,
    title: "Building Analysis Scripts",
    prereq: "70_rest_api_automation.md",
    learn: "How to build reusable analysis scripts using the NeoDAX JavaScript API.",
    level_label: "7 - Integration and Automation",
    content: `# Building Analysis Scripts

**Level:** 7 - Integration and Automation
**Prerequisites:** 70_rest_api_automation.md
**What You Will Learn:** How to build reusable analysis scripts using the NeoDAX JavaScript API.

## Script Design Principles

Good analysis scripts are:

- **Idempotent:** Running the script twice gives the same result.
- **Error tolerant:** A failed binary does not crash the whole batch.
- **Informative:** The script prints progress and clear error messages.
- **Reusable:** Common logic is in functions, not copy-pasted.

## A Reusable Analysis Base

\`\`\`javascript
const neodax = require('neodax')
const path   = require('path')
const fs     = require('fs')

function analyzeSafe(filePath) {
    try {
        let result = null
        neodax.withBinary(filePath, bin => {
            result = {
                name:       path.basename(filePath),
                path:       filePath,
                sha256:     bin.sha256,
                arch:       bin.arch,
                format:     bin.format,
                isPie:      bin.isPie,
                isStripped: bin.isStripped,
                sections:   bin.sections().length,
                functions:  bin.functions().length,
                symbols:    bin.symbols().length,
            }
        })
        return result
    } catch (e) {
        return {
            name:  path.basename(filePath),
            path:  filePath,
            error: e.message
        }
    }
}

function analyzeDirectory(dirPath, outputPath) {
    const entries = fs.readdirSync(dirPath)
        .map(name => path.join(dirPath, name))
        .filter(p => fs.statSync(p).isFile())

    console.log(\`Analyzing \${entries.length} files in \${dirPath}\`)
    const results = entries.map((filePath, i) => {
        process.stdout.write(\`\\r\${i+1}/\${entries.length}: \${path.basename(filePath)}\`)
        return analyzeSafe(filePath)
    })
    console.log()

    fs.writeFileSync(outputPath, JSON.stringify(results, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v, 2))
    console.log(\`Results saved to \${outputPath}\`)
    return results
}

const [,, dir = '/usr/bin', out = '/tmp/analysis.json'] = process.argv
const results = analyzeDirectory(dir, out)
const successful = results.filter(r => !r.error)
console.log(\`\\nSuccessful: \${successful.length}, Failed: \${results.length - successful.length}\`)
\`\`\`

## A Suspicious Binary Detector

\`\`\`javascript
const neodax = require('neodax')

function suspicionScore(filePath) {
    const signals = []
    let score = 0

    neodax.withBinary(filePath, bin => {
        const secs = bin.sections()
        const syms = bin.symbols()
        const fns  = bin.functions()

        if (syms.length < 3) {
            signals.push('very few symbols')
            score += 2
        }

        if (secs.length < 3) {
            signals.push('few sections')
            score += 1
        }

        const entropy = bin.entropy()
        if (entropy.includes('PACKED')) {
            signals.push('high entropy')
            score += 3
        }

        const ivf = bin.ivf()
        if (!ivf.includes('No suspicious')) {
            signals.push('IVF flags')
            score += 2
        }

        const strings = bin.strings()
        if (strings.length < 5) {
            signals.push('few strings')
            score += 1
        }
    })

    return { score, signals, suspicious: score >= 4 }
}
\`\`\`

## Practice

1. Build the directory analysis script and run it on a directory of binaries.
2. Sort the results by function count and identify the most complex binaries.
3. Build the suspicion score script and test it on a packed binary vs a normal binary.

## Next

Continue to \`72_web_ui_usage.md\`.
`
  },
  {
    id: "72_web_ui_usage",
    num: 72,
    level: 7,
    title: "Web UI Usage",
    prereq: "71_building_analysis_scripts.md",
    learn: "How to use the NeoDAX web interface effectively for interactive analysis.",
    level_label: "7 - Integration and Automation",
    content: `# Web UI Usage

**Level:** 7 - Integration and Automation
**Prerequisites:** 71_building_analysis_scripts.md
**What You Will Learn:** How to use the NeoDAX web interface effectively for interactive analysis.

## Starting the Web UI

\`\`\`bash
node js/server/server.js
# Then open: http://localhost:7070/ui
\`\`\`

Or, if you are using the standalone web app:

\`\`\`bash
node server.js
# Then open: http://localhost:3000
\`\`\`

## Navigating the Interface

The web UI has a sidebar with analysis panels. In the single-command version, you type a file path directly in the header input and press Enter or click LOAD.

Once a binary is loaded, panels become available:

- **Overview:** Binary metadata, section/function/xref counts, hottest functions
- **Sections:** Full section table
- **Symbols:** Searchable symbol list
- **Functions:** Searchable function list with flags
- **Xrefs:** Cross-reference table
- **Disassembly:** Structured disassembly with section selector
- **Decompiler:** Pseudo-C output (ARM64)
- **Symbolic Exec:** Symbolic execution trace (ARM64)
- **Entropy:** Entropy scan output
- **Validity:** Instruction validity filter output
- **Strings:** ASCII and Unicode strings
- **Rec. Descent:** Recursive descent analysis

## Effective Analysis Workflow in the UI

1. Load the binary by typing its path.
2. Check the Overview for quick stats.
3. Check the Sections panel to understand the layout.
4. Check the Symbols panel to see what symbols are available.
5. Go to Functions and search for interesting names.
6. Select a function, switch to Disassembly, choose the section.
7. For ARM64, use the Decompiler panel for a higher-level view.
8. Use the Entropy panel to check for packing.

## Using Search in Tables

The Symbols and Functions panels have search fields. Type part of a name to filter instantly. This is useful when you are looking for a specific function in a binary with hundreds of detected functions.

## Client-Side Routing

The URL updates as you navigate between panels. You can bookmark a specific panel and return to it directly:

\`\`\`
http://localhost:3000/disasm
http://localhost:3000/functions
http://localhost:3000/entropy
\`\`\`

## Disassembly Panel Tips

Use the section selector to choose which section to disassemble. For most analysis, \`.text\` is correct.

Use the limit input to control how many instructions to load. For large functions, increase this.

Use the filter field to search within the disassembly for specific mnemonics or operands.

## Practice

1. Start the web server and open the UI.
2. Load \`/bin/ls\` by typing the path.
3. Navigate through each panel and note what each shows.
4. Use the function search to find a specific function by name.
5. Load the disassembly and filter for \`call\` instructions.

## Next

Continue to \`73_express_integration.md\`.
`
  },
  {
    id: "73_express_integration",
    num: 73,
    level: 7,
    title: "Express Integration",
    prereq: "72_web_ui_usage.md",
    learn: "How to integrate NeoDAX into an Express web application.",
    level_label: "7 - Integration and Automation",
    content: `# Express Integration

**Level:** 7 - Integration and Automation
**Prerequisites:** 72_web_ui_usage.md
**What You Will Learn:** How to integrate NeoDAX into an Express web application.

## Adding NeoDAX to an Existing Express App

If you have an existing Express application and want to add binary analysis:

\`\`\`javascript
const express = require('express')
const neodax  = require('neodax')
const app     = express()

app.use(express.json())

// Cache binaries by SHA-256
const cache = new Map()

function getBinary(filePath) {
    const bin = neodax.load(filePath)
    const key = bin.sha256
    if (cache.has(key)) { bin.close(); return cache.get(key) }
    cache.set(key, bin)
    return bin
}

// Analysis endpoint
app.post('/analyze', (req, res) => {
    const { file } = req.body
    if (!file) return res.status(400).json({ error: 'file required' })

    try {
        const bin = getBinary(file)
        const r   = bin.analyze()
        res.json({
            arch:      r.info.arch,
            format:    r.info.format,
            sha256:    r.info.sha256,
            functions: r.functions.length,
            sections:  r.sections.length,
        })
    } catch (e) {
        res.status(500).json({ error: e.message })
    }
})

app.listen(3000)
\`\`\`

## Handling BigInt in JSON Responses

NeoDAX addresses are BigInt values. \`JSON.stringify\` cannot serialize BigInt natively. Use a replacer:

\`\`\`javascript
function safeSer(obj) {
    return JSON.parse(JSON.stringify(obj, (_, v) =>
        typeof v === 'bigint' ? '0x' + v.toString(16) : v
    ))
}

res.json(safeSer(result))
\`\`\`

## Middleware for Analysis

If multiple routes need analysis, create middleware:

\`\`\`javascript
const loadBinary = (req, res, next) => {
    const file = req.body.file || req.query.file
    if (!file) return res.status(400).json({ error: 'file parameter required' })

    try {
        req.bin = getBinary(file)
        next()
    } catch (e) {
        res.status(404).json({ error: \`Cannot open: \${e.message}\` })
    }
}

app.post('/sections', loadBinary, (req, res) => {
    res.json(safeSer({ sections: req.bin.sections() }))
})

app.post('/functions', loadBinary, (req, res) => {
    res.json(safeSer({ functions: req.bin.functions() }))
})
\`\`\`

## Rate Limiting

Analysis is CPU-intensive. Protect your server:

\`\`\`javascript
const rateLimit = {}

const rateLimiter = (req, res, next) => {
    const ip  = req.ip
    const now = Date.now()
    if (rateLimit[ip] && now - rateLimit[ip] < 5000) {
        return res.status(429).json({ error: 'Too many requests' })
    }
    rateLimit[ip] = now
    next()
}

app.post('/analyze', rateLimiter, loadBinary, (req, res) => {
    // ...
})
\`\`\`

## Practice

1. Build a minimal Express server with one \`/analyze\` endpoint.
2. Test it with curl.
3. Add a \`/disasm\` endpoint that accepts a section name parameter.
4. Add the BigInt serializer to all responses.

## Next

Continue to \`74_batch_analysis.md\`.
`
  },
  {
    id: "74_batch_analysis",
    num: 74,
    level: 7,
    title: "Batch Analysis",
    prereq: "73_express_integration.md",
    learn: "How to analyze many binaries efficiently and store results.",
    level_label: "7 - Integration and Automation",
    content: `# Batch Analysis

**Level:** 7 - Integration and Automation
**Prerequisites:** 73_express_integration.md
**What You Will Learn:** How to analyze many binaries efficiently and store results.

## Batch Analysis Architecture

When analyzing many binaries, the key concerns are:

- **Memory:** Each binary handle uses memory. Release handles when done.
- **Error handling:** One bad binary should not stop the batch.
- **Progress:** Long batches need progress tracking.
- **Output:** Results need to be stored in a queryable format.

## A Complete Batch Script

\`\`\`javascript
const neodax = require('neodax')
const fs     = require('fs')
const path   = require('path')

function analyzeFile(filePath) {
    try {
        let result = null
        neodax.withBinary(filePath, bin => {
            const fns     = bin.functions()
            const secs    = bin.sections()
            const entropy = bin.entropy()

            result = {
                path:       filePath,
                name:       path.basename(filePath),
                sha256:     bin.sha256,
                arch:       bin.arch,
                format:     bin.format,
                isPie:      bin.isPie,
                isStripped: bin.isStripped,
                sections:   secs.length,
                functions:  fns.length,
                symbols:    bin.symbols().length,
                hasLoops:   fns.filter(f => f.hasLoops).length,
                codeSize:   secs.filter(s => s.type === 'code')
                                .reduce((n, s) => n + Number(s.size), 0),
                highEntropy: entropy.includes('HIGH') || entropy.includes('PACKED'),
                timestamp:  new Date().toISOString(),
            }
        })
        return { ok: true, result }
    } catch (e) {
        return { ok: false, error: e.message, path: filePath }
    }
}

function findBinaries(dir) {
    const result = []
    function walk(d) {
        for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
            const full = path.join(d, entry.name)
            if (entry.isDirectory()) walk(full)
            else if (entry.isFile()) result.push(full)
        }
    }
    walk(dir)
    return result
}

async function batchAnalyze(sourceDir, outputFile, batchSize = 8) {
    const files = findBinaries(sourceDir)
    console.log(\`Found \${files.length} files in \${sourceDir}\`)

    const results = []
    const errors  = []

    for (let i = 0; i < files.length; i += batchSize) {
        const batch = files.slice(i, i + batchSize)
        for (const file of batch) {
            const r = analyzeFile(file)
            if (r.ok) results.push(r.result)
            else errors.push(r)
        }
        process.stdout.write(\`\\r\${Math.min(i+batchSize, files.length)}/\${files.length}\`)
    }
    console.log()

    const output = { results, errors, total: files.length, analyzed: results.length }
    fs.writeFileSync(outputFile, JSON.stringify(output, null, 2))
    console.log(\`Results: \${results.length} analyzed, \${errors.length} failed\`)
    console.log(\`Saved to: \${outputFile}\`)
}

const [,, sourceDir = '/usr/bin', outputFile = '/tmp/batch_results.json'] = process.argv
batchAnalyze(sourceDir, outputFile)
\`\`\`

## Querying Results

After batch analysis, load the JSON and query it:

\`\`\`javascript
const data = JSON.parse(fs.readFileSync('/tmp/batch_results.json'))
const results = data.results

// Most complex binaries
const complex = results
    .sort((a, b) => b.functions - a.functions)
    .slice(0, 10)

// Suspicious binaries
const suspicious = results.filter(r =>
    r.highEntropy && r.isStripped && r.functions < 10
)

// By architecture
const armBinaries = results.filter(r => r.arch.includes('ARM'))
\`\`\`

## Practice

1. Run the batch analysis script on \`/usr/bin\`.
2. Find the binary with the most functions.
3. Find all stripped binaries with fewer than 5 detected functions.
4. Calculate the average number of sections across all analyzed binaries.

## Next

Continue to \`75_ci_cd_integration.md\`.
`
  },
  {
    id: "75_ci_cd_integration",
    num: 75,
    level: 7,
    title: "CI/CD Integration",
    prereq: "74_batch_analysis.md",
    learn: "How to integrate NeoDAX into continuous integration pipelines for automated security checks.",
    level_label: "7 - Integration and Automation",
    content: `# CI/CD Integration

**Level:** 7 - Integration and Automation
**Prerequisites:** 74_batch_analysis.md
**What You Will Learn:** How to integrate NeoDAX into continuous integration pipelines for automated security checks.

## Use Cases in CI/CD

NeoDAX can be part of an automated security gate that checks every build:

- Verify that a binary does not import unexpected functions
- Check that a shared library exports the expected API
- Detect if a build output has unexpectedly high entropy
- Verify that a binary is not stripped when it should not be
- Check that the binary has the expected architecture and format

## GitHub Actions Example

\`\`\`yaml
name: Binary Analysis

on:
  push:
    branches: [main]
  pull_request:

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build project
        run: make

      - name: Setup NeoDAX
        run: |
          git clone https://github.com/VersaNexusIX/NeoDAX.git /tmp/neodax
          cd /tmp/neodax && make
          echo "/tmp/neodax" >> $GITHUB_PATH

      - name: Install Node.js addon
        run: |
          cd /tmp/neodax
          npm install --prefix js/

      - name: Analyze build output
        run: node .github/scripts/check_binary.js ./mybinary
\`\`\`

## The Check Script

\`\`\`javascript
// .github/scripts/check_binary.js
const neodax = require('/tmp/neodax/js')
const path   = process.argv[2]

if (!path) { console.error('Usage: check_binary.js <path>'); process.exit(1) }

let passed = true

neodax.withBinary(path, bin => {
    // Check 1: Expected architecture
    if (!bin.arch.includes('x86_64')) {
        console.error(\`FAIL: Expected x86_64, got \${bin.arch}\`)
        passed = false
    }

    // Check 2: Not too many unexpected imports
    const dangerousImports = ['system', 'execve', 'popen']
    const symbols = bin.symbols()
    for (const name of dangerousImports) {
        if (symbols.some(s => s.name.includes(name))) {
            console.error(\`FAIL: Found dangerous import: \${name}\`)
            passed = false
        }
    }

    // Check 3: No high entropy sections
    const entropy = bin.entropy()
    if (entropy.includes('PACKED')) {
        console.error('FAIL: High entropy detected, binary may be packed')
        passed = false
    }

    // Check 4: Not stripped (for debug builds)
    if (process.env.BUILD_TYPE === 'debug' && bin.isStripped) {
        console.error('FAIL: Binary is stripped but debug build expected symbols')
        passed = false
    }

    if (passed) {
        console.log('PASS: Binary analysis checks passed')
        console.log(\`  Arch: \${bin.arch}\`)
        console.log(\`  Functions: \${bin.functions().length}\`)
        console.log(\`  SHA-256: \${bin.sha256}\`)
    }
})

process.exit(passed ? 0 : 1)
\`\`\`

## Generating Analysis Reports

For inclusion in pull request comments or build artifacts:

\`\`\`javascript
neodax.withBinary(path, bin => {
    const r = bin.analyze()
    const report = \`
## Binary Analysis Report

| Property | Value |
|----------|-------|
| Architecture | \${r.info.arch} |
| Format | \${r.info.format} |
| SHA-256 | \${r.info.sha256} |
| PIE | \${r.info.isPie} |
| Stripped | \${r.info.isStripped} |
| Functions | \${r.functions.length} |
| Sections | \${r.sections.length} |
| Symbols | \${r.symbols.length} |
\`
    require('fs').writeFileSync('binary_report.md', report)
})
\`\`\`

## Practice

1. Build a check script that fails if a binary imports more than 50 external symbols.
2. Test it on a statically linked binary (should fail) and a dynamically linked binary (might pass).
3. Write a GitHub Actions workflow that runs the check on every push.

## Next

Continue to \`76_building_plugins.md\`.
`
  },
  {
    id: "76_building_plugins",
    num: 76,
    level: 7,
    title: "Building Custom Analysis Plugins",
    prereq: "75_ci_cd_integration.md",
    learn: "How to build reusable analysis modules on top of NeoDAX.",
    level_label: "7 - Integration and Automation",
    content: `# Building Custom Analysis Plugins

**Level:** 7 - Integration and Automation
**Prerequisites:** 75_ci_cd_integration.md
**What You Will Learn:** How to build reusable analysis modules on top of NeoDAX.

## Plugin Architecture

A NeoDAX plugin is a JavaScript module that takes a binary handle and returns structured analysis results. This pattern makes plugins composable: you can run multiple plugins on the same binary and combine their results.

## A Plugin Interface

\`\`\`javascript
// plugin interface
// analyze(bin: NeoDAXBinary) => { name: string, passed: boolean, data: any, message: string }

function createPlugin(name, analyzeFn) {
    return { name, analyze: analyzeFn }
}
\`\`\`

## Example Plugins

\`\`\`javascript
// Plugin: detect packing indicators
const packingDetector = createPlugin('packing-detector', bin => {
    const entropy = bin.entropy()
    const symbols = bin.symbols()
    const fns     = bin.functions()

    const highEntropy   = entropy.includes('PACKED') || entropy.includes('HIGH')
    const fewImports    = symbols.filter(s => s.name.includes('@plt')).length < 3
    const fewFunctions  = fns.length < 5

    const score   = [highEntropy, fewImports, fewFunctions].filter(Boolean).length
    const passed  = score < 2

    return {
        passed,
        data: { highEntropy, fewImports, fewFunctions, score },
        message: passed ? 'No packing indicators' : \`\${score} packing indicators detected\`,
    }
})

// Plugin: check for dangerous imports
const dangerousImportChecker = createPlugin('dangerous-imports', bin => {
    const dangerous = ['system', 'execve', 'popen', 'ShellExecute']
    const found     = bin.symbols()
        .filter(s => dangerous.some(d => s.name.toLowerCase().includes(d.toLowerCase())))
        .map(s => s.name)

    return {
        passed:  found.length === 0,
        data:    { found },
        message: found.length === 0 ? 'No dangerous imports' : \`Found: \${found.join(', ')}\`,
    }
})

// Plugin: measure code complexity
const complexityAnalyzer = createPlugin('complexity', bin => {
    const fns        = bin.functions()
    const loopFns    = fns.filter(f => f.hasLoops)
    const avgInsns   = fns.reduce((s, f) => s + f.insnCount, 0) / Math.max(fns.length, 1)
    const complexity = loopFns.length / Math.max(fns.length, 1)

    return {
        passed:  true,
        data:    { total: fns.length, withLoops: loopFns.length, avgInsns: avgInsns.toFixed(0) },
        message: \`\${fns.length} functions, \${loopFns.length} with loops, avg \${avgInsns.toFixed(0)} insns\`,
    }
})
\`\`\`

## Running Plugins

\`\`\`javascript
function runPlugins(filePath, plugins) {
    const results = { file: filePath, plugins: [] }
    neodax.withBinary(filePath, bin => {
        for (const plugin of plugins) {
            try {
                const r = plugin.analyze(bin)
                results.plugins.push({ name: plugin.name, ...r })
            } catch (e) {
                results.plugins.push({ name: plugin.name, error: e.message })
            }
        }
    })
    results.allPassed = results.plugins.every(p => p.passed !== false)
    return results
}

// Usage
const plugins = [packingDetector, dangerousImportChecker, complexityAnalyzer]
const result  = runPlugins('/bin/ls', plugins)

result.plugins.forEach(p => {
    const status = p.passed ? 'PASS' : 'FAIL'
    console.log(\`[\${status}] \${p.name}: \${p.message}\`)
})
\`\`\`

## Sharing Plugins

Plugins are regular JavaScript modules. Package them for sharing:

\`\`\`javascript
// neodax-plugin-security.js
module.exports = {
    packingDetector,
    dangerousImportChecker,
    createPlugin,
}
\`\`\`

## Practice

1. Write a plugin that detects whether a binary has more than 10 functions with loops.
2. Write a plugin that checks whether the entry point is in the \`.text\` section.
3. Combine multiple plugins and run them against 5 different binaries.
4. Print a table showing which binaries passed which checks.

## Next

You have completed Level 7 - Integration and Automation. Continue to the Appendix, starting with \`80_common_patterns_reference.md\`.
`
  },
  {
    id: "80_common_patterns_reference",
    num: 80,
    level: 8,
    title: "Common Patterns Reference",
    prereq: "",
    learn: "",
    level_label: "Appendix",
    content: `# Common Patterns Reference

**Level:** Appendix
**What This Is:** A reference sheet of common assembly patterns and their meanings.

## Function Boundaries

x86-64 prologue:
\`\`\`
push   rbp
mov    rbp, rsp
sub    rsp, N         ; N = local variable space
\`\`\`

x86-64 epilogue:
\`\`\`
leave                 ; equivalent to: mov rsp, rbp; pop rbp
ret
\`\`\`

ARM64 prologue:
\`\`\`
stp    x29, x30, [sp, #-N]!
mov    x29, sp
\`\`\`

ARM64 epilogue:
\`\`\`
ldp    x29, x30, [sp], #N
ret
\`\`\`

## Calling Conventions

x86-64 Linux (arguments):
\`\`\`
arg1 = rdi
arg2 = rsi
arg3 = rdx
arg4 = rcx
arg5 = r8
arg6 = r9
return = rax
\`\`\`

ARM64 (arguments):
\`\`\`
arg1 = x0
arg2 = x1
arg3 = x2
...
arg8 = x7
return = x0
\`\`\`

## Common Idioms

Zero a register (x86-64):
\`\`\`
xor    eax, eax       ; faster than mov eax, 0
\`\`\`

Test if zero:
\`\`\`
test   rax, rax       ; sets ZF if rax == 0
jz     somewhere      ; jump if zero
\`\`\`

Multiply by power of 2:
\`\`\`
shl    rax, 3         ; rax = rax * 8
lea    rax, [rax*4]   ; rax = rax * 4
\`\`\`

Array access (element size 8):
\`\`\`
mov    rax, [rbx + rcx*8]    ; rax = array[index]
\`\`\`

Null check:
\`\`\`
test   rdi, rdi
jz     handle_null
\`\`\`

## String Operations

Strlen pattern:
\`\`\`
; rdi = string pointer
xor    eax, eax
repne  scasb          ; scan for null byte
not    rcx
dec    rcx            ; rcx = string length
\`\`\`

Copy loop:
\`\`\`
loop:
  movzx  eax, BYTE PTR [rsi + rcx]
  mov    BYTE PTR [rdi + rcx], al
  inc    rcx
  test   al, al
  jnz    loop
\`\`\`

## Heap Patterns

Typical allocation:
\`\`\`
mov    edi, SIZE      ; size argument
call   malloc@plt
test   rax, rax       ; check for NULL
jz     alloc_failed
mov    rbx, rax       ; save pointer
\`\`\`

Typical free:
\`\`\`
mov    rdi, rbx       ; pointer argument
call   free@plt
xor    ebx, ebx       ; null out saved pointer (good practice)
\`\`\`

## Conditional Patterns

Ternary (a > b ? x : y):
\`\`\`
cmp    rdi, rsi
jle    else_branch
mov    rax, x
jmp    end
else_branch:
mov    rax, y
end:
\`\`\`

Min/max pattern:
\`\`\`
cmp    rdi, rsi
cmovg  rdi, rsi       ; rdi = min(rdi, rsi)
\`\`\`

## Loop Patterns

Counted loop (for i = 0; i < N; i++):
\`\`\`
xor    ecx, ecx       ; i = 0
loop_top:
  ; loop body using rcx as index
  inc    rcx
  cmp    rcx, N
  jl     loop_top
\`\`\`

While loop (while *ptr != 0):
\`\`\`
loop_top:
  movzx  eax, BYTE PTR [rdi]
  test   al, al
  jz     loop_end
  ; body
  inc    rdi
  jmp    loop_top
loop_end:
\`\`\`
`
  },
  {
    id: "81_flag_quick_reference",
    num: 81,
    level: 8,
    title: "CLI Flag Quick Reference",
    prereq: "",
    learn: "",
    level_label: "Appendix",
    content: `# CLI Flag Quick Reference

**Level:** Appendix
**What This Is:** Every NeoDAX CLI flag in one place.

## Core Disassembly

| Flag | Long Form | Description |
|------|-----------|-------------|
| (none) | | Disassemble .text section |
| -s NAME | --section | Disassemble specific section |
| -S | --all-sections | Disassemble all executable sections |
| -A ADDR | --start | Start address for disassembly |
| -E ADDR | --end | End address for disassembly |

## Analysis Flags

| Flag | Description |
|------|-------------|
| -l | List sections |
| -y | Show symbols |
| -f | Detect and list functions |
| -r | Build cross-references |
| -C | Build control flow graphs |
| -L | Detect loops |
| -G | Build call graph |
| -W | Detect switch tables |
| -g | Show instruction groups |
| -t | Extract ASCII strings |
| -u | Extract unicode strings |

## Advanced Analysis

| Flag | Description |
|------|-------------|
| -e | Entropy analysis |
| -R | Recursive descent disassembly |
| -V | Instruction validity filter |
| -P | Symbolic execution (ARM64) |
| -D | Decompiler output (ARM64) |
| -Q | SSA lifting (ARM64) |
| -I | Concrete emulator (ARM64) |

## Meta Flags

| Flag | Description |
|------|-------------|
| -x | Run all standard analysis |
| -X | Run all analysis including advanced |
| -h | Show help |
| -v | Verbose output |
| -n | No color output |
| -a | Show raw bytes |
| -d | Demangle C++ names |

## Input/Output

| Flag | Description |
|------|-------------|
| -o FILE | Save DAXC snapshot |
| -c FILE | Load DAXC snapshot |

## Format-Specific

| Flag | Description |
|------|-------------|
| -m ARCH | Force architecture (for raw binaries) |
| -b ADDR | Set base address (for raw binaries) |

## Examples

Quick look at a binary:
\`\`\`bash
./neodax -l -y /bin/ls
\`\`\`

Full analysis, save to file:
\`\`\`bash
./neodax -n -x /bin/ls > analysis.txt
\`\`\`

Full analysis with snapshot:
\`\`\`bash
./neodax -x -o ls.daxc /bin/ls
\`\`\`

Focus on one address range:
\`\`\`bash
./neodax -a -A 0x401000 -E 0x401200 /bin/ls
\`\`\`

C++ demangling:
\`\`\`bash
./neodax -d -y /path/to/cpp_program
\`\`\`
`
  },
  {
    id: "82_js_api_quick_reference",
    num: 82,
    level: 8,
    title: "JavaScript API Quick Reference",
    prereq: "",
    learn: "",
    level_label: "Appendix",
    content: `# JavaScript API Quick Reference

**Level:** Appendix
**What This Is:** Every NeoDAX JavaScript API method in one place.

## Loading

\`\`\`javascript
const neodax = require('neodax')

// Auto-close after callback
neodax.withBinary(path, bin => { ... })

// Manual lifecycle
const bin = neodax.load(path)
// ... use bin ...
bin.close()

// Async callback
await neodax.withBinaryAsync(path, async bin => { ... })
\`\`\`

## Binary Properties (no call needed)

\`\`\`javascript
bin.arch        // 'x86_64' | 'AArch64 (ARM64)' | 'RISC-V RV64' | ...
bin.format      // 'ELF64' | 'ELF32' | 'PE64' | 'PE32' | 'Mach-O 64' | ...
bin.os          // 'Linux' | 'Windows' | 'macOS' | 'Android' | ...
bin.entry       // BigInt: entry point virtual address
bin.sha256      // string: hex SHA-256 of the binary
bin.buildId     // string: GNU build ID or empty string
bin.isPie       // boolean
bin.isStripped  // boolean
bin.hasDebug    // boolean
bin.file        // string: absolute file path
\`\`\`

## Sections

\`\`\`javascript
bin.sections()              // Section[]
bin.sectionByName('.text')  // Section | null
bin.sectionAt(addr)         // Section | null (addr = BigInt)
\`\`\`

Section object:
\`\`\`javascript
{
    name: string,       // '.text', '.data', etc.
    type: string,       // 'code' | 'data' | 'rodata' | 'bss' | 'plt' | 'got' | 'other'
    vaddr: bigint,
    size: bigint,
    offset: bigint,
    flags: number,
    insnCount: number,
}
\`\`\`

## Symbols

\`\`\`javascript
bin.symbols()              // Symbol[]
bin.symAt(addr)            // Symbol | null
\`\`\`

Symbol object:
\`\`\`javascript
{
    name: string,       // raw (possibly mangled) name
    demangled: string,  // demangled name or empty string
    address: bigint,
    size: bigint,
    type: string,       // 'func' | 'object' | 'other'
}
\`\`\`

## Functions

\`\`\`javascript
bin.functions()            // DaxFunction[]
bin.funcAt(addr)           // DaxFunction | null
bin.hottestFunctions(n)    // { function: DaxFunction, callCount: number }[]
\`\`\`

DaxFunction object:
\`\`\`javascript
{
    name: string,
    start: bigint,
    end: bigint,
    size: bigint,
    insnCount: number,
    blockCount: number,
    hasLoops: boolean,
    hasCalls: boolean,
}
\`\`\`

## Cross References

\`\`\`javascript
bin.xrefs()             // Xref[]
bin.xrefsTo(addr)       // Xref[] (incoming)
bin.xrefsFrom(addr)     // Xref[] (outgoing)
\`\`\`

Xref object:
\`\`\`javascript
{
    from: bigint,
    to: bigint,
    isCall: boolean,    // false = branch
}
\`\`\`

## Disassembly

\`\`\`javascript
bin.disasmJson(section, { limit: number, offset: number })  // Instruction[]
\`\`\`

Instruction object:
\`\`\`javascript
{
    address: bigint,
    mnemonic: string,
    operands: string,
    length: number,
    group: string,     // 'call' | 'branch' | 'ret' | 'stack' | 'arithmetic' | ...
    bytes: Uint8Array,
    symbol: string | null,
}
\`\`\`

## Full Analysis

\`\`\`javascript
bin.analyze()  // AnalyzeResult
\`\`\`

AnalyzeResult:
\`\`\`javascript
{
    info: { arch, format, os, entry, sha256, isPie, isStripped, hasDebug, codeSize, imageSize },
    sections: Section[],
    symbols: Symbol[],
    functions: DaxFunction[],
    xrefs: Xref[],
    blocks: Block[],
    loadTimeMs: number,
    analysisTimeMs: number,
}
\`\`\`

## Raw Access

\`\`\`javascript
bin.readBytes(addr, length)  // Uint8Array | null
\`\`\`

## Advanced (ARM64 only)

\`\`\`javascript
bin.entropy()            // string report
bin.rda(section)         // string report
bin.ivf()                // string report
bin.symexec(funcIdx)     // string report
bin.decompile(funcIdx)   // string report
bin.ssa(funcIdx)         // string report
bin.strings()            // { address: bigint, value: string }[]
bin.unicodeStrings()     // { address: bigint, value: string, encoding: string }[]
bin.emulate(funcIdx, initRegs)  // string report
\`\`\`

## BigInt Tips

\`\`\`javascript
// Literal BigInt
const addr = 0x401234n

// Convert number to BigInt
const addr = BigInt(0x401234)

// Convert BigInt to hex string
addr.toString(16)        // '401234'
'0x' + addr.toString(16) // '0x401234'

// JSON serialization
JSON.stringify(obj, (_, v) => typeof v === 'bigint' ? '0x' + v.toString(16) : v)
\`\`\`
`
  },
  {
    id: "83_architecture_cheatsheet",
    num: 83,
    level: 8,
    title: "Architecture Cheatsheet",
    prereq: "",
    learn: "",
    level_label: "Appendix",
    content: `# Architecture Cheatsheet

**Level:** Appendix
**What This Is:** Key architecture facts for x86-64, ARM64, and RISC-V side by side.

## Register Summary

| Purpose | x86-64 | ARM64 | RISC-V |
|---------|--------|-------|--------|
| Arg 1 | rdi | x0 | a0 |
| Arg 2 | rsi | x1 | a1 |
| Arg 3 | rdx | x2 | a2 |
| Arg 4 | rcx | x3 | a3 |
| Arg 5 | r8 | x4 | a4 |
| Arg 6 | r9 | x5 | a5 |
| Return | rax | x0 | a0 |
| Stack ptr | rsp | sp | sp |
| Frame ptr | rbp | x29/fp | s0/fp |
| Link reg | (on stack) | x30/lr | ra |
| Zero reg | (none) | xzr | zero |
| Scratch | rax, rcx, rdx, rsi, rdi, r8-r11 | x9-x17 | t0-t6 |
| Saved | rbx, rbp, r12-r15 | x19-x28 | s1-s11 |

## Instruction Width

| Architecture | Instruction Width |
|-------------|------------------|
| x86-64 | Variable (1-15 bytes) |
| ARM64 | Fixed 4 bytes |
| RISC-V | 4 bytes (2 bytes for C extension) |

## Function Call Mechanics

x86-64:
- \`call target\` pushes RIP then jumps
- \`ret\` pops and jumps
- Return address is on the stack at [rsp] on function entry

ARM64:
- \`bl target\` stores return address in x30 (lr)
- \`ret\` branches to x30
- \`blr x0\` is an indirect call (calls function pointer in x0)

RISC-V:
- \`jal ra, target\` stores return address in ra
- \`jalr zero, ra, 0\` returns (often written as \`ret\`)
- \`jalr ra, t0, 0\` is an indirect call

## System Calls

x86-64 Linux:
\`\`\`
; syscall number in rax
; args: rdi, rsi, rdx, r10, r8, r9
; result in rax
syscall
\`\`\`

ARM64 Linux:
\`\`\`
; syscall number in x8
; args: x0, x1, x2, x3, x4, x5
; result in x0
svc #0
\`\`\`

RISC-V Linux:
\`\`\`
; syscall number in a7
; args: a0-a5
; result in a0
ecall
\`\`\`

## Magic Numbers

| Format | Bytes | Value |
|--------|-------|-------|
| ELF | 7F 45 4C 46 | .ELF |
| PE | 4D 5A | MZ |
| Mach-O 64-bit LE | CF FA ED FE | (FEEDFACF) |
| Mach-O FAT | CA FE BA BE | (CAFEBABE) |
| DAXC | 4E 45 4F 58 | NEOX |

## Entropy Thresholds (NeoDAX)

| Range | Classification |
|-------|---------------|
| 0.0 - 3.0 | Very structured (sparse data, ASCII) |
| 3.0 - 6.0 | Normal (compiled code, data) |
| 6.0 - 6.8 | Moderately compressed |
| 6.8 - 7.0 | HIGH (likely compressed or encrypted) |
| 7.0 - 8.0 | PACKED (almost certainly compressed or encrypted) |

## Section Types (NeoDAX Normalization)

| NeoDAX Type | ELF Name | PE Name | Mach-O Name |
|-------------|----------|---------|-------------|
| code | .text | .text | __TEXT,__text |
| data | .data | .data | __DATA,__data |
| rodata | .rodata | .rdata | __TEXT,__cstring |
| bss | .bss | .bss | __DATA,__bss |
| plt | .plt | (none) | __TEXT,__stubs |
| got | .got | (none) | __DATA,__got |
`
  },
  {
    id: "84_glossary",
    num: 84,
    level: 8,
    title: "Glossary",
    prereq: "",
    learn: "",
    level_label: "Appendix",
    content: `# Glossary

**Level:** Appendix
**What This Is:** Definitions of all technical terms used in this learning path.

## A

**ABI (Application Binary Interface):** The low-level interface between compiled code and the operating system or between different compiled modules. Defines calling conventions, data type sizes, and system call mechanics.

**ASLR (Address Space Layout Randomization):** An OS security feature that randomizes the base address of executables and libraries on each run. Makes exploitation harder by making addresses unpredictable.

**Assembly language:** A low-level programming language where each statement typically corresponds to one machine instruction.

## B

**Base address:** The address at which a binary is loaded in memory. For PIE executables, this varies due to ASLR.

**Basic block:** A sequence of instructions with exactly one entry point (the first instruction) and one exit point (the last instruction). No branches enter or leave from the middle.

**BigInt:** JavaScript's arbitrary-precision integer type. NeoDAX uses BigInt for memory addresses.

**BSS section:** A section containing uninitialized data. Takes no space in the file but is zero-filled in memory at load time.

**Build ID:** A unique identifier embedded in ELF binaries by the linker. Used to match a binary to its debug symbols.

## C

**C2 (Command and Control):** A server that malware connects to for instructions. Also written as C&C.

**Call graph:** A directed graph where nodes are functions and edges represent calling relationships.

**CFG (Control Flow Graph):** A directed graph representing all execution paths through a function. Nodes are basic blocks; edges are possible control transfers.

**COFF (Common Object File Format):** A binary format that preceded PE. Windows PE is based on COFF.

**Concrete emulation:** Running code with actual values, as opposed to symbolic execution which uses symbolic expressions.

**Cross-reference (xref):** A relationship between two addresses recording that one refers to the other.

## D

**DAXC:** NeoDAX's binary snapshot format. Stores analysis results for fast reloading.

**Dead code:** Code that can never be executed. Created by unreachable blocks or bytes after unconditional branches.

**Decompiler:** A tool that converts machine code back into a higher-level language (pseudo-C in NeoDAX's case).

**Demangle:** To reverse C++ name mangling, converting \`_ZN3fooEv\` back to \`foo::bar()\`.

**Dynamic analysis:** Analyzing a program by running it and observing behavior. Contrasts with static analysis.

**Dynamic linking:** A method where shared library code is linked at runtime rather than compile time.

## E

**ELF (Executable and Linkable Format):** The standard binary format on Linux, Android, and most Unix systems.

**Entry point:** The address where execution begins when an OS loads a binary.

**Entropy:** A measure of information density. High entropy bytes approach random; low entropy bytes have significant structure.

**Export:** A symbol that a shared library makes available to other modules.

## F

**FAT binary:** A Mach-O container holding multiple architecture-specific slices.

**Function pointer:** A variable that holds the address of a function. Used for callbacks and virtual dispatch.

## G

**GOT (Global Offset Table):** A table of addresses used in position-independent code to access global data.

**GNU build ID:** A unique hash embedded in ELF binaries identifying a specific build.

## H

**Heuristic:** An approximation strategy that works well in practice but has no theoretical guarantee. NeoDAX uses heuristics for function detection in stripped binaries.

## I

**Import:** A symbol that a binary uses from an external shared library.

**Indirect call:** A function call through a register or memory location (\`call [rax]\`, \`blr x0\`) rather than a direct address.

**Instruction group:** NeoDAX's classification of instructions by semantic type (call, branch, arithmetic, etc.).

**IVF (Instruction Validity Filter):** NeoDAX's analysis that flags unusual instruction patterns.

## J

**JNI (Java Native Interface):** The interface through which Java code calls native (C/C++) functions on Android.

**Jump table:** An array of addresses used to implement switch statements efficiently.

## L

**Link register:** In ARM and RISC-V, a dedicated register (x30/lr and ra respectively) that holds the return address.

**Linear sweep:** A disassembly strategy that reads instructions sequentially from start to finish.

## M

**Mach-O:** The binary format used on macOS, iOS, and other Apple platforms.

**Magic number:** A distinctive byte sequence at the start of a file that identifies its format.

**Mangling:** The encoding of type information into C++ symbol names by the compiler.

**Mnemonic:** The human-readable name of a machine instruction (mov, add, jmp, etc.).

## N

**Native addon:** A compiled C/C++ module loaded by Node.js. NeoDAX's JavaScript API is implemented as a native addon.

**NOP (No Operation):** An instruction that does nothing. Used for alignment padding.

## O

**Obfuscation:** Deliberate transformation of code to make it harder to analyze without changing its behavior.

**Opaque predicate:** A conditional branch whose outcome is always the same but appears to depend on runtime values.

**Operand:** The arguments to an instruction (registers, memory addresses, or immediate values).

## P

**PE (Portable Executable):** The binary format used on Windows.

**PIE (Position Independent Executable):** An executable that can be loaded at any address.

**PLT (Procedure Linkage Table):** A section of code stubs used to call shared library functions.

**Packing:** Compressing or encrypting a binary and wrapping it in a small unpacking stub.

**Prologue:** The opening instructions of a function that set up the stack frame.

**Pseudo-C:** Decompiler output that resembles C code but may not compile.

## R

**RDA (Recursive Descent Analysis):** Disassembly by following control flow from known entry points.

**Relocatable:** A binary whose addresses need adjustment when loaded at a different base address.

**Reverse engineering:** Analyzing a compiled program to understand its design without access to source code.

**RISC-V:** An open-source instruction set architecture. NeoDAX supports the RV64GC variant.

## S

**Section:** A named region within a binary file containing code, data, or metadata.

**SHA-256:** A cryptographic hash function. NeoDAX computes a SHA-256 hash of each binary for identification.

**Snapshot:** In NeoDAX, a saved analysis result stored in DAXC format.

**SSA (Static Single Assignment):** A program representation where each variable is assigned exactly once.

**Static analysis:** Analyzing a program without running it.

**Strip:** To remove debug symbols and the symbol table from a binary.

**Symbol:** A named address in a binary, typically a function or global variable.

**Symbolic execution:** Running code with symbolic (expression-valued) instead of concrete inputs.

## T

**Tail call:** A function call that is the last action of the calling function, often optimized to a jump.

## V

**Virtual address:** The address of data or code as seen by the running program, after the OS maps the binary into memory.

## X

**xref:** Abbreviation for cross-reference. See Cross-reference.

## Z

**Zero register:** In ARM64 (xzr) and RISC-V (zero), a register that always reads as 0. Writes to it are discarded.
`
  },
];

const levels = {
  0: { name: "Foundation", icon: "◈" },
  1: { name: "Basic Analysis", icon: "⊕" },
  2: { name: "Intermediate Analysis", icon: "◧" },
  3: { name: "JavaScript API", icon: "⬡" },
  4: { name: "Advanced Analysis", icon: "◉" },
  5: { name: "Symbolic Execution & Decompilation", icon: "⊛" },
  6: { name: "Real World RE", icon: "▷" },
  7: { name: "Integration & Automation", icon: "◧" },
  8: { name: "Appendix", icon: "◈" },
};
