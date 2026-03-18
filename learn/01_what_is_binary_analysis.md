# What is Binary Analysis

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

```bash
xxd /bin/ls | head -20
```

You should see the first bytes are `7f 45 4c 46` which spells out "ELF" in ASCII preceded by a non-printable byte. This is the magic number that identifies ELF files.

On macOS, the first bytes of `/bin/ls` are `ca fe ba be` which is the FAT (universal binary) magic number.

Now look at the same file as NeoDAX sees it:

```bash
./neodax -l /bin/ls
```

This lists all the sections. Notice how the raw bytes you saw in hex have been interpreted into a structured view.

## Next

Continue to `02_setting_up_neodax.md`.
