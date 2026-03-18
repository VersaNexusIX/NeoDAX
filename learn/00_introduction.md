# NeoDAX Learning Path

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

Start with file `00` and work forward. Do not skip levels unless you already have the background knowledge.

## Getting the Most from Practice Exercises

Each file has a practice section. These exercises use real binaries you already have on your system such as `/bin/ls` on Linux, `/usr/bin/file` on macOS, or compiled programs from the NeoDAX repository itself.

Do not rush through the practice sections. Understanding why an output looks the way it does is more valuable than moving to the next topic quickly.

## Next

Continue to `01_what_is_binary_analysis.md`.
