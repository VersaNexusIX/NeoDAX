# Glossary

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

**Demangle:** To reverse C++ name mangling, converting `_ZN3fooEv` back to `foo::bar()`.

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

**Indirect call:** A function call through a register or memory location (`call [rax]`, `blr x0`) rather than a direct address.

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
