# Glossary

**Level:** Appendix  
**What This Is:** Definitions of all technical terms used in this learning path.

## A

**ABI (Application Binary Interface):** The low-level interface between compiled code and the operating system or between compiled modules. Defines calling conventions, data type sizes, and system call mechanics.

**AIRE (Assisted Intelligence Reverse Engineering):** NeoDAX's rule-based insight engine. Runs after all other analysis passes and synthesizes results into ranked, human-readable findings with confidence scores. AIRE is context-aware (detects what kind of binary you're looking at), provides a next-step guide (suggests the most useful commands), and has persistent memory (recalls previous analyses of the same binary by SHA-256). Invoked with `--aire` on the CLI or `aire`/`ai` in the interactive shell.

**AIRE Memory:** A binary file (`.aire_memory`) written to the working directory by AIRE after each analysis run. Stores up to 32 entries keyed by SHA-256. Each entry records run count, timestamp, dominant insight category, top finding summary, and last interactive command. Displayed as a recall banner at the start of subsequent AIRE runs on the same binary.

**ASLR (Address Space Layout Randomization):** An OS security feature that randomizes the base address of executables and libraries on each run.

**Assembly language:** A low-level programming language where each statement typically corresponds to one machine instruction.

## B

**Base address:** The address at which a binary is loaded in memory. For PIE executables, this varies due to ASLR.

**Basic block:** A sequence of instructions with exactly one entry point (the first instruction) and one exit point (the last instruction).

**BigInt:** JavaScript's arbitrary-precision integer type. NeoDAX uses BigInt for memory addresses.

**BSS section:** A section containing uninitialized data. Takes no space in the file but is zero-filled in memory at load time.

**Build ID:** A unique identifier embedded in ELF binaries by the linker.

## C

**C2 (Command and Control):** A server that malware connects to for instructions.

**Call graph:** A directed graph where nodes are functions and edges represent calling relationships.

**CFG (Control Flow Graph):** A directed graph representing all execution paths through a function. Nodes are basic blocks; edges are possible control transfers.

**CFF (Control Flow Flattening):** An obfuscation technique that replaces structured control flow (if-else, loops) with a state-machine dispatch loop. The `ivf` command's VM detector identifies CFF.

**COFF (Common Object File Format):** A binary format that preceded PE. Windows PE is based on COFF.

**Concrete emulation:** Running code with actual values, as opposed to symbolic execution which uses symbolic expressions.

**Cross-reference (xref):** A relationship between two addresses recording that one refers to the other.

## D

**DAXC:** NeoDAX's AOT C source snapshot format. Stores analysis results — functions, disassembly, comments — as a compilable C file (`.daxc`).

**DAX_GUARD_BIN:** A macro that validates a `dax_binary_t*` before any module does work. Checks that the pointer is non-NULL, `data` is non-NULL, `size > 0`, and all counter fields are within their `DAX_MAX_*` bounds. On failure, calls `dax_fault_set()` and executes `return`. Defined in `include/dax_guard.h`.

**DAX_RUN_PASS:** A macro used in `main.c` to wrap every analysis pass. Clears the global fault register, executes the pass, then checks if a fault was set. On fault, prints a yellow `[!] pass '...' recovered` notice and resets for the next pass. Ensures one bad module cannot stop the rest.

**dax_clamp_counts:** A function that normalizes all `dax_binary_t` counter fields to their legal `DAX_MAX_*` upper bounds. Called after every loader phase to prevent downstream loops from iterating over garbage values.

**Dead code:** Code that can never be executed. Created by unreachable blocks or bytes after unconditional branches.

**Decompiler:** A tool that converts machine code back into a higher-level language (pseudo-C in NeoDAX's case).

**Demangle:** To reverse C++ name mangling, converting `_ZN3fooEv` back to `foo::bar()`.

**DSA (Dynamic Single Assignment):** NeoDAX's runtime-value-annotated IR. Unlike SSA which is purely static, DSA records concrete values observed during emulation at every definition site. Useful for identifying opaque predicates (defs with constant values across all traces) and tracing VM dispatch sequences. Each DSA phase has its own fault flag so a corrupt function aborts only its own phase without affecting others. Invoked with `--dsa` or `dsa <func>` in the interactive shell.

**Dynamic analysis:** Analyzing a program by running it and observing behavior.

**Dynamic linking:** A method where shared library code is linked at runtime.

## E

**ELF (Executable and Linkable Format):** The standard binary format on Linux, Android, and most Unix systems.

**Entropy:** A measure of randomness. High entropy (≥7.0 bits/byte) in a code section suggests packing or encryption.

**EXTR:** ARM64 `extr` instruction — extract bits from a concatenation of two registers. Alias for `ror` when both source registers are the same.

## F

**Fibonacci hashing:** A hash function using the golden ratio. Not used by NeoDAX but appears in obfuscated code.

**Fault isolation:** NeoDAX's microkernel-inspired model where each of 32 analysis passes runs independently. A structural error (NULL pointer, out-of-bounds index, corrupt counter) causes the faulted pass to return early and emit a `[!] pass '...' recovered from fault` notice on stderr. All other passes continue normally. Implemented via `DAX_RUN_PASS`, `DAX_GUARD_BIN`, and the global fault register `g_dax_fault` in `include/dax_guard.h`.

**Function boundary detection:** The process of identifying where functions start and end in a stripped binary.

## G

**GOT (Global Offset Table):** A data section in ELF used by the dynamic linker to store absolute addresses for shared library symbols.

## H

**Hash chain:** In obfuscation contexts, a sequence of arithmetic operations (add, mul, ror, xor) applied consecutively to the same register to produce an opaque value. Detected by NeoDAX's poly map `hash-chain` signal.

## I

**IVF (Instruction Validity Filter):** NeoDAX's multi-category scanner that flags invalid encodings, privileged instructions, SMC patterns, opaque predicates, dead code, and register aliasing tricks.

**Indirect branch:** A branch (`br xN`, `blr xN`) where the target address is computed at runtime and stored in a register. Used for VM dispatchers, vtable calls, and function pointers.

**Itanium ABI:** The C++ name mangling convention used by GCC and Clang on Linux/Android.

## L

**Leaf function:** A function that makes no calls to other functions. Usually short.

## M

**Mach-O:** The binary format used on macOS and iOS.

**MISALIGN (IVF category):** A `dw` (data word) found in a code stream that is not preceded by an unconditional branch. Used for anti-disassembly.

**MOVK:** ARM64 instruction that writes a 16-bit immediate into one of four 16-bit slots of a register without touching the other slots. Dense `movk` chains are flagged by the poly map as `const-obfuscation`.

**Mutation chain (SMC):** An address in a code section that was written more than once during analysis. Scored ×2 in the obfuscation rating. Indicates a polymorphic loop that repeatedly patches the same bytes.

## N

**NR (NeoDAX Representation):** NeoDAX's program IR, replacing the old SSA layer. NR has 30 opcodes, 8 inferred types, inter-function linkage (callers/callees per function), and a program-level call graph module. Invoked with `-Q` or `ssa <func>` in the interactive shell.

**NRT (NR Type):** The type system used by NR variables: `NRT_U8`, `NRT_U16`, `NRT_U32`, `NRT_U64`, `NRT_PTR`, `NRT_PTR_CODE`, `NRT_BOOL`, `NRT_FLAGS`.

## O

**Opaque predicate:** A conditional branch whose outcome is always the same (always taken or never taken) but appears to depend on runtime values. NeoDAX detects these via symexec (`-P`) and IVF patterns `OPAQUE-C`/`OPAQUE-SR`.

**OLLVM / Hikari:** Open-source obfuscator frameworks built on LLVM that apply CFF, opaque predicates, string encryption, and instruction substitution. NeoDAX's poly map fingerprints this as `OLLVM/Hikari`.

## P

**PAC (Pointer Authentication Code):** ARM64 security feature that signs pointers with a cryptographic hash. `autiasp`/`autia` — authentication instructions that can be abused for CFI bypass if signing keys are weak.

**PE (Portable Executable):** The binary format used on Windows.

**PHI node:** In SSA/NR form, a pseudo-instruction at a control flow join point that selects between values from different incoming paths.

**PIE (Position Independent Executable):** A binary that can be loaded at any base address. Required for ASLR.

**PLT (Procedure Linkage Table):** A section in ELF that provides stubs for dynamically linked functions.

**Poly map:** NeoDAX's polymorphic obfuscation detector. Scans 48-byte windows across code sections, scores 18 signals, and reports mutation clusters with an obfuscator fingerprint.

**Polymorphic code:** Code that modifies itself or contains self-decrypting stubs. Detected by the poly map (`xor-mutation-loop`) and IVF (`SMC` category).

## R

**RDA (Recursive Descent Analysis):** A disassembly strategy that follows branches to discover all reachable code, as opposed to linear scanning.

**ROR (Rotate Right):** ARM64 instruction. Dense `ror` chains appear in hash/checksum routines and obfuscation. NR models this as `NR_ROR`; the decompiler emits `__ror(v, n)`.

## S

**SHA-256:** The hash NeoDAX computes for every loaded binary. Used as the key for AIRE memory entries.

**SMC (Self-Modifying Code):** Code that writes to its own executable section at runtime, patching instructions before they execute. NeoDAX detects SMC via three independent passes: static IVF pattern, symexec write tracking, and emulator real-time capture.

**SMC mutation chain:** An executable address that was patched more than once during analysis. Strong indicator of a polymorphic loop. NeoDAX tracks up to 32 chains.

**SSA (Static Single Assignment):** A classical compiler IR where each variable is defined exactly once. NeoDAX's NR supersedes SSA with richer semantics and inter-function linkage.

**Stripped binary:** A binary with its symbol table removed. Makes function names unavailable; NeoDAX uses heuristics to recover function boundaries.

**Symbolic execution:** Running code with symbolic values instead of concrete values, tracking constraints on those values to reason about all possible paths.

**Syscall:** A request to the operating system kernel. Modeled in NR as `NR_SYSCALL`.

## T

**Tail call:** A function call that is the last action of the caller. The compiler can replace it with a jump. NeoDAX's decompiler detects tail calls and emits `return func(/*tail*/);`.

**TBZ / TBNZ:** ARM64 test-and-branch instructions. `tbz xN, #bit, label` — branches if bit N of xN is zero. Used in obfuscation as data-dependent branches; flagged by the poly map as `data-dep-branch`.

**Tigress:** A C source-level obfuscator that applies CFF, opaque predicates, and deep arithmetic encoding. NeoDAX's poly map fingerprints this as `hash-chain/Tigress`.

## V

**VM dispatcher:** A function that reads an opcode and jumps to a handler based on its value. NeoDAX's IVF VM detector scores dispatcher candidates 0–6 and flags those ≥4.

**VM trace:** The log of VM dispatch events recorded during emulation. Printed by `--vm-trace` / `vt`. Shows dispatch PC, handler PC, opcode value, and VM IP for each dispatch step.

## X

**XREF:** Short for cross-reference. NeoDAX builds xref tables linking every instruction that references an address to that address.

**XOR mutation:** A polymorphic technique where code bytes are XOR'd with a key before storage and decrypted just before execution. Detected by the poly map `xor-mutation-loop` signal and IVF `SMC` pattern.
