# Instruction Groups

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 27_unicode_strings.md
**What You Will Learn:** How NeoDAX classifies instructions and how this aids analysis.

## What Instruction Groups Are

NeoDAX classifies every disassembled instruction into one of several groups based on its type and function:

- **call**: Function calls (x86 `call`, ARM64 `bl`/`blr`)
- **branch**: Conditional and unconditional jumps that stay within the function
- **ret**: Return instructions
- **stack**: Stack manipulation (push, pop, frame setup)
- **syscall**: System call instructions
- **arithmetic**: Mathematical operations (add, sub, mul, div, shift)
- **data-move**: Data transfer between registers and memory
- **nop**: No-operation instructions

## Using Instruction Groups

Enable groups with the `-g` flag:

```bash
./neodax -g /bin/ls
```

In color-enabled terminals, each group has a distinct color. When output is plain text, the group name appears as an annotation.

## Reading Group Distribution

The distribution of instruction groups in a function tells you about its character.

A function with many `call` instructions is an orchestrator: it coordinates work done by other functions.

A function with many `arithmetic` instructions and few `call` instructions is a computational kernel: it does math or bit manipulation.

A function with many `data-move` instructions copies data between memory and registers, suggesting buffer processing or struct manipulation.

A function with a `syscall` instruction directly invokes the OS kernel.

## Detecting Suspicious Patterns

Instruction groups help identify unusual code:

**No `ret` instruction:** The function exits through an indirect jump or never returns (an infinite loop or a function that exits the process).

**Many `nop` instructions:** Padding between functions (normal) or part of a NOP sled used in exploitation (suspicious if appearing before a specific address).

**`syscall` in unexpected places:** Direct system calls are normal in libc but unusual in application code. A binary making direct syscalls is trying to bypass library-level monitoring.

**Arithmetic on seemingly random data:** Combined with high entropy, heavy arithmetic may indicate decryption or decompression.

## Groups in CFG Analysis

When building CFGs manually, knowing which instructions are branches (`branch` group) tells you where basic block boundaries are. The CFG builder uses this same classification internally.

## Practice

1. Run `./neodax -g /bin/ls` and identify a function where most instructions are `arithmetic`.
2. Find a function that calls many external functions (many `call` instructions to PLT stubs).
3. Find at least one `syscall` instruction if your binary has any direct system calls.

## Next

You have completed Level 2 - Intermediate Analysis. Continue to `30_js_api_introduction.md` to begin Level 3.
