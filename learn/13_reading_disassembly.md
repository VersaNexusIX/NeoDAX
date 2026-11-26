# Reading Disassembly

**Level:** 1 - Basic Analysis
**Prerequisites:** 12_symbols_and_names.md
**What You Will Learn:** How to read NeoDAX disassembly output and understand instruction-level information.

## Basic Disassembly Output

Running NeoDAX without flags disassembles the `.text` section:

```bash
./neodax /bin/ls
```

Each line of disassembly shows:

```
0x401000  push   rbp
0x401001  mov    rbp, rsp
0x401004  sub    rsp, 0x40
0x401008  mov    QWORD PTR [rbp-0x8], rdi
```

The address column shows the virtual address where this instruction lives in memory.

The mnemonic is the instruction name: `push`, `mov`, `sub`, `call`, `ret`.

The operands describe what the instruction operates on.

## Adding Context with Flags

### Bytes

```bash
./neodax -a /bin/ls
```

Adds the raw hex bytes:

```
0x401000  55              push   rbp
0x401001  48 89 e5        mov    rbp, rsp
0x401004  48 83 ec 40     sub    rsp, 0x40
```

This is useful when you need to verify encoding or identify specific byte patterns.

### Symbols and Strings

```bash
./neodax -y -t /bin/ls
```

Annotates call targets with symbol names and string references:

```
0x40120a  call   0x401510  ; malloc@plt
0x401230  lea    rdi, [0x402100]  ; "Hello, World"
0x401237  call   0x401520  ; printf@plt
```

This makes the disassembly much more readable.

## Instruction Groups

```bash
./neodax -g /bin/ls
```

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

Use `-A` and `-E` to focus on a known address range:

```bash
./neodax -A 0x401000 -E 0x4010f0 /bin/ls
```

Use `-A` alone to start at a specific address and disassemble until the end of the section:

```bash
./neodax -A 0x401234 /bin/ls
```

## Reading the Instruction Stream

When reading disassembly, pay attention to patterns:

A function prologue (setup) typically begins with saving registers and allocating stack space:
```
push   rbp
mov    rbp, rsp
sub    rsp, 0x40
```

A function epilogue (teardown) restores registers and returns:
```
mov    rsp, rbp
pop    rbp
ret
```

Calls to external functions appear as `call <address>` with the PLT symbol annotated.

Branches change the flow of execution. An unconditional `jmp` always transfers control. A conditional `je` (jump if equal) only transfers control if the zero flag is set.

## Practice

1. Disassemble `/bin/ls` and find the first `call` instruction.
2. What function is being called? Use `-y` flag to get symbol annotations.
3. Find a `ret` instruction. What is the address of the instruction immediately before it?
4. Use `-g` to enable instruction groups and identify a block of arithmetic instructions.

## Next

Continue to `14_x86_64_primer.md`.
