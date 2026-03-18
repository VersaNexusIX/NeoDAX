# Switch Tables

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 25_call_graphs.md
**What You Will Learn:** How compilers implement switch statements and how NeoDAX detects them.

## How Compilers Implement Switch

A switch statement with many cases is too inefficient to compile as a series of if-else comparisons. Instead, compilers generate a jump table: an array of addresses, one per case. The switch expression is used as an index into the table to load the target address, then execution jumps to that address.

In x86-64, this typically looks like:

```
cmp    eax, 10            ; check if index is within bounds
ja     default_case       ; if > 10, go to default
mov    rax, [table + rax*8]  ; load target from table
jmp    rax               ; jump to case handler
```

In ARM64:

```
cmp    w0, #10
b.hi   default_case
adr    x1, table
ldr    x0, [x1, x0, lsl #3]
br     x0
```

## Switch Table Detection

```bash
./neodax -W /bin/ls
```

NeoDAX scans for the pattern of a bounds check followed by a computed indirect jump. When found, it reports the switch table:

```
Switch table at 0x402100:
  case 0: 0x401234
  case 1: 0x401280
  case 2: 0x4012c0
  default: 0x401200
```

## Why This Matters

Switch tables appear in:

- Command dispatchers that handle different opcodes or commands
- State machines that transition based on current state
- Protocol parsers that handle different message types
- Interpreters that dispatch based on instruction type

Finding a switch table in a binary immediately tells you that the function is a dispatcher. The cases correspond to the dispatched operations.

## Obfuscated Switch Tables

Obfuscated binaries sometimes disguise switch tables by encrypting the addresses or using a different indirection scheme. NeoDAX's detection heuristic catches standard compiler patterns but may miss heavily obfuscated dispatch.

In such cases, the indirect `jmp` instruction still appears in the disassembly. Looking for unconditional indirect jumps (`jmp [rax]`, `br x0`) and the code that sets up the target register is a manual approach.

## Practice

1. Run `./neodax -W /bin/ls` and note how many switch tables are found.
2. Find the function containing a switch table and look at the cases.
3. Can you determine what values are being dispatched?

## Next

Continue to `27_unicode_strings.md`.
