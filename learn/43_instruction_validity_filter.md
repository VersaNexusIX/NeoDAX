# Instruction Validity Filter

**Level:** 4 - Advanced Analysis
**Prerequisites:** 42_recursive_descent.md
**What You Will Learn:** How the instruction validity filter works and what it tells you about code quality and obfuscation.

## What the IVF Does

The instruction validity filter scans code sections and flags instructions or byte sequences that are unlikely to be legitimate compiled code:

- **Invalid opcodes:** Byte sequences that do not decode to any valid instruction for the target architecture.
- **Privileged instructions:** Instructions that only make sense in kernel mode (like `wrmsr`, `invlpg`, `lgdt`). These appearing in userspace code is suspicious.
- **NOP runs:** Long sequences of NOP instructions (8 or more consecutive). A few NOPs are normal padding; long NOP sleds suggest exploitation artifacts or obfuscation.
- **INT3 runs:** Multiple consecutive breakpoint instructions suggest debugging artifacts left in the binary.
- **Dead bytes after unconditional branches:** Code that follows a `jmp` and is never targeted by any other branch. These are often fake instructions injected to confuse disassemblers.

## Running the IVF

```bash
./neodax -V /bin/ls
```

The output reports any flagged regions:

```
Instruction Validity Filter: /bin/ls

No suspicious patterns detected.
```

Or for a suspicious binary:

```
Instruction Validity Filter: suspicious_binary

0x401234: Invalid opcode (0xFF 0xFF)
0x401300: NOP run (12 consecutive NOPs)
0x4014a0: Privileged instruction: wrmsr
0x401500: Dead bytes after unconditional branch (14 bytes)
```

## In JavaScript

```javascript
neodax.withBinary('/path/to/binary', bin => {
    const report = bin.ivf()
    if (report.includes('No suspicious')) {
        console.log('Binary appears clean')
    } else {
        console.log('Suspicious patterns found:')
        console.log(report)
    }
})
```

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

1. Run `./neodax -V /bin/ls` on a clean system binary and verify no flags.
2. If you have any suspicious binary samples, run the IVF and note the results.
3. Combine with entropy: `./neodax -e -V /path/to/binary` to see both signals at once.

## Next

Continue to `44_hottest_functions.md`.
