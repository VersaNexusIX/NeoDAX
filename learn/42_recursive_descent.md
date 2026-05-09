# Recursive Descent Disassembly

**Level:** 4 - Advanced Analysis
**Prerequisites:** 41_packed_binary_detection.md
**What You Will Learn:** What recursive descent is, how it differs from linear sweep, and when to use it.

## Two Disassembly Strategies

There are two main approaches to disassembling a binary:

**Linear sweep** reads the code section byte by byte from start to finish, decoding each instruction in sequence. It is simple and fast but can be confused by data embedded within code or by jump tricks.

**Recursive descent** starts at a known entry point and follows control flow. When it encounters a conditional branch, it queues both targets. When it encounters an unconditional jump, it follows it. When it reaches a return, it backtracks. Code that is not reachable from any known entry point is not disassembled.

NeoDAX uses a combination: the primary disassembler uses linear sweep with the two-pass jump trick fix, and the recursive descent module is available as a separate analysis.

## Running Recursive Descent

```bash
./neodax -R /bin/ls
```

Or for a specific section:

```bash
./neodax -R -s .text /bin/ls
```

The output marks bytes that are not reachable from any known entry point as dead bytes.

## In JavaScript

```javascript
neodax.withBinary('/bin/ls', bin => {
    const report = bin.rda('.text')
    console.log(report)
})
```

## What Recursive Descent Reveals

**Dead bytes:** Bytes between function boundaries, alignment padding, or data embedded in code sections that is never executed.

**Unreachable code:** Functions that exist in the binary but are never called. These may be dead code left by the compiler, debugging remnants, or code that is only reachable dynamically.

**Jump tricks:** Code where a disassembler would be confused by data after an unconditional jump. Recursive descent naturally skips these bytes.

**Coverage gaps:** If a significant portion of the code section is marked dead, the binary may have self-modifying code or dynamic code generation that RDA cannot follow.

## Limitations

Recursive descent cannot follow indirect branches (`call rax`, `jmp [rax]`) without knowing the target value. These appear as unresolved edges. If many indirect branches exist, the coverage will be lower than the actual executed code.

For binaries with many indirect calls (virtual dispatch in C++, function tables, callbacks), recursive descent misses significant portions of the reachable code.

## Combining with Entropy

A section with high entropy that also has many unreachable bytes according to RDA is a strong indicator of packed or encrypted code. The unreachable bytes are the encrypted payload; the small amount of reachable code is the decryptor stub.

## Practice

1. Run `./neodax -R /bin/ls` and note how many dead bytes are reported.
2. Find the largest gap (sequence of unreachable bytes) in the code section.
3. Compare RDA coverage on a stripped binary vs an unstripped binary of the same program.

## Next

Continue to `43_instruction_validity_filter.md`.
