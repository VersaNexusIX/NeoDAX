# Obfuscation Detection

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

```bash
./neodax -C /bin/suspicious
```

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

```bash
./neodax -V -R /bin/suspicious
```

Dead bytes after unconditional branches, unreachable blocks reported by RDA, and invalid opcodes together suggest systematic dead code injection.

## Building an Obfuscation Score

```javascript
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
```

## Practice

1. Run the combined analysis (`./neodax -e -V -R -C`) on a normal binary and on any binary you suspect is obfuscated.
2. Compare the CFG shapes of functions in both.
3. Look for the pattern of a large dispatcher block in any function.

## Next

Continue to `46_symbol_demangling.md`.
