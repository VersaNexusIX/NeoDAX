# Stripping and Obfuscation in Practice

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 64_android_binary_analysis.md
**What You Will Learn:** Practical strategies for analyzing stripped and lightly obfuscated binaries.

## The Reality of Stripped Binaries

Most released software is stripped. You will rarely have symbol names for internal functions. The question is not "how do I avoid stripped binaries" but "how do I work effectively with them."

## Rebuilding Semantic Understanding

When working with a stripped binary, rebuild understanding from context:

**Behavior clues:** What does the function do to its inputs? Does it return 0 or 1? Does it modify a buffer? Does it call specific external functions?

**Call context:** If `sub_401234` is always called with a pointer and a length, and always precedes a network send, it is probably a serialization function.

**String context:** If a function prints a specific string, you know something about its purpose.

**Naming strategy:** Give functions names as you understand them. `sub_401234` becomes `check_license` once you understand it. Document your names alongside the addresses.

## Working with Function Lists

Build your own symbol table as you analyze:

```javascript
const mySymbols = {
    0x401234n: 'check_license',
    0x401500n: 'decrypt_string',
    0x401800n: 'send_request',
}

neodax.withBinary('/binary', bin => {
    const fns = bin.functions()
    fns.forEach(fn => {
        const name = mySymbols[fn.start] || fn.name
        console.log('0x' + fn.start.toString(16), name)
    })
})
```

## Light Obfuscation Patterns

Some binaries use light obfuscation that NeoDAX's standard analysis handles:

**Jump tables used as dispatch:** Covered by switch table detection.

**Dead code insertion:** Covered by IVF and RDA.

**Instruction substitution (e.g., `xor eax, eax` instead of `mov eax, 0`):** Recognized by the assembler; the decompiler normalizes these.

**String obfuscation:** Covered by the emulator and symbolic execution.

## When Standard Analysis Fails

For heavily obfuscated code:

1. Identify the obfuscation technique from the patterns (high block count, switch-heavy dispatch, etc.).
2. Look for the deobfuscator: the function that transforms obfuscated code to runnable form.
3. Analyze the deobfuscator, not the obfuscated code.
4. Use dynamic analysis tools to observe the deobfuscated code at runtime.

## Documentation Habits

Good reverse engineering requires good notes:

- Record your hypotheses and the evidence for them
- Record addresses alongside your interpretations
- Record what you have ruled out as well as what you have confirmed

A well-maintained notes file is more valuable than hours of undocumented analysis.

## Practice

1. Take a stripped binary and list all functions.
2. Without any symbol names, identify at least 3 functions based on behavior analysis.
3. Document your reasoning for each identification.

## Next

Continue to `66_daxc_snapshots.md`.
