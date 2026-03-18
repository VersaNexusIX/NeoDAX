# Decompiler Output

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 51_ssa_lifting.md
**What You Will Learn:** How to use the NeoDAX decompiler and interpret its pseudo-C output.

## The Decompiler

NeoDAX includes a decompiler that converts ARM64 assembly to pseudo-C. It works by lifting assembly to SSA IR and then applying structural analysis to recover C-like constructs.

The output is pseudo-C: it resembles C but may not compile directly. It is intended as a human-readable approximation of the original code.

## Running the Decompiler

CLI:

```bash
./neodax -D /bin/ls
```

This decompiles all detected functions.

To decompile a specific function by address range:

```bash
./neodax -D -A 0x401000 -E 0x401200 /bin/ls
```

JavaScript:

```javascript
neodax.withBinary('/bin/ls', bin => {
    const fns = bin.functions()
    fns.forEach((fn, i) => {
        const code = bin.decompile(i)
        if (code.trim()) {
            console.log('// Function:', fn.name)
            console.log(code)
            console.log()
        }
    })
})
```

## Reading Pseudo-C Output

A simple function that counts the length of an array:

Assembly:

```
sub_401000:
  mov  x2, #0
loop:
  ldr  x3, [x0, x2, lsl #3]
  cbz  x3, done
  add  x2, x2, #1
  b    loop
done:
  mov  x0, x2
  ret
```

Pseudo-C output:

```c
uint64_t sub_401000(uint64_t *x0) {
    uint64_t x2 = 0;
    while (1) {
        uint64_t x3 = x0[x2];
        if (x3 == 0) break;
        x2 = x2 + 1;
    }
    return x2;
}
```

The decompiler correctly identifies the loop structure and the break condition.

## When Decompiler Output Is Imperfect

The decompiler produces less readable output for:

- Heavily optimized code with register reuse
- Functions using indirect calls or virtual dispatch
- Code with complex memory operations
- SIMD or floating-point operations (not fully supported)

In these cases, the output may look like:

```c
uint64_t sub_401234(uint64_t x0, uint64_t x1) {
    x0 = x0 + x1;
    x0 = x0 << 2;
    // ... many register operations ...
    return x0;
}
```

This is still useful as a starting point for manual analysis.

## Combining with Symbolic Execution

For small functions, symbolic execution (Level 5, file 50) may give you a cleaner view of what the function computes. The decompiler gives you structure; symbolic execution gives you the formula.

Use both:

```javascript
neodax.withBinary('/bin/ls', bin => {
    const i = 5  // function index
    console.log('=== Decompiled ===')
    console.log(bin.decompile(i))
    console.log('=== Symbolic ===')
    console.log(bin.symexec(i))
})
```

## Practice

1. Run `./neodax -D /bin/ls` on an ARM64 binary.
2. Find a function where the decompiled output clearly shows a loop.
3. Identify the loop variable and the termination condition.
4. Compare the pseudo-C to the assembly for the same function.

## Next

Continue to `53_reading_pseudo_c.md`.
