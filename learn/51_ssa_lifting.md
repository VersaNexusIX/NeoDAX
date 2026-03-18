# SSA Lifting

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 50_symbolic_execution_intro.md
**What You Will Learn:** What Static Single Assignment form is and how NeoDAX uses it as an intermediate representation.

## What SSA Is

Static Single Assignment (SSA) is a program representation where each variable is assigned exactly once. When a variable is used in multiple code paths, a special phi function merges the different values at the join point.

SSA form makes data flow analysis easier because each use of a variable has exactly one definition. You can trace any value back to its origin without complex aliasing analysis.

## From Assembly to SSA

NeoDAX lifts ARM64 instructions to SSA IR in several steps:

1. Assign unique versions to each register write: `x0` becomes `x0_1` on the first write, `x0_2` on the second, and so on.
2. Insert phi nodes at control flow join points.
3. Replace all register reads with references to the appropriate versioned value.

The result is an IR where data flow is explicit.

## Running SSA Lifting

CLI:

```bash
./neodax -Q /bin/ls
```

JavaScript:

```javascript
neodax.withBinary('/bin/ls', bin => {
    const ssa = bin.ssa(0)  // SSA for function at index 0
    console.log(ssa)
})
```

## Reading SSA Output

A simple loop in assembly:

```
mov  x0, #0          ; counter = 0
loop:
add  x0, x0, #1      ; counter++
cmp  x0, #10
b.lt loop            ; if counter < 10, continue
ret
```

In SSA form:

```
x0_1 = 0
loop_header:
  x0_2 = phi(x0_1, x0_3)  ; x0 at loop top is either initial or from prev iteration
  x0_3 = x0_2 + 1
  if x0_3 < 10 goto loop_header
  return
```

The phi node at the loop header makes explicit that `x0` at that point can come from two places: the initial value or the result of the previous iteration.

## SSA and the Decompiler

NeoDAX's decompiler uses SSA as its intermediate representation. After lifting to SSA, it applies transformations to reconstruct higher-level constructs:

- Recognizes loop patterns (a phi node at a block with a back edge)
- Recognizes if-else patterns (phi nodes at merge points with condition context)
- Eliminates redundant phi nodes (phi with all same value)
- Propagates constants

The output of this process is the pseudo-C decompiler output.

## Limitations

SSA lifting in NeoDAX is designed for ARM64 only. It handles straightforward functions well but may struggle with:

- Functions using advanced SIMD or floating-point registers
- Functions with complex memory aliasing
- Heavily optimized or obfuscated code

## Practice

1. Run `./neodax -Q /bin/ls` on an ARM64 binary and examine the SSA output.
2. Find a phi node in the output and identify which control flow merge it corresponds to.
3. Compare the SSA output of a simple loop function with its assembly.

## Next

Continue to `52_decompiler_output.md`.
