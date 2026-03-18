# Symbolic Execution Introduction

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 46_symbol_demangling.md
**What You Will Learn:** What symbolic execution is, how NeoDAX implements it, and when it is useful.

## What Symbolic Execution Is

Symbolic execution runs code with symbolic values instead of concrete values. Instead of tracking that register `x0` contains the value `42`, symbolic execution tracks that `x0` contains the symbolic expression `arg0 + 8`.

As execution proceeds, symbolic expressions accumulate. When a branch condition depends on a symbolic value, symbolic execution notes both possible outcomes without committing to either.

The result is a mapping from function inputs to observable behavior: what does this function return given symbolic inputs? What expressions reach which code paths?

## NeoDAX's Symbolic Execution

NeoDAX implements symbolic execution for ARM64 functions. It builds an expression tree that tracks how register values change throughout a function.

The engine:

- Tracks all 32 ARM64 registers as symbolic expressions
- Evaluates expressions concretely when possible (constant folding)
- Records the symbolic state at each basic block
- Reports the final state of return registers

## Running Symbolic Execution

CLI:

```bash
./neodax -P /bin/ls
```

This runs symbolic execution on all detected functions and prints the results.

JavaScript:

```javascript
neodax.withBinary('/bin/ls', bin => {
    const result = bin.symexec(0)  // analyze function at index 0
    console.log(result)
})
```

## Reading Symbolic Execution Output

The output for a simple function looks like:

```
Function sub_401000 symbolic execution:

  Entry state:
    x0 = arg0
    x1 = arg1

  Block 0x401000:
    x0 = arg0 + 1
    x2 = arg0 * 2

  Exit state:
    x0 = arg0 + 1     (return value)
```

This tells you the function takes one argument and returns `argument + 1`.

For a more complex function with conditionals:

```
  Path 1 (condition: arg0 > 0):
    x0 = arg0 * 2

  Path 2 (condition: arg0 <= 0):
    x0 = 0
```

## Limitations

NeoDAX's symbolic execution is intentionally limited for performance:

- ARM64 only (not x86-64 or RISC-V)
- Does not track memory state (only registers)
- Limited to a single function (no interprocedural analysis)
- Does not handle indirect branches to unknown targets

These limitations mean symbolic execution is most useful for small, self-contained functions that manipulate values arithmetically.

## When to Use It

Symbolic execution is most valuable for:

- Understanding what a mathematical transformation function computes
- Identifying the formula used to check a license key or password
- Understanding how values are encoded or decoded
- Identifying constant folding opportunities

It is less useful for functions that depend heavily on memory state or make many function calls.

## Practice

1. Run `./neodax -P /bin/ls` and find a function where symbolic execution produces a readable expression.
2. In JavaScript, call `bin.symexec(0)` on the first function and print the result.
3. Find a function that takes one integer argument and determine what it returns.

## Next

Continue to `51_ssa_lifting.md`.
