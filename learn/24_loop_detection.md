# Loop Detection

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 23_cfg_in_practice.md
**What You Will Learn:** How NeoDAX detects loops and what that tells you about a function's complexity.

## What Loop Detection Does

NeoDAX uses dominator analysis to find natural loops in the CFG. A natural loop has a single entry point and at least one back edge.

The dominator analysis works as follows: block A dominates block B if every path from the entry to B passes through A. A back edge is an edge from block B to block A where A dominates B. Such an edge always creates a loop.

## Running Loop Detection

```bash
./neodax -L /bin/ls
```

Output shows functions with detected loops:

```
Function sub_401300: 2 loops detected
  Loop 1: header 0x401320, body blocks: 0x401320, 0x401340
  Loop 2: header 0x401380, body blocks: 0x401380, 0x4013a0, 0x4013c0
```

Functions with the `[loops]` flag in the `-f` output also have loops.

## What Loops Indicate

**A function with no loops** is simple and bounded. It does a fixed amount of work.

**A function with one loop** iterates over something: an array, a list, a string. The number of iterations depends on input.

**A function with nested loops** is more complex. Nested loops often indicate O(n^2) algorithms: comparing all pairs, building a matrix, parsing structured data.

**A function with many loops** is a processing engine: a parser, a serializer, a cryptographic algorithm, a state machine.

Loop count is a proxy for complexity. Functions with many loops deserve more attention.

## Loop Identification vs Loop Unrolling

Compilers sometimes unroll loops: replicate the loop body multiple times to reduce branch overhead. An unrolled loop may appear as a long linear block with no back edge. NeoDAX cannot detect unrolled loops through dominator analysis alone.

Entropy analysis (Level 4) sometimes catches unrolled loops because the repeated instruction pattern produces characteristic entropy signatures.

## Nested Loops

When one loop contains another, the inner loop's header block is inside the outer loop's body. You can identify nesting by looking at the loop header addresses: if loop B's header is within the block range of loop A, then B is nested inside A.

## Practice

1. Run `./neodax -f -L /bin/ls` to see function listing with loop annotations.
2. Find the function with the most loops.
3. Disassemble that function and identify which part of the code corresponds to the loop body.

## Next

Continue to `25_call_graphs.md`.
