# Control Flow Graphs

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 21_cross_references.md
**What You Will Learn:** What CFGs are, how NeoDAX builds them, and how to read them.

## What a Control Flow Graph Is

A control flow graph (CFG) represents all possible execution paths through a function. Each node in the graph is a basic block: a sequence of instructions with one entry point and one exit point. Edges connect blocks according to possible control transfers.

A basic block ends when execution must leave it:
- A conditional branch creates two edges (taken and not taken)
- An unconditional jump creates one edge
- A `ret` creates no outgoing edges (function exit)

## Why CFGs Matter

Reading code linearly as a sequence of instructions gives you a flat view. The CFG gives you the structure. You can see:

- Which conditions lead to which code paths
- Which code is unreachable
- How loops are formed (back edges that go to an earlier block)
- How switch statements fan out

Understanding the CFG of a function is often required before you can reliably understand what the function does.

## Building CFGs in NeoDAX

```bash
./neodax -C /bin/ls
```

NeoDAX builds and prints the CFG for each detected function.

Output looks like:

```
Function main [0x401070 .. 0x401200]

Block 0x401070 [entry]
  0x401070  push   rbp
  0x401071  mov    rbp, rsp
  0x401074  sub    rsp, 0x40
  -> block 0x401078

Block 0x401078
  0x401078  cmp    edi, 1
  0x40107b  jle    0x4010c0
  -> block 0x40107f (fall-through)
  -> block 0x4010c0 (conditional)

Block 0x40107f
  ...
```

Each block shows its start address, the instructions it contains, and the outgoing edges.

## The Two-Pass Algorithm

NeoDAX builds CFGs using a two-pass algorithm that correctly handles a challenge called the "jump trick."

In some binaries (especially obfuscated ones), unconditional jumps are used to mislead disassemblers. For example:

```
jmp  0x401010
db   0xff      ; dead byte that looks like an instruction prefix
0x401010:
mov  eax, 0
```

A naive disassembler would try to decode the `0xff` byte as an instruction. NeoDAX's first pass registers all branch targets. In the second pass, it skips dead bytes after unconditional branches and resumes at the next known target.

This means NeoDAX's CFGs are more accurate than single-pass disassemblers.

## Reading a CFG

When looking at a function's CFG:

1. Find the entry block (marked `[entry]`).
2. Trace each path forward.
3. When you encounter a conditional branch, trace both paths.
4. Note where paths rejoin (a block with multiple incoming edges is a join point).
5. Note where back edges create loops.

The structure of the CFG often reveals the algorithm more clearly than reading the linear instruction sequence.

## Practice

1. Run `./neodax -C /bin/ls` and find a function with more than 5 basic blocks.
2. Trace through the CFG of that function and count the number of conditional branches.
3. Identify whether any function has a back edge (a loop).

## Next

Continue to `23_cfg_in_practice.md`.
