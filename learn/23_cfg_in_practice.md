# CFGs in Practice

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 22_control_flow_graphs.md
**What You Will Learn:** Practical techniques for using CFGs to understand function logic.

## Classifying Function Shapes

CFG shape gives you a quick read of a function's complexity before you read a single instruction.

**Linear function:** One block from entry to return. No branches. Simple operation.

**Diamond shape:** Entry block branches into two paths that rejoin at a merge block before returning. Typical of a simple if-else.

**If without else:** Entry block branches. One path goes directly to the return block. Other path does some work then reaches the same return block.

**Loop body:** A back edge exists. The CFG has a block that branches back to an earlier block. At least one exit condition eventually breaks out of the loop.

**Switch statement:** One block with many outgoing edges, one per case. Each case has its own subgraph that merges back at the end.

## Reading Conditionals

When you see a conditional branch, ask:

1. What is being compared?
2. Which path is taken on success?
3. Which path is the "error" or "cleanup" path?

The fall-through path (the block immediately after the branch in memory) is often the normal success path. The taken branch target is often the error handler or early return.

This is a convention, not a rule. Some compilers invert this. You learn the convention by reading a lot of code.

## Identifying Loops

A loop has three parts:

**Initialization:** Done once before the loop starts (may be in the entry block or the first loop block).

**Condition check:** Decides whether to continue or exit. The block with the back edge usually contains this check.

**Body:** The work done each iteration.

In NeoDAX output, identify the loop by finding the back edge. The source of the back edge is the block that increments the counter or updates the loop variable.

## Unreachable Code

After an unconditional jump or a `ret`, code that follows is unreachable if there is no other way to reach it. NeoDAX's two-pass CFG builder marks such bytes as dead.

Dead bytes between legitimate instructions are sometimes an obfuscation technique or a compiler artifact.

## Connecting CFG to Semantics

The CFG is purely structural. To understand semantics, you combine CFG structure with instruction reading:

1. Read the entry block to understand initialization.
2. For each conditional, determine what condition is being checked.
3. For each path, trace what the code computes.
4. At the return block, determine what is being returned.

This process is essentially manual decompilation. The NeoDAX decompiler (Level 5) automates it for ARM64.

## Practice

1. Pick a function with at least 3 basic blocks from `/bin/ls`.
2. Draw the CFG on paper (boxes for blocks, arrows for edges).
3. Write in each box what the block appears to do.
4. Write a one-sentence description of what the function does.

## Next

Continue to `24_loop_detection.md`.
