# Call Graphs

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 24_loop_detection.md
**What You Will Learn:** How to generate and use call graphs to understand program architecture.

## What a Call Graph Is

A call graph is a directed graph where nodes are functions and edges connect callers to callees. If function A calls function B, there is an edge from A to B.

The call graph shows the program's high-level architecture: which functions depend on which, which functions are utility functions called by many others, and which functions are top-level operations called rarely.

## Generating a Call Graph

```bash
./neodax -G /bin/ls
```

Output lists each function and its callees:

```
main -> process_args, print_files, sort_entries
process_args -> getopt, strcmp, malloc
print_files -> format_entry, printf, stat
```

The function at the top of the call graph (called by no other function) is an entry point or a constructor.

The functions at the bottom (calling no other functions in the binary) are either leaf functions that do simple computations or wrappers around system calls.

## Call Graph Layers

You can think of the call graph as having layers:

**Layer 0 (root):** Entry points like `main` or constructors. Called by nothing within the binary.

**Layer 1:** Functions called directly from entry points. Often high-level orchestration functions.

**Layer N:** Functions called from layer N-1. Each layer is more specialized and lower-level.

**Leaf layer:** Functions that make only external calls (to libraries, system calls) or no calls at all.

Understanding which layer a function lives in helps you understand what it does. A leaf function does a specific primitive operation. A root function orchestrates the whole program.

## Indirect Calls

Some calls go through function pointers: `call [rax]` or `blr x1`. These are indirect calls. NeoDAX records them in the call graph but cannot statically determine the target. They appear as edges to an unknown target.

A high number of indirect calls suggests the binary uses callbacks, virtual dispatch, or a function table.

## Recursive Functions

A function is recursive if it appears in its own call subgraph: it calls itself directly or calls another function that eventually calls it back.

Direct recursion appears as a self-loop in the call graph. Mutual recursion appears as a cycle between two or more functions.

Recursive functions often implement tree traversal, divide-and-conquer algorithms, or parsers.

## Practice

1. Run `./neodax -G /bin/ls` and find the function that calls the most other functions.
2. Find a leaf function (calls nothing else).
3. Trace the call path from `main` down to a leaf function through at least 3 levels.

## Next

Continue to `26_switch_tables.md`.
