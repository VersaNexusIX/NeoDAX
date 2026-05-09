# Cross References

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 20_functions_detection.md
**What You Will Learn:** How to build and interpret cross-references to understand program structure.

## What Cross References Are

A cross-reference (xref) records a relationship between two addresses: from where a reference is made and to where it points.

There are two types:

**Call xrefs:** One function calls another. `0x401200 calls 0x401500` means there is a `call 0x401500` instruction at address `0x401200`.

**Branch xrefs:** A conditional or unconditional jump. `0x401234 branches to 0x401260` means a `jmp` or `je` instruction at `0x401234` targets `0x401260`.

## Building Cross References

```bash
./neodax -r /bin/ls
```

The output lists all detected xrefs. The list can be long for a real binary.

## What Cross References Tell You

**Who calls a function?** If you find a function that does something interesting, the call xrefs to it tell you which other functions invoke it. This reveals how the interesting function fits into the larger program.

**What does a function call?** The call xrefs from a function tell you what it depends on. A function that calls `malloc`, `memcpy`, and `free` is probably managing a buffer.

**Data references:** Xrefs to data addresses (strings, tables, constants) show you which functions use specific data.

## Xref Depth

The xref graph has depth. If function A calls function B which calls function C, then A indirectly depends on C. Tracing these chains reveals the call hierarchy of the program.

At the top of the hierarchy are high-level operations. At the bottom are primitive operations like memory allocation, string operations, and system calls.

## Cross References and Strings

A particularly useful technique: find an interesting string, note its address, then look up which functions reference that address in the xref table.

For example, if a binary contains the string `"password incorrect"` at address `0x402100`, searching the xrefs for references to `0x402100` tells you which function handles password checking.

## Practice

1. Run `./neodax -r /bin/ls` and find a function that is called by many others.
2. Find the function that calls the most other functions.
3. Identify at least one string reference xref (a branch or load that targets a data address rather than a code address).

## Next

Continue to `22_control_flow_graphs.md`.
