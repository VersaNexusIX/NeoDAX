# Hottest Functions

**Level:** 4 - Advanced Analysis
**Prerequisites:** 43_instruction_validity_filter.md
**What You Will Learn:** How to identify the most-called functions and why they matter.

## What "Hottest" Means

In NeoDAX, the hottest functions are those with the most incoming call xrefs. A function called 50 times by other functions is hotter than one called twice.

This is a static measure, not a dynamic profiling result. It counts how many times the function is called in the code, not how many times it actually runs at runtime.

## Running Hottest Functions

CLI:

```bash
./neodax -f -r -v /bin/ls
```

JavaScript:

```javascript
neodax.withBinary('/bin/ls', bin => {
    const hottest = bin.hottestFunctions(10)
    hottest.forEach((entry, i) => {
        console.log(i+1, entry.function.name, entry.callCount + ' calls')
    })
})
```

## What Hottest Functions Tell You

The most-called functions in a program are typically:

- **Utility functions:** Memory allocation, string manipulation, error handling.
- **Logging functions:** Debug or error output called throughout the code.
- **Initialization routines:** Setup functions called at many startup paths.
- **Critical dispatch points:** Functions that route execution to different handlers.

If you need to understand a codebase quickly, the hottest functions are often the best starting point. Understanding what the most-called function does tells you about the program's core patterns.

## Hottest Functions in Malware Analysis

In malware, the hottest functions may be:

- **Decryption helpers:** Called each time an encrypted string or payload needs to be decrypted.
- **Anti-analysis checks:** Called before each significant operation to verify the environment.
- **Communication wrappers:** Called whenever data is sent or received.

Identifying these functions and understanding them reveals the malware's core techniques.

## Ranking by Size vs Call Count

Two different ranking strategies give different insights:

By call count (hottest): Find utility and infrastructure functions.
By size (largest): Find complex algorithms and core logic.

Neither is strictly better. Use both to triangulate the important parts of a binary.

## Practice

1. Run hottest functions on `/bin/ls` and identify the top 5.
2. Disassemble the hottest function and determine what it does.
3. Compare the hottest function list to the largest function list. Are they the same functions?

## Next

Continue to `45_obfuscation_detection.md`.
