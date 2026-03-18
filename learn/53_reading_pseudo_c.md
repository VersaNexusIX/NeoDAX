# Reading Pseudo-C Output

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 52_decompiler_output.md
**What You Will Learn:** Techniques for reading and understanding decompiler output, including handling imperfect output.

## The Goal of Pseudo-C

The decompiler does not need to produce compilable C. It needs to produce something a human can read faster than raw assembly. Even imperfect pseudo-C is valuable if it conveys the structure.

## Simplifying the Output Mentally

When reading pseudo-C, apply these mental transformations:

**Rename variables based on context.** The decompiler uses generic names like `x0`, `x1`, `var_8`. When you understand what a variable represents, rename it mentally.

If you see:

```c
uint64_t x0 = strlen(x1);
```

Rename: `x1` is a string pointer, `x0` is the string length.

**Recognize patterns.** Common code patterns appear in predictable pseudo-C forms:

A length-bounded copy:

```c
uint64_t i = 0;
while (i < length) {
    dest[i] = src[i];
    i = i + 1;
}
```

A null-terminated string scan:

```c
uint64_t p = str;
while (*p != 0) {
    p = p + 1;
}
return p - str;
```

**Ignore register artifact noise.** Sometimes the decompiler produces:

```c
x3 = x0;
x0 = x3 + 1;
```

This is really just `x0 = x0 + 1`. The extra assignment is an artifact of the register versioning.

## Handling Unknown Functions

When the decompiler shows a call to an unknown function address:

```c
x0 = sub_401234(x0, x1);
```

Cross-reference it with the symbol table. The address `0x401234` may correspond to a known PLT symbol, making the call:

```c
x0 = malloc(x0);
```

Use the `-y` flag or the JavaScript `symAt()` method to look up addresses.

## Data Type Inference

The decompiler uses `uint64_t` for most values because ARM64 registers are 64-bit. When you know a value is actually a 32-bit int, a pointer, or a boolean, you can mentally substitute the correct type.

Clues:
- A value passed to `strlen` is a `char*`
- A value compared with small constants (0, 1, -1) is probably an `int` or `bool`
- A value used with array indexing is a pointer
- A value that only appears in comparisons and branches is likely a status code

## Iterative Refinement

Understanding complex decompiler output is iterative:

1. Read the whole function once to get the big picture.
2. Identify the most important variables.
3. Rename them.
4. Re-read with the new names.
5. Identify any sub-functions that are called and understand what they do.
6. Re-read with that knowledge.

After a few iterations, most functions become clear.

## Practice

1. Decompile a function that has at least two nested loops.
2. Rename all variables to meaningful names based on context.
3. Write a one-paragraph description of what the function does.
4. Verify your understanding by checking against any available documentation or source code.

## Next

Continue to `54_arm64_emulator.md`.
