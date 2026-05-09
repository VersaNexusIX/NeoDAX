# Finding Vulnerabilities

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 61_crackme_walkthrough.md
**What You Will Learn:** How to use NeoDAX to identify common vulnerability patterns in binary code.

## What NeoDAX Can Help With

NeoDAX is a static analysis tool. It excels at finding patterns in code that suggest vulnerabilities. It does not automatically discover exploitable vulnerabilities, but it helps you find areas worth investigating more closely.

## Buffer Overflow Patterns

A classic buffer overflow occurs when code copies data into a fixed-size buffer without checking the length.

Look for:
- Calls to `strcpy`, `gets`, `sprintf` (unsafe string functions)
- A `malloc` or stack allocation followed by a `memcpy` or loop that writes without bounds checking

In NeoDAX:

```bash
./neodax -y -r /binary
```

Look in the xref table for calls to `strcpy@plt` or `gets@plt`. Each call site is a potential overflow location.

## Use-After-Free Patterns

Use-after-free bugs occur when memory is freed but then accessed again. In static analysis, look for:

- A `free` call followed by a use of the same pointer
- A pointer stored in a structure that is freed while the pointer is still accessible

Trace the lifetime of pointers from `malloc` through `free` and any subsequent uses.

## Format String Vulnerabilities

Format string bugs occur when user-controlled input is passed as the format argument to `printf`-family functions.

Search for:

```bash
./neodax -y -t /binary | grep "printf@plt"
```

Then examine the call sites. If `rdi` (the first argument, the format string) is loaded from user input rather than a constant string, it is a format string vulnerability.

## Integer Overflow Patterns

Integer overflow occurs when arithmetic wraps around the integer size boundary. Common patterns:

- A length value is computed with arithmetic on user input, then used as a `malloc` size
- A multiplication `size * count` without overflow checking
- A subtraction that can produce a negative result used as an unsigned size

Look for arithmetic instructions before `malloc` calls.

## NeoDAX Analysis for Vulnerabilities

A practical workflow:

1. Find all calls to unsafe functions:
   ```bash
   ./neodax -y /binary | grep -E "strcpy|gets|sprintf|scanf"
   ```

2. For each dangerous call, disassemble around it to understand the context:
   ```bash
   ./neodax -A <call_address - 50> -E <call_address + 50> /binary
   ```

3. Identify whether input validation happens before the dangerous call.

4. If no validation: potential vulnerability. Note the location.

## Practice

1. Write a small C program with a known buffer overflow (`strcpy` without length check).
2. Compile it and analyze it with NeoDAX.
3. Find the call to `strcpy@plt` in the output.
4. Verify that no length check exists before the call.

## Next

Continue to `63_reverse_engineering_protocols.md`.
