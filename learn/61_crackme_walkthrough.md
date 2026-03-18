# Crackme Walkthrough

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 60_analyzing_malware_basics.md
**What You Will Learn:** A complete walkthrough of analyzing a crackme challenge using NeoDAX techniques.

## What is a Crackme

A crackme is a program designed for reverse engineering practice. It typically asks for a password, serial number, or key, and your goal is to find the correct input through analysis rather than guessing.

Crackmes are ideal for practice because they are intentionally solvable and you can verify your answer.

## Step 1: Initial Recon

Start with triage:

```bash
./neodax -l -y -t /crackme
```

Key questions:
- Is there a string like "Correct!" or "Wrong password"?
- Are there imported functions suggesting how input is processed?
- Is the binary stripped?

## Step 2: Find the Check Function

Look for the function that prints "Correct!" or "Wrong". Use cross-references:

```bash
./neodax -r -t /crackme
```

Find the address of the "Correct!" string in the output. Then find which code address references that string. That code is in the check function.

## Step 3: Analyze the Check

Disassemble the check function:

```bash
./neodax -A <check_function_start> -E <check_function_end> /crackme
```

Look for:
- How is the input read? (via `read`, `scanf`, `gets`, `fgets`)
- What transformations are applied to the input?
- What is the input compared against?

## Step 4: Use the Decompiler (ARM64)

On ARM64 crackmes, the decompiler gives you pseudo-C:

```bash
./neodax -D -A <start> -E <end> /crackme
```

Read the pseudo-C to understand the algorithm directly.

## Step 5: Use Symbolic Execution

Run symbolic execution on the check function:

```bash
./neodax -P /crackme
```

This may directly tell you the relationship between input and the expected value.

## Step 6: Verify

Once you have determined the expected input:

1. Run the crackme with your answer.
2. If you see "Correct!", you have solved it.

## Common Crackme Patterns

**Direct comparison:** The input is compared byte-by-byte or as a whole against a hardcoded string. Read the string from the binary.

**Transformed comparison:** The input is transformed (hashed, encrypted, XOR'd) before comparison. Use symbolic execution or the decompiler to understand the transform.

**Checksum-based:** The sum, product, or XOR of the input's characters must equal a specific value. Multiple inputs satisfy the condition.

**Time-based:** The check uses the current time. Understand the expected state.

## Practice

1. Find a crackme challenge online (crackmes.one is a common resource).
2. Apply the full NeoDAX analysis pipeline.
3. Write notes at each step documenting your findings.
4. Solve the crackme and verify your solution.

## Next

Continue to `62_finding_vulnerabilities.md`.
