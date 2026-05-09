# Your First Binary Analysis

**Level:** 0 - Foundation
**Prerequisites:** 02_setting_up_neodax.md
**What You Will Learn:** How to run a complete analysis on a binary and understand the output at a high level.

## The -x Flag

The `-x` flag runs all standard analysis in one command. It is the best starting point when you encounter a new binary:

```bash
./neodax -x /bin/ls
```

This runs: disassembly, section listing, symbol resolution, cross-references, string extraction, function detection, instruction groups, CFG building, loop detection, call graph, switch table detection, and unicode string scanning.

The output is long. Do not try to read all of it in one go. The goal for now is to see what kinds of information NeoDAX extracts.

## Reading the Output Structure

The output has several clearly labeled sections. Each section begins with a header line.

The disassembly section shows lines like:

```
0x401000  55              push   rbp
0x401001  48 89 e5        mov    rbp, rsp
0x401004  48 83 ec 20     sub    rsp, 0x20
```

The first column is the virtual address. The second column is the raw bytes. The third and fourth columns are the mnemonic and operands.

The sections listing shows entries like:

```
.text      code    0x401000  size 0x1234  offset 0x1000
.rodata    rodata  0x402234  size 0x0200  offset 0x2234
.data      data    0x403000  size 0x0050  offset 0x3000
```

The strings section shows printable strings found in the binary.

## A Targeted First Look

Rather than running `-x` immediately, a useful habit is to start with the sections:

```bash
./neodax -l /bin/ls
```

Then look at symbols:

```bash
./neodax -y /bin/ls
```

Then disassemble:

```bash
./neodax /bin/ls
```

This builds up your understanding layer by layer instead of flooding you with all information at once.

## What to Look For

When approaching an unknown binary for the first time, ask:

- How many sections are there? A stripped binary with unusual sections is suspicious.
- Are there symbols? Stripped binaries have no symbol names.
- What strings are present? Strings often reveal what a program does.
- What functions are detected? A binary with only a few functions or thousands of small ones is unusual.

## Practice

1. Run `./neodax -x /bin/ls` and scroll through the output.
2. Count how many sections `/bin/ls` has on your system.
3. Find one string in the output that tells you something about what `ls` does.
4. Run `./neodax -f /bin/ls` to list only the detected functions. Note how many there are.

## Next

Continue to `04_understanding_elf_format.md`.
