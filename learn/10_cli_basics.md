# CLI Basics

**Level:** 1 - Basic Analysis
**Prerequisites:** 07_binary_formats_comparison.md
**What You Will Learn:** The complete set of NeoDAX command-line flags and how to combine them.

## Running NeoDAX

The basic syntax is:

```
./neodax [flags] <binary>
```

Without flags, NeoDAX disassembles the `.text` section of the binary.

## Essential Flags

### -l: List Sections

```bash
./neodax -l /bin/ls
```

Shows all sections with name, type, virtual address, size, and file offset. Always start here to understand the binary's layout.

### -y: Show Symbols

```bash
./neodax -y /bin/ls
```

Lists all symbols with their addresses. On stripped binaries, only dynamic symbols (imported functions) appear.

### -f: Detect Functions

```bash
./neodax -f /bin/ls
```

Runs the function detector and lists detected functions with start address, end address, size, and instruction count.

### -t: Extract Strings

```bash
./neodax -t /bin/ls
```

Extracts printable ASCII strings and annotates them inline in the disassembly.

### -r: Cross-References

```bash
./neodax -r /bin/ls
```

Builds a cross-reference table showing which addresses call or branch to which targets.

### -C: Control Flow Graph

```bash
./neodax -C /bin/ls
```

Builds and prints the CFG for each detected function.

## Targeting Specific Areas

### -s: Target a Specific Section

```bash
./neodax -s .rodata /bin/ls
```

Disassembles only the specified section instead of the default `.text`.

### -A and -E: Address Range

```bash
./neodax -A 0x401000 -E 0x401200 /bin/ls
```

Disassembles only the bytes between two virtual addresses. Useful when you know which function you want to examine.

### -S: All Sections

```bash
./neodax -S /bin/ls
```

Disassembles all executable sections, not just `.text`. Useful when code is spread across multiple sections.

## Output Modifiers

### -n: No Color

```bash
./neodax -n /bin/ls
```

Disables ANSI color codes. Use this when piping output to a file or another tool.

### -a: Show Raw Bytes

```bash
./neodax -a /bin/ls
```

Shows the hex bytes alongside the disassembly.

### -v: Verbose

```bash
./neodax -v /bin/ls
```

Shows additional information about the analysis process.

### -d: Demangle C++ Names

```bash
./neodax -d /path/to/cpp_binary
```

Runs Itanium ABI demangling on C++ symbol names, turning `_ZN3foo3barEv` into `foo::bar()`.

## Combining Flags

Flags can be combined freely:

```bash
./neodax -f -r -t /bin/ls
```

This detects functions, builds xrefs, and extracts strings in one pass.

The `-x` flag is a shorthand for all standard analysis flags combined:

```bash
./neodax -x /bin/ls
```

The `-X` flag includes everything, including the advanced analysis features:

```bash
./neodax -X /bin/ls
```

## Saving Output

Pipe the output to a file for later reading:

```bash
./neodax -n -x /bin/ls > analysis.txt
```

Use `-n` (no color) when saving to a file to avoid embedding ANSI escape codes.

## DAXC Snapshots

You can save an analysis snapshot to a `.daxc` file and reload it later:

```bash
./neodax -x -o snapshot.daxc /bin/ls
./neodax -c snapshot.daxc
```

The snapshot preserves all analysis results so you do not need to reanalyze the binary each time.

## Practice

1. Run `./neodax -h` and read every flag description.
2. Run `./neodax -l -y /bin/ls` to see sections and symbols together.
3. Run `./neodax -f /bin/ls` and count the detected functions.
4. Run `./neodax -n -x /bin/ls > /tmp/ls_analysis.txt` and open the file.

## Next

Continue to `11_reading_sections.md`.
