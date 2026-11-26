# DAXC Snapshots

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 65_stripping_and_obfuscation.md
**What You Will Learn:** How `.daxc` snapshots work, how to create and load them, and how to compile and run them as standalone binaries.

## What DAXC Is

`.daxc` is NeoDAX's snapshot format. It saves the full result of an analysis - functions, disassembly, symbols, comments, cross-references - as a **compilable C source file**.

This is not a binary blob. You can open a `.daxc` file in any text editor and read it. You can grep it, diff it, and commit it to version control. You can also compile it directly with GCC or Clang and run it as a standalone viewer without NeoDAX installed.

## Creating a Snapshot

```bash
neodax -x -o analysis.daxc ./binary
```

The `-o` flag specifies the output path. After writing, NeoDAX prints:

```
  [DAXC] Written : analysis.daxc
  [DAXC] Insns   : 4217
  [DAXC] Funcs   : 38
  [DAXC] Format  : NEOX v4 (AOT C source)
  [DAXC] Compile : clang -O2 -o snapshot analysis.daxc
  [DAXC] Run     : ./snapshot  [-n no-color]  [-f funcs-only]
  [DAXC] Load    : neodax analysis.daxc
```

## What Gets Saved

The snapshot embeds:

- Binary metadata: arch, format, OS, entry point, base address, SHA-256, build ID, PIE/stripped/debug flags
- Every detected function with start and end address
- Every disassembled instruction with address, mnemonic, operands, raw bytes, and instruction group
- All comments added during interactive or analysis sessions
- The NeoDAX version that produced the file

## The DAXC File Format

A `.daxc` file is a single C translation unit. Open one and you will see:

```c
#define DAXC_MAGIC     "NEOX"
#define DAXC_VERSION   4
#define DAXC_ARCH      1
#define DAXC_ENTRY     0x0000000000004050ULL
#define DAXC_NFUNCS    38
#define DAXC_NINSNS    4217

static const char daxc_filepath[] = "/bin/ls";
static const char daxc_sha256[]   = "3b4c...";

static const daxc_func_t daxc_functions[38] = {
    { "main", 0x0000000000004050ULL, 0x0000000000004280ULL },
    ...
};

static const daxc_insn_t daxc_insns[4217] = {
    { 0x0000000000004050ULL, "push", "rbp", {85}, 1, 8 },
    ...
};

int main(int argc, char **argv) { ... }
```

The format uses magic `NEOX` at version 4. See `FORMAT_DAXC.md` for the full specification.

## Compiling and Running Standalone

```bash
clang -O2 -o snap analysis.daxc
./snap           # color disassembly viewer
./snap -n        # no color (pipe-friendly)
./snap -f        # functions list only
```

The compiled binary works on any machine - no NeoDAX installation required. This is useful for sharing analysis results with colleagues or embedding snapshots in CI artifacts.

## Loading Back into NeoDAX

```bash
neodax analysis.daxc            # load and show disassembly
neodax -l analysis.daxc         # list functions only
neodax -c analysis.daxc         # convert to annotated .S assembly
```

NeoDAX detects `.daxc` files by their extension and parses the C source directly. It extracts arch, format, functions, and comments without compiling the file.

## Converting to Annotated Assembly

```bash
neodax -c analysis.daxc
```

This reads the instruction table from the snapshot and writes a `.S` file with function labels, symbol annotations, and comments interleaved:

```asm
.file "analysis.daxc"
.arch x86_64

.global main
.type main, @function
main:
    push       rbp                           /* 0x0000000000004050 */
    mov        rbp, rsp                      /* 0x0000000000004051 */
    ...
```

## Diffing Snapshots

Because `.daxc` is plain text, you can diff two snapshots across builds:

```bash
diff build_a.daxc build_b.daxc
git diff v1.daxc v2.daxc
```

This is useful for tracking what changed between binary builds - new functions, removed functions, changed instruction sequences.

## Sharing Without the Binary

You can share a `.daxc` file with a colleague who has NeoDAX installed and they can load the full analysis:

```bash
neodax their_analysis.daxc
```

They see the same disassembly, functions, and comments you produced - without needing the original binary. This is useful for malware analysis teams where the sample cannot leave a sandboxed environment.

## config.dax-ng

The `[daxc]` section of `config.dax-ng` documents the format in use:

```ini
[daxc]
format_version  = 4
magic           = NEOX
extension       = .daxc
compile_hint    = clang -O2 -o snapshot <file.daxc>
```

To change the default output extension or update version hints after a NeoDAX upgrade, edit this file rather than hunting through source.

## Practice

1. Run `neodax -x -o ls.daxc /bin/ls` to create a snapshot.
2. Open `ls.daxc` in a text editor. Find the `daxc_functions` table and count the entries.
3. Compile it: `clang -O2 -o ls_snap ls.daxc && ./ls_snap -f`
4. Load it: `neodax ls.daxc`
5. Convert it: `neodax -c ls.daxc && head -40 ls.S`

## Next

You have completed Level 6. Continue to `70_rest_api_automation.md` to begin Level 7 - Integration and Automation.
