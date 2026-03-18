# DAXC Snapshots

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 65_stripping_and_obfuscation.md
**What You Will Learn:** How to use DAXC snapshots to save and reload analysis state.

## What DAXC Is

DAXC (NeoDAX Compiled) is NeoDAX's binary snapshot format. It saves the results of a complete analysis to a file that can be reloaded instantly without re-analyzing the original binary.

This is useful when:
- The original binary is large and analysis is slow
- You want to share analysis results without sharing the binary
- You want to resume analysis later from a saved state

## Creating a Snapshot

```bash
./neodax -x -o snapshot.daxc /path/to/binary
```

The `-o` flag specifies the output file. The snapshot includes:

- Binary metadata (arch, format, SHA-256, etc.)
- Section layout
- Symbols
- Detected functions
- Cross-references
- CFG blocks
- Extracted strings

## Loading a Snapshot

```bash
./neodax -c snapshot.daxc
```

The `-c` flag loads a DAXC snapshot. The output is the same as running the full analysis on the original binary, but much faster because everything was precomputed.

## DAXC Format Details

The DAXC format uses the magic bytes `NEOX` followed by a version number. The current version is 4.

The format is compact and binary, not human-readable. It is designed for fast loading, not inspection. See `FORMAT_DAXC.md` for the complete specification.

## Sharing Analysis

You can share a DAXC snapshot with a colleague who also has NeoDAX installed. They can load the snapshot and see your analysis results without needing the original binary.

This is useful for:
- Team analysis workflows
- Sharing malware analysis results (without sharing the malware)
- Archiving analysis of specific binary versions

## Limitations

A DAXC snapshot captures the analysis state at the time of creation. If you discover new information later (a renamed function, new cross-references), you need to re-run the analysis and create a new snapshot.

The snapshot does not include the original binary's bytes. Disassembly can be re-run from the snapshot because the relevant bytes are stored, but you cannot extract arbitrary sections of the original binary from a snapshot.

## Practice

1. Run `./neodax -x -o test.daxc /bin/ls`.
2. Load it with `./neodax -c test.daxc` and verify the output matches.
3. Compare the load times between analyzing from the original binary and loading the snapshot.

## Next

You have completed Level 6 - Real World RE. Continue to `70_rest_api_automation.md` to begin Level 7.
