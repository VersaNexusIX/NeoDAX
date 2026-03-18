# String Extraction

**Level:** 1 - Basic Analysis
**Prerequisites:** 16_riscv_primer.md
**What You Will Learn:** How to extract strings from binaries and use them to understand program behavior.

## Why Strings Matter

Strings embedded in a binary reveal a lot about what a program does. Error messages, file paths, URLs, command names, cryptographic algorithm names, registry keys, and user-facing text all appear as strings in the binary.

Analyzing strings is often the quickest way to form a hypothesis about a program's purpose before diving into disassembly.

## ASCII String Extraction

```bash
./neodax -t /bin/ls
```

NeoDAX extracts printable ASCII strings from all sections (not just .rodata). Strings appear as annotations in the disassembly output next to the instructions that reference them.

A string is printed when a `lea` or `mov` instruction loads its address.

## Unicode String Extraction

```bash
./neodax -u /bin/ls
```

Modern software often uses UTF-16 (Windows) or UTF-8 (everywhere else) for internationalized strings. NeoDAX's unicode scanner applies a multi-layer filter to reduce false positives:

- Requires at least 4 characters
- Skips code points below U+02FF (avoids treating binary data as text)
- Rejects strings composed entirely of ASCII characters in UTF-16 encoding (these are typically not human-readable text)
- Handles surrogate pairs for characters outside the Basic Multilingual Plane

Run both flags together for complete coverage:

```bash
./neodax -t -u /bin/ls
```

## Interpreting String Results

When you see a string like `/etc/passwd`, you know the program accesses that file. When you see `OPENSSL_init_ssl`, you know it uses TLS. When you see `SELECT * FROM`, you know it queries a database.

Some strings are less obvious. A long string of random-looking characters might be a base64-encoded payload. A string like `TVqQAAMAAAA...` is almost certainly a base64-encoded PE file (the MZ header in base64 starts with "TVq").

## False Positives in Raw Sections

String extraction from `.text` (code section) produces false positives. Some byte sequences in code happen to look like printable characters. NeoDAX reports them anyway because a human can filter them.

The most reliable strings come from `.rodata` and `.data` sections. If a string appears in one of these sections, it is almost certainly intentional.

## Using Strings to Navigate

Strings give you entry points for analysis. Once you find an interesting string, note its address. Then search for code that references that address:

```bash
./neodax -r /bin/ls
```

The cross-reference output shows which code addresses load each data address. Find the address of your string in the xref table to discover which functions use it.

## Practice

1. Run `./neodax -t /bin/ls` and find three strings that tell you something about what `ls` does.
2. Find the address of one of those strings in the output.
3. Run `./neodax -u /bin/ls` and note how many unicode strings are found (likely zero for `ls`).
4. Find a binary with unicode strings on your system (Windows binaries, or macOS system frameworks).

## Next

Continue to `18_entry_points_and_flow.md`.
