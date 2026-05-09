# Unicode Strings

**Level:** 2 - Intermediate Analysis
**Prerequisites:** 26_switch_tables.md
**What You Will Learn:** How NeoDAX scans for unicode strings and why this matters for modern software analysis.

## Unicode in Binaries

Modern software increasingly uses unicode strings for user-facing text. On Windows, most system APIs accept UTF-16LE strings (two bytes per character for the Basic Multilingual Plane). On Linux and macOS, UTF-8 is dominant.

When analyzing malware or Windows software, unicode strings often contain important clues that a pure ASCII scan misses.

## Running the Unicode Scanner

```bash
./neodax -u /path/to/binary
```

The scanner searches all sections for UTF-16LE encoded strings.

## The False Positive Problem

A naive unicode scanner produces enormous amounts of noise. Any two-byte sequence can look like a UTF-16LE character. Binary data is full of short sequences that accidentally appear as plausible characters.

NeoDAX applies a seven-layer filter to reduce false positives:

1. Skips strings found in `.dynstr` and `.dynsym` sections (these are ELF internal names, not user strings).
2. Requires at least 6 code units (3 characters minimum).
3. Rejects strings where all characters are in the ASCII range and could be a null-padded ASCII string.
4. Rejects code points below U+02FF (avoids treating binary patterns as text).
5. Checks the bytes preceding the string to verify they are not part of another string.
6. Handles surrogate pairs correctly for characters outside the Basic Multilingual Plane (code points above U+FFFF).
7. Requires that each code unit forms a valid unicode code point.

## What Unicode Strings Reveal

On Windows binaries, unicode strings commonly include:

- File paths and registry keys
- Error messages and dialog text
- URL patterns and hostnames
- Command names and configuration keys

In malware analysis, finding a unicode string like `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` immediately tells you the binary modifies the Windows autorun registry key.

## Comparing ASCII and Unicode Results

Run both scanners and compare:

```bash
./neodax -t -u /path/to/binary
```

If the ASCII scanner finds few strings but the unicode scanner finds many, the binary likely targets Windows or stores its strings in UTF-16 to complicate analysis.

## Practice

1. Run `./neodax -u /bin/ls` on a Linux binary. How many unicode strings are found?
2. If you have a Windows PE binary, run the unicode scanner and compare results with the ASCII scanner.
3. Find a unicode string that reveals something about the binary's functionality.

## Next

Continue to `28_instruction_groups.md`.
