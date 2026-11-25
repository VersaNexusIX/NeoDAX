# Entropy Analysis

**Level:** 4 - Advanced Analysis
**Prerequisites:** 38_async_patterns.md
**What You Will Learn:** What entropy is, how NeoDAX measures it, and how to use it to detect packed and encrypted sections.

## What Entropy Measures

Shannon entropy measures the information density of a byte sequence. High entropy means the bytes are close to random. Low entropy means there is significant repetition or structure.

For binary analysis, entropy is measured in bits per byte on a scale from 0 to 8:

- **0 to 3**: Highly structured data. Executable code with many zeros, sparse arrays, or ASCII text.
- **4 to 6**: Normal range for compiled code and data.
- **6.8 to 7.0 (HIGH)**: Compressed data, encrypted data, or packed code.
- **7.0 to 8.0 (PACKED)**: Almost certainly compressed or encrypted. Random data approaches 8.0.

NeoDAX uses these thresholds: HIGH at 6.8 bits/byte and PACKED at 7.0 bits/byte.

## Running Entropy Analysis

```bash
./neodax -e /bin/ls
```

The output shows entropy for the entire file using a sliding window of 256 bytes with a 64-byte step size:

```
Entropy scan: /bin/ls
  .text      avg 5.82 bits/byte  max 6.41
  .rodata    avg 4.21 bits/byte  max 5.89
  .data      avg 2.15 bits/byte  max 3.44

  No HIGH entropy regions detected.
```

If packed sections exist:

```
  .text      avg 7.81 bits/byte  max 7.95  [PACKED]
  HIGH: 0x401000 - 0x410000 (entropy 7.81)
```

## In JavaScript

```javascript
neodax.withBinary('/bin/ls', bin => {
    const report = bin.entropy()
    console.log(report)
})
```

## Interpreting Results

A normal unobfuscated binary has low to medium entropy throughout. The `.text` section typically sits between 5.0 and 6.5. The `.rodata` section is lower because strings have significant ASCII structure.

When a section has entropy above 7.0, the data inside is likely:

- Compressed with zlib, lz4, or similar
- Encrypted with AES, RC4, or XOR
- A native code stub that decrypts something into memory before running it

## UPX and Other Packers

UPX is a common binary packer. It compresses the original binary and adds a small unpacking stub. The packed binary has very high entropy in its main section and a small low-entropy `.text` stub.

NeoDAX detects the high entropy but cannot unpack the binary. If you suspect packing:

1. Check the entropy with `-e`.
2. Look for a small code section (the unpacker stub) alongside a large high-entropy section.
3. Use a dynamic analysis tool or unpacker to extract the original code.

## Entropy and Encryption

Malware often stores encrypted payloads. A `.data` or custom section with very high entropy combined with code that reads and processes that section is a strong indicator of encryption.

The recursive descent analysis (`-R`) combined with entropy can help: if the code reads from a high-entropy section and passes the result to a function full of XOR operations, that function is likely a decryptor.

## Practice

1. Run `./neodax -e /bin/ls` and note the entropy of each section.
2. If available, run entropy analysis on a UPX-packed binary and compare.
3. Find the section with the highest entropy in three different binaries.

## Next

Continue to `41_packed_binary_detection.md`.
