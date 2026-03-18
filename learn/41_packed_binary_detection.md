# Packed Binary Detection

**Level:** 4 - Advanced Analysis
**Prerequisites:** 40_entropy_analysis.md
**What You Will Learn:** How to identify packed, obfuscated, or encrypted binaries using multiple NeoDAX features.

## Signs of Packing

No single indicator confirms packing. Use multiple signals together:

**High entropy sections:** The clearest indicator. Legitimate code rarely exceeds 7.0 bits/byte.

**Few imports:** A packed binary often imports only the functions needed for the unpacker stub. The real import table is inside the packed payload.

**Suspicious section names:** Non-standard names like `.UPX0`, `_RDATA`, or random strings where `.text` should be.

**Small code section with large data section:** The unpacker stub is small; the compressed payload is large.

**No readable strings:** If a binary has almost no ASCII strings, its data is likely encrypted.

**No recognizable functions:** Few detected functions with no identifiable names suggests the analysis-visible code is minimal.

## Combining Signals in NeoDAX

```bash
./neodax -l -y -t -e /bin/suspicious
```

This runs sections, symbols, strings, and entropy together. Look for:

1. Section count: typical packed binary has 2-4 sections
2. Symbol count: stripped and few PLT symbols
3. Strings: almost none
4. Entropy: at least one section above 7.0

## In JavaScript

```javascript
function isProbablyPacked(bin) {
    const sections = bin.sections()
    const symbols  = bin.symbols()
    const result   = bin.analyze()
    const entropy  = bin.entropy()

    const signals = {
        highEntropy:    entropy.includes('PACKED') || entropy.includes('HIGH'),
        fewImports:     symbols.filter(s => s.name.includes('@plt')).length < 5,
        fewSections:    sections.length < 4,
        fewFunctions:   result.functions.length < 10,
        fewStrings:     result.strings?.length < 5,
    }

    const score = Object.values(signals).filter(Boolean).length
    return { signals, score, likelyPacked: score >= 3 }
}
```

## Identifying the Unpacker Stub

If you have identified a likely packed binary, find the unpacker stub:

1. Run `./neodax -e binary` to find the low-entropy section (the stub).
2. Disassemble the stub section.
3. Look for a loop that reads from the high-entropy section and writes to an executable region.
4. The loop contains the decryption or decompression logic.

## Common Packer Signatures

While NeoDAX does not include a packer signature database, the entropy patterns are distinctive:

**UPX:** Two sections, both nearly 8.0 entropy. Very few imports.

**MPRESS:** One section with 7.5+ entropy, very small stub.

**Enigma Protector:** Multiple sections, some high entropy, code section is virtualized.

**Custom XOR stub:** Single high-entropy data section, small code section with arithmetic-heavy loop.

## Practice

1. Download a UPX binary (or pack one yourself with `upx myprog`) and run the full detection analysis.
2. Compare the import count before and after packing.
3. Write a JavaScript function that scores a binary on the packing indicators.

## Next

Continue to `42_recursive_descent.md`.
