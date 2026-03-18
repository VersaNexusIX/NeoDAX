# JavaScript API Quick Reference

**Level:** Appendix
**What This Is:** Every NeoDAX JavaScript API method in one place.

## Loading

```javascript
const neodax = require('neodax')

// Auto-close after callback
neodax.withBinary(path, bin => { ... })

// Manual lifecycle
const bin = neodax.load(path)
// ... use bin ...
bin.close()

// Async callback
await neodax.withBinaryAsync(path, async bin => { ... })
```

## Binary Properties (no call needed)

```javascript
bin.arch        // 'x86_64' | 'AArch64 (ARM64)' | 'RISC-V RV64' | ...
bin.format      // 'ELF64' | 'ELF32' | 'PE64' | 'PE32' | 'Mach-O 64' | ...
bin.os          // 'Linux' | 'Windows' | 'macOS' | 'Android' | ...
bin.entry       // BigInt: entry point virtual address
bin.sha256      // string: hex SHA-256 of the binary
bin.buildId     // string: GNU build ID or empty string
bin.isPie       // boolean
bin.isStripped  // boolean
bin.hasDebug    // boolean
bin.file        // string: absolute file path
```

## Sections

```javascript
bin.sections()              // Section[]
bin.sectionByName('.text')  // Section | null
bin.sectionAt(addr)         // Section | null (addr = BigInt)
```

Section object:
```javascript
{
    name: string,       // '.text', '.data', etc.
    type: string,       // 'code' | 'data' | 'rodata' | 'bss' | 'plt' | 'got' | 'other'
    vaddr: bigint,
    size: bigint,
    offset: bigint,
    flags: number,
    insnCount: number,
}
```

## Symbols

```javascript
bin.symbols()              // Symbol[]
bin.symAt(addr)            // Symbol | null
```

Symbol object:
```javascript
{
    name: string,       // raw (possibly mangled) name
    demangled: string,  // demangled name or empty string
    address: bigint,
    size: bigint,
    type: string,       // 'func' | 'object' | 'other'
}
```

## Functions

```javascript
bin.functions()            // DaxFunction[]
bin.funcAt(addr)           // DaxFunction | null
bin.hottestFunctions(n)    // { function: DaxFunction, callCount: number }[]
```

DaxFunction object:
```javascript
{
    name: string,
    start: bigint,
    end: bigint,
    size: bigint,
    insnCount: number,
    blockCount: number,
    hasLoops: boolean,
    hasCalls: boolean,
}
```

## Cross References

```javascript
bin.xrefs()             // Xref[]
bin.xrefsTo(addr)       // Xref[] (incoming)
bin.xrefsFrom(addr)     // Xref[] (outgoing)
```

Xref object:
```javascript
{
    from: bigint,
    to: bigint,
    isCall: boolean,    // false = branch
}
```

## Disassembly

```javascript
bin.disasmJson(section, { limit: number, offset: number })  // Instruction[]
```

Instruction object:
```javascript
{
    address: bigint,
    mnemonic: string,
    operands: string,
    length: number,
    group: string,     // 'call' | 'branch' | 'ret' | 'stack' | 'arithmetic' | ...
    bytes: Uint8Array,
    symbol: string | null,
}
```

## Full Analysis

```javascript
bin.analyze()  // AnalyzeResult
```

AnalyzeResult:
```javascript
{
    info: { arch, format, os, entry, sha256, isPie, isStripped, hasDebug, codeSize, imageSize },
    sections: Section[],
    symbols: Symbol[],
    functions: DaxFunction[],
    xrefs: Xref[],
    blocks: Block[],
    loadTimeMs: number,
    analysisTimeMs: number,
}
```

## Raw Access

```javascript
bin.readBytes(addr, length)  // Uint8Array | null
```

## Advanced (ARM64 only)

```javascript
bin.entropy()            // string report
bin.rda(section)         // string report
bin.ivf()                // string report
bin.symexec(funcIdx)     // string report
bin.decompile(funcIdx)   // string report
bin.ssa(funcIdx)         // string report
bin.strings()            // { address: bigint, value: string }[]
bin.unicodeStrings()     // { address: bigint, value: string, encoding: string }[]
bin.emulate(funcIdx, initRegs)  // string report
```

## BigInt Tips

```javascript
// Literal BigInt
const addr = 0x401234n

// Convert number to BigInt
const addr = BigInt(0x401234)

// Convert BigInt to hex string
addr.toString(16)        // '401234'
'0x' + addr.toString(16) // '0x401234'

// JSON serialization
JSON.stringify(obj, (_, v) => typeof v === 'bigint' ? '0x' + v.toString(16) : v)
```
