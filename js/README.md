# NeoDAX JavaScript API

Node.js native addon and REST API for the NeoDAX binary analysis engine.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Installation

The JS addon must be compiled on the target device — it is a native binary.

```bash
# From the NeoDAX root:
make js

# Or use the standalone script:
bash build_js.sh
```

This produces `js/neodax.node`. No `npm install` required.

---

## Quick Start

```js
const neodax = require('./js');

// Auto-close with withBinary
neodax.withBinary('/path/to/binary', bin => {
    console.log(bin.arch);        // 'AArch64 (ARM64)'
    console.log(bin.sha256);      // 'a3f8...'
    console.log(bin.isPie);       // true / false

    const fns  = bin.functions();
    const syms = bin.symbols();
    console.log(fns.length, 'functions');
});

// Manual lifecycle
const bin = neodax.load('/path/to/binary');
console.log(bin.info);
bin.close();

// Async
await neodax.withBinaryAsync('./binary', async bin => {
    const r = bin.analyze();
    return r.functions.length;
});
```

---

## `NeoDAXBinary` Class

### Properties

| Property | Type | Description |
|---|---|---|
| `info` | `BinaryInfo` | Full binary metadata object |
| `arch` | `string` | Architecture string |
| `format` | `string` | Format string (ELF64, PE32+, …) |
| `os` | `string` | OS/ABI string |
| `entry` | `bigint` | Entry point virtual address |
| `sha256` | `string` | SHA-256 hex digest |
| `buildId` | `string` | GNU Build-ID hex string |
| `isPie` | `boolean` | Position-independent executable |
| `isStripped` | `boolean` | No symbol table |
| `hasDebug` | `boolean` | DWARF debug sections present |
| `file` | `string` | Absolute file path |
| `loadTimeMs` | `number` | Time to load and parse (ms) |

---

### Analysis Methods

#### `sections() → Section[]`
All sections with name, type, virtual address, file offset, size, flags, instruction count.

#### `symbols() → Symbol[]`
All symbols from `.symtab`, `.dynsym`, or PE export table.

#### `functions() → Function[]`
Detected function boundaries.

#### `xrefs() → Xref[]`
All cross-references (call + branch).

#### `xrefsTo(address) → Xref[]`
Cross-references targeting a specific address.

#### `xrefsFrom(address) → Xref[]`
Cross-references originating from an address.

#### `blocks() → Block[]`
CFG basic blocks.

#### `unicodeStrings() → UnicodeString[]`
Genuine multi-byte Unicode strings in non-code sections.

#### `strings() → AsciiString[]`
ASCII printable strings of length ≥ 4 from non-code sections.

#### `analyze() → AnalysisResult`
Full pipeline (symbols → functions → xrefs → CFG → unicode) in one call.

---

### Lookup Methods

#### `symAt(address) → Symbol | null`
#### `funcAt(address) → Function | null`
#### `sectionByName(name) → Section | null`
#### `sectionAt(address) → Section | null`
#### `readBytes(address, length) → Uint8Array | null`
#### `hottestFunctions(n?) → HottestFunction[]`

---

### Disassembly Methods

#### `disasm(section?) → string`
Plain-text disassembly.

#### `disasmJson(section?, opts?) → Instruction[]`
Structured disassembly with `address`, `mnemonic`, `operands`, `bytes`, `symbol`, `group`.

Options: `{ limit: 400, offset: 0 }`

---

### Advanced Analysis (ARM64)

#### `symexec(funcIdx?) → string`
Symbolic execution trace showing register state as symbolic expressions.

#### `ssa(funcIdx?) → string`
SSA-form IR: `r0_2 = r0_0 + 0x7`.

#### `decompile(funcIdx?) → string`
Pseudo-C output from SSA IR.

#### `emulate(funcIdx?, initRegs?) → string`
Concrete emulation with step-by-step trace and final register state.

```js
bin.emulate(0, { '0': 42n, '1': 7n })
```

---

### Lifecycle

#### `close()`
Free all native resources.

#### `[Symbol.dispose]()`
Supports `using` declarations in TypeScript 5+.

---

## Module Functions

```js
neodax.load(filePath)                         // → NeoDAXBinary
neodax.version()                              // → '1.0.0'
neodax.withBinary(filePath, cb)              // → T
neodax.withBinaryAsync(filePath, cb)         // → Promise<T>
```

---

### Detection Methods

#### `entropy() → string`
Shannon entropy sliding window scan. Returns annotated text output identifying HIGH (≥ 6.8 bits/byte) and PACKED/ENCRYPTED (≥ 7.0) regions per section.

#### `rda(section?) → string`
Recursive descent disassembly on `section` (default `.text`). BFS from entry + all symbols. Dead byte ranges marked `[DEAD: 0xstart .. 0xend]`.

#### `ivf() → string`
Instruction validity filter scan of all code sections. Reports: invalid opcodes, privileged instructions in userspace, NOP-runs ≥ 8, INT3-runs ≥ 3, dead bytes after unconditional branches.

---

## TypeScript

```ts
import { load, withBinary, NeoDAXBinary,
         BinaryInfo, Section, Symbol, Function,
         Xref, Block, Instruction, UnicodeString,
         AsciiString, HottestFunction, AnalysisResult } from './js';
```

---

## REST API Server

```bash
node js/server/server.js
# PORT=8080 node js/server/server.js
```

Default port **7070** — Web UI at `http://localhost:7070/ui`

All endpoints: `POST` with `Content-Type: application/json` and `{ "file": "/absolute/path" }`.

| Path | Extra body fields | Description |
|------|-------------------|-------------|
| `/api/info` | — | Binary metadata |
| `/api/sections` | — | Section table |
| `/api/symbols` | — | Symbol table |
| `/api/functions` | — | Function list |
| `/api/xrefs` | — | All xrefs |
| `/api/xrefs-to` | `address` | Xrefs to address |
| `/api/xrefs-from` | `address` | Xrefs from address |
| `/api/blocks` | — | CFG blocks |
| `/api/unicode` | — | Unicode strings |
| `/api/strings` | — | ASCII strings |
| `/api/disasm` | `section?` | Plain-text disasm |
| `/api/disasm/json` | `section?`, `group?`, `limit?` | Structured disasm |
| `/api/analyze` | — | Full analysis pipeline |
| `/api/sym-at` | `address` | Symbol at address |
| `/api/func-at` | `address` | Function at address |
| `/api/section-at` | `address` | Section at address |
| `/api/hottest` | `n?` | Hottest functions |
| `/api/read-bytes` | `address`, `length` | Raw bytes |
| `/api/symexec` | `funcIdx?` | Symbolic execution |
| `/api/ssa` | `funcIdx?` | SSA form |
| `/api/decompile` | `funcIdx?` | Pseudo-C |
| `/api/emulate` | `funcIdx?`, `initRegs?` | Concrete emulation |

`address` values: `"0x..."` hex strings. `bigint` values in responses: `"0x..."` hex strings.

---

## Examples

```bash
node js/examples/01_binary_info.js /bin/ls
node js/examples/02_symbols_functions.js /bin/ls
node js/examples/03_disasm_json.js /bin/ls
node js/examples/04_unicode_strings.js /bin/ls
node js/examples/05_xrefs_callgraph.js /bin/ls
node js/examples/06_full_analysis.js /bin/ls
```
