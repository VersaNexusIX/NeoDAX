# JavaScript API Introduction

**Level:** 3 - JavaScript API
**Prerequisites:** 28_instruction_groups.md
**What You Will Learn:** What the NeoDAX JavaScript API is, when to use it, and how it relates to the CLI.

## Why a JavaScript API

The CLI is excellent for interactive analysis. But when you need to analyze many binaries programmatically, integrate analysis into a larger tool, or build a web-based interface, the CLI becomes inconvenient.

The JavaScript API exposes all NeoDAX analysis capabilities through a native Node.js addon. You call Node.js functions that run the same C analysis engine under the hood, no separate process needed.

## What the API Provides

The same features available through the CLI are available through the API:

- Load and parse any supported binary format
- List sections, symbols, and functions
- Disassemble to structured JSON
- Build CFGs and detect loops
- Extract strings and unicode strings
- Build cross-references
- Run entropy analysis
- Run symbolic execution and decompilation (ARM64)

Additional capabilities only in the API:

- Binary SHA-256 and metadata access
- Programmatic filtering and processing of results
- Integration with web servers and databases
- Batch processing of many files
- TypeScript type declarations for IDE support

## Installation

Via npm (builds the native addon automatically):

```bash
npm install neodax
```

Or build from source after cloning the repository:

```bash
make js
```

This produces `js/neodax.node`.

## A Minimal Example

```javascript
const neodax = require('neodax')

neodax.withBinary('/bin/ls', bin => {
    console.log('Architecture:', bin.arch)
    console.log('Format:', bin.format)
    console.log('SHA-256:', bin.sha256)
    console.log('Sections:', bin.sections().length)
    console.log('Functions:', bin.functions().length)
})
```

Save this as `analyze.js` and run:

```bash
node analyze.js
```

## The withBinary Pattern

The `withBinary` function handles opening and closing the binary handle automatically. The callback receives the binary object and the handle is closed when the callback returns.

This is the recommended pattern for simple scripts. For long-running programs that analyze many files, use `neodax.load()` directly and manage the lifecycle manually.

## BigInt Addresses

All memory addresses in the NeoDAX API are JavaScript BigInt values. This is because 64-bit addresses can exceed the safe integer range of regular JavaScript numbers.

When printing addresses, use `.toString(16)` to get hex:

```javascript
const sections = bin.sections()
sections.forEach(s => {
    console.log(s.name, '0x' + s.vaddr.toString(16))
})
```

## Practice

1. Install NeoDAX via npm or build from source.
2. Run the minimal example above against `/bin/ls`.
3. Modify it to also print the entry point address.

## Next

Continue to `31_loading_binaries_in_js.md`.
