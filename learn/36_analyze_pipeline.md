# The Analyze Pipeline

**Level:** 3 - JavaScript API
**Prerequisites:** 35_xrefs_in_js.md
**What You Will Learn:** How to use the full analysis pipeline and process the combined result object.

## Running Full Analysis

The `analyze()` method runs the complete analysis pipeline in one call:

```javascript
neodax.withBinary('/bin/ls', bin => {
    const result = bin.analyze()
})
```

This is equivalent to the CLI's `-x` flag.

## Result Object Structure

```javascript
result.info         // binary metadata (same as bin.arch, bin.format, etc.)
result.sections     // array of section objects
result.symbols      // array of symbol objects
result.functions    // array of function objects
result.xrefs        // array of xref objects
result.blocks       // array of CFG block objects
result.loadTimeMs   // number: time to load in milliseconds
result.analysisTimeMs // number: time to analyze in milliseconds
```

## The info Object

```javascript
result.info.arch        // architecture string
result.info.format      // format string
result.info.os          // OS string
result.info.entry       // BigInt: entry point
result.info.sha256      // SHA-256 hash
result.info.isPie       // boolean
result.info.isStripped  // boolean
result.info.hasDebug    // boolean
result.info.codeSize    // BigInt: total code bytes
result.info.imageSize   // BigInt: total image size
```

## Building a Summary Report

```javascript
const neodax = require('neodax')

function summarize(filePath) {
    neodax.withBinary(filePath, bin => {
        const r = bin.analyze()
        const i = r.info

        const codeSecs = r.sections.filter(s => s.type === 'code')
        const loopFns  = r.functions.filter(f => f.hasLoops)
        const calls    = r.xrefs.filter(x => x.isCall)

        console.log('File:', filePath)
        console.log('Format:', i.format, '|', i.arch)
        console.log('SHA-256:', i.sha256)
        console.log('PIE:', i.isPie, '| Stripped:', i.isStripped)
        console.log('Code sections:', codeSecs.length)
        console.log('Functions:', r.functions.length, '(', loopFns.length, 'with loops)')
        console.log('Symbols:', r.symbols.length)
        console.log('Xrefs:', r.xrefs.length, '(', calls.length, 'calls)')
        console.log('Load time:', r.loadTimeMs, 'ms')
        console.log()
    })
}

// Analyze all arguments
process.argv.slice(2).forEach(summarize)
```

## Timing Considerations

The `analyze()` method does all work synchronously. For large binaries, it may take several seconds.

For a web server, run analysis in a worker thread or offload it to avoid blocking the event loop:

```javascript
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads')

if (!isMainThread) {
    const neodax = require('neodax')
    neodax.withBinary(workerData.path, bin => {
        const result = bin.analyze()
        parentPort.postMessage(result)
    })
}
```

## Practice

1. Use `analyze()` on three different binaries and compare their stats.
2. Build the summary report script above and run it on five different system binaries.
3. Identify which binary has the highest ratio of functions to symbols (indicating how stripped it is).

## Next

Continue to `37_typescript_usage.md`.
