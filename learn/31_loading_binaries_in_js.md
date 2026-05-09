# Loading Binaries in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 30_js_api_introduction.md
**What You Will Learn:** The different ways to load and manage binary handles in the NeoDAX API.

## Three Loading Patterns

NeoDAX provides three functions for loading binaries:

```javascript
const neodax = require('neodax')
```

### neodax.load(path)

Loads a binary and returns a handle. You are responsible for calling `.close()` when done.

```javascript
const bin = neodax.load('/bin/ls')
try {
    console.log(bin.arch)
    // ... analysis ...
} finally {
    bin.close()
}
```

### neodax.withBinary(path, callback)

Loads a binary, passes it to your callback, and closes it automatically when the callback returns or throws.

```javascript
neodax.withBinary('/bin/ls', bin => {
    console.log(bin.arch)
})
```

### neodax.withBinaryAsync(path, asyncCallback)

Same as `withBinary` but supports async callbacks.

```javascript
await neodax.withBinaryAsync('/bin/ls', async bin => {
    const result = await someAsyncOperation(bin.sha256)
    console.log(result)
})
```

## Binary Metadata Properties

Once loaded, the binary object exposes these properties directly (no function call needed):

```javascript
bin.arch        // 'x86_64', 'AArch64 (ARM64)', 'RISC-V RV64'
bin.format      // 'ELF64', 'ELF32', 'PE64', 'PE32', 'Mach-O 64'
bin.os          // 'Linux', 'BSD', 'Windows', 'Android'
bin.entry       // BigInt: entry point virtual address
bin.sha256      // string: hex SHA-256 hash
bin.buildId     // string: GNU build ID if present
bin.isPie       // boolean: Position Independent Executable
bin.isStripped  // boolean: symbol table was stripped
bin.hasDebug    // boolean: debug sections present
bin.file        // string: absolute path to the binary
```

## Handle Lifecycle

Binary handles hold the loaded binary in memory and maintain analysis state. They should be closed when no longer needed.

For short-lived analysis scripts, `withBinary` handles this for you.

For servers that analyze many binaries, consider caching handles by SHA-256:

```javascript
const cache = new Map()

function getOrLoad(filePath) {
    const bin = neodax.load(filePath)
    const key = bin.sha256
    if (cache.has(key)) {
        bin.close()  // discard duplicate
        return cache.get(key)
    }
    cache.set(key, bin)
    return bin
}

// Clean up on exit
process.on('exit', () => cache.forEach(b => b.close()))
```

## Error Handling

`neodax.load()` throws if:
- The file does not exist
- The file is not a supported format
- Memory allocation fails

Always use try-catch or withBinary which handles errors for you:

```javascript
try {
    neodax.withBinary(path, bin => {
        // ...
    })
} catch (e) {
    console.error('Failed to analyze:', e.message)
}
```

## Practice

1. Load `/bin/ls` and print all metadata properties.
2. Load a non-existent file and observe the error message.
3. Load three different binaries and compare their architectures and formats.
4. Implement the cache pattern above and verify it works by loading the same binary twice.

## Next

Continue to `32_working_with_sections.md`.
