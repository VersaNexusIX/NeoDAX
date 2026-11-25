# Async Patterns

**Level:** 3 - JavaScript API
**Prerequisites:** 37_typescript_usage.md
**What You Will Learn:** How to structure async analysis code and handle multiple binaries concurrently.

## Synchronous Nature of Analysis

NeoDAX analysis is CPU-bound and synchronous. The `analyze()`, `functions()`, `disasmJson()`, and similar methods run synchronously and block until complete.

This is not a problem for command-line scripts. It becomes important in web servers and multi-file batch processing.

## withBinaryAsync

For cases where your callback contains async operations, use `withBinaryAsync`:

```javascript
const neodax = require('neodax')
const fs = require('fs/promises')

async function analyzeAndSave(filePath, outputPath) {
    await neodax.withBinaryAsync(filePath, async bin => {
        const result = bin.analyze()
        const summary = {
            sha256: result.info.sha256,
            arch: result.info.arch,
            functions: result.functions.length,
        }
        await fs.writeFile(outputPath, JSON.stringify(summary, null, 2))
    })
}
```

Note: the analysis itself still runs synchronously within the callback. The `async` allows you to use `await` for I/O operations around the analysis.

## Processing Multiple Files

To analyze multiple files concurrently, use `Promise.all`:

```javascript
async function analyzeAll(filePaths) {
    const results = await Promise.all(
        filePaths.map(filePath =>
            new Promise((resolve, reject) => {
                try {
                    neodax.withBinary(filePath, bin => {
                        resolve({
                            path: filePath,
                            sha256: bin.sha256,
                            functions: bin.functions().length,
                        })
                    })
                } catch (e) {
                    reject({ path: filePath, error: e.message })
                }
            })
        )
    )
    return results
}
```

Be cautious: loading many large binaries simultaneously consumes significant memory. Consider batching:

```javascript
async function analyzeBatch(filePaths, batchSize = 4) {
    const results = []
    for (let i = 0; i < filePaths.length; i += batchSize) {
        const batch = filePaths.slice(i, i + batchSize)
        const batchResults = await analyzeAll(batch)
        results.push(...batchResults)
        console.log(`Processed ${Math.min(i + batchSize, filePaths.length)} / ${filePaths.length}`)
    }
    return results
}
```

## Worker Threads

For true parallelism, run analysis in worker threads. Each worker has its own event loop and can run NeoDAX synchronously without blocking the main thread:

```javascript
// worker.js
const { workerData, parentPort } = require('worker_threads')
const neodax = require('neodax')

neodax.withBinary(workerData.path, bin => {
    const result = bin.analyze()
    parentPort.postMessage({
        path: workerData.path,
        sha256: result.info.sha256,
        functions: result.functions.length,
        sections: result.sections.length,
    })
})
```

```javascript
// main.js
const { Worker } = require('worker_threads')

function analyzeInWorker(filePath) {
    return new Promise((resolve, reject) => {
        const worker = new Worker('./worker.js', { workerData: { path: filePath } })
        worker.on('message', resolve)
        worker.on('error', reject)
    })
}
```

## Practice

1. Write a script that analyzes all executables in `/usr/bin` (or a subset) and prints a summary table.
2. Use batching to keep memory usage bounded.
3. Handle errors gracefully so one failed binary does not stop the entire batch.

## Next

You have completed Level 3 - JavaScript API. Continue to `40_entropy_analysis.md` to begin Level 4.
