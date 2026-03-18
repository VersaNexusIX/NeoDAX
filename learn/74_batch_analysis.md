# Batch Analysis

**Level:** 7 - Integration and Automation
**Prerequisites:** 73_express_integration.md
**What You Will Learn:** How to analyze many binaries efficiently and store results.

## Batch Analysis Architecture

When analyzing many binaries, the key concerns are:

- **Memory:** Each binary handle uses memory. Release handles when done.
- **Error handling:** One bad binary should not stop the batch.
- **Progress:** Long batches need progress tracking.
- **Output:** Results need to be stored in a queryable format.

## A Complete Batch Script

```javascript
const neodax = require('neodax')
const fs     = require('fs')
const path   = require('path')

function analyzeFile(filePath) {
    try {
        let result = null
        neodax.withBinary(filePath, bin => {
            const fns     = bin.functions()
            const secs    = bin.sections()
            const entropy = bin.entropy()

            result = {
                path:       filePath,
                name:       path.basename(filePath),
                sha256:     bin.sha256,
                arch:       bin.arch,
                format:     bin.format,
                isPie:      bin.isPie,
                isStripped: bin.isStripped,
                sections:   secs.length,
                functions:  fns.length,
                symbols:    bin.symbols().length,
                hasLoops:   fns.filter(f => f.hasLoops).length,
                codeSize:   secs.filter(s => s.type === 'code')
                                .reduce((n, s) => n + Number(s.size), 0),
                highEntropy: entropy.includes('HIGH') || entropy.includes('PACKED'),
                timestamp:  new Date().toISOString(),
            }
        })
        return { ok: true, result }
    } catch (e) {
        return { ok: false, error: e.message, path: filePath }
    }
}

function findBinaries(dir) {
    const result = []
    function walk(d) {
        for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
            const full = path.join(d, entry.name)
            if (entry.isDirectory()) walk(full)
            else if (entry.isFile()) result.push(full)
        }
    }
    walk(dir)
    return result
}

async function batchAnalyze(sourceDir, outputFile, batchSize = 8) {
    const files = findBinaries(sourceDir)
    console.log(`Found ${files.length} files in ${sourceDir}`)

    const results = []
    const errors  = []

    for (let i = 0; i < files.length; i += batchSize) {
        const batch = files.slice(i, i + batchSize)
        for (const file of batch) {
            const r = analyzeFile(file)
            if (r.ok) results.push(r.result)
            else errors.push(r)
        }
        process.stdout.write(`\r${Math.min(i+batchSize, files.length)}/${files.length}`)
    }
    console.log()

    const output = { results, errors, total: files.length, analyzed: results.length }
    fs.writeFileSync(outputFile, JSON.stringify(output, null, 2))
    console.log(`Results: ${results.length} analyzed, ${errors.length} failed`)
    console.log(`Saved to: ${outputFile}`)
}

const [,, sourceDir = '/usr/bin', outputFile = '/tmp/batch_results.json'] = process.argv
batchAnalyze(sourceDir, outputFile)
```

## Querying Results

After batch analysis, load the JSON and query it:

```javascript
const data = JSON.parse(fs.readFileSync('/tmp/batch_results.json'))
const results = data.results

// Most complex binaries
const complex = results
    .sort((a, b) => b.functions - a.functions)
    .slice(0, 10)

// Suspicious binaries
const suspicious = results.filter(r =>
    r.highEntropy && r.isStripped && r.functions < 10
)

// By architecture
const armBinaries = results.filter(r => r.arch.includes('ARM'))
```

## Practice

1. Run the batch analysis script on `/usr/bin`.
2. Find the binary with the most functions.
3. Find all stripped binaries with fewer than 5 detected functions.
4. Calculate the average number of sections across all analyzed binaries.

## Next

Continue to `75_ci_cd_integration.md`.
