# Building Analysis Scripts

**Level:** 7 - Integration and Automation
**Prerequisites:** 70_rest_api_automation.md
**What You Will Learn:** How to build reusable analysis scripts using the NeoDAX JavaScript API.

## Script Design Principles

Good analysis scripts are:

- **Idempotent:** Running the script twice gives the same result.
- **Error tolerant:** A failed binary does not crash the whole batch.
- **Informative:** The script prints progress and clear error messages.
- **Reusable:** Common logic is in functions, not copy-pasted.

## A Reusable Analysis Base

```javascript
const neodax = require('neodax')
const path   = require('path')
const fs     = require('fs')

function analyzeSafe(filePath) {
    try {
        let result = null
        neodax.withBinary(filePath, bin => {
            result = {
                name:       path.basename(filePath),
                path:       filePath,
                sha256:     bin.sha256,
                arch:       bin.arch,
                format:     bin.format,
                isPie:      bin.isPie,
                isStripped: bin.isStripped,
                sections:   bin.sections().length,
                functions:  bin.functions().length,
                symbols:    bin.symbols().length,
            }
        })
        return result
    } catch (e) {
        return {
            name:  path.basename(filePath),
            path:  filePath,
            error: e.message
        }
    }
}

function analyzeDirectory(dirPath, outputPath) {
    const entries = fs.readdirSync(dirPath)
        .map(name => path.join(dirPath, name))
        .filter(p => fs.statSync(p).isFile())

    console.log(`Analyzing ${entries.length} files in ${dirPath}`)
    const results = entries.map((filePath, i) => {
        process.stdout.write(`\r${i+1}/${entries.length}: ${path.basename(filePath)}`)
        return analyzeSafe(filePath)
    })
    console.log()

    fs.writeFileSync(outputPath, JSON.stringify(results, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v, 2))
    console.log(`Results saved to ${outputPath}`)
    return results
}

const [,, dir = '/usr/bin', out = '/tmp/analysis.json'] = process.argv
const results = analyzeDirectory(dir, out)
const successful = results.filter(r => !r.error)
console.log(`\nSuccessful: ${successful.length}, Failed: ${results.length - successful.length}`)
```

## A Suspicious Binary Detector

```javascript
const neodax = require('neodax')

function suspicionScore(filePath) {
    const signals = []
    let score = 0

    neodax.withBinary(filePath, bin => {
        const secs = bin.sections()
        const syms = bin.symbols()
        const fns  = bin.functions()

        if (syms.length < 3) {
            signals.push('very few symbols')
            score += 2
        }

        if (secs.length < 3) {
            signals.push('few sections')
            score += 1
        }

        const entropy = bin.entropy()
        if (entropy.includes('PACKED')) {
            signals.push('high entropy')
            score += 3
        }

        const ivf = bin.ivf()
        if (!ivf.includes('No suspicious')) {
            signals.push('IVF flags')
            score += 2
        }

        const strings = bin.strings()
        if (strings.length < 5) {
            signals.push('few strings')
            score += 1
        }
    })

    return { score, signals, suspicious: score >= 4 }
}
```

## Practice

1. Build the directory analysis script and run it on a directory of binaries.
2. Sort the results by function count and identify the most complex binaries.
3. Build the suspicion score script and test it on a packed binary vs a normal binary.

## Next

Continue to `72_web_ui_usage.md`.
