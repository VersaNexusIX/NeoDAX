# Building Custom Analysis Plugins

**Level:** 7 - Integration and Automation
**Prerequisites:** 75_ci_cd_integration.md
**What You Will Learn:** How to build reusable analysis modules on top of NeoDAX.

## Plugin Architecture

A NeoDAX plugin is a JavaScript module that takes a binary handle and returns structured analysis results. This pattern makes plugins composable: you can run multiple plugins on the same binary and combine their results.

## A Plugin Interface

```javascript
// plugin interface
// analyze(bin: NeoDAXBinary) => { name: string, passed: boolean, data: any, message: string }

function createPlugin(name, analyzeFn) {
    return { name, analyze: analyzeFn }
}
```

## Example Plugins

```javascript
// Plugin: detect packing indicators
const packingDetector = createPlugin('packing-detector', bin => {
    const entropy = bin.entropy()
    const symbols = bin.symbols()
    const fns     = bin.functions()

    const highEntropy   = entropy.includes('PACKED') || entropy.includes('HIGH')
    const fewImports    = symbols.filter(s => s.name.includes('@plt')).length < 3
    const fewFunctions  = fns.length < 5

    const score   = [highEntropy, fewImports, fewFunctions].filter(Boolean).length
    const passed  = score < 2

    return {
        passed,
        data: { highEntropy, fewImports, fewFunctions, score },
        message: passed ? 'No packing indicators' : `${score} packing indicators detected`,
    }
})

// Plugin: check for dangerous imports
const dangerousImportChecker = createPlugin('dangerous-imports', bin => {
    const dangerous = ['system', 'execve', 'popen', 'ShellExecute']
    const found     = bin.symbols()
        .filter(s => dangerous.some(d => s.name.toLowerCase().includes(d.toLowerCase())))
        .map(s => s.name)

    return {
        passed:  found.length === 0,
        data:    { found },
        message: found.length === 0 ? 'No dangerous imports' : `Found: ${found.join(', ')}`,
    }
})

// Plugin: measure code complexity
const complexityAnalyzer = createPlugin('complexity', bin => {
    const fns        = bin.functions()
    const loopFns    = fns.filter(f => f.hasLoops)
    const avgInsns   = fns.reduce((s, f) => s + f.insnCount, 0) / Math.max(fns.length, 1)
    const complexity = loopFns.length / Math.max(fns.length, 1)

    return {
        passed:  true,
        data:    { total: fns.length, withLoops: loopFns.length, avgInsns: avgInsns.toFixed(0) },
        message: `${fns.length} functions, ${loopFns.length} with loops, avg ${avgInsns.toFixed(0)} insns`,
    }
})
```

## Running Plugins

```javascript
function runPlugins(filePath, plugins) {
    const results = { file: filePath, plugins: [] }
    neodax.withBinary(filePath, bin => {
        for (const plugin of plugins) {
            try {
                const r = plugin.analyze(bin)
                results.plugins.push({ name: plugin.name, ...r })
            } catch (e) {
                results.plugins.push({ name: plugin.name, error: e.message })
            }
        }
    })
    results.allPassed = results.plugins.every(p => p.passed !== false)
    return results
}

// Usage
const plugins = [packingDetector, dangerousImportChecker, complexityAnalyzer]
const result  = runPlugins('/bin/ls', plugins)

result.plugins.forEach(p => {
    const status = p.passed ? 'PASS' : 'FAIL'
    console.log(`[${status}] ${p.name}: ${p.message}`)
})
```

## Sharing Plugins

Plugins are regular JavaScript modules. Package them for sharing:

```javascript
// neodax-plugin-security.js
module.exports = {
    packingDetector,
    dangerousImportChecker,
    createPlugin,
}
```

## Practice

1. Write a plugin that detects whether a binary has more than 10 functions with loops.
2. Write a plugin that checks whether the entry point is in the `.text` section.
3. Combine multiple plugins and run them against 5 different binaries.
4. Print a table showing which binaries passed which checks.

## Next

You have completed Level 7 - Integration and Automation. Continue to the Appendix, starting with `80_common_patterns_reference.md`.
