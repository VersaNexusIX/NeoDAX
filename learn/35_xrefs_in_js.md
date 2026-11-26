# Cross References in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 34_disasm_json.md
**What You Will Learn:** How to query cross-references programmatically and build analysis tools from them.

## Getting All Cross References

```javascript
neodax.withBinary('/bin/ls', bin => {
    const xrefs = bin.xrefs()
    console.log('Total xrefs:', xrefs.length)

    const calls = xrefs.filter(x => x.isCall)
    const branches = xrefs.filter(x => !x.isCall)
    console.log('Calls:', calls.length)
    console.log('Branches:', branches.length)
})
```

## Xref Object Properties

```javascript
x.from      // BigInt: address of the instruction making the reference
x.to        // BigInt: address being referenced
x.isCall    // boolean: true for calls, false for branches
```

## Querying by Target

Find all callers of a specific function:

```javascript
function callers(bin, targetAddr) {
    return bin.xrefs()
        .filter(x => x.isCall && x.to === targetAddr)
        .map(x => x.from)
}

neodax.withBinary('/bin/ls', bin => {
    const fns = bin.functions()
    const mainFn = fns.find(f => f.name === 'main')
    if (mainFn) {
        const mainCallers = callers(bin, mainFn.start)
        console.log('main is called from:', mainCallers.length, 'places')
    }
})
```

## Targeted Queries

Use the targeted methods for better performance than filtering all xrefs:

```javascript
// All xrefs that point TO a given address
const incoming = bin.xrefsTo(0x401234n)

// All xrefs FROM a given address
const outgoing = bin.xrefsFrom(0x401234n)
```

## Building a Call Graph Programmatically

```javascript
neodax.withBinary('/bin/ls', bin => {
    const functions = bin.functions()
    const xrefs = bin.xrefs().filter(x => x.isCall)

    // Build a map from start address to function name
    const fnMap = new Map()
    functions.forEach(fn => fnMap.set(fn.start, fn.name))

    // Build adjacency list
    const callGraph = new Map()
    functions.forEach(fn => callGraph.set(fn.name, new Set()))

    xrefs.forEach(x => {
        const callerFn = bin.funcAt(x.from)
        const calleeName = fnMap.get(x.to) || 'unknown'
        if (callerFn) {
            callGraph.get(callerFn.name)?.add(calleeName)
        }
    })

    // Print top-level entries
    callGraph.forEach((callees, caller) => {
        if (callees.size > 0) {
            console.log(caller, '->', [...callees].join(', '))
        }
    })
})
```

## Finding Unused Functions

Functions that are never called (no incoming xrefs) are potential dead code, constructors, or entry points:

```javascript
neodax.withBinary('/bin/ls', bin => {
    const xrefs = bin.xrefs().filter(x => x.isCall)
    const calledAddrs = new Set(xrefs.map(x => x.to))

    const unused = bin.functions().filter(fn => !calledAddrs.has(fn.start))
    console.log('Uncalled functions:', unused.map(f => f.name))
})
```

## Practice

1. Count how many unique functions are called by `main` directly.
2. Find the function that has the most incoming call xrefs.
3. List all functions that are never called by other functions in the binary.

## Next

Continue to `36_analyze_pipeline.md`.
