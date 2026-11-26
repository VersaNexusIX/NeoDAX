# Working with Functions in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 32_working_with_sections.md
**What You Will Learn:** How to query function data and use it in analysis scripts.

## Listing Functions

```javascript
neodax.withBinary('/bin/ls', bin => {
    const functions = bin.functions()
    console.log('Total functions:', functions.length)

    functions.forEach(fn => {
        const size = Number(fn.end - fn.start)
        console.log(fn.name, '0x' + fn.start.toString(16), size + ' bytes')
    })
})
```

## Function Object Properties

```javascript
fn.name       // string: function name or 'sub_<hex>' for unnamed
fn.start      // BigInt: start address
fn.end        // BigInt: end address (equals start if unknown)
fn.size       // BigInt: end - start (0 if unknown)
fn.insnCount  // number: instruction count
fn.blockCount // number: number of basic blocks
fn.hasLoops   // boolean: loops detected
fn.hasCalls   // boolean: function makes calls
fn.symIndex   // number: index into symbol table (-1 if no symbol)
```

## Finding a Specific Function

By address:

```javascript
const fn = bin.funcAt(0x401234n)  // note BigInt literal with n suffix
if (fn) {
    console.log('Function at that address:', fn.name)
}
```

By name (search manually):

```javascript
function findByName(bin, name) {
    return bin.functions().find(fn => fn.name === name)
}

const main = findByName(bin, 'main')
```

## Hottest Functions

```javascript
const hottest = bin.hottestFunctions(10)
hottest.forEach((entry, i) => {
    const fn = entry.function
    console.log(`${i+1}. ${fn.name} called ${entry.callCount} times`)
})
```

The hottest functions are those most frequently called by other functions in the binary. This helps identify utility functions and central dispatch points.

## Filtering Functions

Find all functions containing loops:

```javascript
const loopFunctions = bin.functions().filter(fn => fn.hasLoops)
console.log('Functions with loops:', loopFunctions.length)
```

Find large functions:

```javascript
const largeFunctions = bin.functions()
    .filter(fn => Number(fn.size) > 500)
    .sort((a, b) => Number(b.size - a.size))

largeFunctions.forEach(fn => {
    console.log(fn.name, Number(fn.size) + ' bytes')
})
```

## Functions and Analysis

The full analysis pipeline runs all analysis in one call:

```javascript
const result = bin.analyze()
// result.functions contains the full function list
// result.xrefs contains cross-references
// result.sections, result.symbols, etc.
```

This is equivalent to running the CLI with `-x` but returns structured JavaScript objects instead of text output.

## Practice

1. List the 5 largest functions in `/bin/ls`.
2. Count how many functions have loops.
3. Find the function with the highest instruction count.
4. Use `hottestFunctions` to find the most-called function and print its name.

## Next

Continue to `34_disasm_json.md`.
