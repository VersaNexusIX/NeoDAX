# Structured Disassembly in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 33_working_with_functions.md
**What You Will Learn:** How to get disassembly as structured JSON and process it programmatically.

## disasmJson

The `disasmJson` method returns disassembly as an array of instruction objects instead of formatted text:

```javascript
neodax.withBinary('/bin/ls', bin => {
    const instructions = bin.disasmJson('.text', { limit: 100, offset: 0 })

    instructions.forEach(insn => {
        const addr = '0x' + insn.address.toString(16)
        console.log(addr, insn.mnemonic, insn.operands)
    })
})
```

## Instruction Object Properties

```javascript
insn.address    // BigInt: virtual address
insn.mnemonic   // string: 'mov', 'call', 'ret', etc.
insn.operands   // string: 'rax, rbx' or 'rdi, [rbp-8]'
insn.length     // number: instruction length in bytes
insn.group      // string: 'call', 'branch', 'ret', 'stack', 'arithmetic', etc.
insn.bytes      // Uint8Array: raw instruction bytes
insn.symbol     // string or null: symbol annotation if available
```

## Using Offset and Limit

The `offset` parameter skips the first N instructions. The `limit` parameter caps the total returned. Use them together for pagination:

```javascript
function getPage(bin, section, pageNum, pageSize) {
    return bin.disasmJson(section, {
        offset: pageNum * pageSize,
        limit: pageSize
    })
}
```

## Counting by Group

```javascript
neodax.withBinary('/bin/ls', bin => {
    const insns = bin.disasmJson('.text', { limit: 10000 })

    const groupCounts = {}
    insns.forEach(insn => {
        groupCounts[insn.group] = (groupCounts[insn.group] || 0) + 1
    })

    console.log('Instruction group distribution:')
    Object.entries(groupCounts)
        .sort((a, b) => b[1] - a[1])
        .forEach(([group, count]) => {
            const pct = ((count / insns.length) * 100).toFixed(1)
            console.log(`  ${group}: ${count} (${pct}%)`)
        })
})
```

## Finding Specific Patterns

Find all call instructions:

```javascript
const calls = insns.filter(i => i.group === 'call')
calls.forEach(i => {
    console.log('0x' + i.address.toString(16), 'calls', i.operands)
})
```

Find instructions referencing a specific address:

```javascript
const targetAddr = '0x401234'
const refs = insns.filter(i => i.operands.includes(targetAddr))
```

## Building a Simple Disassembler Script

```javascript
const neodax = require('neodax')
const path = process.argv[2]
if (!path) { console.error('Usage: node disasm.js <binary>'); process.exit(1) }

neodax.withBinary(path, bin => {
    const sections = bin.sections().filter(s => s.type === 'code')
    sections.forEach(section => {
        console.log(`\n=== ${section.name} ===`)
        const insns = bin.disasmJson(section.name, { limit: 500 })
        insns.forEach(i => {
            const addr = '0x' + i.address.toString(16).padStart(16, '0')
            const bytes = Array.from(i.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ')
            console.log(addr, bytes.padEnd(20), i.mnemonic, i.operands)
        })
    })
})
```

## Practice

1. Use `disasmJson` on `/bin/ls` and print all `call` instructions with their target operands.
2. Count the total number of instructions in `.text`.
3. Find the instruction group that appears most frequently.
4. Build the simple disassembler script above and test it.

## Next

Continue to `35_xrefs_in_js.md`.
