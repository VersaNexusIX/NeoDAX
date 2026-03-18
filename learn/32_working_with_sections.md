# Working with Sections in JavaScript

**Level:** 3 - JavaScript API
**Prerequisites:** 31_loading_binaries_in_js.md
**What You Will Learn:** How to query and process section data programmatically.

## Listing Sections

```javascript
neodax.withBinary('/bin/ls', bin => {
    const sections = bin.sections()
    sections.forEach(s => {
        console.log(s.name, s.type, '0x' + s.vaddr.toString(16), s.size.toString())
    })
})
```

## Section Object Properties

Each section object has:

```javascript
s.name      // string: '.text', '.data', etc.
s.type      // string: 'code', 'data', 'rodata', 'bss', 'plt', 'got', 'other'
s.vaddr     // BigInt: virtual address
s.size      // BigInt: size in bytes
s.offset    // BigInt: offset in file
s.flags     // number: raw section flags
s.insnCount // number: instruction count (for code sections)
```

## Filtering Sections

Filter to only code sections:

```javascript
const codeSections = bin.sections().filter(s => s.type === 'code')
```

Find a section by name:

```javascript
const textSection = bin.sectionByName('.text')
if (textSection) {
    console.log('.text size:', textSection.size.toString())
}
```

Find which section contains an address:

```javascript
const section = bin.sectionAt(bin.entry)
console.log('Entry point is in:', section?.name)
```

## Reading Raw Bytes

```javascript
const bytes = bin.readBytes(bin.entry, 16)
// Returns Uint8Array or null if address out of range

if (bytes) {
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ')
    console.log('First 16 bytes at entry:', hex)
}
```

This is useful for extracting shellcode, reading embedded data, or verifying specific byte patterns.

## Computing Section Statistics

```javascript
neodax.withBinary('/bin/ls', bin => {
    const sections = bin.sections()

    const totalCode = sections
        .filter(s => s.type === 'code')
        .reduce((sum, s) => sum + Number(s.size), 0)

    const totalData = sections
        .filter(s => s.type === 'data' || s.type === 'rodata')
        .reduce((sum, s) => sum + Number(s.size), 0)

    console.log('Total code bytes:', totalCode)
    console.log('Total data bytes:', totalData)
    console.log('Code to data ratio:', (totalCode / totalData).toFixed(2))
})
```

Note: convert BigInt to Number with `Number()` for arithmetic. For very large files this may lose precision, but for section sizes it is safe.

## Practice

1. List all sections of a binary and print only the ones with size greater than 1000 bytes.
2. Find the section with the largest size.
3. Read the first 8 bytes of the entry point and print them as hex.
4. Calculate what percentage of the file is executable code.

## Next

Continue to `33_working_with_functions.md`.
