# Emulator Use Cases

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 54_arm64_emulator.md
**What You Will Learn:** Practical ways to apply the ARM64 emulator in real analysis scenarios.

## Use Case 1: Decrypting Strings

Many malware samples encrypt their strings at compile time and decrypt them at runtime. The decryption function is called with an index or a pointer to encrypted data.

To use the emulator to decrypt strings:

1. Identify the string decryption function using hottest functions analysis (it is called many times) and decompiler output (it has XOR or arithmetic operations).
2. Find the encrypted string data in the binary using `readBytes`.
3. Set up the emulator with the appropriate arguments.
4. Read the output buffer from the emulator trace.

```javascript
neodax.withBinary('/path/to/malware', bin => {
    const fnIndex = 5  // index of suspected string decryptor
    const encryptedAddr = 0x401234n

    // Emulate with pointer to encrypted string as argument
    const result = bin.emulate(fnIndex, { '0': encryptedAddr })
    console.log(result)
})
```

## Use Case 2: Understanding Hash Functions

Security-critical code sometimes includes custom hash or checksum functions for integrity verification. The emulator reveals what the function computes:

```javascript
neodax.withBinary('/path/to/binary', bin => {
    // Try several inputs to understand the hash function
    [0n, 1n, 255n, 65536n].forEach(input => {
        const result = bin.emulate(fnIndex, { '0': input })
        console.log(`hash(${input}) = ...`)  // read from result
    })
})
```

## Use Case 3: Identifying Key Derivation

If a binary derives encryption keys from some input, the key derivation function takes a password or seed and produces key material. Emulating with known inputs lets you verify the key derivation algorithm.

## Use Case 4: Verification Functions

License check functions, serial number validators, and crackme challenges typically take a string or number as input and return a boolean. The emulator can quickly test whether specific inputs pass the check.

## Use Case 5: Understanding State Machines

Binaries that implement protocol parsers or command processors often have state machine functions. Emulating with specific state inputs shows you the transitions.

## Limitations to Keep in Mind

The emulator stops at external function calls. If the function you want to emulate calls `malloc` early on, the trace will stop before the interesting part.

Workaround: if the function only calls internal helper functions, and you know the indices of those helpers, you can emulate the helper first and then continue from where it left off.

## Extending with JavaScript

The emulator output is a string report. For automated analysis, you may want to parse the final register state from the output:

```javascript
function getReturnValue(emulateOutput) {
    const match = emulateOutput.match(/Final x0:\s*(0x[0-9a-f]+|\d+)/)
    if (match) return BigInt(match[1])
    return null
}
```

## Practice

1. Find a function in any ARM64 binary that takes one integer argument.
2. Emulate it with 5 different inputs.
3. Determine the relationship between input and output (linear, lookup table, etc.).

## Next

You have completed Level 5. Continue to `60_analyzing_malware_basics.md` to begin Level 6.
