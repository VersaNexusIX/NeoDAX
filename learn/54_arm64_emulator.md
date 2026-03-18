# ARM64 Emulator

**Level:** 5 - Symbolic Execution and Decompilation
**Prerequisites:** 53_reading_pseudo_c.md
**What You Will Learn:** How the NeoDAX ARM64 emulator works and when concrete emulation is useful.

## Concrete vs Symbolic Execution

Symbolic execution (file 50) tracks values as symbolic expressions. Concrete emulation runs the code with actual values, just like the real CPU would, but inside a controlled environment.

NeoDAX includes a concrete ARM64 emulator that:

- Maintains a full 32-register file
- Simulates a page-based memory model (64 pages of 4KB each)
- Tracks CPSR (condition flags)
- Stops at `ret`, `bl`/`blr` (to prevent running into called functions), or after a maximum step count

## Running the Emulator

CLI:

```bash
./neodax -I /bin/ls
```

JavaScript:

```javascript
neodax.withBinary('/bin/ls', bin => {
    // Emulate function 0 with x0=42
    const result = bin.emulate(0, { '0': 42n })
    console.log(result)
})
```

The second argument is a map of register index (as string) to BigInt initial value. Register indices: 0=x0, 1=x1, ..., 30=x30.

## Reading Emulator Output

The emulator prints a trace of register state changes:

```
Emulating function sub_401000 (x0=42)

Step 1: 0x401000  mov x2, #0
  x2: 0 -> 0

Step 2: 0x401004  add x2, x2, #1
  x2: 0 -> 1

...

Emulation complete: 15 steps
  Final x0: 5 (return value)
  Halt reason: ret
```

## What Concrete Emulation Shows

Unlike symbolic execution, concrete emulation produces actual values. This is useful when:

**Testing decryption functions:** Set x0 to the address of an encrypted buffer and x1 to the key, then run the emulator to see what the output would be.

**Tracing initialization routines:** Run the initializer with specific inputs to see what state it produces.

**Understanding arithmetic transformations:** For a function that transforms a value through complex bit manipulation, emulation immediately shows you the input-output relationship for specific values.

## Limitations

The emulator stops at function calls (`bl`/`blr`) because it cannot emulate external functions like `malloc` or `printf`. If the function under analysis calls other functions early on, the trace will be short.

The page-based memory model is simplified. Complex memory operations that span page boundaries or rely on specific memory layouts may not work correctly.

The emulator does not handle SIMD instructions, system registers, or privileged instructions.

## Combining with Symbolic Execution

Use symbolic execution to understand the general formula, and concrete emulation to verify specific inputs:

1. Symbolic execution: "This function computes `arg0 * 2 + arg1`"
2. Concrete emulation with `{0: 5n, 1: 3n}`: "Returns 13, which confirms `5*2+3=13`"

## Practice

1. Run `./neodax -I /bin/ls` on an ARM64 binary.
2. Using JavaScript, emulate function index 0 with different initial register values.
3. Find a function that takes one argument and determine its return value for inputs 0, 1, and 2.

## Next

Continue to `55_emulator_use_cases.md`.
