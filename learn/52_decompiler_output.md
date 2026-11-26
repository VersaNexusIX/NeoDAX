# Decompiler Output

**Level:** 5 - Symbolic Execution and Decompilation  
**Prerequisites:** 51_ssa_lifting.md  
**What You Will Learn:** How to run the NeoDAX decompiler and interpret its pseudo-C output.

## The Decompiler

NeoDAX includes a decompiler that converts ARM64 and RISC-V assembly to pseudo-C. It lifts assembly to NR (NeoDAX Representation) and then applies type inference, argument detection, and inter-function call resolution to produce readable output.

The output is pseudo-C: it resembles C but does not necessarily compile. It is a human-readable approximation of the original logic.

## Running the Decompiler

CLI — decompile all detected functions:

```bash
./neodax -D ./binary
```

CLI — decompile with full analysis context:

```bash
./neodax -x -D ./binary
```

Interactive shell:

```
> dec main
> dec vm_run
> dec smc_run
```

JavaScript:

```javascript
neodax.withBinary('./binary', bin => {
    bin.analyze();
    bin.functions().forEach((fn, i) => {
        const code = bin.decompile(i);
        if (code.trim()) {
            console.log('// Function:', fn.name);
            console.log(code);
        }
    });
});
```

## Reading Pseudo-C Output

Example output for a function that calls into a VM interpreter:

```c
/* 0xd0c — 460 insns  called_from=1 */
uint64_t main(uint64_t a0, uint64_t a1, uint64_t a2) {
  /* locals */
  u64 v10_1;
  ptr p19;
  u64 v20_1;

  v10_1 = 0x43c;
  p19   = 0x624;
  /* cmp v8_1, 0x0 */
  v0_2  = vm_run(a0, a1); /* func[0] */
  *(p19) = v0_2;
  if (flags eq) goto loc_0x1414;
  v0_3  = smc_run(v0_2); /* func[4] */
  return v0_3;
}
```

### What each part means

**Comment block** — `/* 0xd0c — 460 insns  called_from=1 */` — function address, instruction count, and how many other functions call it.

**Return type** — `uint64_t` (default) or `void` for short leaf functions (< 4 instructions).

**Arguments** — `a0, a1, ...` inferred from ARM64 calling convention (x0–x7). The decompiler stops at the first register not used as a source.

**Locals** — declared with inferred types:
- `u64` — 64-bit value
- `u32` — 32-bit (w-register operations)
- `ptr` — result of `adr`/`adrp` or pointer load
- `u8_`, `u16_` — byte/halfword operations
- `bool` — boolean result

**Call sites** — `vm_run(a0, a1) /* func[0] */` — callee name resolved from symbol table or function boundary detection. The `/* func[N] */` annotation is the index into the function table.

**Indirect calls** — `((uint64_t(...))fp8)()` for `blr` through a register.

**Rotation intrinsics** — `__ror(v9, 7)` and `__rol(v9, 25)` for `ror`/`rol` instructions.

**Sign-extension** — `(int32_t)(v8)` for `sxtw` operations.

**Tail calls** — if an unconditional branch targets another known function, emitted as `return func(/*tail*/);`.

**Branches** — `goto loc_0xADDR;` for intra-function branches. `if (flags eq) goto loc_0x...;` for conditional branches.

## Program Module

After decompiling all functions, `./neodax -D` prints a cross-function call graph:

```
══════════════ NR MODULE — Inter-Function Call Graph ══════════════

main                →  vm_run               @ 0x0e30
main                →  smc_run              @ 0x12d4
main                →  run_cipher_chain      @ 0x13fc
cff_compute         →  <indirect>            @ 0x1098

SMC-modified functions:
⚠  smc_run          @ 0x12a0

5 call edge(s)  |  31 function(s)  |  3 SMC patch(es)
```

This shows the full call topology of the binary in one place. External calls (PLT, unresolved) appear as `<extern>` or `sub_0xADDR`.

## Limitations

The decompiler is a best-effort RE aid, not a perfect decompiler:

- Control flow recovery is linear — loop structures appear as `goto` chains
- Heavily obfuscated functions (CFF, opaque predicates) produce sparse output
- x86-64 support is partial — ARM64 and RISC-V give the best output
- SIMD / vector instructions are emitted as `nop` (not lifted)
- Stack slot aliasing is not tracked — spilled values may appear as separate variables

For obfuscated code, combine with DSA (`--dsa`), symexec (`-P`), and AIRE (`--aire`) for the full picture.

## Practice

```bash
# Decompile and keep output for diffing between runs
./neodax -f -D ./binary > output_v1.c
```
