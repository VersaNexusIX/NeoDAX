# ARM64 Emulator

Concrete execution engine for ARM64 binaries.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX  
> **Implementation:** `src/emulate.c`  
> **CLI flag:** `-I`  
> **JS API:** `bin.emulate(funcIdx, initRegs?)`

---

## Overview

NeoDAX includes a concrete emulator that steps through ARM64 instructions with real register values and a simulated memory model. Unlike symbolic execution, which tracks unknowns symbolically, the emulator requires known initial inputs and produces exact outputs.

---

## Memory Model

| Component | Details |
|-----------|---------|
| Register file | 32 × 64-bit general purpose (`x0`–`x30`, `xzr`) |
| Stack pointer | Separate `sp` register, initialized at `0x7fff0000 + 0x10000 - 0x80` |
| CPSR flags | Z (zero), N (negative), C (carry), V (overflow) |
| Memory | 64 × 4 KB pages, allocated on first write |
| ROM fallback | `ldr` from unmapped addresses falls back to binary section data |
| Max steps | 8192 instructions per call |

---

## CLI Usage

```bash
# Emulate all functions (up to first 4) with default registers {0,1,2,3,4,5,6,7}
./neodax -f -I ./arm64_binary

# Output shows step-by-step trace with register changes and final state
```

---

## JavaScript API

```js
neodax.withBinary('./arm64_binary', bin => {
    // Emulate function 0 with x0=1337
    const trace = bin.emulate(0, { '0': 1337n });
    console.log(trace);
});
```

`initRegs` keys are register index strings (`'0'`–`'7'`), values are `bigint` or `number`.

---

## Trace Format

```
  Emulation: tricky

  Initial registers: x0=0x539 x1=0x1 x2=0x0 x3=0x3

  0x000000000000078c  mov    w8, w0        → x8=0x539
  0x0000000000000790  b      0x7a4         (branch taken)
  0x00000000000007a4  add    w0, w0, #0x7  → x0=0x540
  0x00000000000007a8  movz   w9, #0x55     → x9=0x55
  0x00000000000007ac  eor    w0, w0, w9    → x0=0x515

  Emulation complete: 5 steps
  Halted: ret w0=0x515
  Final register state:
    x0 = 0x0000000000000515  (1301)
    x1 = 0x0000000000000001  (1)
    x2 = 0x0000000000000000  (0)
    ...
```

---

## Supported Instructions

| Category | Instructions |
|----------|-------------|
| Data move | `mov`, `movz`, `movn` |
| Arithmetic | `add`, `adds`, `sub`, `subs` |
| Logic | `and`, `ands`, `orr`, `eor` |
| Shift | `lsl`, `lsr`, `asr` |
| Compare | `cmp`, `tst` |
| Memory | `ldr`, `ldrb`, `ldrh`, `ldrsw`, `str`, `strb`, `stp` |
| Bitfield | `ubfm`, `sbfm` |
| Branch | `b`, `b.<cond>`, `cbz`, `cbnz`, `br` |
| Call | `bl` (stops with "call to external" message) |
| Return | `ret` |
| No-op | `nop`, `bti`, `paciaz`, `autiasp` |

---

## Termination Conditions

The emulator stops cleanly at:

| Condition | Message |
|-----------|---------|
| `ret` | `ret w0=<value>` — return value printed |
| `bl` to external | `call to external 0x<addr>` — library call, cannot follow |
| `blr` | `indirect call 0x<reg_value>` — computed call |
| Unimplemented instruction | `unimplemented: <mnemonic>` |
| Step limit (8192) | Loop protection |
| Infinite loop detection | PC unchanged after step |
| Jump to different function | Stops at function boundary |

---

## Use Cases

### Verify a cryptographic transform

```js
// For a function that computes: result = (input + 7) ^ 0x55
neodax.withBinary('./binary', bin => {
    for (let i = 0; i < 6; i++) {
        const trace = bin.emulate(funcIdx, { '0': BigInt(i) });
        const retLine = trace.split('\n').find(l => l.includes('ret w0='));
        console.log(`input=${i}: ${retLine}`);
    }
});
```

### Trace register flow through obfuscated code

```js
neodax.withBinary('./binary', bin => {
    // Try several inputs, compare final x0 values
    const results = [0, 1, 42, 100, 255].map(v => {
        const trace = bin.emulate(0, { '0': BigInt(v) });
        const last = trace.split('\n').filter(l => l.includes('x0 =')).pop();
        return { input: v, output: last?.trim() };
    });
    console.table(results);
});
```

---

## Limitations

- **ARM64 only.** x86-64 emulation is not implemented.
- **No SIMD/FP.** Vector registers (`v0`–`v31`) and floating-point instructions are not supported — encountering them causes a halt.
- **No OS syscalls.** `svc` and `syscall` halt the emulator.
- **Partial `stp`.** The `stp` (store pair) instruction has basic support but may behave incorrectly with write-back forms (`[sp, #-n]!`).
- **No PAC.** Pointer authentication (`pacia`, `autia`, etc.) is treated as a no-op.
