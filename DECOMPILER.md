# Decompiler & SSA Lifting

How NeoDAX lifts binary code to SSA form and decompiles to pseudo-C.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX  
> **Implementation:** `src/decomp.c`  
> **CLI flags:** `-Q` (SSA), `-D` (decompile)  
> **JS API:** `bin.ssa(funcIdx)`, `bin.decompile(funcIdx)`

---

## Pipeline

```
ARM64 instructions
      ↓
  ssa_lift_arm64_insn()
      ↓
  SSA statement list  (ssa_stmt_t[])
      ↓
  dax_ssa_lift_func()  →  prints SSA form (-Q)
      ↓
  lift_to_ir_arm64()
      ↓
  IR node list  (ir_node_t[])
      ↓
  dax_decompile_func()  →  prints pseudo-C (-D)
```

---

## SSA Form

Static Single Assignment form guarantees each variable is written exactly once. NeoDAX implements a simplified SSA — no phi-node insertion at join points, but each register write creates a new versioned variable.

**Naming convention:** `r<N>_<version>` where N is the register number and version increments on each write.

**Example — `tricky(int x)`:**

```c
// ARM64 input
mov  w8, w0        // copy arg
b    target        // unconditional jump (dead bytes follow)
target:
add  w0, w0, #7   // compute
movz w9, #0x55    // load constant
eor  w0, w0, w9   // xor
ret
```

**SSA output (`-Q`):**

```
0x790  r8_1  = r0_0
0x794  branch → 0x7a4
0x7a4  r0_2  = r0_0 + 0x7
0x7a8  r9_1  = 0x55
0x7ac  r0_3  = r0_2 ^ r9_1
0x7b0  ret r0_3
```

---

## Pseudo-C Decompiler

The decompiler renders the IR as C-like output with type annotations.

**Decompiler output (`-D`):**

```c
int32_t tricky(int arg0) {
  r8 = arg0;
  r0 = arg0 + 0x7;
  r9 = 0x55;
  r0 = r0 ^ r9;
  return r0;
}
```

---

## Supported Instruction Coverage (ARM64)

| Instruction | SSA/IR operation | Notes |
|-------------|-----------------|-------|
| `mov`, `movz` | `ASSIGN` | Immediate or register |
| `movn` | `ASSIGN` | Bitwise NOT of immediate |
| `add`, `adds` | `ADD` | Immediate or register |
| `sub`, `subs` | `SUB` | Immediate or register |
| `and`, `ands` | `AND` | Immediate or register |
| `orr` | `OR` | Register only |
| `eor` | `XOR` | Immediate or register |
| `lsl` | `SHL` | Shift left |
| `lsr`, `asr` | `SHR` | Shift right |
| `ldr`, `ldrb`, `ldrsw` | `LOAD` | Memory read |
| `str`, `strb` | `STORE` | Memory write |
| `cmp`, `cmn` | `CMP` | Sets flags variable |
| `bl` | `CALL` | Direct call; symbol resolved if known |
| `ret` | `RET` | Return with w0/x0 as return value |
| `b` | `BRANCH` (unconditional) | Target recorded |
| `b.<cond>`, `cbz`, `cbnz` | `IF` | Condition + target |
| Other | `NOP` | Printed as comment |

---

## Limitations

**No phi nodes:** When two control-flow paths merge (if/else, loop back-edges), the correct SSA form requires a φ (phi) node that selects between two versions. NeoDAX does not insert phi nodes — it uses the most recently written version, which may be incorrect across join points.

**No type system:** All variables are treated as either 32-bit (`w` registers) or 64-bit (`x` registers). No struct types, pointer arithmetic, or array indexing.

**Linear only:** The decompiler processes instructions in linear order without following branches. For functions with complex control flow, the output may not perfectly reflect execution order.

**ARM64 only:** The SSA/decompiler currently only handles ARM64. x86-64 support is planned.

---

## Reading the Output

**Versioned variables** like `r0_2` mean "the second write to register 0." If you see `r0_0` in an expression, it refers to the original function argument.

**`flags` variable:** The `cmp` instruction produces a `flags` variable that is consumed by conditional branches rendered as `if (flags <cond>) → 0xaddr`.

**Calls:** `result = call(0xaddr)` or `result = <symbol_name>()` when the symbol is resolved.

---

## Example: `chaos(int v)`

Source:
```c
int chaos(int v) {
    int a = tricky(v);
    if ((a ^ v) & 1)
        return a + secret;
    else
        return a - secret;
}
```

NeoDAX decompiler output:
```c
int32_t chaos(int arg0) {
  r0 = arg0;
  result = tricky();        // bl to tricky
  r8 = result;
  r8 = r8 ^ r0_0;          // a ^ v
  flags = cmp(r8, 0x0);    // test LSB
  if (flags & 1) → 0x...   // branch on condition
  ldr r9, [x10]            // load secret
  r0 = r8 + r9;            // a + secret
  return r0;
}
```
