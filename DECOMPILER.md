# NR — NeoDAX Representation & Pseudo-C Decompiler

NeoDAX's program IR is called **NR (NeoDAX Representation)**. It replaces the old SSA layer with a richer opcode set, type inference, and cross-function linkage that treats the entire binary as a single program module rather than isolated functions.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX
> **Implementation:** `src/decomp.c`
> **CLI flags:** `-Q` (NR form), `-D` (pseudo-C decompile)
> **Interactive:** `ssa <func>` (NR), `dec <func>` (pseudo-C)
> **JS API:** `bin.ssa(funcIdx)`, `bin.decompile(funcIdx)`

---

## Pipeline

```
ARM64 / RISC-V / x86-64 instructions
            |
    nr_lift_arm64()  /  nr_lift_riscv()
            |
    NR statement list  (nr_stmt_t[])
     with inter-function call resolution
            |
    dax_ssa_lift_func()  -- prints NR form  (-Q)
            |
   decomp_print_func()  -- prints pseudo-C  (-D)
            |
  dax_decompile_all()  -- NR Module (call graph)
```

---

## NR Opcode Set

NR has 30 opcodes across six categories:

| Category | Opcodes |
|----------|---------|
| Data movement | `NR_ASSIGN`, `NR_LOAD`, `NR_STORE`, `NR_MEMCPY` |
| Arithmetic | `NR_ADD`, `NR_SUB`, `NR_MUL`, `NR_DIV`, `NR_NEG` |
| Bitwise | `NR_AND`, `NR_OR`, `NR_XOR`, `NR_NOT`, `NR_SHL`, `NR_SHR`, `NR_ROL`, `NR_ROR` |
| Type | `NR_CAST`, `NR_SEXT`, `NR_ZEXT` |
| Control | `NR_CMP`, `NR_BRANCH`, `NR_COND_BR`, `NR_PHI`, `NR_UNDEF` |
| Calls / returns | `NR_CALL`, `NR_INDIRECT_CALL`, `NR_SYSCALL`, `NR_RET` |
| Misc | `NR_NOP`, `NR_LABEL` |

---

## Type System

Every NR variable (`nr_var_t`) carries an inferred type:

| Type | Meaning | How inferred |
|------|---------|--------------|
| `NRT_U8` | 8-bit unsigned | `ldrb`, `strb`, extend ops |
| `NRT_U16` | 16-bit unsigned | `ldrh`, `strh` |
| `NRT_U32` | 32-bit unsigned | w-register writes |
| `NRT_U64` | 64-bit unsigned | x-register writes (default) |
| `NRT_PTR` | Pointer (any width) | result of `adr`/`adrp`, or `load` of 64-bit |
| `NRT_PTR_CODE` | Code pointer | function pointer context |
| `NRT_BOOL` | Boolean | conditional test result |
| `NRT_FLAGS` | CPU flags | `cmp`/`tst` result register |

Types feed directly into the decompiler's variable naming and declaration output.

---

## Inter-Function Linkage

Every `NR_CALL` node carries:

- `callee_func_idx` — index into `bin->functions[]`, or `-1` for external
- `callee_name` — resolved symbol name or `sub_0xADDR`

The NR print output for each function shows:

```
callers:  main@0xd1c  _start_main@0xc20
callees:  vm_run  smc_run  __printf_chk
[SMC-modified]   (shown if smc_target_addr falls inside this function)
```

The decompiler annotates every call site with `/* func[N] */`.

---

## Program-Level NR Module

`dax_decompile_all()` (CLI `-D`) lifts all functions and emits a cross-function call graph:

```
NR MODULE -- Inter-Function Call Graph

main                    ->  vm_run                @ 0xe30
main                    ->  smc_run               @ 0x12d4
main                    ->  run_cipher_chain       @ 0x13fc
cff_compute             ->  <indirect>             @ 0x1098
vm_run                  ->  <indirect>             @ 0xf90

SMC-modified functions:
  smc_run              @ 0x12a0

5 call edge(s)  |  31 function(s)  |  3 SMC patch(es)
```

---

## Running NR Lifting

### CLI

```bash
# NR form for all functions
./neodax -Q ./binary

# Pseudo-C decompiler (includes program module at end)
./neodax -D ./binary

# Combined with full analysis
./neodax -x -Q -D ./binary
```

### Interactive shell

```
> ssa main          # NR form for function 'main'
> dec main          # pseudo-C for 'main'
> dec opaque_false  # decompile a specific function
```

### JavaScript

```js
neodax.withBinary('./binary', bin => {
    bin.analyze();
    const nr   = bin.ssa(0);        // NR form for function index 0
    const code = bin.decompile(0);  // pseudo-C
    console.log(nr);
    console.log(code);
});
```

---

## Reading NR Output

Example NR output for a simple function:

```
NR: main
callers:  _start_main@0xc20
callees:  vm_run  smc_run

0x0d1c  r10:u64 = 0x43c
0x0d24  r8:u64  = 0x8
0x0e30  r0:u64  = call vm_run [-> func[0] insns=54 loops=no]
0x12d4  r0:u64  = call smc_run [-> func[4] insns=32 loops=no]
0x13fc  r0:u64  = call run_cipher_chain [-> func[6] insns=28 loops=no]
0x1408  r0:u64  = indirect_call [r8]
0x1414  ret r0

69 NR stmts  |  68 vars  |  func_idx=15
```

Key points:

- Each line: `address  dest:type = operation`
- `call` shows the callee name and a summary: `[-> func[N] insns=M loops=yes/no]`
- `indirect_call` shows the register holding the function pointer
- `callers/callees` headers show cross-function linkage
- SMC-modified functions are labelled `[SMC-modified]` in the function header

---

## Reading Pseudo-C Output

```c
/* 0xd0c -- 460 insns  called_from=1 */
uint64_t main(uint64_t a0, uint64_t a1, uint64_t a2) {
  /* locals */
  u64 v10_1;
  ptr p19;
  u64 v0_5;

  v10_1 = 0x43c;
  p19   = 0x624;
  v0_5  = vm_run(a0, a1); /* func[0] */
  *(p19) = v0_5;
  /* cmp v8_2, 0x0 */
  if (flags eq) goto loc_0x1414;
  v0_6  = smc_run(v0_5); /* func[4] */
  return v0_6;
}
```

Key points:

- Type-aware locals: `u64`, `ptr`, `u8_`, `u16_`, `bool`
- Arguments `a0..a7` are inferred from the ARM64 calling convention (x0-x7)
- Calls show resolved callee names with `/* func[N] */`
- `cmp` is rendered as a comment; flags are tested in the subsequent `if`
- `goto loc_0x...` for branches within the function
- `return func(/*tail*/);` for detected tail calls

---

## Architecture Coverage

| Architecture | NR Lifting | Decompiler |
|---|---|---|
| ARM64 | Full — all integer, load/store, branch, call, sysreg | Full |
| RISC-V RV64 | Full — all integer, load/store, jal/jalr/ret | Full |
| x86-64 | Partial — routed through ARM64 lifter for common patterns | Partial |

---

## NR vs Old SSA

| Aspect | Old SSA | NR |
|--------|---------|-----|
| Opcodes | 20 | 30 |
| Type system | None (all vars untyped) | 8 types with inference |
| Inter-function | None | callers/callees, call edges |
| Program module | None | Cross-function call graph |
| RISC-V support | Routed to ARM64 lifter | Dedicated `nr_lift_riscv()` |
| Rotation ops | None | `NR_ROL`, `NR_ROR` |
| Syscall | None | `NR_SYSCALL` (mrs/msr/svc) |
| Indirect call | Basic `NR_CALL` | Dedicated `NR_INDIRECT_CALL` |
| Decompiler locals | Raw register names | Type-prefixed names |
| Tail-call detection | None | `return func(/*tail*/);` |
| SMC flag | None | Inline label per function |
