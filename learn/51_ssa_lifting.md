# NR — NeoDAX Representation

**Level:** 5 - Symbolic Execution and Decompilation  
**Prerequisites:** 50_symbolic_execution_intro.md  
**What You Will Learn:** What NR is, how it differs from traditional SSA, and how to read NR output.

## What NR Is

NR (NeoDAX Representation) is NeoDAX's native program IR. It replaces the old SSA (Static Single Assignment) layer with a richer opcode set, type inference, and cross-function linkage that treats the entire binary as a single program module.

Where traditional SSA focuses on single functions in isolation, NR connects every function to its callers and callees across the whole binary.

## NR vs Traditional SSA

| Aspect | Traditional SSA | NR |
|---|---|---|
| Scope | One function at a time | Whole-binary module |
| Types | None — all vars untyped | 8 inferred types (u8/u16/u32/u64/ptr/bool/flags) |
| Call edges | Opaque | `callee_func_idx` resolved, name embedded |
| RISC-V | Partial | Dedicated lifter |
| Rotation | Not modeled | `NR_ROL`, `NR_ROR` |
| Syscall | Not modeled | `NR_SYSCALL` (svc/mrs/msr) |
| SMC | Not marked | ⚠ flag if smc_target inside function |
| Program graph | None | Cross-function call graph at end |

## NR Opcodes

NR has 30 opcodes:

**Data movement:** `NR_ASSIGN`, `NR_LOAD`, `NR_STORE`, `NR_MEMCPY`  
**Arithmetic:** `NR_ADD`, `NR_SUB`, `NR_MUL`, `NR_DIV`, `NR_NEG`  
**Bitwise:** `NR_AND`, `NR_OR`, `NR_XOR`, `NR_NOT`, `NR_SHL`, `NR_SHR`, `NR_ROL`, `NR_ROR`  
**Type:** `NR_CAST`, `NR_SEXT`, `NR_ZEXT`  
**Control:** `NR_CMP`, `NR_BRANCH`, `NR_COND_BR`, `NR_PHI`, `NR_UNDEF`  
**Calls:** `NR_CALL`, `NR_INDIRECT_CALL`, `NR_SYSCALL`, `NR_RET`  
**Misc:** `NR_NOP`, `NR_LABEL`

## Running NR Lifting

CLI:

```bash
./neodax -Q ./binary
```

Interactive shell:

```
> ssa main
> ssa vm_run
```

JavaScript:

```javascript
neodax.withBinary('./binary', bin => {
    bin.analyze();
    const nr = bin.ssa(0);  // NR for function at index 0
    console.log(nr);
});
```

## Reading NR Output

```
══════════════ NR: main ══════════════
▸ callers:  _start_main@0xc20
▸ callees:  vm_run  smc_run  run_cipher_chain

0x0d1c  r10:u64 = 0x43c
0x0d24  r8:u64  = 0x8
0x0e30  r0:u64  = call vm_run [→ func[0] insns=54 loops=no]
0x0e3c  r20:ptr = load[r0]
0x12d4  r0:u64  = call smc_run [→ func[4] insns=32 loops=no]
0x1408  r0:u64  = indirect_call [r8] → <indirect>
0x1414  ret r0

69 NR stmts  |  68 vars  |  func_idx=15
```

Each line: `address  dest:type = operation`

The `▸ callers` and `▸ callees` lines show cross-function linkage resolved at lift time. The `[→ func[N] insns=M loops=yes/no]` annotation on calls embeds a summary of the callee.

## Type Inference

NR infers variable types from instruction context:

- `adr`/`adrp` result → `NRT_PTR`
- `cmp`/`tst` result → `NRT_FLAGS`
- w-register writes → `NRT_U32`
- x-register writes → `NRT_U64`
- `ldrb`/`strb` → `NRT_U8`
- `sxtw`/`sxth`/`sxtb` → `NRT_U64` (sign-extended)

Types are printed as the suffix after `:` in each variable.

## SMC Flag

If a function contains an address that was patched by self-modifying code (detected by symexec or emulator), the function header shows:

```
⚠ SMC-modified function
```

## Program-Level NR Module

Running `-D` (decompile all) generates a full cross-function call graph at the end of output:

```
══════════════ NR MODULE — Inter-Function Call Graph ══════════════

main                    →  vm_run                @ 0xe30
main                    →  smc_run               @ 0x12d4
cff_compute             →  <indirect>             @ 0x1098

SMC-modified functions:
⚠  smc_run              @ 0x12a0

5 call edge(s)  |  31 function(s)  |  3 SMC patch(es)
```

## Practice

Try NR on a binary with function calls:

```bash
./neodax -Q -f ./binary
```

The `-f` ensures function boundaries are detected before NR lifting begins.
