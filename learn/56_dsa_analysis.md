# DSA — Dynamic Single Assignment

**Level:** 5 - Symbolic Execution and Decompilation  
**Prerequisites:** 54_arm64_emulator.md  
**What You Will Learn:** What DSA is, how it differs from NR/SSA, and how to use it to identify obfuscated values.

## What DSA Is

DSA (Dynamic Single Assignment) is NeoDAX's runtime-value-annotated IR. Where NR is a static lift of the binary, DSA records **concrete values** observed during emulation at every definition site.

This makes DSA uniquely powerful for:
- Identifying **opaque predicates** — definitions that always hold the same value across all execution paths, yet feed conditional branches
- Tracing **VM dispatch values** — which opcodes went through which handlers
- Finding **key material** — definitions tagged with crypto constants (0x9E3779B9, 0x61C88647, etc.)
- Exposing **dead code** — definitions with zero frequency mean the defining path was never taken

## DSA vs NR

| Aspect | NR | DSA |
|---|---|---|
| Values | Not tracked — structural lift only | Concrete runtime values per def |
| Phi nodes | Static structural | Dynamic frequency per path |
| Opaque predicates | Detected by symexec | Visible as constant-value defs |
| SMC | Flagged structurally | Tracks write PCs during emulation |
| Primary use | Code structure, call graph | Value flow, opaque analysis |

## Running DSA

### CLI

```bash
./neodax --dsa ./binary
```

Runs DSA over all detected functions. Requires `-f` or `-x` to have run first (functions must be detected), or use `-X` which includes everything:

```bash
./neodax -X ./binary
```

### Interactive shell

```
> dsa main           # DSA for one function
> dsa vm_run         # trace dispatcher values
> dsa smc_run        # trace SMC writer
> dsa all            # all functions sequentially
> dsa               # shows usage + first 10 functions (no crash)
```

---

## Reading DSA Output

```
══════════════════════════════════════════════════════════
DSA — Dynamic Single Assignment  ·  func: main
══════════════════════════════════════════════════════════

69 def(s)  1024 use(s)  69 chain(s)  0 dyn-phi(s)

── Definitions ─────────────────────────────────────
DEF[  0]  x10 v1  @0xd1c  tag=normal
         0x000000000000043c  freq=1
DEF[  1]  x8  v1  @0xd24  tag=normal
         0x0000000000000008  freq=1
DEF[ 14]  x9  v1  @0xdbc  tag=crypto_const
         0x00000000000005d0  freq=1
```

**DEF[N]** — definition index in this function.  
**xN vM** — register `xN`, version `M` (SSA version counter).  
**@0xADDR** — address of the instruction that produced this value.  
**tag** — classification of the value:
- `normal` — plain computed value
- `crypto_const` — matches a known cryptographic constant
- `dispatch_idx` — fed a VM opcode dispatch
- `induction` — loop induction variable (delta-consistent across traces)
- `smc_write` — this definition wrote to an executable address

**value** — the concrete 64-bit value observed.  
**freq=N** — how many emulation traces produced this value. `freq=1` with a single constant value means it was the same every time — strong opaque signal.

---

## Identifying Opaque Predicates with DSA

An opaque predicate is a conditional branch whose outcome is fixed. In DSA, it appears as a definition that:
1. Always holds the same concrete value (`freq=1`, constant)
2. Feeds a `cmp`/`tst` instruction
3. The resulting flags always resolve the same way

Example: function `opaque_false` has all defs with `freq=0` because no traces entered it — it was dead code inserted by the obfuscator. Function `main` has `DEF[63] x10 v9 @0x1348 tag=normal, value=0x1, freq=1` — x10 always holds 1 at this point, making any `cbz x10` an opaque never-taken branch.

Compare this to the symexec output (`-P`): symexec resolves opaque predicates symbolically, DSA shows you the concrete values that prove them.

---

## Def-Use Chains

```
── Def-Use Chains (top by use count) ───────────────
CHAIN[  1]  x8 v1  @0xd24  uses=32
CHAIN[ 11]  x12 v3  @0xd9c  uses=32
CHAIN[ 27]  x1 v3  @0xe64  uses=29
```

A chain with 32 uses of a single definition is a long-lived value — likely a loop base or a structure pointer used throughout the function. In CFF contexts, chains with very high use counts often correspond to the dispatcher state variable.

---

## DSA Tags

| Tag | Meaning |
|-----|---------|
| `normal` | Plain computed value |
| `crypto_const` | Matches 0x9E3779B9, 0x61C88647, 0xDEADBEEF, or similar crypto constants |
| `dispatch_idx` | Value fed into a known VM dispatch table |
| `induction` | Loop induction variable — delta consistent across multiple traces |
| `smc_write` | This definition resulted in a write to an executable address |
| `key_material` | High-entropy value in context suggesting cryptographic key |

---

## Practical Workflow

### 1. Find the VM dispatcher state variable

```
> dsa cff_compute
```

Look for the def with the most uses (the state variable) and all constant-value defs feeding conditional branches.

### 2. Verify opaque predicates

```
> dsa main
```

Find defs with `freq=1` and a constant value feeding branches. Cross-check with:

```
> ivf          # OPAQUE-C / OPAQUE-SR flags
> sym main     # symexec resolves them symbolically
```

### 3. Locate crypto constants

Look for defs tagged `crypto_const`. These anchor the cryptographic routine and help identify the algorithm (AES, ChaCha20, XTEA, etc.).

### 4. Trace SMC write sites

```
> dsa smc_run
```

Defs tagged `smc_write` show you exactly which instruction patches which address and with what value.

---

## Notes

- DSA requires the emulator to have run (internally or via `-I`). If no emulation data is present, def counts will be 0.
- `dsa all` processes every function sequentially — useful for a full binary scan but can be slow on large binaries.
- `dsa` without arguments in the interactive shell shows usage and lists the first 10 functions instead of crashing.
- **Fault isolation:** Each DSA phase (`simulate`, `build_chains`, `mark_dead`, `build_phis`, `print`) has its own fault flag. If the simulate phase aborts on a corrupt function (e.g. section not found, function bounds outside any section), the remaining phases still run on whatever data was collected — partial results are shown rather than nothing. A completely unreachable function will print a `simulate phase skipped` notice and move on.
