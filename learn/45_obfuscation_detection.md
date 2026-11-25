# Obfuscation Detection

**Level:** 4 - Advanced Analysis  
**Prerequisites:** 44_hottest_functions.md  
**What You Will Learn:** How to detect and analyse common obfuscation techniques using NeoDAX's combined tools.

## What Obfuscation Is

Obfuscation deliberately makes code harder to analyze without changing its functional behavior. Unlike packing (which compresses code), obfuscation transforms the code structure itself.

Common techniques:
- **Control flow flattening (CFF):** Replaces structured control flow with a state-machine dispatcher.
- **Opaque predicates:** Conditional branches whose outcome is always fixed but appears runtime-dependent.
- **Instruction substitution:** Replaces simple instructions with equivalent complex sequences.
- **String encryption:** Strings stored encrypted and decrypted at runtime.
- **Dead code insertion:** Fake instructions mixed into real code to confuse disassemblers.
- **XOR mutation:** Code bytes XOR'd at rest and decrypted just before execution (polymorphic stubs).
- **Anti-debug:** Sysreg reads (ARM64 `mrs`/`msr`) used as timing checks or opaque predicate inputs.

---

## Tool Overview

NeoDAX has four dedicated obfuscation analysis tools that work together:

| Tool | Flag | Shell | What it finds |
|------|------|-------|---------------|
| IVF | `-V` | `ivf` | Invalid bytes, SMC patterns, opaque predicates, dead code |
| Poly Map | `--poly` | `poly` | Mutation clusters, XOR-loops, hash-chains, high-entropy windows |
| DSA | `--dsa` | `dsa` | Runtime value annotation per definition site |
| AIRE | `--aire` | `aire` | Synthesized insights, obfuscator fingerprint, next-step guide |

---

## Step 1 — IVF Scan

```bash
./neodax -V ./binary
```

The IVF reports a table of suspicious patterns and an obfuscation score:

```
Category    Address               Mnemonic       Detail
INDIRECT    0x0000000000001098  br             target=x4 — static target unknown
OPAQUE-C    0x00000000000010d4  sub            subs xN,xA,xA: always zero — opaque zero subtraction
SMC         0x00000000000012a0  str            str→adr-derived exec addr 0x1234 — confirmed code mutation

Summary:  invalid=68  priv=6  dead=3  indirect=6  opaque=7
Obfuscation score: 24  [EXTREME — professional obfuscation/packer]
```

A score above 17 indicates professional-grade obfuscation.

SMC detection in v1.1.1 uses four passes:
1. `str` preceded by `adr/adrp` to exec address (look-back up to 8 instructions)
2. `eor + str` — XOR mutation stub
3. Store inside a known poly region
4. Cross-reference from emulator real-time write log

---

## Step 2 — Polymorphic Map

```bash
./neodax --poly ./binary
```

The poly map scans 48-byte windows scoring 18 signals. Each region above threshold is reported:

```
[POLY]  0x1000 .. 0x1200  (512 bytes)
  score      8/10
  techniques  xor-mutation-loop hash-chain const-obfuscation
  obfuscator  XOR-poly/custom-packer
```

Obfuscator fingerprints the tool can identify:
- `OLLVM/Hikari` — opaque predicates + split immediates
- `XOR-poly/custom-packer` — XOR mutation + movk chains
- `XOR+ROR self-decrypt` — XOR mutation + rotation ops
- `hash-chain/Tigress` — deep arithmetic chains on same register
- `antidebug+opaque-gate` — sysreg + data-dependent branches
- `NOP-packer` — dense NOP sleds
- `packed/encrypted` — near-random byte content

---

## Step 3 — DSA (Dynamic Single Assignment)

DSA records concrete runtime values for each definition site, making opaque predicates and dead paths visible.

```bash
./neodax --dsa ./binary
```

Interactive (more useful for targeting specific functions):

```
> dsa cff_compute
> dsa vm_run
> dsa all
```

Reading DSA output:

```
DEF[  5]  x10 v2  @0xd60  tag=normal
         0x0000000000000908  freq=1
```

A definition with a constant value (`freq=1` across all traces) that feeds a conditional branch is likely an opaque predicate. The branch target it feeds will always be taken.

DSA without arguments shows usage and lists the first 10 functions. If a function has corrupt section data, its simulate phase is skipped and a notice is shown — analysis continues with the next function.

---

## Step 4 — AIRE Synthesis

```bash
./neodax --poly --aire ./binary
```

AIRE cross-correlates all analysis results and produces:
- Ranked insights with confidence scores (0–100)
- Obfuscator category and confidence
- Context banner describing what kind of binary this is
- Next-step guide with 3 concrete shell commands

Example AIRE output for CFF + XOR binary:

```
[95%] vm-dispatch — CFF dispatcher hub (OLLVM-style)
  WHAT:  subs xN,xA,xA → blr pattern — state machine opcode dispatch
  WHY:   This is CFF with indirect dispatch. The dispatcher resolves the
         next handler from a lookup table keyed by computed state value.
  ACTION run `vt` to trace dispatch sequence, then `cfg cff_compute`

Context: VM interpreter / control-flow-flattened binary
Next:    vt  →  cfg cff_compute  →  dsa cff_compute
```

---

## Control Flow Flattening (CFF)

CFF replaces `if-else` and loops with a single dispatcher block. Signatures:

- Function with very high block count relative to instruction count
- Many back-edges all targeting the same block (the dispatcher)
- Many short basic blocks (2–4 instructions) ending with the same `br xN`
- IVF reports `INDIRECT` for the dispatch `br`
- VM detector in IVF scores the function 4–6/6

```bash
./neodax -C -V ./binary    # CFG + IVF together
```

---

## Opaque Predicates

Opaque predicates appear as conditional branches whose outcome never changes. Signatures:

- IVF reports `OPAQUE-C` (subs xN,xA,xA) or `OPAQUE-SR` (mrs→cmp→b.cond)
- DSA shows a def with constant value feeding a conditional branch
- Symexec resolves the branch and marks the dead arm

```bash
./neodax -P -V ./binary    # symexec + IVF
```

---

## XOR Mutation / Polymorphic Stubs

Self-decrypting code that XORs itself before execution. Signatures:

- Poly map reports `xor-mutation-loop`
- IVF reports `SMC` pattern
- Emulator real-time log shows writes to code section
- Symexec records `smc_write_pc[]` entries

```bash
./neodax -I -P --poly -V ./binary
```

---

## Recommended Combined Workflow

```bash
# Full sweep, interactive at end
./neodax -x -V --poly --aire --dsa -I -i ./binary
```

Inside the shell:
```
> ivf           # detailed IVF table
> poly          # poly regions
> run main      # emulate to capture SMC
> vt            # VM dispatch trace
> dsa main      # runtime values in main
> aire          # AIRE final synthesis
> dec cff_compute  # pseudo-C of dispatcher
```
