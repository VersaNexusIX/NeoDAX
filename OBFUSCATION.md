# Analyzing Obfuscated Binaries

Practical guide for using NeoDAX against packed, obfuscated, and anti-analysis binaries.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Quick reference — obfuscation analysis flags

| Flag | Shell command | What it does |
|------|--------------|--------------| 
| `-e` | `ent` | Entropy scan — finds packed/encrypted regions |
| `-V` | `ivf` / `aa` | Instruction validity filter + VM detector + SMC patterns |
| `--poly` | `poly` / `pm` | **Polymorphic obfuscation map** — mutation cluster detection |
| `--dsa` | `dsa <func>` | **DSA** — Dynamic Single Assignment, runtime value annotation |
| `--aire` | `aire` / `ai` | **AIRE** — Assisted Intelligence Reverse Engineering insights |
| `-I` | `run` | Concrete emulation + real-time SMC capture + VM dispatch trace |
| `--vm-trace` | `vmtrace` / `vt` | Print VM dispatch log from last emulation |
| `-P` | `sym` | Symbolic execution — resolves opaque predicates, SMC patches |
| `-Q` | `ssa <func>` | NR form — shows inter-function data flow |
| `-D` | `dec <func>` | Pseudo-C decompiler — resolved calls, type inference |

**Fastest full-obfuscation sweep:**

```bash
./neodax -V --poly --aire -I --dsa ./binary
```

---

## Detecting Obfuscation

### Step 1 — Entropy scan

```bash
./neodax -e ./binary
```

| Output | Interpretation |
|--------|---------------|
| `.text` entropy ≥ 7.0 | Section is packed or encrypted |
| `.data` entropy ≥ 7.0 | Encrypted payload in data section |
| `.text` entropy 5.5–6.8 | Normal for ARM64/x86-64 |
| Multiple sections PACKED | Full packer (UPX, custom) |
| Only one region HIGH | Partial obfuscation / stub |

### Step 2 — Instruction validity filter

```bash
./neodax -V ./binary
```

IVF categories reported:

| Category | Meaning |
|----------|---------|
| `INVALID` | Byte sequence not a valid instruction |
| `MISALIGN` | Valid bytes but not after a branch — anti-disasm data |
| `embedded` | `0xF2xxxxxx` movk-pattern constants misidentified (fixed in v1.1.1) |
| `PRIV` | Privileged instruction in userspace (sysreg, autiasp) |
| `SMC` | Store to adr-derived exec address — code mutation confirmed |
| `OPAQUE-C` | `subs xN,xA,xA` — opaque zero subtraction |
| `OPAQUE-SR` | `mrs`→`cmp`→`b.cond` — sysreg opaque predicate |
| `DEAD` | Unreachable instruction after unconditional branch |
| `INDIRECT` | `br`/`blr` with register target — dynamic dispatch |
| `REG-ALIAS` | 32-bit w-reg write after x-reg — value truncation trick |

### Step 3 — Polymorphic map

```bash
./neodax --poly ./binary
```

The poly map scans 48-byte windows across all code sections and scores each window across 18 signals:

| Signal | What it detects |
|--------|----------------|
| `indirect-dispatch` | Dense `br`/`blr` instructions |
| `nop-junk` | NOP sleds used as alignment or obfuscation |
| `dead-code` | Unreachable code after unconditional branches |
| `const-obfuscation` | Dense `movk` chains splitting immediate values |
| `opaque-predicate` | `mrs` sysreg reads in code windows |
| `opcode-subst` | Same dest register written consecutively — substitution |
| `xor-arith` | Dense `eor`/`eon` — XOR-based arithmetic |
| `rotation-obf` | `ror`/`extr` rotation chains |
| `data-dep-branch` | `tbz`/`tbnz` on recently computed registers |
| `antidebug-gate` | `mrs`/`msr` sysreg access in window |
| `subst-chain` | Def-use chain depth ≥ 3 on same register |
| `xor-mutation-loop` | `ldr → eor → str` to exec address (polymorphic stub) |
| `hash-chain` | Consecutive arithmetic on same dest (Tigress-style) |
| `high-entropy` | Near-random bytes in code region (≥220/256 distinct) |

Obfuscator fingerprints detected:
- `OLLVM/Hikari` — opaque predicates + dense const splitting
- `XOR-poly/custom-packer` — XOR mutation + movk chains
- `XOR+ROR self-decrypt` — XOR mutation + rotation
- `antidebug+opaque-gate` — sysreg + data-dependent branches
- `hash-chain/Tigress` — deep arithmetic chains
- `NOP-packer` — dense NOP sleds
- `const-obf/split-imm` — split immediate chains
- `packed/encrypted` — near-random byte content
- `custom-VM` — dense indirect dispatch + dead code

### Step 4 — DSA for runtime value annotation

```bash
./neodax --dsa ./binary        # all functions
```

Interactive:
```
> dsa main           # DSA for one function
> dsa vm_run         # trace opaque dispatch values
> dsa all            # all functions
```

DSA records concrete values observed during emulation for every definition site, making opaque predicates visible:

```
DEF[  5]  x10 v2  @0xd60  tag=normal
         0x0000000000000908  freq=1
```

A def with `freq=1` and a constant value across all traces is a dead path — strong opaque predicate signal.

### Step 5 — AIRE for synthesis

```bash
./neodax --aire ./binary
```

AIRE cross-correlates all analysis results and produces ranked insights with confidence scores and a next-step guide tailored to the dominant obfuscation category.

---

## SMC — Self-Modifying Code

NeoDAX detects SMC through three independent passes:

### Pass 1: Static pattern (IVF)
`-V` scans for `str` instructions that:
- Follow an `adr`/`adrp` to an executable address (look-back up to 8 instructions)
- Precede an `eor` — XOR mutation stub pattern
- Fall inside a known poly region
- Match a known emulator SMC write record

### Pass 2: Symbolic execution
`-P` models memory writes symbolically. Any write to an executable address is recorded in `bin->smc_write_pc[]` with the old word, new word, and writing PC.

### Pass 3: Emulator real-time (new in v1.1.1)
`-I` runs concrete emulation. `emu_write8()` now checks every byte write against all code sections and records hits in `bin->emu_smc_*`. This catches SMC patterns that neither static analysis nor symexec can see.

All three passes are combined in the IVF output:

```
SMC patches (from symexec simulation):
    0x0000000000001234  [0x94000012 bl] → [0xd2800000 movz]

SMC writes (emulator real-time capture):
    write@0x000000000000129c → exec 0x0000000000001234

SMC mutation chains (addr written ≥2×):
    0x0000000000001234  patched 3× — probable polymorphic loop
```

---

## VM Dispatch Analysis

NeoDAX detects VM interpreter patterns in two ways:

### IVF VM detector
`-V` scans for the VM dispatch signature: a function with ≥4/6 of these features:
- Indirect branch (`br xN`)
- Large basic block count / instruction count ratio
- Tight loop back to the same block (opcode fetch)
- Known handler table base address
- High xref density to a single dispatch address

Output:
```
══════════════ VM DISPATCH DETECTION ══════════════

[VM_DISPATCH]  func=cff_compute  score=4/6
  dispatch br  : 0x0000000000001098

[VM_DISPATCH]  func=main  score=5/6
  dispatch br  : 0x0000000000001098
  table base   : 0x000000000000a130
```

### Emulator VM trace
`-I --vm-trace` records every indirect branch that resolves to a different function during emulation. After run:

```
Step  Dispatch@            Handler@              Opcode  VM_IP
  1   0x0000000000001098   0x000000000000143c    0x00    0x0
  2   0x0000000000001098   0x0000000000001464    0x02    0x1
  3   0x0000000000001098   0x0000000000001498    0x03    0x2
```

---

## IVF Obfuscation Score

The IVF prints an obfuscation score at the end of each scan:

| Score | Grade |
|-------|-------|
| 0 | CLEAN — no obfuscation detected |
| 1–3 | LOW — minimal obfuscation |
| 4–8 | MEDIUM — moderate obfuscation |
| 9–16 | HIGH — heavily obfuscated |
| 17+ | EXTREME — professional obfuscation/packer |

Score formula: `SMC×3 + opaque×2 + indirect + antidebug×2`

---

## Recommended Workflows

### Unknown stripped binary

```bash
./neodax -x -V --poly --aire ./binary
```

Gives: sections, functions, symbols, CFG, strings, IVF score, poly regions, AIRE summary with next-step guide.

### Suspected VM interpreter

```bash
./neodax -f -V -I --vm-trace ./binary
```

Gives: function list, IVF with VM detector, emulation with dispatch trace.

### Suspected SMC / self-decrypting

```bash
./neodax -P -I -V --poly ./binary
```

Gives: symexec SMC patches, emulator real-time SMC, IVF patterns, poly mutation regions.

### Deep deobfuscation session (interactive)

```bash
./neodax -X -i ./binary
```

Then in shell:
```
> ivf              # full IVF scan
> poly             # poly map
> run vm_run       # emulate VM
> vt               # VM dispatch trace
> dsa cff_compute  # DSA on dispatcher
> dec cff_compute  # pseudo-C decompiler
> aire             # AIRE synthesis
```
