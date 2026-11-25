# Instruction Validity Filter

**Level:** 4 - Advanced Analysis  
**Prerequisites:** 42_recursive_descent.md  
**What You Will Learn:** How the IVF works, what each category means, and how to use it for obfuscation analysis.

## What the IVF Does

The instruction validity filter (`-V`) scans all code sections and flags instructions or byte sequences that look suspicious — either invalid encodings, privileged ops out of place, or patterns associated with obfuscation techniques.

Run it:

```bash
./neodax -V ./binary
```

---

## IVF Categories

### INVALID

Byte sequence that does not decode to any valid instruction.

In v1.1.1, three ARM64 decoder bugs were fixed that were causing valid instructions to appear as INVALID:
- `movk xN, #imm, lsl #32/48` (encoding `0xF2xxxxxx`) — now correctly decoded
- `movn wN, #imm` (encoding `0x12xxxxxx`) — now correctly decoded  
- `ror wN/xN` and `extr` variants — mask corrected from `0x13000000` → `0x13800000`

### MISALIGN

A byte sequence that looks like data in the middle of a code stream — found without a preceding unconditional branch. Classic anti-disassembly: embed a `dw` word that would confuse linear disassemblers but is never actually executed.

### SMC

A store instruction (`str`/`strb`) writing to an address in an executable section. Multiple detection patterns:

1. `str` where the base register was loaded from `adr`/`adrp` pointing into code (look-back up to 8 instructions)
2. `eor xN, xN, key` immediately before the store — XOR mutation stub
3. Store instruction inside a region already flagged by the poly map
4. Cross-reference match with emulator real-time SMC write log

```
SMC   0x000000000000129c  str   str→adr-derived exec addr 0x1234 — confirmed code mutation
```

### OPAQUE-C

`subs xN, xA, xA` — subtracting a register from itself always produces zero. If this feeds a conditional branch, the branch outcome is fixed — an opaque predicate.

### OPAQUE-SR

`mrs` sysreg read followed by `cmp`/`tst` and a `b.cond` — using a system register value as the basis for a conditional branch that always resolves the same way. Common in OLLVM and Hikari.

### PRIV

Privileged instruction appearing in a user-mode ELF binary:
- `autiasp` / `autia` / `autib` — PAC authentication (CFI bypass risk)
- `mrs`/`msr` — system register access (anti-debug, timing)
- `paciza`/`pacdza` — PAC signing with zero key (weak authentication)

### INDIRECT

`br xN` or `blr xN` with a register target that cannot be statically resolved. These are potential VM dispatch points or function pointer calls. Run `-P` (symexec) or `-I` (emulator) to attempt resolution.

### REG-ALIAS

A 32-bit w-register write following a 64-bit x-register write to the same logical register. Writing `wN` implicitly zeros the upper 32 bits of `xN`. Used as a value truncation / hiding technique.

### DEAD

An instruction that follows an unconditional branch and is not the target of any other branch. Bytes injected to confuse disassemblers or as padding.

### ANTIDEBUG

Anti-debugging timing patterns: `mrs` reading `CNTVCT_EL0`, `PMCCNTR_EL0` (cycle counter), or similar performance counters followed by comparison.

---

## Reading the Summary

```
Summary:  invalid=68  priv=6  dead=3  indirect=6  opaque=7
Obfuscation score: 24  [EXTREME — professional obfuscation/packer]
Components:  SMC×3=9  opaque×2=14  indirect=1
```

Score formula: `SMC_count × 3 + opaque_count × 2 + indirect_count + antidebug_count × 2`

| Score | Grade |
|-------|-------|
| 0 | CLEAN |
| 1–3 | LOW |
| 4–8 | MEDIUM |
| 9–16 | HIGH |
| 17+ | EXTREME |

---

## SMC Report Sections

If symexec (`-P`) or the emulator (`-I`) were run before IVF, the output includes additional SMC sections:

```
SMC patches (from symexec simulation):
    0x0000000000001234  [0x94000012 bl] → [0xd2800000 movz]

SMC writes (emulator real-time capture):
    write@0x000000000000129c → exec 0x0000000000001234

SMC mutation chains (addr written ≥2×):
    0x0000000000001234  patched 3× — probable polymorphic loop
```

Mutation chains (addresses written more than once) are scored ×2 in the obfuscation rating.

---

## VM Dispatch Detection

After the IVF table, a VM detection section scores each function:

```
══════════════ VM DISPATCH DETECTION ══════════════

[VM_DISPATCH]  func=cff_compute  score=4/6
  dispatch br  : 0x0000000000001098

[VM_DISPATCH]  func=main  score=5/6
  dispatch br  : 0x0000000000001098
  table base   : 0x000000000000a130
```

Score 4/6 or higher indicates a probable VM interpreter or CFF dispatcher.

---

## Control Flow Movement Trace

IVF also prints a plain-language explanation of each suspicious indirect transfer:

```
0x0000000000001098  <cff_compute>
  WHAT:  Indirect branch — target computed at runtime
  WHY:   The destination is not fixed in the binary.
  STATUS: Unresolved — run with -P (symbolic exec) to attempt resolution
```

---

## Practice

```bash
# IVF alone
./neodax -V ./binary

# IVF + symexec to resolve indirect branches and detect SMC
./neodax -P -V ./binary

# IVF + emulator for real-time SMC capture
./neodax -I -V ./binary

# Everything — IVF, poly, SMC, AIRE synthesis
./neodax -V --poly --aire -I ./binary
```
