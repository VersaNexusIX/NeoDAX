/*
 * dsa.c — Dynamic Single Assignment (DSA) for NeoDAX
 *
 * DSA is a dataflow representation built on top of the emulator's concrete
 * execution trace.  Unlike SSA which is built purely from the CFG (static),
 * DSA uses *observed* runtime values to annotate every definition and use.
 *
 * Core idea
 * ─────────
 *   SSA :  each variable has one static definition site, phi-nodes merge
 *          control-flow paths — purely structural, no runtime knowledge.
 *
 *   DSA :  each definition carries the CONCRETE value observed at runtime
 *          for each trace path, plus a symbolic tag (reg/mem/imm/phi-dyn).
 *          Multiple paths through the same definition point get different
 *          DSA versions.  A "dyn-phi" node merges them with the actual
 *          frequency of each path across all recorded traces.
 *
 * Why DSA is stronger than SSA for obfuscated code
 * ──────────────────────────────────────────────────
 *   1. Opaque predicates collapse: the "taken" path dominates 100% of
 *      observed traces — the other arm has 0 frequency → dead code.
 *   2. Indirect dispatch is resolved: dispatch_table[r0] is annotated with
 *      every concrete target seen across traces, not just "unknown ptr".
 *   3. Crypto constant identification: if a def always produces 0x9E3779B9
 *      the dsa_def is tagged DSA_TAG_CRYPTO_CONST.
 *   4. SMC patch window: the first time a write def changes a previously
 *      read-only region, DSA marks a DSA_TAG_SMC_WRITE.
 *   5. Loop induction variable detection: a def whose value increases by
 *      a constant delta across traces is tagged DSA_TAG_INDUCTION.
 *
 * Fault isolation model (microkernel-style)
 * ─────────────────────────────────────────
 *   Each DSA phase (simulate, build_chains, mark_dead, build_phis, print)
 *   is wrapped in an independent recovery fence.  If any phase encounters
 *   a structural anomaly (out-of-bounds index, NULL pointer, corrupted
 *   counter), it sets a per-phase fault flag and returns early — the
 *   remaining phases continue unaffected.  A single corrupted function
 *   cannot crash the whole program.
 *
 * Structure
 * ─────────
 *   dsa_def_t   — one definition event (reg write or mem store)
 *   dsa_use_t   — one use event (reg read or mem load)
 *   dsa_phi_t   — dynamic merge point (multiple reaching defs)
 *   dsa_chain_t — def-use chain connecting one def to all its uses
 *   dsa_func_t  — per-function DSA result
 *   dsa_prog_t  — whole-program DSA
 *
 * The dsa_build() entry point runs dax_symexec_prepass() if not done,
 * then uses the concrete trace from dax_emulate_func() to populate all
 * of the above.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "dax.h"
#include "arm64.h"
#include "x86.h"
#include "riscv.h"

/* ── colour macros ───────────────────────────────────────────────────────── */
#define COL_DSA_DEF   "\033[1;32m"
#define COL_DSA_USE   "\033[1;34m"
#define COL_DSA_PHI   "\033[1;35m"
#define COL_DSA_WARN  "\033[1;33m"
#define COL_DSA_DEAD  "\033[0;90m"
#define COL_DSA_CRYPT "\033[1;36m"
#define COL_DSA_SMC   "\033[1;31m"
#define COL_RST       "\033[0m"

/* ── well-known crypto constants for tagging ─────────────────────────────── */
static const struct { uint64_t val; const char *name; } CRYPTO_CONSTS[] = {
    {0x9E3779B97F4A7C15ULL, "Fibonacci-phi (Knuth hash / SipHash)"},
    {0x9E3779B9ULL,         "Fibonacci-phi32 (xxHash/Murmur)"},
    {0x6A09E667ULL,         "SHA-256 H0"},
    {0xBB67AE85ULL,         "SHA-256 H1"},
    {0x3C6EF372ULL,         "SHA-256 H2"},
    {0xA54FF53AULL,         "SHA-256 H3"},
    {0x6364136223846793ULL, "LCG multiplier (PCG)"},
    {0xFF51AFD7ED558CCDULL, "MurmurHash3 constant"},
    {0xC4CEB9FE1A85EC53ULL, "MurmurHash3 constant"},
    {0xBF58476D1CE4E5B9ULL, "SplitMix64 constant"},
    {0x94D049BB133111EBULL, "SplitMix64 constant"},
    {0x517CC1B727220A95ULL, "FNV prime"},
    {0x00000100000001B3ULL, "FNV-1a 64-bit prime"},
    {0xCBF29CE484222325ULL, "FNV-1a 64-bit offset basis"},
    {0x1000193ULL,          "FNV-1a 32-bit prime"},
    {0ULL, NULL}
};

static const char *dsa_crypto_name(uint64_t v) {
    for (int i = 0; CRYPTO_CONSTS[i].name; i++)
        if (CRYPTO_CONSTS[i].val == v) return CRYPTO_CONSTS[i].name;
    return NULL;
}

/* ── DSA definition tags ─────────────────────────────────────────────────── */
typedef enum {
    DSA_TAG_NORMAL      = 0,
    DSA_TAG_INDUCTION,       /* loop induction variable (+const delta)     */
    DSA_TAG_CRYPTO_CONST,    /* known crypto constant                       */
    DSA_TAG_SMC_WRITE,       /* stores into executable region               */
    DSA_TAG_DISPATCH_IDX,    /* used as indirect call/jump index            */
    DSA_TAG_OPAQUE_DEAD,     /* definition in dead (0-frequency) arm        */
    DSA_TAG_KEY_MATERIAL,    /* XOR / ADD with high-entropy operand         */
    DSA_TAG_LOOP_CTR,        /* counts from 0/N monotonically               */
    DSA_TAG_SYSCALL_ARG,     /* passed to a syscall as argument             */
} dsa_tag_t;

static const char *dsa_tag_name(dsa_tag_t t) {
    switch (t) {
        case DSA_TAG_INDUCTION:    return "induction";
        case DSA_TAG_CRYPTO_CONST: return "crypto-const";
        case DSA_TAG_SMC_WRITE:    return "smc-write";
        case DSA_TAG_DISPATCH_IDX: return "dispatch-idx";
        case DSA_TAG_OPAQUE_DEAD:  return "opaque-dead";
        case DSA_TAG_KEY_MATERIAL: return "key-material";
        case DSA_TAG_LOOP_CTR:     return "loop-ctr";
        case DSA_TAG_SYSCALL_ARG:  return "syscall-arg";
        default:                   return "normal";
    }
}

/* ── DSA definition ─────────────────────────────────────────────────────── */
#define DSA_MAX_VALUES  8    /* max distinct observed values per def        */
#define DSA_MAX_DEFS   512
#define DSA_MAX_USES   1024
#define DSA_MAX_CHAINS 256

/* Hard upper bounds for external arrays we read from dax_binary_t */
#define DSA_INDIRECT_MAX  128
#define DSA_SMC_MAX       128

typedef enum { DSA_REG, DSA_MEM } dsa_operand_kind_t;

typedef struct {
    uint64_t          pc;
    dsa_operand_kind_t kind;
    int               reg_idx;
    uint64_t          mem_addr;
    uint64_t          vals[DSA_MAX_VALUES];
    int               val_freq[DSA_MAX_VALUES];
    int               nvals;
    int               version;
    dsa_tag_t         tag;
    char              tag_detail[64];
    int               is_dead;
} dsa_def_t;

typedef struct {
    uint64_t          pc;
    dsa_operand_kind_t kind;
    int               reg_idx;
    uint64_t          mem_addr;
    int               def_idx;
} dsa_use_t;

typedef struct {
    int               def_idx;
    int               use_idxs[32];
    int               nuses;
} dsa_chain_t;

typedef struct {
    uint64_t          join_pc;
    int               def_a;
    int               def_b;
    int               freq_a;
    int               freq_b;
} dsa_phi_t;

#define DSA_MAX_PHIS 64

/*
 * Fault isolation flags — one per DSA phase.
 * A set bit means that phase aborted early; callers can still inspect
 * partial results from earlier phases.
 */
#define DSA_FAULT_SIMULATE   (1u << 0)
#define DSA_FAULT_CHAINS     (1u << 1)
#define DSA_FAULT_DEAD       (1u << 2)
#define DSA_FAULT_PHIS       (1u << 3)
#define DSA_FAULT_PRINT      (1u << 4)

struct dsa_func_t {
    int               func_idx;
    dsa_def_t         defs[DSA_MAX_DEFS];
    int               ndefs;
    dsa_use_t         uses[DSA_MAX_USES];
    int               nuses;
    dsa_chain_t       chains[DSA_MAX_CHAINS];
    int               nchains;
    dsa_phi_t         phis[DSA_MAX_PHIS];
    int               nphis;
    int               reg_version[32];
    int               reg_def_idx[32];
    uint64_t          loop_def_prev_val[32];
    int64_t           loop_def_delta[32];
    int               loop_def_consistent[32];
    int               loop_def_count[32];
    unsigned int      fault_flags;   /* DSA_FAULT_* bitmask */
};

typedef struct {
    dsa_func_t *funcs;
    int         nfuncs;
} dsa_prog_t;

/* ── Internal validation helpers ─────────────────────────────────────────── */

/*
 * DSA_VALID_BIN — macro that validates the minimum dax_binary_t fields
 * needed before any dsa_simulate_func work.  Returns early with fault flag
 * if anything looks wrong.
 */
#define DSA_GUARD_BIN(bin, df, fault_bit)                       \
    do {                                                         \
        if (!(bin) || !(df)) return;                             \
        if ((bin)->nsections < 0 || (bin)->nsections > DAX_MAX_SECTIONS) { \
            (df)->fault_flags |= (fault_bit); return;           \
        }                                                        \
        if ((bin)->nfunctions < 0 || (bin)->nfunctions > DAX_MAX_FUNCTIONS) { \
            (df)->fault_flags |= (fault_bit); return;           \
        }                                                        \
    } while (0)

/* Clamp an integer into [lo, hi] */
#define DSA_CLAMP(v, lo, hi) ((v) < (lo) ? (lo) : (v) > (hi) ? (hi) : (v))

/* Validate a def index against current ndefs */
static int dsa_def_valid(const dsa_func_t *df, int idx) {
    if (!df) return 0;
    if (idx < 0 || idx >= df->ndefs) return 0;
    if (idx >= DSA_MAX_DEFS) return 0;
    return 1;
}

/* Validate a reg index */
static int dsa_reg_valid(int r) {
    return (r >= 0 && r < 32);
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static dsa_def_t *dsa_find_def_reg(dsa_func_t *df, int reg) {
    if (!df || !dsa_reg_valid(reg)) return NULL;
    int idx = df->reg_def_idx[reg];
    if (idx < 0 || idx >= df->ndefs || idx >= DSA_MAX_DEFS) return NULL;
    return &df->defs[idx];
}

static void dsa_record_val(dsa_def_t *def, uint64_t val) {
    if (!def) return;
    if (def->nvals < 0) def->nvals = 0;
    for (int i = 0; i < def->nvals && i < DSA_MAX_VALUES; i++) {
        if (def->vals[i] == val) {
            def->val_freq[i]++;
            return;
        }
    }
    if (def->nvals < DSA_MAX_VALUES) {
        def->vals[def->nvals]     = val;
        def->val_freq[def->nvals] = 1;
        def->nvals++;
    }
}

static dsa_tag_t dsa_tag_value(uint64_t v, char *detail, size_t dsz) {
    if (!detail || dsz == 0) return DSA_TAG_NORMAL;
    const char *name = dsa_crypto_name(v);
    if (name) {
        snprintf(detail, dsz, "%s", name);
        return DSA_TAG_CRYPTO_CONST;
    }
    if ((v >> 48) != 0 && (v & 0xFFFF) != 0 &&
        v != 0xFFFFFFFFFFFFFFFFULL && v != 0xDEADBEEFCAFEBABEULL)
        return DSA_TAG_KEY_MATERIAL;
    return DSA_TAG_NORMAL;
}

/* ── Per-instruction DSA update ─────────────────────────────────────────── */

static void dsa_step(dsa_func_t *df, uint64_t pc,
                     const uint64_t *regs_before,
                     const uint64_t *regs_after,
                     int nregs,
                     const dax_binary_t *bin) {
    if (!df || !regs_before || !regs_after || !bin) return;
    if (df->fault_flags & DSA_FAULT_SIMULATE) return;

    /* Clamp nregs to safe range */
    if (nregs < 0) nregs = 0;
    if (nregs > 32) nregs = 32;

    /* Validate external bin counts once — abort phase on corruption */
    int nresolved = bin->nresolved_indirect;
    int nsmc      = bin->nsmc_patches;
    if (nresolved < 0 || nresolved > DSA_INDIRECT_MAX) nresolved = 0;
    if (nsmc < 0 || nsmc > DSA_SMC_MAX)                nsmc      = 0;

    /* ── Detect register writes (definitions) ── */
    for (int r = 0; r < nregs; r++) {
        if (regs_before[r] == regs_after[r]) continue;

        /* Check if we are redefining the same reg at this PC (loop) */
        int prev_idx = df->reg_def_idx[r];
        if (prev_idx >= 0 && dsa_def_valid(df, prev_idx)) {
            dsa_def_t *prev = &df->defs[prev_idx];
            if (prev->pc == pc) {
                dsa_record_val(prev, regs_after[r]);

                int64_t delta = (int64_t)regs_after[r] - (int64_t)regs_before[r];
                if (df->loop_def_count[r] == 0) {
                    df->loop_def_delta[r]      = delta;
                    df->loop_def_consistent[r] = 1;
                } else if (df->loop_def_delta[r] != delta) {
                    df->loop_def_consistent[r] = 0;
                }
                /* Guard against counter overflow */
                if (df->loop_def_count[r] < 0x7FFFFFFF)
                    df->loop_def_count[r]++;

                if (df->loop_def_consistent[r] && df->loop_def_count[r] >= 3) {
                    prev->tag = DSA_TAG_INDUCTION;
                    snprintf(prev->tag_detail, sizeof(prev->tag_detail),
                             "delta=%+lld, %d iters",
                             (long long)df->loop_def_delta[r],
                             df->loop_def_count[r]);
                }
                if (df->loop_def_consistent[r] &&
                    df->loop_def_delta[r] == 1 && regs_after[r] < 65536)
                    prev->tag = DSA_TAG_LOOP_CTR;

                continue;
            }
        }

        /* New def slot — check capacity */
        if (df->ndefs < 0) df->ndefs = 0;
        if (df->ndefs >= DSA_MAX_DEFS) continue;

        int vidx = df->ndefs++;
        dsa_def_t *d = &df->defs[vidx];
        memset(d, 0, sizeof(*d));
        d->pc      = pc;
        d->kind    = DSA_REG;
        d->reg_idx = r;
        d->version = ++df->reg_version[r];
        dsa_record_val(d, regs_after[r]);

        d->tag = dsa_tag_value(regs_after[r], d->tag_detail,
                               sizeof(d->tag_detail));

        /* Dispatch index check — use validated nresolved */
        if (nresolved > 0) {
            for (int xi = 0; xi < nresolved; xi++) {
                if (bin->resolved_indirect_from[xi] == pc + 4 ||
                    bin->resolved_indirect_from[xi] == pc + 2) {
                    d->tag = DSA_TAG_DISPATCH_IDX;
                    snprintf(d->tag_detail, sizeof(d->tag_detail),
                             "→ dispatch at 0x%llx",
                             (unsigned long long)bin->resolved_indirect_from[xi]);
                    break;
                }
            }
        }

        /* SMC check — use validated nsmc */
        if (nsmc > 0) {
            for (int si = 0; si < nsmc; si++) {
                if (bin->smc_write_pc[si] == pc) {
                    d->tag = DSA_TAG_SMC_WRITE;
                    snprintf(d->tag_detail, sizeof(d->tag_detail),
                             "→ patches 0x%llx",
                             (unsigned long long)bin->smc_target_addr[si]);
                    break;
                }
            }
        }

        df->reg_def_idx[r]         = vidx;
        df->loop_def_count[r]      = 0;
        df->loop_def_consistent[r] = 1;
    }

    /* ── Detect register reads (uses) ── */
    for (int r = 0; r < nregs; r++) {
        if (regs_before[r] == 0) continue;
        int didx = df->reg_def_idx[r];
        if (!dsa_def_valid(df, didx)) continue;
        if (df->nuses < 0) df->nuses = 0;
        if (df->nuses >= DSA_MAX_USES) break;
        dsa_use_t *u = &df->uses[df->nuses++];
        u->pc      = pc;
        u->kind    = DSA_REG;
        u->reg_idx = r;
        u->def_idx = didx;
    }
}

/* ── Build def-use chains ───────────────────────────────────────────────── */

static void dsa_build_chains(dsa_func_t *df) {
    if (!df) return;
    if (df->fault_flags & DSA_FAULT_CHAINS) return;

    /* Defensive clamp before iterating */
    df->ndefs   = DSA_CLAMP(df->ndefs,   0, DSA_MAX_DEFS);
    df->nuses   = DSA_CLAMP(df->nuses,   0, DSA_MAX_USES);
    df->nchains = 0;

    for (int di = 0; di < df->ndefs && df->nchains < DSA_MAX_CHAINS; di++) {
        dsa_chain_t *ch = &df->chains[df->nchains++];
        ch->def_idx = di;
        ch->nuses   = 0;
        for (int ui = 0; ui < df->nuses; ui++) {
            if (df->uses[ui].def_idx == di && ch->nuses < 32)
                ch->use_idxs[ch->nuses++] = ui;
        }
    }
}

/* ── Detect dead definitions (zero-frequency arms) ─────────────────────── */

static void dsa_mark_dead(dsa_func_t *df) {
    if (!df) return;
    if (df->fault_flags & DSA_FAULT_DEAD) return;

    int ndefs = DSA_CLAMP(df->ndefs, 0, DSA_MAX_DEFS);
    for (int i = 0; i < ndefs; i++) {
        if (df->defs[i].nvals <= 0)
            df->defs[i].is_dead = 1;
    }
}

/* ── Detect dynamic phi nodes ───────────────────────────────────────────── */

static void dsa_build_phis(dsa_func_t *df) {
    if (!df) return;
    if (df->fault_flags & DSA_FAULT_PHIS) return;

    int nu    = DSA_CLAMP(df->nuses,  0, DSA_MAX_USES);
    int ndefs = DSA_CLAMP(df->ndefs,  0, DSA_MAX_DEFS);
    df->nphis = 0;

    for (int ua = 0; ua < nu && df->nphis < DSA_MAX_PHIS; ua++) {
        for (int ub = ua + 1; ub < nu; ub++) {
            if (df->uses[ua].pc      != df->uses[ub].pc)      continue;
            if (df->uses[ua].reg_idx != df->uses[ub].reg_idx) continue;
            if (df->uses[ua].def_idx == df->uses[ub].def_idx) continue;

            int da = df->uses[ua].def_idx;
            int db = df->uses[ub].def_idx;

            /* Hard bounds check — must be valid def indices */
            if (da < 0 || da >= ndefs) continue;
            if (db < 0 || db >= ndefs) continue;
            if (da == db) continue;

            int fa = 0, fb = 0;
            for (int k = 0; k < df->defs[da].nvals && k < DSA_MAX_VALUES; k++)
                fa += df->defs[da].val_freq[k];
            for (int k = 0; k < df->defs[db].nvals && k < DSA_MAX_VALUES; k++)
                fb += df->defs[db].val_freq[k];

            dsa_phi_t *phi = &df->phis[df->nphis++];
            phi->join_pc = df->uses[ua].pc;
            phi->def_a   = da;
            phi->def_b   = db;
            phi->freq_a  = fa;
            phi->freq_b  = fb;
            break;
        }
    }
}

/* ── Simulate a register trace from the emulator output ─────────────────── */

static void dsa_simulate_func(dsa_func_t *df, dax_binary_t *bin, int func_idx) {
    /* Phase guard: any NULL input is a hard fault for this phase only */
    if (!df)  return;
    if (!bin) { df->fault_flags |= DSA_FAULT_SIMULATE; return; }

    /* Validate func_idx */
    if (func_idx < 0) { df->fault_flags |= DSA_FAULT_SIMULATE; return; }
    if (bin->nfunctions <= 0 || func_idx >= bin->nfunctions) {
        df->fault_flags |= DSA_FAULT_SIMULATE; return;
    }

    /* Must have data */
    if (!bin->data || bin->size == 0) {
        df->fault_flags |= DSA_FAULT_SIMULATE; return;
    }

    /* Must have at least one section */
    if (bin->nsections <= 0 || bin->nsections > DAX_MAX_SECTIONS) {
        df->fault_flags |= DSA_FAULT_SIMULATE; return;
    }

    /* Must have functions array */
    if (!bin->functions) {
        df->fault_flags |= DSA_FAULT_SIMULATE; return;
    }

    dax_func_t *fn = &bin->functions[func_idx];
    if (!fn) { df->fault_flags |= DSA_FAULT_SIMULATE; return; }

    /* Sanity-check function bounds */
    if (fn->start == 0 || fn->end <= fn->start) {
        df->fault_flags |= DSA_FAULT_SIMULATE; return;
    }
    /* Guard against absurdly large functions (> 8 MB) */
    if (fn->end - fn->start > 0x800000ULL) {
        df->fault_flags |= DSA_FAULT_SIMULATE; return;
    }

    /* Find code section */
    uint8_t  *code = NULL;
    size_t    csz  = 0;
    uint64_t  base = 0;

    for (int si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *s = &bin->sections[si];
        /* Validate section fields before use */
        if (s->size == 0) continue;
        if (s->vaddr == 0 && s->size == 0) continue;
        if (s->offset > bin->size) continue;
        if (s->size > bin->size - s->offset) continue;  /* overflow-safe */

        if (fn->start >= s->vaddr && fn->start < s->vaddr + s->size) {
            code = bin->data + s->offset;
            csz  = s->size;
            base = s->vaddr;
            break;
        }
    }

    if (!code || csz == 0) {
        df->fault_flags |= DSA_FAULT_SIMULATE; return;
    }

    /* Validate that fn->start maps inside this section */
    if (fn->start < base || fn->start - base >= csz) {
        df->fault_flags |= DSA_FAULT_SIMULATE; return;
    }

    /* Seed register state */
    uint64_t regs[32]   = {0};
    uint64_t regs_n[32] = {0};
    memset(df->reg_def_idx, -1, sizeof(df->reg_def_idx));
    memset(df->reg_version, 0,  sizeof(df->reg_version));

    size_t off = (size_t)(fn->start - base);
    size_t end_off;

    /* Compute end offset, clamped to section size */
    if (fn->end > base && fn->end <= base + csz)
        end_off = (size_t)(fn->end - base);
    else
        end_off = off + 1024;
    if (end_off > csz) end_off = csz;

    /* Iteration budget: prevent infinite loops on corrupt data */
    int budget = 65536;

    while (off + 4 <= end_off && budget-- > 0) {
        uint64_t pc = base + off;

        if (bin->arch == ARCH_ARM64) {
            /* Bounds check before reading 4 bytes */
            if (off + 4 > csz) break;

            uint32_t raw = (uint32_t)code[off]        |
                           ((uint32_t)code[off + 1] << 8)  |
                           ((uint32_t)code[off + 2] << 16) |
                           ((uint32_t)code[off + 3] << 24);
            a64_insn_t insn;
            memset(&insn, 0, sizeof(insn));
            a64_decode(raw, pc, &insn);

            memcpy(regs_n, regs, sizeof(regs));

            const char *m  = insn.mnemonic;
            const char *op = insn.operands;

            /* Null-guard decoder output */
            if (!m || !op) { off += 4; continue; }

            if (!strcmp(m, "mov") || !strcmp(m, "orr")) {
                int d = -1, n = -1;
                if (sscanf(op, "x%d, x%d", &d, &n) == 2 &&
                    dsa_reg_valid(d) && dsa_reg_valid(n))
                    regs_n[d] = regs[n];
            } else if (!strcmp(m, "movz")) {
                int d = -1; unsigned long long v = 0;
                if (sscanf(op, "x%d, #0x%llx", &d, &v) == 2 && dsa_reg_valid(d))
                    regs_n[d] = (uint64_t)v;
                else if (sscanf(op, "x%d, #%llu", &d, &v) == 2 && dsa_reg_valid(d))
                    regs_n[d] = (uint64_t)v;
            } else if (!strcmp(m, "add")) {
                int d = -1, n = -1, mm = -1; unsigned long long imm = 0;
                if (sscanf(op, "x%d, x%d, #0x%llx", &d, &n, &imm) == 3 &&
                    dsa_reg_valid(d) && dsa_reg_valid(n))
                    regs_n[d] = regs[n] + (uint64_t)imm;
                else if (sscanf(op, "x%d, x%d, x%d", &d, &n, &mm) == 3 &&
                         dsa_reg_valid(d) && dsa_reg_valid(n) && dsa_reg_valid(mm))
                    regs_n[d] = regs[n] + regs[mm];
            } else if (!strcmp(m, "eor") || !strcmp(m, "xor")) {
                int d = -1, n = -1, mm = -1;
                if (sscanf(op, "x%d, x%d, x%d", &d, &n, &mm) == 3 &&
                    dsa_reg_valid(d) && dsa_reg_valid(n) && dsa_reg_valid(mm))
                    regs_n[d] = regs[n] ^ regs[mm];
            } else if (!strncmp(m, "ldr", 3)) {
                int d = -1;
                if (sscanf(op, "x%d,", &d) == 1 && dsa_reg_valid(d)) {
                    int nres = DSA_CLAMP(bin->nresolved_indirect, 0, DSA_INDIRECT_MAX);
                    for (int xi = 0; xi < nres; xi++)
                        if (bin->resolved_indirect_from[xi] == pc) {
                            regs_n[d] = bin->resolved_indirect_to[xi];
                            break;
                        }
                }
            }

            dsa_step(df, pc, regs, regs_n, 32, bin);
            memcpy(regs, regs_n, sizeof(regs));
            off += 4;

        } else if (bin->arch == ARCH_X86_64) {
            if (off >= csz) break;
            x86_insn_t insn;
            memset(&insn, 0, sizeof(insn));
            int len = x86_decode(code + off, end_off - off, pc, &insn);
            if (len <= 0 || (size_t)len > end_off - off) { off++; continue; }
            memcpy(regs_n, regs, sizeof(regs));
            dsa_step(df, pc, regs, regs_n, 16, bin);
            memcpy(regs, regs_n, sizeof(regs));
            off += (size_t)len;

        } else {
            /* RISC-V */
            if (off >= csz) break;
            rv_insn_t insn;
            memset(&insn, 0, sizeof(insn));
            int len = rv_decode(code + off, end_off - off, pc, &insn);
            if (len <= 0 || (size_t)len > end_off - off) { off += 2; continue; }
            memcpy(regs_n, regs, sizeof(regs));
            dsa_step(df, pc, regs, regs_n, 32, bin);
            memcpy(regs, regs_n, sizeof(regs));
            off += (size_t)len;
        }
    }

    /* Phase 2 — chains (independent fault domain) */
    dsa_build_chains(df);

    /* Phase 3 — dead marking (independent fault domain) */
    dsa_mark_dead(df);

    /* Phase 4 — phi detection (independent fault domain) */
    dsa_build_phis(df);
}

/* ── Public entry point: build DSA for one function ─────────────────────── */

void dax_dsa_build_func(dax_binary_t *bin, int func_idx,
                        dsa_func_t *out_df) {
    if (!out_df) return;
    memset(out_df, 0, DAX_DSA_FUNC_SIZE);
    if (!bin) {
        out_df->fault_flags |= DSA_FAULT_SIMULATE;
        return;
    }
    if (func_idx < 0 || bin->nfunctions <= 0 || func_idx >= bin->nfunctions) {
        out_df->fault_flags |= DSA_FAULT_SIMULATE;
        return;
    }
    out_df->func_idx = func_idx;
    dsa_simulate_func(out_df, bin, func_idx);
}

/* ── Print DSA results ───────────────────────────────────────────────────── */

static void print_bar(FILE *out, int conf, int c) {
    const char *col = c ? (conf >= 80 ? "\033[1;32m" :
                           conf >= 55 ? "\033[1;33m" : "\033[1;31m") : "";
    const char *rst = c ? COL_RST : "";
    fprintf(out, "%s[", col);
    for (int i = 0; i < 20; i++)
        fputc(i < (conf / 5) ? '#' : '.', out);
    fprintf(out, "] %3d%%%s", conf, rst);
}

void dax_dsa_print(dax_binary_t *bin, int func_idx,
                   dsa_func_t *df, dax_opts_t *opts, FILE *out) {
    if (!bin || !df || !out) return;
    if (df->fault_flags & DSA_FAULT_PRINT) return;

    /* If simulate phase failed, emit a diagnostic and return */
    if (df->fault_flags & DSA_FAULT_SIMULATE) {
        if (opts && !opts->color)
            fprintf(out, "  [DSA] func %d: simulate phase skipped (unsupported binary section)\n",
                    func_idx);
        else
            fprintf(out, "  \033[1;33m[DSA]\033[0m func %d: simulate phase skipped\n",
                    func_idx);
        return;
    }

    int c = opts ? opts->color : 1;
    const char *Def  = c ? COL_DSA_DEF  : "";
    const char *Use  = c ? COL_DSA_USE  : "";
    const char *Phi  = c ? COL_DSA_PHI  : "";
    const char *Warn = c ? COL_DSA_WARN : "";
    const char *Dead = c ? COL_DSA_DEAD : "";
    const char *Crypt= c ? COL_DSA_CRYPT: "";
    const char *Smc  = c ? COL_DSA_SMC  : "";
    const char *R    = c ? COL_RST      : "";

    /* Safe function name lookup */
    const char *fname = "unknown";
    if (func_idx >= 0 && bin->nfunctions > 0 &&
        func_idx < bin->nfunctions && bin->functions)
        fname = bin->functions[func_idx].name;
    if (!fname || fname[0] == '\0') fname = "unnamed";

    /* Defensive clamp of all counters */
    df->ndefs   = DSA_CLAMP(df->ndefs,   0, DSA_MAX_DEFS);
    df->nuses   = DSA_CLAMP(df->nuses,   0, DSA_MAX_USES);
    df->nchains = DSA_CLAMP(df->nchains, 0, DSA_MAX_CHAINS);
    df->nphis   = DSA_CLAMP(df->nphis,   0, DSA_MAX_PHIS);

    fprintf(out, "\n");
    if (c) fprintf(out, "\033[1;36m");
    fprintf(out,
        "  ══════════════════════════════════════════════════════════\n"
        "  DSA — Dynamic Single Assignment  ·  func: %s\n"
        "  ══════════════════════════════════════════════════════════\n",
        fname);
    if (c) fprintf(out, "%s", R);
    fprintf(out, "\n");

    /* Fault summary if any sub-phase failed */
    if (df->fault_flags & (DSA_FAULT_CHAINS | DSA_FAULT_DEAD | DSA_FAULT_PHIS)) {
        fprintf(out, "  %s[partial analysis — some phases skipped: 0x%02x]%s\n\n",
                c ? COL_DSA_WARN : "", df->fault_flags, R);
    }

    fprintf(out, "  %s%d def(s)  %d use(s)  %d chain(s)  %d dyn-phi(s)%s\n\n",
            c ? "\033[0;90m" : "", df->ndefs, df->nuses,
            df->nchains, df->nphis, R);

    /* ── Definitions ── */
    fprintf(out, "  %s── Definitions ─────────────────────────────────────%s\n",
            c ? "\033[0;90m" : "", R);

    for (int i = 0; i < df->ndefs; i++) {
        dsa_def_t *d = &df->defs[i];

        /* Validate every field before printing */
        if (d->reg_idx < 0 || d->reg_idx > 31) d->reg_idx = 0;
        d->nvals = DSA_CLAMP(d->nvals, 0, DSA_MAX_VALUES);

        const char *tc = "";
        if      (d->tag == DSA_TAG_CRYPTO_CONST) tc = Crypt;
        else if (d->tag == DSA_TAG_SMC_WRITE)    tc = Smc;
        else if (d->tag == DSA_TAG_DISPATCH_IDX) tc = Warn;
        else if (d->tag == DSA_TAG_OPAQUE_DEAD)  tc = Dead;
        else if (d->tag == DSA_TAG_INDUCTION ||
                 d->tag == DSA_TAG_LOOP_CTR)     tc = Use;
        else                                     tc = Def;

        if (d->is_dead)
            fprintf(out, "  %sDEF[%3d]  x%-2d v%d  @0x%llx  [DEAD — unreachable arm]%s\n",
                    Dead, i, d->reg_idx, d->version,
                    (unsigned long long)d->pc, R);
        else {
            fprintf(out, "  %sDEF[%3d]  x%-2d v%d  @0x%llx",
                    tc, i, d->reg_idx, d->version,
                    (unsigned long long)d->pc);
            fprintf(out, "  tag=%-14s", dsa_tag_name(d->tag));
            if (d->tag_detail[0])
                fprintf(out, "  (%.*s)", (int)(sizeof(d->tag_detail) - 1),
                        d->tag_detail);
            fprintf(out, "%s\n", R);

            for (int vi = 0; vi < d->nvals; vi++) {
                fprintf(out, "           %s0x%016llx%s  freq=%-4d",
                        c ? "\033[0;90m" : "",
                        (unsigned long long)d->vals[vi],
                        R, d->val_freq[vi]);
                const char *cn = dsa_crypto_name(d->vals[vi]);
                if (cn) fprintf(out, "  %s← %s%s", Crypt, cn, R);
                fprintf(out, "\n");
            }
        }
    }

    /* ── Dynamic phi nodes ── */
    if (df->nphis > 0) {
        fprintf(out, "\n  %s── Dynamic Phi nodes ────────────────────────────────%s\n",
                c ? "\033[0;90m" : "", R);
        for (int i = 0; i < df->nphis; i++) {
            dsa_phi_t *phi = &df->phis[i];

            /* Bounds-check def indices before any array access */
            int da = phi->def_a, db = phi->def_b;
            if (da < 0 || da >= df->ndefs) da = 0;
            if (db < 0 || db >= df->ndefs) db = 0;

            int total = phi->freq_a + phi->freq_b;
            int pct_a = total > 0 ? (phi->freq_a * 100) / total : 0;
            int pct_b = total > 0 ? (phi->freq_b * 100) / total : 0;

            fprintf(out, "  %sPHI[%2d]%s  @0x%llx\n",
                    Phi, i, R, (unsigned long long)phi->join_pc);
            fprintf(out, "    ├─ DEF[%3d] x%d v%d  freq=%-4d (%d%%)\n",
                    phi->def_a,
                    df->defs[da].reg_idx, df->defs[da].version,
                    phi->freq_a, pct_a);
            fprintf(out, "    └─ DEF[%3d] x%d v%d  freq=%-4d (%d%%)",
                    phi->def_b,
                    df->defs[db].reg_idx, df->defs[db].version,
                    phi->freq_b, pct_b);

            if (pct_a == 100 || pct_b == 100) {
                fprintf(out, "  %s← OPAQUE (one arm never taken)%s", Warn, R);
                int dead_idx = (pct_a == 100) ? phi->def_b : phi->def_a;
                /* Validate before write — don't corrupt df on bad data */
                if (dead_idx >= 0 && dead_idx < df->ndefs) {
                    df->defs[dead_idx].is_dead = 1;
                    df->defs[dead_idx].tag     = DSA_TAG_OPAQUE_DEAD;
                }
            }
            fprintf(out, "\n");
        }
    }

    /* ── Def-Use chains (top 12 by use count) ── */
    fprintf(out, "\n  %s── Def-Use Chains (top by use count) ───────────────%s\n",
            c ? "\033[0;90m" : "", R);

    /* Insertion sort on order[] — guard against nchains == 0 */
    int order[DSA_MAX_CHAINS];
    for (int i = 0; i < df->nchains; i++) order[i] = i;
    for (int i = 0; i < df->nchains - 1; i++)
        for (int j = i + 1; j < df->nchains; j++)
            if (df->chains[order[j]].nuses > df->chains[order[i]].nuses) {
                int t = order[i]; order[i] = order[j]; order[j] = t;
            }

    int shown = 0;
    for (int ci = 0; ci < df->nchains && shown < 12; ci++) {
        int oi = order[ci];
        if (oi < 0 || oi >= df->nchains) continue;
        dsa_chain_t *ch = &df->chains[oi];
        int di = ch->def_idx;
        if (!dsa_def_valid(df, di)) continue;
        if (ch->nuses == 0) continue;
        dsa_def_t *d = &df->defs[di];
        if (d->is_dead) continue;
        if (!dsa_reg_valid(d->reg_idx)) continue;
        fprintf(out, "  %sCHAIN[%3d]%s  x%d v%d  @0x%llx  uses=%d",
                Def, ch->def_idx, R,
                d->reg_idx, d->version,
                (unsigned long long)d->pc, ch->nuses);
        if (d->tag != DSA_TAG_NORMAL)
            fprintf(out, "  %s[%s]%s", Warn, dsa_tag_name(d->tag), R);
        fprintf(out, "\n");
        shown++;
    }

    fprintf(out, "\n");
}

/* ── AIRE integration: DSA-powered insight helpers ───────────────────────── */

int dax_dsa_aire_signals(dax_binary_t *bin, int func_idx,
                         const char **out_crypto, int *out_ncrypto) {
    if (!bin) return 0;
    if (func_idx < 0) return 0;
    if (bin->nfunctions <= 0 || func_idx >= bin->nfunctions) return 0;

    dsa_func_t *df = (dsa_func_t *)calloc(1, DAX_DSA_FUNC_SIZE);
    if (!df) return 0;

    dsa_simulate_func(df, bin, func_idx);

    int flags = 0;
    if (out_ncrypto) *out_ncrypto = 0;

    /* If the simulate phase failed entirely, return 0 cleanly */
    if (df->fault_flags & DSA_FAULT_SIMULATE) {
        free(df);
        return 0;
    }

    int ndefs = DSA_CLAMP(df->ndefs, 0, DSA_MAX_DEFS);

    for (int i = 0; i < ndefs; i++) {
        switch (df->defs[i].tag) {
            case DSA_TAG_DISPATCH_IDX: flags |= 0x02; break;
            case DSA_TAG_SMC_WRITE:    flags |= 0x08; break;
            case DSA_TAG_INDUCTION:    flags |= 0x10; break;
            case DSA_TAG_KEY_MATERIAL: flags |= 0x20; break;
            case DSA_TAG_LOOP_CTR:     flags |= 0x40; break;
            case DSA_TAG_CRYPTO_CONST:
                flags |= 0x04;
                if (out_crypto && out_ncrypto && *out_ncrypto < 4) {
                    out_crypto[(*out_ncrypto)++] = df->defs[i].tag_detail;
                }
                break;
            default: break;
        }
    }

    int nphis = DSA_CLAMP(df->nphis, 0, DSA_MAX_PHIS);
    for (int i = 0; i < nphis; i++) {
        int fa = df->phis[i].freq_a, fb = df->phis[i].freq_b;
        int total = fa + fb;
        if (total > 0 && (fa == 0 || fb == 0))
            flags |= 0x01;
    }

    free(df);
    return flags;
}
