#ifndef DAX_GUARD_H
#define DAX_GUARD_H

/*
 * dax_guard.h — NeoDAX Microkernel Fault Isolation Layer
 *
 * Philosophy
 * ──────────
 * Each analysis pass in NeoDAX is an independent "service". Like a
 * microkernel, a failing service is fenced off: it emits a diagnostic,
 * marks itself as faulted, and the kernel (main.c) continues to the
 * next service. No single bad binary or corrupted state can crash the
 * entire program.
 *
 * Three layers of protection
 * ──────────────────────────
 *  1. Input validation macros  — check pointers, sizes, and counts
 *     before any module does real work.
 *  2. Safe accessors           — bounds-checked array reads that
 *     return a sentinel instead of segfaulting.
 *  3. Pass wrappers            — DAX_RUN_PASS() wraps every top-level
 *     call in main.c; on return it checks a global fault register and
 *     prints a recovery notice if the pass set it.
 *
 * Usage in main.c
 * ───────────────
 *   DAX_RUN_PASS("disasm", dax_disasm_arm64(&bin, &opts, stdout));
 *   DAX_RUN_PASS("CFG",    { for (fi=0;fi<bin.nfunctions;fi++)
 *                                dax_cfg_print(&bin,fi,&opts,stdout); });
 *
 * Usage inside a module (e.g. cfg.c, emulate.c)
 * ───────────────────────────────────────────────
 *   DAX_GUARD_BIN(bin);          // returns void on bad bin
 *   DAX_GUARD_BIN_INT(bin, -1);  // returns -1 on bad bin
 *   DAX_GUARD_FUNC(bin, fi);     // bounds-checks func index
 *   DAX_GUARD_SEC(bin, si);      // bounds-checks section index
 *
 *   uint8_t *p = DAX_SEC_PTR(bin, si);   // NULL if out-of-bounds
 *   dax_func_t *fn = DAX_FUNC(bin, fi);  // NULL if out-of-bounds
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dax.h"

/* ── Global fault register ───────────────────────────────────────────────── */
/*
 * Set by any module that encounters a fatal-but-recoverable error.
 * Cleared at the start of each DAX_RUN_PASS.
 * Checked by DAX_RUN_PASS after the call returns.
 */
extern volatile int g_dax_fault;
extern char         g_dax_fault_msg[256];

static inline void dax_fault_set(const char *msg) {
    g_dax_fault = 1;
    if (msg && g_dax_fault_msg[0] == '\0')
        snprintf(g_dax_fault_msg, sizeof(g_dax_fault_msg), "%s", msg);
}

/* ── Color helpers (inline, no external dep) ─────────────────────────────── */
#define DG_COL_WARN  "\033[1;33m"
#define DG_COL_ERR   "\033[1;31m"
#define DG_COL_OK    "\033[1;32m"
#define DG_COL_DIM   "\033[0;90m"
#define DG_COL_RST   "\033[0m"

/* ── Pass-level wrapper ──────────────────────────────────────────────────── */
/*
 * DAX_RUN_PASS(name, color_enabled, stmt)
 *
 * Clears the fault register, runs stmt, then checks if it faulted.
 * On fault: prints a yellow recovery notice and resets for the next pass.
 * All passes in main.c should use this.
 */
#define DAX_RUN_PASS(name, color, stmt)                                      \
    do {                                                                      \
        g_dax_fault = 0;                                                      \
        g_dax_fault_msg[0] = '\0';                                            \
        { stmt; }                                                             \
        if (g_dax_fault) {                                                    \
            if (color)                                                        \
                fprintf(stderr,                                               \
                    "\n  " DG_COL_WARN "[!] pass '%s' recovered from fault" DG_COL_RST \
                    DG_COL_DIM " — %s" DG_COL_RST "\n",                      \
                    (name), g_dax_fault_msg[0] ? g_dax_fault_msg : "see above"); \
            else                                                              \
                fprintf(stderr,                                               \
                    "\n  [!] pass '%s' recovered from fault — %s\n",          \
                    (name), g_dax_fault_msg[0] ? g_dax_fault_msg : "see above"); \
            g_dax_fault = 0;                                                  \
            g_dax_fault_msg[0] = '\0';                                        \
        }                                                                     \
    } while (0)

/* ── Binary validation ───────────────────────────────────────────────────── */

/*
 * DAX_BIN_OK — returns 1 if bin has the minimum valid state to proceed,
 * 0 otherwise. Does NOT set the fault register; call dax_fault_set()
 * before returning from the module if you want a diagnostic.
 */
static inline int dax_bin_ok(const dax_binary_t *bin) {
    if (!bin)                     return 0;
    if (!bin->data)               return 0;
    if (bin->size == 0)           return 0;
    if (bin->nsections < 0 || bin->nsections > DAX_MAX_SECTIONS)  return 0;
    if (bin->nfunctions < 0 || bin->nfunctions > DAX_MAX_FUNCTIONS) return 0;
    if (bin->nsymbols   < 0 || bin->nsymbols   > DAX_MAX_SYMBOLS)   return 0;
    return 1;
}

/*
 * DAX_GUARD_BIN — validates bin and returns (void) if invalid.
 * Use at the top of every analysis function that takes dax_binary_t*.
 */
#define DAX_GUARD_BIN(bin)                                                   \
    do {                                                                      \
        if (!dax_bin_ok(bin)) {                                               \
            dax_fault_set("invalid dax_binary_t");                            \
            return;                                                           \
        }                                                                     \
    } while (0)

/* Variant that returns a value (for non-void functions) */
#define DAX_GUARD_BIN_RET(bin, retval)                                       \
    do {                                                                      \
        if (!dax_bin_ok(bin)) {                                               \
            dax_fault_set("invalid dax_binary_t");                            \
            return (retval);                                                  \
        }                                                                     \
    } while (0)

/* ── Function index validation ───────────────────────────────────────────── */

static inline int dax_func_idx_ok(const dax_binary_t *bin, int fi) {
    if (!bin || !bin->functions) return 0;
    if (fi < 0 || fi >= bin->nfunctions) return 0;
    if (fi >= DAX_MAX_FUNCTIONS) return 0;
    return 1;
}

#define DAX_GUARD_FUNC(bin, fi)                                              \
    do {                                                                      \
        if (!dax_func_idx_ok((bin), (fi))) {                                  \
            dax_fault_set("func index out of bounds");                        \
            return;                                                           \
        }                                                                     \
    } while (0)

#define DAX_GUARD_FUNC_RET(bin, fi, retval)                                  \
    do {                                                                      \
        if (!dax_func_idx_ok((bin), (fi))) {                                  \
            dax_fault_set("func index out of bounds");                        \
            return (retval);                                                  \
        }                                                                     \
    } while (0)

/* ── Section index validation ────────────────────────────────────────────── */

static inline int dax_sec_idx_ok(const dax_binary_t *bin, int si) {
    if (!bin) return 0;
    if (si < 0 || si >= bin->nsections) return 0;
    if (si >= DAX_MAX_SECTIONS) return 0;
    return 1;
}

#define DAX_GUARD_SEC(bin, si)                                               \
    do {                                                                      \
        if (!dax_sec_idx_ok((bin), (si))) {                                   \
            dax_fault_set("section index out of bounds");                     \
            return;                                                           \
        }                                                                     \
    } while (0)

/* ── Safe section byte pointer ───────────────────────────────────────────── */
/*
 * DAX_SEC_PTR — returns a pointer to section si's data, or NULL if:
 *   - si is out of range
 *   - section offset+size would exceed bin->size
 *   - section size is 0
 * Never dereferences before the bounds check.
 */
static inline uint8_t *dax_sec_ptr(const dax_binary_t *bin, int si) {
    const dax_section_t *s;
    if (!bin || !bin->data) return NULL;
    if (si < 0 || si >= bin->nsections || si >= DAX_MAX_SECTIONS) return NULL;
    s = &bin->sections[si];
    if (s->size == 0) return NULL;
    if (s->offset > bin->size) return NULL;
    if (s->size > bin->size - s->offset) return NULL;   /* overflow-safe */
    return bin->data + s->offset;
}

/* ── Safe function pointer ───────────────────────────────────────────────── */
static inline dax_func_t *dax_func_ptr(const dax_binary_t *bin, int fi) {
    if (!bin || !bin->functions) return NULL;
    if (fi < 0 || fi >= bin->nfunctions || fi >= DAX_MAX_FUNCTIONS) return NULL;
    return &bin->functions[fi];
}

/* ── Safe symbol pointer ─────────────────────────────────────────────────── */
static inline dax_symbol_t *dax_sym_ptr(const dax_binary_t *bin, int si) {
    if (!bin || !bin->symbols) return NULL;
    if (si < 0 || si >= bin->nsymbols || si >= DAX_MAX_SYMBOLS) return NULL;
    return &bin->symbols[si];
}

/* ── Safe block pointer ──────────────────────────────────────────────────── */
static inline dax_block_t *dax_block_ptr(const dax_binary_t *bin, int bi) {
    if (!bin || !bin->blocks) return NULL;
    if (bi < 0 || bi >= bin->nblocks || bi >= DAX_MAX_BLOCKS) return NULL;
    return &bin->blocks[bi];
}

/* ── Clamp helpers ───────────────────────────────────────────────────────── */
#define DAX_CLAMP(v, lo, hi)  ((v) < (lo) ? (lo) : (v) > (hi) ? (hi) : (v))

/* Clamp all dax_binary_t counters to their defined maximums.
 * Call this after any code that might corrupt them. */
static inline void dax_clamp_counts(dax_binary_t *bin) {
    if (!bin) return;
    bin->nsections  = DAX_CLAMP(bin->nsections,  0, DAX_MAX_SECTIONS);
    bin->nsymbols   = DAX_CLAMP(bin->nsymbols,   0, DAX_MAX_SYMBOLS);
    bin->nxrefs     = DAX_CLAMP(bin->nxrefs,     0, DAX_MAX_XREFS);
    bin->nfunctions = DAX_CLAMP(bin->nfunctions, 0, DAX_MAX_FUNCTIONS);
    bin->nblocks    = DAX_CLAMP(bin->nblocks,     0, DAX_MAX_BLOCKS);
    bin->ncomments  = DAX_CLAMP(bin->ncomments,  0, DAX_MAX_COMMENTS);
    bin->npoly_regions = DAX_CLAMP(bin->npoly_regions, 0, DAX_POLY_MAX);
    bin->naire_insights= DAX_CLAMP(bin->naire_insights,0, DAX_AIRE_MAX);
    bin->nresolved_indirect = DAX_CLAMP(bin->nresolved_indirect, 0, 128);
    bin->nsmc_patches       = DAX_CLAMP(bin->nsmc_patches,       0, 128);
    bin->nsmc_chains        = DAX_CLAMP(bin->nsmc_chains,        0, 32);
    bin->nemu_smc           = DAX_CLAMP(bin->nemu_smc,           0, 64);
}

/* ── Code-window helpers ─────────────────────────────────────────────────── */
/*
 * dax_code_window — given a function index, finds its section and
 * returns code pointer + size + base address for decode loops.
 * Returns 0 on failure (section not found or bounds invalid).
 */
static inline int dax_code_window(const dax_binary_t *bin, int fi,
                                  uint8_t **out_code, size_t *out_sz,
                                  uint64_t *out_base,
                                  size_t *out_fn_off, size_t *out_fn_end) {
    int si;
    const dax_func_t *fn;

    if (!bin || !bin->functions || !bin->data) return 0;
    if (fi < 0 || fi >= bin->nfunctions) return 0;

    fn = &bin->functions[fi];
    if (fn->start == 0 || fn->end <= fn->start) return 0;
    if (fn->end - fn->start > 0x800000ULL) return 0;   /* >8 MB = corrupt */

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        const dax_section_t *s = &bin->sections[si];
        if (s->size == 0) continue;
        if (s->offset > bin->size) continue;
        if (s->size > bin->size - s->offset) continue;
        if (fn->start < s->vaddr || fn->start >= s->vaddr + s->size) continue;

        size_t fn_off = (size_t)(fn->start - s->vaddr);
        size_t fn_end = (fn->end <= s->vaddr + s->size)
                        ? (size_t)(fn->end - s->vaddr)
                        : fn_off + 1024;
        if (fn_end > s->size) fn_end = s->size;

        if (out_code)   *out_code   = bin->data + s->offset;
        if (out_sz)     *out_sz     = s->size;
        if (out_base)   *out_base   = s->vaddr;
        if (out_fn_off) *out_fn_off = fn_off;
        if (out_fn_end) *out_fn_end = fn_end;
        return 1;
    }
    return 0;
}

/* ── Iteration budget guard ──────────────────────────────────────────────── */
/*
 * Used by decode loops to prevent infinite spin on corrupt/adversarial data.
 * Typical value: 65536 instructions per function is more than enough.
 */
#define DAX_BUDGET_INIT(n)   int _dax_budget = (n)
#define DAX_BUDGET_CHECK()   if (--_dax_budget <= 0) { dax_fault_set("decode loop budget exceeded"); break; }

/* ── NULL-safe string helpers ────────────────────────────────────────────── */
static inline const char *dax_safe_str(const char *s) {
    return (s && s[0]) ? s : "";
}

static inline const char *dax_func_name(const dax_binary_t *bin, int fi) {
    if (!dax_func_idx_ok(bin, fi)) return "?";
    const char *n = bin->functions[fi].name;
    return (n && n[0]) ? n : "unnamed";
}

/* ── Declare globals (define in main.c) ──────────────────────────────────── */
#ifndef DAX_GUARD_DEFINE_GLOBALS
extern volatile int g_dax_fault;
extern char         g_dax_fault_msg[256];
#endif

#endif /* DAX_GUARD_H */
