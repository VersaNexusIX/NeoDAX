#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"
#include "dax_guard.h"
#include "x86.h"
#include "arm64.h"
#include "riscv.h"

extern dax_igrp_t dax_classify_x86(const char *m);
extern dax_igrp_t dax_classify_arm64(const char *m);
extern dax_igrp_t dax_classify_riscv(const char *m);

static dax_igrp_t classify_any(dax_binary_t *bin, const char *m) {
    if (bin->arch == ARCH_X86_64)  return dax_classify_x86(m);
    if (bin->arch == ARCH_RISCV64) return dax_classify_riscv(m);
    return dax_classify_arm64(m);
}

static int decode_insn(dax_binary_t *bin, const uint8_t *code, size_t avail,
                       uint64_t addr, char *mnem, char *ops) {
    mnem[0] = ops[0] = '\0';
    if (bin->arch == ARCH_X86_64) {
        x86_insn_t insn;
        int len = x86_decode(code, avail, addr, &insn);
        if (len <= 0) return -1;
        snprintf(mnem, 32,  "%s", insn.mnemonic);
        snprintf(ops,  256, "%s", insn.ops);
        return len;
    }
    if (bin->arch == ARCH_RISCV64) {
        rv_insn_t insn;
        int len = rv_decode(code, avail, addr, &insn);
        if (len <= 0) return -1;
        snprintf(mnem, 32,  "%s", insn.mnemonic);
        snprintf(ops,  256, "%s", insn.operands);
        return len;
    }
    if (avail < 4) return -1;
    {
        uint32_t raw = (uint32_t)code[0]|(code[1]<<8)|(code[2]<<16)|(code[3]<<24);
        a64_insn_t insn;
        a64_decode(raw, addr, &insn);
        snprintf(mnem, 32,  "%s", insn.mnemonic);
        snprintf(ops,  256, "%s", insn.operands);
        return 4;
    }
}

/* ── Poly-region helpers ──────────────────────────────────────────────────────
 * Returns 1 if addr falls inside any known poly/SMC region.
 * Used to skip garbled bytes gracefully instead of walking them one-by-one.
 * ─────────────────────────────────────────────────────────────────────────── */
static int addr_in_poly_region(dax_binary_t *bin, uint64_t addr) {
    int i;
    for (i = 0; i < bin->npoly_regions; i++) {
        if (addr >= bin->poly_regions[i].start &&
            addr <  bin->poly_regions[i].end)
            return 1;
    }
    return 0;
}

/* Returns the end address of the poly region containing addr, or 0. */
static uint64_t poly_region_end(dax_binary_t *bin, uint64_t addr) {
    int i;
    for (i = 0; i < bin->npoly_regions; i++) {
        if (addr >= bin->poly_regions[i].start &&
            addr <  bin->poly_regions[i].end)
            return bin->poly_regions[i].end;
    }
    return 0;
}

/* Returns 1 if addr was patched by SMC (treat as opaque / skip). */
static int addr_is_smc_patch(dax_binary_t *bin, uint64_t addr) {
    int i;
    for (i = 0; i < bin->nsmc_patches; i++) {
        if (bin->smc_target_addr[i] == addr)
            return 1;
    }
    return 0;
}

static int find_block_by_addr(dax_binary_t *bin, uint64_t addr) {
    int i;
    if (!bin || !bin->blocks || bin->nblocks <= 0) return -1;
    for (i = 0; i < bin->nblocks; i++)
        if (bin->blocks[i].start == addr) return i;
    return -1;
}

static int find_or_add_block(dax_binary_t *bin, uint64_t addr, int func_idx) {
    int idx;
    if (!bin || !bin->blocks) return -1;
    idx = find_block_by_addr(bin, addr);
    if (idx >= 0) return idx;
    if (bin->nblocks >= DAX_MAX_BLOCKS) return -1;
    idx = bin->nblocks++;
    memset(&bin->blocks[idx], 0, sizeof(dax_block_t));
    bin->blocks[idx].start    = addr;
    bin->blocks[idx].end      = addr;
    bin->blocks[idx].func_idx = func_idx;
    bin->blocks[idx].id       = idx;
    return idx;
}

/* ── Edge helpers — expanded successor cap ──────────────────────────────────
 * Original cap was 4. Poly dispatch tables can have many more successors.
 * dax.h defines DAX_MAX_SUCC — if it doesn't exist we use 16.
 * ─────────────────────────────────────────────────────────────────────────── */
#ifndef DAX_MAX_SUCC
#define DAX_MAX_SUCC 16
#endif

static void block_add_succ(dax_block_t *b, int succ_id, dax_edge_type_t etype) {
    int i;
    if (b->nsucc >= DAX_MAX_SUCC) return;
    for (i = 0; i < b->nsucc; i++)
        if (b->succ[i] == succ_id) return;
    b->succ[b->nsucc]      = succ_id;
    b->edge_type[b->nsucc] = etype;
    b->nsucc++;
}

#ifndef DAX_MAX_PRED
#define DAX_MAX_PRED 16
#endif

static void block_add_pred(dax_block_t *b, int pred_id) {
    int i;
    if (b->npred >= DAX_MAX_PRED) return;
    for (i = 0; i < b->npred; i++)
        if (b->pred[i] == pred_id) return;
    b->pred[b->npred++] = pred_id;
}

/* ── get_or_make_indirect_block ─────────────────────────────────────────────
 * Deduplicated sentinel block for unresolved indirect targets.
 * Old code called find_or_add_block with the 0xFF sentinel, creating
 * duplicates because find_block_by_addr matched only on exact start.
 * Now we cache the index after first creation.
 * ─────────────────────────────────────────────────────────────────────────── */
static int get_or_make_indirect_block(dax_binary_t *bin, int func_idx) {
    const uint64_t SENTINEL = (uint64_t)0xFFFFFFFFFFFFFFFFULL;
    int idx;
    if (!bin || !bin->blocks) return -1;
    idx = find_block_by_addr(bin, SENTINEL);
    if (idx >= 0) return idx;
    if (bin->nblocks >= DAX_MAX_BLOCKS) return -1;
    idx = bin->nblocks++;
    memset(&bin->blocks[idx], 0, sizeof(dax_block_t));
    bin->blocks[idx].start    = SENTINEL;
    bin->blocks[idx].end      = SENTINEL;
    bin->blocks[idx].func_idx = func_idx;
    bin->blocks[idx].id       = idx;
    bin->blocks[idx].is_exit  = 1;
    return idx;
}

/* ── Poly-aware "find next known block" ─────────────────────────────────────
 * After an unconditional branch, we need to resume at the next registered
 * block boundary. Old code walked byte-by-byte (x86) or 2-by-2 (ARM64),
 * which inside a poly region could walk hundreds of garbled bytes and
 * overshoot the actual next block. This version:
 *   1. Checks if we're inside a poly region → jumps to poly_end directly.
 *   2. Otherwise, walks forward but only up to a reasonable stride limit
 *      (max_insn_sz) before giving up to avoid infinite micro-stepping.
 * Returns the block index found, or -1. Updates *off_inout.
 * ─────────────────────────────────────────────────────────────────────────── */
static int seek_next_known_block(dax_binary_t *bin, uint8_t *code,
                                 size_t code_sz, uint64_t base,
                                 size_t *off_inout, int func_idx) {
    size_t off = *off_inout;
    const size_t stride = (bin->arch == ARCH_X86_64) ? 1 :
                          (bin->arch == ARCH_RISCV64) ? 2 : 4;

    while (off < code_sz) {
        uint64_t cur_addr = base + off;

        /* Inside a poly region — jump straight to its end */
        if (addr_in_poly_region(bin, cur_addr)) {
            uint64_t pend = poly_region_end(bin, cur_addr);
            if (pend > cur_addr && pend > base)
                off = (size_t)(pend - base);
            else
                off += stride;
            /* After skipping, mark poly region end as a block boundary so
             * fall-through from before the region reaches here. */
            find_or_add_block(bin, base + off, func_idx);
            continue;
        }

        /* Check if a known block starts exactly here */
        int bi = find_block_by_addr(bin, cur_addr);
        if (bi >= 0) {
            *off_inout = off;
            return bi;
        }

        off += stride;
    }
    *off_inout = off;
    return -1;
}

int dax_cfg_build(dax_binary_t *bin, uint8_t *code, size_t sz,
                  uint64_t base, int func_idx) {
    size_t   off   = 0;
    int      cur   = -1;
    int      first = 1;

    DAX_GUARD_BIN_RET(bin, -1);
    if (!code || sz == 0) return -1;
    if (func_idx < 0 || func_idx >= bin->nfunctions) return -1;

    if (!bin->blocks) {
        bin->blocks = (dax_block_t *)calloc(DAX_MAX_BLOCKS, sizeof(dax_block_t));
        if (!bin->blocks) return -1;
    }

    if (func_idx >= 0 && func_idx < bin->nfunctions && func_idx < DAX_MAX_FUNCTIONS) {
        uint64_t fstart = bin->functions[func_idx].start;
        uint64_t fend   = bin->functions[func_idx].end;

        /* ── Derive end from nearest next function/symbol when end==0 ────────
         * analysis.c sets end=0 for functions found via call-target heuristic
         * or symbol scan without a paired ret. Find the closest start address
         * that is strictly greater than fstart to bound this function.
         * ─────────────────────────────────────────────────────────────────── */
        if (fend == 0 || fend <= fstart) {
            uint64_t nearest = base + sz;   /* default: end of section */
            int j;
            /* Check other functions */
            for (j = 0; j < bin->nfunctions && j < DAX_MAX_FUNCTIONS && j < DAX_MAX_FUNCTIONS; j++) {
                if (j == func_idx) continue;
                uint64_t s = bin->functions[j].start;
                if (s > fstart && s < nearest)
                    nearest = s;
            }
            /* Check symbols too — they often mark function boundaries */
            for (j = 0; j < bin->nsymbols && j < DAX_MAX_SYMBOLS; j++) {
                uint64_t s = bin->symbols[j].address;
                if (s > fstart && s < nearest)
                    nearest = s;
            }
            fend = nearest;
            /* Persist so dax_cfg_print and future callers see the right end */
            bin->functions[func_idx].end = fend;
        }

        if (fstart >= base && fstart < base + sz) {
            off = (size_t)(fstart - base);
            sz  = (fend > fstart && fend <= base + sz)
                  ? (size_t)(fend - base) : sz;
        }
    }

    cur = find_or_add_block(bin, base + off, func_idx);
    if (cur < 0) return 0;
    bin->blocks[cur].is_entry = first;
    first = 0;

    /* ── PASS 1: Pre-register all branch targets as block boundaries ────────
     * Also pre-registers poly region boundaries so the main pass never gets
     * lost inside garbled bytes.
     * ─────────────────────────────────────────────────────────────────────── */
    {
        size_t pre_off = (func_idx >= 0 && func_idx < bin->nfunctions && func_idx < DAX_MAX_FUNCTIONS)
                         ? (size_t)(bin->functions[func_idx].start - base)
                         : 0;
        size_t pre_end = sz;

        /* Register poly region boundaries as block starts */
        {
            int pi;
            for (pi = 0; pi < bin->npoly_regions; pi++) {
                uint64_t ps = bin->poly_regions[pi].start;
                uint64_t pe = bin->poly_regions[pi].end;
                if (ps >= base && ps < base + sz)
                    find_or_add_block(bin, ps, func_idx);
                if (pe >= base && pe < base + sz)
                    find_or_add_block(bin, pe, func_idx);
            }
        }

        while (pre_off < pre_end) {
            uint64_t pre_addr = base + pre_off;

            /* Skip poly region bytes entirely during pre-pass */
            if (addr_in_poly_region(bin, pre_addr)) {
                uint64_t pend = poly_region_end(bin, pre_addr);
                if (pend > pre_addr && pend > base)
                    pre_off = (size_t)(pend - base);
                else
                    pre_off++;
                continue;
            }

            /* Skip SMC-patched addresses */
            if (addr_is_smc_patch(bin, pre_addr)) {
                pre_off += (bin->arch == ARCH_X86_64) ? 1 : 4;
                continue;
            }

            char     pre_mnem[32] = "";
            char     pre_ops[256] = "";
            int      pre_len = 0;
            uint64_t pre_tgt = 0;

            pre_len = decode_insn(bin, code + pre_off, pre_end - pre_off,
                                  pre_addr, pre_mnem, pre_ops);
            if (pre_len <= 0) {
                pre_off += (bin->arch == ARCH_X86_64) ? 1 : 4;
                continue;
            }

            {
                dax_igrp_t grp2 = classify_any(bin, pre_mnem);
                if (grp2 == IGRP_BRANCH || grp2 == IGRP_CALL) {
                    if (pre_ops[0] == '0')
                        sscanf(pre_ops, "0x%llx", (unsigned long long *)&pre_tgt);

                    if (pre_tgt && pre_tgt >= base && pre_tgt < base + pre_end)
                        find_or_add_block(bin, pre_tgt, func_idx);

                    /* Fall-through block after conditional branch */
                    {
                        int is_uncond =
                            (grp2 == IGRP_BRANCH) &&
                            (strcmp(pre_mnem,"b")==0   || strcmp(pre_mnem,"jmp")==0 ||
                             strcmp(pre_mnem,"br")==0  || strncmp(pre_mnem,"jmp",3)==0 ||
                             strcmp(pre_mnem,"j")==0);
                        if (!is_uncond && pre_off + (size_t)pre_len < pre_end)
                            find_or_add_block(bin,
                                base + pre_off + (size_t)pre_len, func_idx);
                    }
                }
            }
            pre_off += (size_t)pre_len;
        }
    }

    /* Pre-register symbol addresses inside this function as block starts */
    {
        int si2;
        uint64_t fn_s = (func_idx >= 0 && func_idx < bin->nfunctions && func_idx < DAX_MAX_FUNCTIONS)
                        ? bin->functions[func_idx].start : base;
        uint64_t fn_e = (func_idx >= 0 && func_idx < bin->nfunctions &&
                         bin->functions[func_idx].end > fn_s)
                        ? bin->functions[func_idx].end : base + sz;
        for (si2 = 0; si2 < bin->nsymbols && si2 < DAX_MAX_SYMBOLS; si2++) {
            uint64_t sa = bin->symbols[si2].address;
            if (sa > fn_s && sa < fn_e)
                find_or_add_block(bin, sa, func_idx);
        }
    }

    /* ── PASS 2: Main CFG walk ───────────────────────────────────────────────
     * Poly-aware: when we hit poly region bytes, emit a poly-stub block and
     * jump to the region's end rather than trying to decode garbage.
     * SMC-aware: patched bytes are treated as opaque stubs.
     * ─────────────────────────────────────────────────────────────────────── */
    while (off < sz) {
        uint64_t cur_addr = base + off;
        int      len      = 0;
        char     mnem[32] = "";
        char     ops[256] = "";
        uint64_t branch_target = 0;
        int      is_branch = 0, is_cond = 0, is_ret = 0, is_call = 0;
        int      is_indirect = 0;

        /* ── Poly region: emit stub block, wire fall-through, skip ── */
        if (addr_in_poly_region(bin, cur_addr)) {
            uint64_t pend = poly_region_end(bin, cur_addr);

            /* Ensure we have a block for this region start */
            int poly_blk = find_or_add_block(bin, cur_addr, func_idx);

            if (poly_blk >= 0) {
                bin->blocks[poly_blk].is_poly = 1;   /* mark as poly stub */
                bin->blocks[poly_blk].end =
                    (pend > cur_addr) ? pend : cur_addr + 4;

                /* Wire edge from previous block into this poly block */
                if (cur >= 0 && cur != poly_blk) {
                    block_add_succ(&bin->blocks[cur], poly_blk, EDGE_FALL);
                    block_add_pred(&bin->blocks[poly_blk], cur);
                }
                cur = poly_blk;

                /* Wire fall-through from poly block to code after region */
                if (pend > base && pend < base + sz) {
                    int after_blk = find_or_add_block(bin, pend, func_idx);
                    if (after_blk >= 0) {
                        block_add_succ(&bin->blocks[cur], after_blk, EDGE_FALL);
                        block_add_pred(&bin->blocks[after_blk], cur);
                        cur = after_blk;
                    }
                } else {
                    bin->blocks[cur].is_exit = 1;
                    cur = -1;
                }
            }

            off = (pend > base) ? (size_t)(pend - base) : off + 4;
            continue;
        }

        /* ── SMC-patched byte: treat as opaque stub ── */
        if (addr_is_smc_patch(bin, cur_addr)) {
            int smc_blk = find_or_add_block(bin, cur_addr, func_idx);
            if (smc_blk >= 0) {
                bin->blocks[smc_blk].is_smc = 1;
                if (cur >= 0 && cur != smc_blk) {
                    block_add_succ(&bin->blocks[cur], smc_blk, EDGE_FALL);
                    block_add_pred(&bin->blocks[smc_blk], cur);
                }
                cur = smc_blk;
            }
            off += (bin->arch == ARCH_X86_64) ? 1 : 4;
            continue;
        }

        len = decode_insn(bin, code + off, sz - off, cur_addr, mnem, ops);
        if (len <= 0) {
            /* Decode failed on non-poly, non-smc byte.
             * If a known block starts at a later address, seek to it. */
            int nb = seek_next_known_block(bin, code, sz, base, &off, func_idx);
            if (nb >= 0) {
                if (cur >= 0 && cur != nb) {
                    block_add_succ(&bin->blocks[cur], nb, EDGE_FALL);
                    block_add_pred(&bin->blocks[nb], cur);
                }
                cur = nb;
            } else {
                off++;
            }
            continue;
        }

        if (cur >= 0) bin->blocks[cur].end = cur_addr + (uint64_t)len;

        {
            dax_igrp_t grp = classify_any(bin, mnem);

            if (grp == IGRP_RET) {
                is_ret = 1;
            } else if (grp == IGRP_BRANCH) {
                is_branch = 1;
                if (ops[0] == '0')
                    sscanf(ops, "0x%llx", (unsigned long long *)&branch_target);
                if ((strcmp(mnem,"br")==0 || strcmp(mnem,"jalr")==0) &&
                    ops[0] != '0' && ops[0] != '\0')
                    is_indirect = 1;
                if (strncmp(mnem,"jmp",3) && strcmp(mnem,"b")  &&
                    strcmp(mnem,"br")     && strcmp(mnem,"j")   &&
                    strcmp(mnem,"jalr"))
                    is_cond = 1;
            } else if (grp == IGRP_CALL) {
                is_call = 1;
                if (ops[0] == '0')
                    sscanf(ops, "0x%llx", (unsigned long long *)&branch_target);
                if ((strcmp(mnem,"blr")==0 || strcmp(mnem,"jalr")==0) &&
                    ops[0] != '0' && ops[0] != '\0')
                    is_indirect = 1;
            }
        }

        off += (size_t)len;

        if (is_ret) {
            if (cur >= 0) bin->blocks[cur].is_exit = 1;
            /* Try to find next registered block after ret */
            if (off < sz) {
                int nb = find_block_by_addr(bin, base + off);
                if (nb < 0) nb = seek_next_known_block(bin, code, sz, base,
                                                        &off, func_idx);
                cur = nb;
            } else {
                cur = -1;
            }
            continue;
        }

        if (is_call && branch_target && !is_indirect) {
            int tgt_idx = find_block_by_addr(bin, branch_target);
            if (tgt_idx >= 0 && cur >= 0) {
                block_add_succ(&bin->blocks[cur], tgt_idx, EDGE_CALL);
                block_add_pred(&bin->blocks[tgt_idx], cur);
            }
        }

        if (is_indirect) {
            if (cur >= 0) {
                int resolved = 0;
                int ri;
                for (ri = 0; ri < bin->nresolved_indirect; ri++) {
                    if (bin->resolved_indirect_from[ri] == cur_addr) {
                        uint64_t tgt_r = bin->resolved_indirect_to[ri];
                        if (tgt_r >= base && tgt_r < base + sz) {
                            int tgt_idx_r = find_or_add_block(bin, tgt_r, func_idx);
                            if (tgt_idx_r >= 0) {
                                block_add_succ(&bin->blocks[cur], tgt_idx_r, EDGE_JUMP);
                                block_add_pred(&bin->blocks[tgt_idx_r], cur);
                                resolved = 1;
                            }
                        }
                    }
                }
                if (!resolved) {
                    int ind_idx = get_or_make_indirect_block(bin, func_idx);
                    if (ind_idx >= 0) {
                        block_add_succ(&bin->blocks[cur], ind_idx, EDGE_JUMP);
                        block_add_pred(&bin->blocks[ind_idx], cur);
                    }
                }
                bin->blocks[cur].is_exit = !resolved;
            }
            cur = -1;
            {
                int nb = seek_next_known_block(bin, code, sz, base, &off, func_idx);
                if (nb >= 0) cur = nb;
            }
            continue;
        }

        if (is_branch && branch_target) {
            int tgt_idx = find_or_add_block(bin, branch_target, func_idx);
            if (tgt_idx >= 0 && cur >= 0) {
                block_add_succ(&bin->blocks[cur], tgt_idx,
                               is_cond ? EDGE_COND_TRUE : EDGE_JUMP);
                block_add_pred(&bin->blocks[tgt_idx], cur);
            }
            if (is_cond && off < sz) {
                int fall_idx = find_or_add_block(bin, base + off, func_idx);
                if (fall_idx >= 0 && cur >= 0) {
                    block_add_succ(&bin->blocks[cur], fall_idx, EDGE_COND_FALSE);
                    block_add_pred(&bin->blocks[fall_idx], cur);
                }
                cur = fall_idx;
            } else if (!is_cond) {
                if (cur >= 0) bin->blocks[cur].is_exit = 1;
                cur = -1;
                {
                    int nb = seek_next_known_block(bin, code, sz, base, &off, func_idx);
                    if (nb >= 0) cur = nb;
                }
            }
        } else if (off < sz) {
            int next_idx = find_block_by_addr(bin, base + off);
            if (next_idx >= 0 && next_idx != cur) {
                if (cur >= 0) {
                    block_add_succ(&bin->blocks[cur], next_idx, EDGE_FALL);
                    block_add_pred(&bin->blocks[next_idx], cur);
                }
                cur = next_idx;
            }
        }
    }

    return bin->nblocks;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * CFG PRINT — tree renderer
 * ─────────────────────────────────────────────────────────────────────────── */

#define TREE_MAX_DEPTH  64
#define TREE_MAX_NODES  512

typedef struct {
    int visited[TREE_MAX_NODES];
    int nvisited;
} tree_ctx_t;

static int count_insns_in_block(dax_binary_t *bin, dax_block_t *blk) {
    int s;
    if (bin->arch == ARCH_ARM64)
        return (int)((blk->end - blk->start) / 4);

    for (s = 0; s < bin->nsections && s < DAX_MAX_SECTIONS; s++) {
        dax_section_t *sec = &bin->sections[s];
        if (blk->start >= sec->vaddr && blk->start < sec->vaddr + sec->size &&
            sec->offset + sec->size <= bin->size) {
            uint8_t *code = bin->data + sec->offset + (blk->start - sec->vaddr);
            size_t   csz  = (size_t)(blk->end - blk->start);
            size_t   off  = 0;
            int      n    = 0;
            if (bin->arch == ARCH_RISCV64) {
                while (off < csz) {
                    rv_insn_t insn;
                    int l = rv_decode(code + off, csz - off, blk->start + off, &insn);
                    if (l <= 0) break;
                    n++;
                    off += (size_t)l;
                }
                return n;
            }
            while (off < csz) {
                x86_insn_t insn;
                int l = x86_decode(code + off, csz - off, blk->start + off, &insn);
                if (l <= 0) break;
                n++;
                off += (size_t)l;
            }
            return n;
        }
    }
    return (int)((blk->end - blk->start) / 4);
}

static const char *edge_label(dax_edge_type_t et) {
    switch (et) {
        case EDGE_COND_TRUE:  return "T";
        case EDGE_COND_FALSE: return "F";
        case EDGE_CALL:       return "C";
        case EDGE_JUMP:       return "J";
        case EDGE_FALL:       return "→";
        default:              return " ";
    }
}

static const char *edge_col(dax_edge_type_t et, int c) {
    if (!c) return "";
    switch (et) {
        case EDGE_COND_TRUE:  return COL_CFG_TRUE;
        case EDGE_COND_FALSE: return COL_CFG_FALSE;
        case EDGE_CALL:       return COL_CFG_CALL;
        default:              return COL_CFG_FALL;
    }
}

static void cfg_tree_node(dax_binary_t *bin, int blk_idx,
                          int depth, char *prefix, int is_last,
                          dax_edge_type_t parent_edge,
                          tree_ctx_t *ctx, dax_opts_t *opts, FILE *out) {
    dax_block_t *blk;
    int          c = opts->color;
    int          i, j;
    int          n_insns;
    int          already_visited = 0;
    char         new_prefix[256];
    char         detail[160];
    const char  *sym_name = NULL;
    const char  *blk_col;
    const char  *ec;

    if (blk_idx < 0 || blk_idx >= bin->nblocks) return;
    if (depth >= TREE_MAX_DEPTH) return;

    blk = &bin->blocks[blk_idx];

    for (j = 0; j < ctx->nvisited; j++) {
        if (ctx->visited[j] == blk_idx) { already_visited = 1; break; }
    }

    if (ctx->nvisited < TREE_MAX_NODES)
        ctx->visited[ctx->nvisited++] = blk_idx;

    n_insns  = count_insns_in_block(bin, blk);
    sym_name = dax_sym_name(bin, blk->start);

    blk_col = c ? (blk->is_entry ? COL_ENTRY :
                   blk->is_exit  ? COL_GRP_RET :
                   blk->is_poly  ? COL_GRP_BRNCH :
                   blk->is_smc   ? COL_GRP_BRNCH : COL_ADDR) : "";
    ec      = edge_col(parent_edge, c);

    fprintf(out, "%s", prefix);

    if (depth == 0) {
        if (c) fprintf(out, "%s", COL_FUNC);
        fprintf(out, "%s", is_last ? "└── " : "├── ");
    } else {
        if (c) fprintf(out, "%s", ec);
        if (is_last)
            fprintf(out, "└─[%s]─ ", edge_label(parent_edge));
        else
            fprintf(out, "├─[%s]─ ", edge_label(parent_edge));
    }

    if (c) fprintf(out, "%s", blk_col);
    if (blk->start == (uint64_t)0xFFFFFFFFFFFFFFFFULL)
        fprintf(out, "[INDIRECT ?]");
    else if (blk->is_poly)
        fprintf(out, "block_%d [POLY]", blk_idx);
    else if (blk->is_smc)
        fprintf(out, "block_%d [SMC]", blk_idx);
    else
        fprintf(out, "block_%d", blk_idx);
    if (c) fprintf(out, "%s", COL_RESET);

    {
        int dot_count;
        int used = (blk->start == (uint64_t)0xFFFFFFFFFFFFFFFFULL) ? 12
                 : blk->is_poly ? (8 + 7 + (blk_idx > 99 ? 3 : blk_idx > 9 ? 2 : 1))
                 : blk->is_smc  ? (8 + 6 + (blk_idx > 99 ? 3 : blk_idx > 9 ? 2 : 1))
                 : (7 + (blk_idx > 99 ? 3 : blk_idx > 9 ? 2 : 1));
        dot_count = 32 - depth * 4 - used;
        if (dot_count < 2) dot_count = 2;
        if (c) fprintf(out, "%s", COL_COMMENT);
        for (i = 0; i < dot_count; i++) fprintf(out, "─");
        fprintf(out, "< ");
        if (c) fprintf(out, "%s", COL_RESET);
    }

    if (blk->start == (uint64_t)0xFFFFFFFFFFFFFFFFULL) {
        if (c) fprintf(out, "%s", COL_GRP_BRNCH);
        fprintf(out, "indirect — target unknown at static analysis time");
        if (c) fprintf(out, "%s", COL_RESET);
        fprintf(out, "\n");
        return;
    }

    if (c) fprintf(out, "%s", COL_ADDR);
    fprintf(out, "0x%llx", (unsigned long long)blk->start);
    if (c) fprintf(out, "%s", COL_RESET);

    if (already_visited && depth > 0) {
        if (c) fprintf(out, "%s", COL_XREF);
        fprintf(out, "  ↩ (back edge)");
        if (c) fprintf(out, "%s", COL_RESET);
        fprintf(out, "\n");
        return;
    }

    {
        char flags[32] = "";
        if (blk->is_entry) strcat(flags, " ENTRY");
        if (blk->is_exit)  strcat(flags, " EXIT");
        if (blk->is_poly)  strcat(flags, " obfuscated");
        if (blk->is_smc)   strcat(flags, " smc-patched");

        if (blk->is_poly || blk->is_smc) {
            snprintf(detail, sizeof(detail), "  %llu bytes%s",
                     (unsigned long long)(blk->end - blk->start), flags);
        } else if (n_insns > 0 && blk->end > blk->start) {
            snprintf(detail, sizeof(detail), "  %d insns  %llu bytes%s",
                     n_insns,
                     (unsigned long long)(blk->end - blk->start),
                     flags);
        } else {
            snprintf(detail, sizeof(detail), "  (empty)%s", flags);
        }

        if (c) fprintf(out, "%s", COL_COMMENT);
        fprintf(out, "%s", detail);
        if (c) fprintf(out, "%s", COL_RESET);
    }

    if (sym_name) {
        if (c) fprintf(out, "  %s", COL_SYM);
        else   fprintf(out, "  ");
        fprintf(out, "<%s>", sym_name);
        if (c) fprintf(out, "%s", COL_RESET);
    }

    fprintf(out, "\n");

    if (already_visited) return;

    snprintf(new_prefix, sizeof(new_prefix), "%s%s",
             prefix, is_last ? "    " : "│   ");

    for (j = 0; j < blk->nsucc; j++) {
        int last_child = (j == blk->nsucc - 1);
        cfg_tree_node(bin, blk->succ[j], depth + 1,
                      new_prefix, last_child, blk->edge_type[j],
                      ctx, opts, out);
    }

    if (blk->nsucc == 0 && !blk->is_exit && blk->end > 0) {
        fprintf(out, "%s%s", new_prefix, "│\n");
    }
}

int dax_cfg_print(dax_binary_t *bin, int func_idx, dax_opts_t *opts, FILE *out) {
    int          i;
    int          c         = opts ? opts->color : 1;
    int          nblocks   = 0;
    int          poly_blks = 0;
    int          smc_blks  = 0;
    int          entry_idx = -1;
    tree_ctx_t   ctx;
    const char  *fname;

    DAX_GUARD_BIN_RET(bin, -1);
    if (!out) return -1;
    if (!dax_func_idx_ok(bin, func_idx)) return -1;
    if (!bin->blocks) return 0;

    for (i = 0; i < bin->nblocks; i++) {
        if (bin->blocks[i].func_idx == func_idx) {
            nblocks++;
            if (bin->blocks[i].is_entry) entry_idx = i;
            if (bin->blocks[i].is_poly)  poly_blks++;
            if (bin->blocks[i].is_smc)   smc_blks++;
        }
    }

    if (nblocks == 0) return 0;

    fname = (func_idx >= 0 && func_idx < bin->nfunctions && func_idx < DAX_MAX_FUNCTIONS)
             ? bin->functions[func_idx].name : "unknown";

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  CFG  ");
    if (c) fprintf(out, "%s", COL_SYM);
    fprintf(out, "%s", fname);
    if (c) fprintf(out, "%s", COL_COMMENT);
    fprintf(out, "  (%d blocks", nblocks);
    if (poly_blks) fprintf(out, ", %d poly", poly_blks);
    if (smc_blks)  fprintf(out, ", %d smc",  smc_blks);
    fprintf(out, ")");
    if (c) fprintf(out, "%s", COL_RESET);
    fprintf(out, "\n");

    if (c) fprintf(out, "%s", COL_COMMENT);
    fprintf(out, "  │\n");
    if (c) fprintf(out, "%s", COL_RESET);

    memset(&ctx, 0, sizeof(ctx));

    if (entry_idx >= 0) {
        cfg_tree_node(bin, entry_idx, 0, "  ", 1,
                      EDGE_FALL, &ctx, opts, out);
    } else {
        for (i = 0; i < bin->nblocks; i++) {
            if (bin->blocks[i].func_idx == func_idx) {
                cfg_tree_node(bin, i, 0, "  ", 1,
                              EDGE_FALL, &ctx, opts, out);
                break;
            }
        }
    }

    fprintf(out, "\n");
    return nblocks;
}
