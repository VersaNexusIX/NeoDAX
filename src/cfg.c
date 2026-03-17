#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"

extern dax_igrp_t dax_classify_x86(const char *m);
extern dax_igrp_t dax_classify_arm64(const char *m);

static int find_block_by_addr(dax_binary_t *bin, uint64_t addr) {
    int i;
    for (i = 0; i < bin->nblocks; i++)
        if (bin->blocks[i].start == addr) return i;
    return -1;
}

static int find_or_add_block(dax_binary_t *bin, uint64_t addr, int func_idx) {
    int idx = find_block_by_addr(bin, addr);
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

static void block_add_succ(dax_block_t *b, int succ_id, dax_edge_type_t etype) {
    int i;
    if (b->nsucc >= 4) return;
    for (i = 0; i < b->nsucc; i++)
        if (b->succ[i] == succ_id) return;
    b->succ[b->nsucc]      = succ_id;
    b->edge_type[b->nsucc] = etype;
    b->nsucc++;
}

static void block_add_pred(dax_block_t *b, int pred_id) {
    int i;
    if (b->npred >= 4) return;
    for (i = 0; i < b->npred; i++)
        if (b->pred[i] == pred_id) return;
    b->pred[b->npred++] = pred_id;
}

int dax_cfg_build(dax_binary_t *bin, uint8_t *code, size_t sz,
                  uint64_t base, int func_idx) {
    size_t   off   = 0;
    int      cur   = -1;
    int      first = 1;

    if (!bin->blocks) {
        bin->blocks = (dax_block_t *)calloc(DAX_MAX_BLOCKS, sizeof(dax_block_t));
        if (!bin->blocks) return -1;
    }

    if (func_idx >= 0 && func_idx < bin->nfunctions) {
        uint64_t fstart = bin->functions[func_idx].start;
        uint64_t fend   = bin->functions[func_idx].end;
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

    /*
     * Pre-pass 1: register all branch targets as block boundaries BEFORE
     * the main pass. This ensures the jump-trick skip logic in the main
     * pass can find legitimate block starts when jumping over dead bytes.
     */
    {
        size_t pre_off = (func_idx >= 0 && func_idx < bin->nfunctions)
                         ? (size_t)(bin->functions[func_idx].start - base)
                         : 0;
        size_t pre_end = sz;
        while (pre_off < pre_end) {
            char     pre_mnem[32] = "";
            char     pre_ops[256] = "";
            int      pre_len = 0;
            uint64_t pre_tgt = 0;
            int      pre_is_branch = 0;

            if (bin->arch == ARCH_X86_64) {
                x86_insn_t insn;
                pre_len = x86_decode(code + pre_off, pre_end - pre_off,
                                     base + pre_off, &insn);
                if (pre_len <= 0) { pre_off++; continue; }
                strncpy(pre_mnem, insn.mnemonic, 31);
                strncpy(pre_ops,  insn.ops, 255);
            } else {
                if (pre_off + 4 > pre_end) break;
                uint32_t raw2 = (uint32_t)(code[pre_off]) |
                                (code[pre_off+1]<<8) |
                                (code[pre_off+2]<<16) |
                                (code[pre_off+3]<<24);
                a64_insn_t a64i;
                a64_decode(raw2, base + pre_off, &a64i);
                pre_len = 4;
                strncpy(pre_mnem, a64i.mnemonic, 31);
                strncpy(pre_ops,  a64i.operands, 255);
            }

            {
                dax_igrp_t grp2 = (bin->arch == ARCH_X86_64)
                                  ? dax_classify_x86(pre_mnem)
                                  : dax_classify_arm64(pre_mnem);
                if (grp2 == IGRP_BRANCH || grp2 == IGRP_CALL) {
                    if (pre_ops[0] == '0')
                        sscanf(pre_ops, "0x%llx",
                               (unsigned long long *)&pre_tgt);
                    pre_is_branch = 1;
                }
            }

            if (pre_is_branch && pre_tgt &&
                pre_tgt >= base && pre_tgt < base + pre_end) {
                find_or_add_block(bin, pre_tgt, func_idx);
                /* Also register fall-through after conditional branches */
                {
                    dax_igrp_t g2 = (bin->arch == ARCH_X86_64)
                                    ? dax_classify_x86(pre_mnem)
                                    : dax_classify_arm64(pre_mnem);
                    int is_uncond = (g2 == IGRP_BRANCH) &&
                        (strcmp(pre_mnem,"b")==0 || strcmp(pre_mnem,"jmp")==0 ||
                         strcmp(pre_mnem,"br")==0 || strncmp(pre_mnem,"jmp",3)==0);
                    if (!is_uncond && pre_off + (size_t)pre_len < pre_end)
                        find_or_add_block(bin, base + pre_off + (size_t)pre_len,
                                          func_idx);
                }
            }
            pre_off += (size_t)pre_len;
        }
    }

    while (off < sz) {
        uint64_t cur_addr = base + off;
        int      len      = 0;
        char     mnem[32] = "";
        char     ops[128] = "";
        uint64_t branch_target = 0;
        int      is_branch = 0, is_cond = 0, is_ret = 0, is_call = 0;

        if (bin->arch == ARCH_X86_64) {
            x86_insn_t insn;
            len = x86_decode(code + off, sz - off, cur_addr, &insn);
            if (len <= 0) { off++; continue; }
            strncpy(mnem, insn.mnemonic, 31);
            strncpy(ops,  insn.ops,      127);
        } else {
            if (off + 4 > sz) break;
            uint32_t raw = (uint32_t)(code[off]) | (code[off+1]<<8) |
                           (code[off+2]<<16)     | (code[off+3]<<24);
            a64_insn_t insn;
            a64_decode(raw, cur_addr, &insn);
            len = 4;
            strncpy(mnem, insn.mnemonic, 31);
            strncpy(ops,  insn.operands, 127);
        }

        if (cur >= 0) bin->blocks[cur].end = cur_addr + (uint64_t)len;

        {
            dax_igrp_t grp = (bin->arch == ARCH_X86_64)
                              ? dax_classify_x86(mnem)
                              : dax_classify_arm64(mnem);

            if (grp == IGRP_RET) {
                is_ret = 1;
            } else if (grp == IGRP_CALL) {
                is_call = 1;
                if (ops[0] == '0') sscanf(ops, "0x%llx", (unsigned long long *)&branch_target);
            } else if (grp == IGRP_BRANCH) {
                is_branch = 1;
                if (ops[0] == '0') sscanf(ops, "0x%llx", (unsigned long long *)&branch_target);
                if (strncmp(mnem,"jmp",3) && strcmp(mnem,"b") && strcmp(mnem,"br"))
                    is_cond = 1;
            }
        }

        off += (size_t)len;

        if (is_ret) {
            if (cur >= 0) bin->blocks[cur].is_exit = 1;
            cur = (off < sz) ? find_or_add_block(bin, base + off, func_idx) : -1;
            continue;
        }

        if (is_call && branch_target) {
            int tgt_idx = find_block_by_addr(bin, branch_target);
            if (tgt_idx >= 0 && cur >= 0) {
                block_add_succ(&bin->blocks[cur], tgt_idx, EDGE_CALL);
                block_add_pred(&bin->blocks[tgt_idx], cur);
            }
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
                /*
                 * Unconditional branch: bytes immediately following are
                 * unreachable (jump trick / opaque predicate padding).
                 * Skip forward to the next KNOWN block boundary.
                 * This prevents dead bytes like 0xdeadbeef being treated
                 * as instructions in a new block.
                 */
                if (cur >= 0) bin->blocks[cur].is_exit = 1;
                cur = -1;
                /* Scan forward to find a pre-registered block boundary */
                while (off < sz) {
                    int next_known = find_block_by_addr(bin, base + off);
                    if (next_known >= 0) {
                        cur = next_known;
                        break;
                    }
                    /* For ARM64 advance 4 bytes, x86 advance 1 */
                    off += (bin->arch == ARCH_ARM64) ? 4 : 1;
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

/* ──────────────────────────────────────────────────────────────────
 *  Tree-style CFG printer
 * ────────────────────────────────────────────────────────────────── */

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

    for (s = 0; s < bin->nsections; s++) {
        dax_section_t *sec = &bin->sections[s];
        if (blk->start >= sec->vaddr && blk->start < sec->vaddr + sec->size &&
            sec->offset + sec->size <= bin->size) {
            uint8_t *code = bin->data + sec->offset + (blk->start - sec->vaddr);
            size_t   csz  = (size_t)(blk->end - blk->start);
            size_t   off  = 0;
            int      n    = 0;
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
    char         detail[128];
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
                   blk->is_exit  ? COL_GRP_RET : COL_ADDR) : "";
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
    fprintf(out, "block_%d", blk_idx);
    if (c) fprintf(out, "%s", COL_RESET);

    {
        int dot_count;
        int used = 7 + (blk_idx > 99 ? 3 : blk_idx > 9 ? 2 : 1);
        dot_count = 28 - depth * 4 - used;
        if (dot_count < 2) dot_count = 2;
        if (c) fprintf(out, "%s", COL_COMMENT);
        for (i = 0; i < dot_count; i++) fprintf(out, "─");
        fprintf(out, "< ");
        if (c) fprintf(out, "%s", COL_RESET);
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
        char flags[16] = "";
        if (blk->is_entry) strcat(flags, " ENTRY");
        if (blk->is_exit)  strcat(flags, " EXIT");

        if (n_insns > 0 && blk->end > blk->start) {
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
    int          c         = opts->color;
    int          nblocks   = 0;
    int          entry_idx = -1;
    tree_ctx_t   ctx;
    const char  *fname;

    for (i = 0; i < bin->nblocks; i++) {
        if (bin->blocks[i].func_idx == func_idx) {
            nblocks++;
            if (bin->blocks[i].is_entry) entry_idx = i;
        }
    }

    if (nblocks == 0) return 0;

    fname = (func_idx >= 0 && func_idx < bin->nfunctions)
             ? bin->functions[func_idx].name : "unknown";

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  CFG  ");
    if (c) fprintf(out, "%s", COL_SYM);
    fprintf(out, "%s", fname);
    if (c) fprintf(out, "%s", COL_COMMENT);
    fprintf(out, "  (%d blocks)", nblocks);
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
