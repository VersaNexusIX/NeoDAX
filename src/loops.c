#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"

#define DOM_MAX  256

typedef struct {
    int    header;
    int    nodes[DAX_MAX_BLOCKS];
    int    nnodes;
    int    depth;
} dax_loop_t;

static int blk_in_func(dax_binary_t *bin, int idx, int func_idx) {
    if (idx < 0 || idx >= bin->nblocks) return 0;
    return bin->blocks[idx].func_idx == func_idx;
}

static void compute_dominators(dax_binary_t *bin, int func_idx,
                                int *bidx, int nb, int *dom_out) {
    int i, j, changed, p, k;

    for (i = 0; i < nb; i++)
        for (j = 0; j < nb; j++)
            dom_out[i * nb + j] = 1;

    dom_out[0 * nb + 0] = 1;
    for (j = 1; j < nb; j++) dom_out[0 * nb + j] = 0;

    changed = 1;
    while (changed) {
        changed = 0;
        for (i = 1; i < nb; i++) {
            int new_dom[256] = {0};
            int first_pred = 1;

            for (p = 0; p < nb; p++) {
                dax_block_t *pb = &bin->blocks[bidx[p]];
                int is_pred = 0;
                for (k = 0; k < pb->nsucc; k++) {
                    if (pb->succ[k] == bidx[i]) { is_pred = 1; break; }
                }
                if (!is_pred) continue;

                if (first_pred) {
                    for (j = 0; j < nb; j++) new_dom[j] = dom_out[p * nb + j];
                    first_pred = 0;
                } else {
                    for (j = 0; j < nb; j++) new_dom[j] &= dom_out[p * nb + j];
                }
            }

            new_dom[i] = 1;

            for (j = 0; j < nb; j++) {
                if (dom_out[i * nb + j] != new_dom[j]) {
                    dom_out[i * nb + j] = new_dom[j];
                    changed = 1;
                }
            }
        }
    }
    (void)func_idx;
}

static int collect_loop_nodes(dax_binary_t *bin, int header_idx,
                               int back_src, int *bidx, int nb,
                               int *loop_nodes, int *nn) {
    int stack[DOM_MAX];
    int sp = 0;
    int visited[DOM_MAX] = {0};
    int i, hi = -1;

    for (i = 0; i < nb; i++)
        if (bidx[i] == header_idx) { hi = i; break; }
    if (hi < 0) return 0;

    *nn = 0;
    loop_nodes[(*nn)++] = header_idx;
    visited[hi] = 1;

    stack[sp++] = back_src;
    for (i = 0; i < nb; i++)
        if (bidx[i] == back_src) { visited[i] = 1; break; }
    if (back_src != header_idx) {
        loop_nodes[(*nn)++] = back_src;
    }

    while (sp > 0) {
        int cur = stack[--sp];
        dax_block_t *blk = (cur >= 0 && cur < bin->nblocks) ? &bin->blocks[cur] : NULL;
        int ci = -1;
        if (!blk) continue;
        for (i = 0; i < nb; i++) if (bidx[i] == cur) { ci = i; break; }

        for (i = 0; i < blk->npred; i++) {
            int pred = blk->pred[i];
            int pi   = -1;
            int j;
            for (j = 0; j < nb; j++) if (bidx[j] == pred) { pi = j; break; }
            if (pi < 0 || visited[pi]) continue;
            visited[pi] = 1;
            loop_nodes[(*nn)++] = pred;
            stack[sp++] = pred;
        }
        (void)ci;
    }
    return *nn;
}

int dax_loop_detect(dax_binary_t *bin, int func_idx, FILE *out, int color) {
    int          i, j, nb = 0;
    int         *bidx;
    int         *dom;
    int          nloops   = 0;
    int          loop_nodes[DOM_MAX];
    int          nn;

    const char *C_LOOP  = color ? "\033[1;35m" : "";
    const char *C_BACK  = color ? "\033[0;33m"  : "";
    const char *C_HDR   = color ? "\033[1;36m"  : "";
    const char *C_ADDR  = color ? "\033[1;34m"  : "";
    const char *C_CMT   = color ? "\033[0;90m"  : "";
    const char *C_RST   = color ? "\033[0m"      : "";

    for (i = 0; i < bin->nblocks; i++)
        if (blk_in_func(bin, i, func_idx)) nb++;

    if (nb == 0 || nb > 256) return 0;  /* cap per-function block count */

    bidx = (int *)malloc(nb * sizeof(int));
    if (!bidx) return -1;

    dom = (int *)calloc(nb * nb, sizeof(int));
    if (!dom) { free(bidx); return -1; }

    { int k = 0;
      for (i = 0; i < bin->nblocks; i++)
          if (blk_in_func(bin, i, func_idx)) bidx[k++] = i; }

    memset(dom, 0, sizeof(int) * nb * nb);
    compute_dominators(bin, func_idx, bidx, nb, dom);

    for (i = 0; i < nb; i++) {
        dax_block_t *blk = &bin->blocks[bidx[i]];
        for (j = 0; j < blk->nsucc; j++) {
            int succ = blk->succ[j];
            int si   = -1;
            int k2;
            for (k2 = 0; k2 < nb; k2++)
                if (bidx[k2] == succ) { si = k2; break; }
            if (si < 0) continue;
            if (!dom[i * nb + si]) continue;

            nloops++;
            nn = 0;
            collect_loop_nodes(bin, succ, bidx[i], bidx, nb, loop_nodes, &nn);

            if (out) {
                fprintf(out, "  %sLoop #%d%s", C_LOOP, nloops, C_RST);
                fprintf(out, "  %sheader%s %s0x%llx%s",
                        C_HDR, C_RST, C_ADDR,
                        (unsigned long long)bin->blocks[succ].start, C_RST);
                fprintf(out, "  %sback-edge%s %s0x%llx%s\xe2\x86\x92%s0x%llx%s",
                        C_BACK, C_RST,
                        C_ADDR, (unsigned long long)blk->start, C_RST,
                        C_ADDR, (unsigned long long)bin->blocks[succ].start, C_RST);
                fprintf(out, "  %s(%d nodes)%s\n", C_CMT, nn, C_RST);

                if (nn > 1) {
                    int m;
                    for (m = 0; m < nn && m < 8; m++) {
                        fprintf(out, "    %s%s%s  ", C_CMT,
                                (m == nn-1 || m == 7) ? "\xe2\x94\x94\xe2\x94\x80"
                                                      : "\xe2\x94\x9c\xe2\x94\x80",
                                C_RST);
                        fprintf(out, "%sblock_%d%s  %s0x%llx%s",
                                C_ADDR, loop_nodes[m], C_RST,
                                C_CMT,
                                (unsigned long long)
                                (loop_nodes[m] < bin->nblocks
                                    ? bin->blocks[loop_nodes[m]].start : 0),
                                C_RST);
                        if (loop_nodes[m] == succ)
                            fprintf(out, "  %s\xe2\x86\x90 header%s", C_LOOP, C_RST);
                        fprintf(out, "\n");
                    }
                    if (nn > 8)
                        fprintf(out, "    %s    ... %d more nodes%s\n",
                                C_CMT, nn - 8, C_RST);
                }
            }
        }
    }

    free(bidx);
    free(dom);
    return nloops;
}

void dax_loop_print_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int fi, total = 0;
    int c = opts->color;
    const char *C_SEC = c ? "\033[1;36m" : "";
    const char *C_RST = c ? "\033[0m"    : "";

    fprintf(out, "\n");
    fprintf(out, "%s  ══════════════ LOOP ANALYSIS ══════════════%s\n", C_SEC, C_RST);

    for (fi = 0; fi < bin->nfunctions; fi++) {
        int n = dax_loop_detect(bin, fi, NULL, 0);
        if (n <= 0) continue;

        fprintf(out, "\n  %s%s%s\n", c ? "\033[1;35m" : "",
                bin->functions[fi].name, C_RST);
        total += dax_loop_detect(bin, fi, out, c);
    }

    if (total == 0) {
        fprintf(out, "%s  (no loops detected)%s\n",
                c ? "\033[0;90m" : "", C_RST);
    } else {
        fprintf(out, "\n%s  Total: %d loop(s) across %d function(s)%s\n",
                c ? "\033[0;90m" : "", total, bin->nfunctions, C_RST);
    }
    fprintf(out, "\n");
}
