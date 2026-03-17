#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"

#define CG_MAX_CALLS  DAX_MAX_XREFS
#define CG_MAX_DEPTH  12

typedef struct {
    int   caller;
    int   callee;
    uint64_t site;
} cg_edge_t;

typedef struct {
    cg_edge_t *edges;
    int        nedges;
} cg_t;

static int addr_to_func(dax_binary_t *bin, uint64_t addr) {
    int i;
    for (i = 0; i < bin->nfunctions; i++) {
        if (bin->functions[i].start == addr) return i;
        if (addr > bin->functions[i].start && bin->functions[i].end > 0
            && addr < bin->functions[i].end) return i;
    }
    return -1;
}

static cg_t *cg_build(dax_binary_t *bin) {
    cg_t *cg;
    int   i;

    cg = (cg_t *)calloc(1, sizeof(cg_t));
    if (!cg) return NULL;
    cg->edges = (cg_edge_t *)calloc(CG_MAX_CALLS, sizeof(cg_edge_t));
    if (!cg->edges) { free(cg); return NULL; }
    cg->nedges = 0;

    for (i = 0; i < bin->nxrefs; i++) {
        dax_xref_t *xr = &bin->xrefs[i];
        int caller_fi, callee_fi, j;

        if (!xr->is_call) continue;

        caller_fi = addr_to_func(bin, xr->from);
        callee_fi = addr_to_func(bin, xr->to);

        if (caller_fi < 0 || callee_fi < 0) continue;
        if (caller_fi == callee_fi) continue;

        for (j = 0; j < cg->nedges; j++) {
            if (cg->edges[j].caller == caller_fi &&
                cg->edges[j].callee == callee_fi) goto skip;
        }

        if (cg->nedges < CG_MAX_CALLS) {
            cg->edges[cg->nedges].caller = caller_fi;
            cg->edges[cg->nedges].callee = callee_fi;
            cg->edges[cg->nedges].site   = xr->from;
            cg->nedges++;
        }
        skip:;
    }
    return cg;
}

static void cg_free(cg_t *cg) {
    if (!cg) return;
    free(cg->edges);
    free(cg);
}

static void cg_print_node(dax_binary_t *bin, cg_t *cg,
                           int fi, int depth, char *prefix, int is_last,
                           int *visited, int nvisited,
                           dax_opts_t *opts, FILE *out) {
    int c = opts->color;
    const char *C_FUNC = c ? "\033[1;36m"  : "";
    const char *C_SYM  = c ? "\033[1;35m"  : "";
    const char *C_CMT  = c ? "\033[0;90m"  : "";
    const char *C_RET  = c ? "\033[1;31m"  : "";
    const char *C_TREE = c ? "\033[0;90m"  : "";
    const char *C_RST  = c ? "\033[0m"     : "";
    const char *C_BACK = c ? "\033[0;33m"  : "";
    char new_prefix[256];
    int  j, already = 0, ncallees = 0;

    if (fi < 0 || fi >= bin->nfunctions) return;
    if (depth >= CG_MAX_DEPTH) {
        fprintf(out, "%s%s%s%s ... (depth limit)%s\n",
                prefix, is_last ? "└── " : "├── ",
                C_CMT, "...", C_RST);
        return;
    }

    for (j = 0; j < nvisited; j++)
        if (visited[j] == fi) { already = 1; break; }

    fprintf(out, "%s", prefix);
    if (c) fprintf(out, "%s", C_TREE);
    fprintf(out, "%s", is_last ? "└── " : "├── ");

    if (already) {
        if (c) fprintf(out, "%s", C_BACK);
        fprintf(out, "%s", bin->functions[fi].name);
        if (c) fprintf(out, "%s", C_CMT);
        fprintf(out, "  ↩ (recursive)");
        if (c) fprintf(out, "%s", C_RST);
        fprintf(out, "\n");
        return;
    }

    {
        int is_entry = (bin->functions[fi].sym_idx >= 0 &&
                        bin->functions[fi].sym_idx < bin->nsymbols &&
                        bin->symbols[bin->functions[fi].sym_idx].is_entry);
        const char *nc = is_entry ? C_RET : C_FUNC;
        int has_callers = 0, ncallers = 0;
        for (j = 0; j < cg->nedges; j++)
            if (cg->edges[j].callee == fi) ncallers++;
        for (j = 0; j < cg->nedges; j++)
            if (cg->edges[j].caller == fi) ncallees++;
        has_callers = (ncallers > 0);
        (void)has_callers;

        if (c) fprintf(out, "%s", nc);
        fprintf(out, "%s", bin->functions[fi].name);
        if (c) fprintf(out, "%s", C_RST);

        {
            uint64_t start = bin->functions[fi].start;
            uint64_t end   = bin->functions[fi].end;
            fprintf(out, "  %s0x%llx%s", c ? C_CMT : "", (unsigned long long)start, c ? C_RST : "");
            if (end > start)
                fprintf(out, "%s  %llu bytes%s",
                        c ? C_CMT : "",
                        (unsigned long long)(end - start),
                        c ? C_RST : "");
        }

        if (ncallees > 0) {
            fprintf(out, "  %s(%d call%s)%s",
                    c ? C_CMT : "",
                    ncallees, ncallees > 1 ? "s" : "",
                    c ? C_RST : "");
        }

        dax_symbol_t *sym = dax_sym_find(bin, bin->functions[fi].start);
        if (sym && sym->demangled[0] &&
            strcmp(sym->demangled, bin->functions[fi].name) != 0) {
            fprintf(out, "  %s[%s]%s", c ? C_SYM : "", sym->demangled, c ? C_RST : "");
        }
        fprintf(out, "\n");
    }

    if (nvisited < CG_MAX_DEPTH * 4) visited[nvisited++] = fi;

    snprintf(new_prefix, sizeof(new_prefix), "%s%s",
             prefix, is_last ? "    " : "│   ");

    {
        int callees[256];
        int nc = 0;
        for (j = 0; j < cg->nedges && nc < 256; j++)
            if (cg->edges[j].caller == fi)
                callees[nc++] = cg->edges[j].callee;

        for (j = 0; j < nc; j++) {
            cg_print_node(bin, cg, callees[j],
                          depth + 1, new_prefix, j == nc - 1,
                          visited, nvisited, opts, out);
        }
    }
}

void dax_callgraph_print(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    cg_t *cg;
    int   i, c = opts->color;
    int   nroots = 0;
    int   visited[CG_MAX_DEPTH * 4];
    int  *is_callee;

    const char *C_SEC  = c ? "\033[1;36m" : "";
    const char *C_RST  = c ? "\033[0m"    : "";
    const char *C_CMT  = c ? "\033[0;90m" : "";

    cg = cg_build(bin);
    if (!cg) return;

    is_callee = (int *)calloc(bin->nfunctions, sizeof(int));
    if (!is_callee) { cg_free(cg); return; }

    for (i = 0; i < cg->nedges; i++)
        if (cg->edges[i].callee >= 0 && cg->edges[i].callee < bin->nfunctions)
            is_callee[cg->edges[i].callee] = 1;

    fprintf(out, "\n");
    fprintf(out, "%s  ══════════════ CALL GRAPH ══════════════%s\n\n", C_SEC, C_RST);

    fprintf(out, "%s  %-40s %-8s %-8s%s\n",
            c ? "\033[1;37m" : "", "Function", "Calls", "Called-by", C_RST);
    fprintf(out, "%s  ", C_CMT);
    { int k; for (k = 0; k < 70; k++) fprintf(out, "─"); }
    fprintf(out, "%s\n", C_RST);

    for (i = 0; i < bin->nfunctions; i++) {
        int ncalls = 0, ncalledby = 0, j;
        for (j = 0; j < cg->nedges; j++) {
            if (cg->edges[j].caller == i) ncalls++;
            if (cg->edges[j].callee == i) ncalledby++;
        }
        if (ncalls == 0 && ncalledby == 0) continue;
        fprintf(out, "  %s%-40s%s %-8d %-8d\n",
                c ? "\033[0;36m" : "",
                bin->functions[i].name, C_RST,
                ncalls, ncalledby);
    }

    fprintf(out, "\n");
    fprintf(out, "%s  Call Tree (roots = functions not called by others):%s\n\n",
            C_SEC, C_RST);

    for (i = 0; i < bin->nfunctions; i++) {
        int has_callees = 0, j;
        if (is_callee[i]) continue;
        for (j = 0; j < cg->nedges; j++)
            if (cg->edges[j].caller == i) { has_callees = 1; break; }
        if (!has_callees) continue;

        memset(visited, -1, sizeof(visited));
        fprintf(out, "%s  │%s\n", C_CMT, C_RST);
        cg_print_node(bin, cg, i, 0, "  ", 1, visited, 0, opts, out);
        nroots++;
    }

    if (nroots == 0) {
        for (i = 0; i < bin->nfunctions && nroots < 3; i++) {
            int j, ncalls = 0;
            for (j = 0; j < cg->nedges; j++)
                if (cg->edges[j].caller == i) ncalls++;
            if (ncalls == 0) continue;
            memset(visited, -1, sizeof(visited));
            fprintf(out, "%s  │%s\n", C_CMT, C_RST);
            cg_print_node(bin, cg, i, 0, "  ", 1, visited, 0, opts, out);
            nroots++;
        }
    }

    fprintf(out, "\n%s  %d edge(s) across %d function(s)%s\n\n",
            C_CMT, cg->nedges, bin->nfunctions, C_RST);

    free(is_callee);
    cg_free(cg);
}
