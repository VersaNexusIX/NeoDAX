#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"

extern dax_igrp_t dax_classify_x86(const char *m);
extern dax_igrp_t dax_classify_arm64(const char *m);

/* ══════════════════════════════════════════════════════════════════════
 *  ENTROPY DETECTOR
 *  Shannon entropy over sliding windows of bytes — identifies packed,
 *  encrypted, or compressed regions. High entropy (>= 7.0 bits/byte)
 *  almost always means non-plaintext content.
 * ════════════════════════════════════════════════════════════════════ */

#define ENT_WINDOW    256
#define ENT_STEP      64
#define ENT_HIGH      6.8
#define ENT_MED       5.5
#define ENT_PACK_MIN  7.0

static double shannon_entropy(const uint8_t *buf, size_t len) {
    uint32_t freq[256] = {0};
    size_t   i;
    double   ent = 0.0;
    if (!buf || len == 0) return 0.0;
    for (i = 0; i < len; i++) freq[buf[i]]++;
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            ent -= p * log2(p);
        }
    }
    return ent;
}

typedef struct {
    uint64_t vaddr;
    double   entropy;
    uint8_t  label;
} ent_region_t;

#define MAX_ENT_REGIONS 4096

static ent_region_t g_ent_regions[MAX_ENT_REGIONS];
static int          g_nent_regions = 0;

void dax_entropy_scan(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int    c = opts ? opts->color : 1;
    int    si;

    const char *CR  = c ? COL_RESET   : "";
    const char *CD  = c ? COL_COMMENT : "";
    const char *CY  = c ? COL_LABEL   : "";
    const char *CG  = c ? "\033[0;32m" : "";
    const char *CR2 = c ? "\033[0;31m" : "";
    const char *CO  = c ? "\033[0;33m" : "";
    const char *CB  = c ? COL_ADDR    : "";
    const char *CM  = c ? COL_MNEM    : "";

    g_nent_regions = 0;

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                 " ENTROPY ANALYSIS "
                 "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n");
    if (c) fprintf(out, "%s", CR);
    fprintf(out, "\n");
    fprintf(out, "%s  Window: %d bytes, Step: %d bytes%s\n", CD, ENT_WINDOW, ENT_STEP, CR);
    fprintf(out, "%s  Thresholds: low <%.1f, medium <%.1f, high >=%.1f%s\n\n",
            CD, ENT_MED, ENT_HIGH, ENT_HIGH, CR);
    fprintf(out, "  %s%-20s %-8s %-6s %s%-8s%s  %s%s\n",
            CM, "Section", "VAddr", "Window", "", "Entropy", "", "Classification", CR);
    { int j; for(j=0;j<70;j++) fprintf(out,"\u2500"); fprintf(out,"\n"); }

    for (si = 0; si < bin->nsections; si++) {
        dax_section_t *sec = &bin->sections[si];
        size_t         off, win;
        int            printed_header = 0;
        double         sec_max = 0.0, sec_sum = 0.0;
        int            sec_n   = 0;

        if (sec->size < (uint64_t)ENT_WINDOW) continue;
        if (sec->offset + sec->size > bin->size) continue;

        for (off = 0; off + ENT_WINDOW <= (size_t)sec->size; off += ENT_STEP) {
            double ent = shannon_entropy(bin->data + sec->offset + off, ENT_WINDOW);
            uint64_t va = sec->vaddr + off;

            sec_sum += ent;
            sec_n++;
            if (ent > sec_max) sec_max = ent;

            if (g_nent_regions < MAX_ENT_REGIONS) {
                g_ent_regions[g_nent_regions].vaddr   = va;
                g_ent_regions[g_nent_regions].entropy = ent;
                g_ent_regions[g_nent_regions].label   = (uint8_t)(ent >= ENT_PACK_MIN ? 2 :
                                                                   ent >= ENT_HIGH    ? 1 : 0);
                g_nent_regions++;
            }

            if (ent >= ENT_HIGH) {
                const char *col   = (ent >= ENT_PACK_MIN) ? CR2 : CO;
                const char *label = (ent >= ENT_PACK_MIN) ? "PACKED/ENCRYPTED" :
                                    (ent >= ENT_HIGH)     ? "HIGH ENTROPY"      :
                                                            "MEDIUM";
                fprintf(out, "  %s%-20s%s %s0x%08llx%s +0x%-5llx  %s%5.2f%s  %s%s%s\n",
                        CY, sec->name, CR,
                        CB, (unsigned long long)sec->vaddr, CR,
                        (unsigned long long)off,
                        col, ent, CR,
                        col, label, CR);
                printed_header = 1;
            }
        }

        if (sec_n > 0) {
            double avg = sec_sum / sec_n;
            const char *col = (sec_max >= ENT_PACK_MIN) ? CR2 :
                              (sec_max >= ENT_HIGH)     ? CO  : CG;
            fprintf(out, "  %s%s%-20s%s  avg=%.2f  max=%.2f  windows=%d%s\n",
                    printed_header ? "" : "  ",
                    col, sec->name, CR, avg, sec_max, sec_n, CR);
        }
    }

    fprintf(out, "\n");
    fprintf(out, "%s  Legend: green = normal  orange = high (>=%.1f)  red = packed/encrypted (>=%.1f)%s\n\n",
            CD, ENT_HIGH, ENT_PACK_MIN, CR);
}

/* ══════════════════════════════════════════════════════════════════════
 *  RECURSIVE DESCENT DISASSEMBLER
 *  Follows control flow from entry points rather than scanning linearly.
 *  Correctly handles jump tables, dead bytes after unconditional branches,
 *  and multiple entry points. Marks unreachable bytes as data.
 * ════════════════════════════════════════════════════════════════════ */

#define RDA_MAX_QUEUE   16384
#define RDA_MAX_VISITED 65536

typedef struct {
    uint64_t addr;
} rda_work_t;

static uint64_t g_visited[RDA_MAX_VISITED];
static int      g_nvisited = 0;

static int rda_is_visited(uint64_t addr) {
    int i;
    for (i = 0; i < g_nvisited; i++)
        if (g_visited[i] == addr) return 1;
    return 0;
}

static void rda_mark_visited(uint64_t addr) {
    if (g_nvisited < RDA_MAX_VISITED)
        g_visited[g_nvisited++] = addr;
}

typedef struct {
    uint64_t entries[RDA_MAX_QUEUE];
    int      head, tail, size;
} rda_queue_t;

static void rda_enqueue(rda_queue_t *q, uint64_t addr) {
    if (q->size >= RDA_MAX_QUEUE) return;
    if (rda_is_visited(addr)) return;
    q->entries[q->tail] = addr;
    q->tail = (q->tail + 1) % RDA_MAX_QUEUE;
    q->size++;
}

static uint64_t rda_dequeue(rda_queue_t *q) {
    uint64_t a;
    if (q->size == 0) return 0;
    a = q->entries[q->head];
    q->head = (q->head + 1) % RDA_MAX_QUEUE;
    q->size--;
    return a;
}

typedef struct {
    uint64_t addr;
    char     mnem[32];
    char     ops[128];
    int      len;
    int      is_call;
    int      is_uncond_branch;
    int      is_ret;
    int      is_cond_branch;
    uint64_t branch_target;
    uint64_t fallthrough;
} rda_insn_t;

#define MAX_RDA_INSNS 65536
static rda_insn_t g_rda_insns[MAX_RDA_INSNS];
static int        g_nrda = 0;

static int rda_compare(const void *a, const void *b) {
    const rda_insn_t *ia = (const rda_insn_t *)a;
    const rda_insn_t *ib = (const rda_insn_t *)b;
    if (ia->addr < ib->addr) return -1;
    if (ia->addr > ib->addr) return  1;
    return 0;
}

static void rda_decode_arm64(uint64_t addr, const uint8_t *code, size_t csz,
                               uint64_t sec_base, rda_insn_t *out) {
    uint32_t raw;
    a64_insn_t insn;
    const char *mnem;

    out->addr = addr;
    out->len  = 4;
    out->is_call = out->is_ret = out->is_uncond_branch = out->is_cond_branch = 0;
    out->branch_target = 0;
    out->fallthrough   = addr + 4;

    if ((size_t)(addr - sec_base) + 4 > csz) { strcpy(out->mnem, "??"); return; }

    raw = (uint32_t)(code[0])|(code[1]<<8)|(code[2]<<16)|(code[3]<<24);
    a64_decode(raw, addr, &insn);
    strncpy(out->mnem, insn.mnemonic, 31);
    strncpy(out->ops,  insn.operands, 127);
    mnem = insn.mnemonic;

    if (strcmp(mnem,"bl")==0 || strcmp(mnem,"blr")==0 || strcmp(mnem,"blraa")==0) {
        out->is_call = 1;
        if (out->ops[0]=='0') sscanf(out->ops,"0x%llx",(unsigned long long*)&out->branch_target);
    } else if (strcmp(mnem,"b")==0 || strcmp(mnem,"br")==0) {
        out->is_uncond_branch = 1;
        if (out->ops[0]=='0') sscanf(out->ops,"0x%llx",(unsigned long long*)&out->branch_target);
    } else if (strncmp(mnem,"b.",2)==0 || strcmp(mnem,"cbz")==0 || strcmp(mnem,"cbnz")==0 ||
               strcmp(mnem,"tbz")==0  || strcmp(mnem,"tbnz")==0) {
        out->is_cond_branch = 1;
        const char *tp = strrchr(out->ops,',');
        if (tp) tp++; else tp = out->ops;
        while (*tp==' ') tp++;
        if (tp[0]=='0') sscanf(tp,"0x%llx",(unsigned long long*)&out->branch_target);
    } else if (strncmp(mnem,"ret",3)==0) {
        out->is_ret = 1;
    }
}

static void rda_decode_x86(uint64_t addr, const uint8_t *code, size_t csz,
                             uint64_t sec_base, rda_insn_t *out) {
    x86_insn_t insn;
    int len;

    out->addr = addr;
    out->is_call = out->is_ret = out->is_uncond_branch = out->is_cond_branch = 0;
    out->branch_target = 0;

    len = x86_decode(code, csz - (size_t)(addr - sec_base), addr, &insn);
    if (len <= 0) { out->len = 1; strcpy(out->mnem, "??"); return; }

    out->len         = len;
    out->fallthrough = addr + (uint64_t)len;
    strncpy(out->mnem, insn.mnemonic, 31);
    strncpy(out->ops,  insn.ops, 127);

    dax_igrp_t grp = dax_classify_x86(insn.mnemonic);
    if (grp == IGRP_CALL) {
        out->is_call = 1;
        if (insn.ops[0]=='0') sscanf(insn.ops,"0x%llx",(unsigned long long*)&out->branch_target);
    } else if (grp == IGRP_BRANCH) {
        if (strcmp(insn.mnemonic,"jmp")==0)
            out->is_uncond_branch = 1;
        else
            out->is_cond_branch = 1;
        if (insn.ops[0]=='0') sscanf(insn.ops,"0x%llx",(unsigned long long*)&out->branch_target);
    } else if (grp == IGRP_RET) {
        out->is_ret = 1;
    }
}

void dax_rda_section(dax_binary_t *bin, dax_section_t *sec,
                     uint64_t start_addr, dax_opts_t *opts, FILE *out) {
    rda_queue_t *q;
    int          c = opts ? opts->color : 1;
    uint8_t     *code;
    size_t       csz;

    const char *CR  = c ? COL_RESET   : "";
    const char *CB  = c ? COL_ADDR    : "";
    const char *CM  = c ? COL_MNEM    : "";
    const char *CO2 = c ? COL_OPS     : "";
    const char *CD  = c ? COL_COMMENT : "";
    const char *CY  = c ? COL_LABEL   : "";
    const char *CG  = c ? "\033[0;32m" : "";
    const char *CR2 = c ? "\033[0;31m" : "";
    const char *CP  = c ? "\033[0;35m" : "";

    if (!bin || !sec || sec->offset + sec->size > bin->size) return;

    code = bin->data + sec->offset;
    csz  = (size_t)sec->size;
    g_nvisited = 0;
    g_nrda     = 0;

    q = (rda_queue_t *)calloc(1, sizeof(rda_queue_t));
    if (!q) return;

    rda_enqueue(q, start_addr);

    for (int i = 0; i < bin->nsymbols && q->size < RDA_MAX_QUEUE/2; i++) {
        dax_symbol_t *sym = &bin->symbols[i];
        if (sym->address >= sec->vaddr && sym->address < sec->vaddr + sec->size)
            rda_enqueue(q, sym->address);
    }

    while (q->size > 0 && g_nrda < MAX_RDA_INSNS) {
        uint64_t addr = rda_dequeue(q);

        if (addr < sec->vaddr || addr >= sec->vaddr + sec->size) continue;
        if (rda_is_visited(addr)) continue;
        rda_mark_visited(addr);

        size_t      off = (size_t)(addr - sec->vaddr);
        rda_insn_t *ri  = &g_rda_insns[g_nrda++];
        memset(ri, 0, sizeof(rda_insn_t));

        if (bin->arch == ARCH_ARM64)
            rda_decode_arm64(addr, code + off, csz, sec->vaddr, ri);
        else
            rda_decode_x86(addr, code + off, csz, sec->vaddr, ri);

        if (ri->is_ret || strcmp(ri->mnem,"??") == 0) continue;

        if (ri->is_call && ri->branch_target &&
            ri->branch_target >= sec->vaddr &&
            ri->branch_target < sec->vaddr + sec->size)
            rda_enqueue(q, ri->branch_target);

        if (ri->is_uncond_branch) {
            if (ri->branch_target &&
                ri->branch_target >= sec->vaddr &&
                ri->branch_target < sec->vaddr + sec->size)
                rda_enqueue(q, ri->branch_target);
        } else {
            rda_enqueue(q, ri->fallthrough);
            if (ri->is_cond_branch && ri->branch_target &&
                ri->branch_target >= sec->vaddr &&
                ri->branch_target < sec->vaddr + sec->size)
                rda_enqueue(q, ri->branch_target);
        }
    }

    qsort(g_rda_insns, (size_t)g_nrda, sizeof(rda_insn_t), rda_compare);

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                 " RECURSIVE DESCENT: %s "
                 "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n",
                 sec->name);
    if (c) fprintf(out, "%s", CR);

    {
        uint64_t total_bytes   = sec->size;
        uint64_t covered_bytes = 0;
        int      i;

        for (i = 0; i < g_nrda; i++)
            covered_bytes += (uint64_t)g_rda_insns[i].len;

        fprintf(out, "\n%s  Discovered: %d instructions  (%.1f%% of %llu bytes covered)%s\n\n",
                CD, g_nrda,
                total_bytes ? (covered_bytes * 100.0 / total_bytes) : 0.0,
                (unsigned long long)total_bytes, CR);

        uint64_t prev_end = sec->vaddr;
        for (i = 0; i < g_nrda; i++) {
            rda_insn_t *ri = &g_rda_insns[i];

            if (ri->addr > prev_end) {
                fprintf(out, "  %s[DEAD: 0x%llx .. 0x%llx  (%llu bytes unreachable)]%s\n",
                        CR2,
                        (unsigned long long)prev_end,
                        (unsigned long long)ri->addr,
                        (unsigned long long)(ri->addr - prev_end),
                        CR);
            }

            const char *sym = dax_sym_name(bin, ri->addr);
            if (sym) fprintf(out, "\n  %s%s:%s\n", CP, sym, CR);

            const char *mnem_col = CM;
            if (ri->is_call)            mnem_col = c ? "\033[0;31m" : "";
            else if (ri->is_ret)        mnem_col = c ? "\033[0;35m" : "";
            else if (ri->is_uncond_branch || ri->is_cond_branch)
                                        mnem_col = c ? "\033[0;33m" : "";

            fprintf(out, "  %s0x%016llx%s  %s%-10s%s %s%s%s",
                    CB, (unsigned long long)ri->addr, CR,
                    mnem_col, ri->mnem, CR,
                    CO2, ri->ops, CR);

            if (ri->is_call && ri->branch_target) {
                const char *ts = dax_sym_name(bin, ri->branch_target);
                if (ts) fprintf(out, "  %s; → %s%s", CD, ts, CR);
            } else if (ri->branch_target) {
                fprintf(out, "  %s; → 0x%llx%s", CD, (unsigned long long)ri->branch_target, CR);
            }

            fprintf(out, "\n");
            prev_end = ri->addr + (uint64_t)ri->len;
        }
    }

    fprintf(out, "\n");
    free(q);
}

void dax_rda_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int si;
    for (si = 0; si < bin->nsections; si++) {
        dax_section_t *sec = &bin->sections[si];
        if (sec->type != SEC_TYPE_CODE) continue;
        if (sec->size == 0 || sec->offset + sec->size > bin->size) continue;
        dax_rda_section(bin, sec, sec->vaddr, opts, out);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  INSTRUCTION VALIDITY FILTER
 *  Scans code sections and flags:
 *   - Invalid / unknown opcodes ("??" from decoder)
 *   - Privileged instructions in user-space binaries
 *   - NOPs that look like padding vs genuine NOPs
 *   - Suspiciously long sequences of the same instruction
 *   - Instructions that decode differently under RDA vs linear scan
 *     (indicates jump tricks or obfuscation)
 * ════════════════════════════════════════════════════════════════════ */

#define IVF_SUSPICIOUS_NOP_RUN  8
#define IVF_SUSPICIOUS_INT3_RUN 3

typedef enum {
    IVF_INVALID = 0,
    IVF_PRIVILEGED,
    IVF_SUSPICIOUS_NOP,
    IVF_SUSPICIOUS_INT3,
    IVF_MISALIGNED,
    IVF_DEAD_AFTER_UNCOND,
    IVF_GOOD
} ivf_kind_t;

typedef struct {
    uint64_t   addr;
    ivf_kind_t kind;
    char       mnem[32];
    char       detail[64];
} ivf_finding_t;

#define MAX_IVF_FINDINGS 4096
static ivf_finding_t g_ivf[MAX_IVF_FINDINGS];
static int           g_nivf = 0;

static void ivf_add(uint64_t addr, ivf_kind_t kind, const char *mnem, const char *detail) {
    if (g_nivf >= MAX_IVF_FINDINGS) return;
    g_ivf[g_nivf].addr = addr;
    g_ivf[g_nivf].kind = kind;
    strncpy(g_ivf[g_nivf].mnem,   mnem,   31);
    strncpy(g_ivf[g_nivf].detail, detail, 63);
    g_nivf++;
}

static int is_privileged_arm64(const char *mnem) {
    static const char *privs[] = {
        "msr","mrs","at","dc","ic","tlbi","sys","sysl",
        "eret","drps","hlt","brk","smc","hvc","wfi","wfe",
        NULL
    };
    int i;
    for (i = 0; privs[i]; i++)
        if (strcmp(mnem, privs[i]) == 0) return 1;
    return 0;
}

static int is_privileged_x86(const char *mnem) {
    static const char *privs[] = {
        "cli","sti","hlt","in","out","ins","outs","int","iret","iretq",
        "lidt","lgdt","ltr","invd","wbinvd","rdmsr","wrmsr",
        "rdtsc","cpuid","vmcall","vmlaunch","vmresume","vmptrld",
        NULL
    };
    int i;
    for (i = 0; privs[i]; i++)
        if (strcmp(mnem, privs[i]) == 0) return 1;
    return 0;
}

void dax_ivf_scan(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int    c    = opts ? opts->color : 1;
    int    si, i;
    int    user_space = !bin->is_pie && bin->os != DAX_PLAT_WINDOWS;

    const char *CR  = c ? COL_RESET    : "";
    const char *CB  = c ? COL_ADDR     : "";
    const char *CM  = c ? COL_MNEM     : "";
    const char *CD  = c ? COL_COMMENT  : "";
    const char *CY  = c ? COL_LABEL    : "";
    const char *CR2 = c ? "\033[0;31m" : "";
    const char *CO  = c ? "\033[0;33m" : "";
    const char *CG  = c ? "\033[0;32m" : "";

    g_nivf = 0;

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                 " INSTRUCTION VALIDITY FILTER "
                 "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n");
    if (c) fprintf(out, "%s", CR);
    fprintf(out, "\n");

    for (si = 0; si < bin->nsections; si++) {
        dax_section_t *sec = &bin->sections[si];
        uint8_t       *code;
        size_t         csz, off;
        int            nop_run   = 0;
        int            int3_run  = 0;
        int            after_uncond = 0;
        int            dead_count   = 0;

        if (sec->type != SEC_TYPE_CODE) continue;
        if (sec->size == 0 || sec->offset + sec->size > bin->size) continue;

        code = bin->data + sec->offset;
        csz  = (size_t)sec->size;
        off  = 0;

        while (off < csz) {
            uint64_t addr = sec->vaddr + off;
            char     mnem[32] = "", ops[256] = "";
            int      len      = 0;
            int      is_nop   = 0, is_int3 = 0, is_uncond = 0, is_invalid = 0;

            if (bin->arch == ARCH_ARM64) {
                if (off + 4 > csz) break;
                uint32_t raw = (uint32_t)(code[off])|(code[off+1]<<8)|
                               (code[off+2]<<16)|(code[off+3]<<24);
                a64_insn_t insn; a64_decode(raw, addr, &insn);
                strncpy(mnem, insn.mnemonic, 31);
                strncpy(ops,  insn.operands, 255);
                len = 4;
                is_nop      = (strcmp(mnem,"nop")==0 || strcmp(mnem,"endbr64")==0);
                is_invalid  = (strcmp(mnem,"??")==0 || strcmp(mnem,"dw")==0 ||
                               strncmp(mnem,"v_",2)==0 || strncmp(mnem,"dp_",3)==0);
                is_uncond   = (strcmp(mnem,"b")==0 || strcmp(mnem,"br")==0 ||
                               strncmp(mnem,"ret",3)==0);
            } else {
                x86_insn_t insn;
                len = x86_decode(code + off, csz - off, addr, &insn);
                if (len <= 0) { len = 1; is_invalid = 1; strcpy(mnem,"??"); }
                else {
                    strncpy(mnem, insn.mnemonic, 31);
                    strncpy(ops,  insn.ops, 255);
                    is_nop    = (strcmp(mnem,"nop")==0);
                    is_int3   = (strcmp(mnem,"int3")==0 || strcmp(mnem,"int")==0);
                    is_uncond = (strcmp(mnem,"jmp")==0 || strcmp(mnem,"ret")==0 ||
                                 strcmp(mnem,"retq")==0);
                    is_invalid = (strcmp(mnem,"??")==0);
                }
            }

            if (after_uncond && !is_invalid) {
                dax_func_t *fn = dax_func_find(bin, addr);
                dax_symbol_t *sym = dax_sym_find(bin, addr);
                if (!fn && !sym) {
                    dead_count++;
                    if (dead_count <= 4) {
                        char detail[64];
                        snprintf(detail, 64, "after unconditional branch (%d bytes)", len);
                        ivf_add(addr, IVF_DEAD_AFTER_UNCOND, mnem, detail);
                    }
                    off += (size_t)len;
                    continue;
                }
            }

            after_uncond = 0; dead_count = 0;

            if (is_invalid) {
                char detail[64];
                snprintf(detail, 64, "bytes: %02x %02x %02x %02x",
                         code[off], off+1<csz?code[off+1]:0,
                         off+2<csz?code[off+2]:0, off+3<csz?code[off+3]:0);
                ivf_add(addr, IVF_INVALID, mnem, detail);
            } else {
                int is_priv = (bin->arch == ARCH_ARM64)
                              ? is_privileged_arm64(mnem)
                              : is_privileged_x86(mnem);
                if (is_priv && bin->os != DAX_PLAT_WINDOWS) {
                    char detail[64];
                    snprintf(detail, 64, "privileged in userspace binary");
                    ivf_add(addr, IVF_PRIVILEGED, mnem, detail);
                }
            }

            if (is_nop) {
                nop_run++;
                if (nop_run == IVF_SUSPICIOUS_NOP_RUN) {
                    char detail[64];
                    snprintf(detail, 64, "run of %d+ NOPs", nop_run);
                    ivf_add(addr - (uint64_t)(nop_run-1)*4, IVF_SUSPICIOUS_NOP, "nop", detail);
                }
            } else {
                nop_run = 0;
            }

            if (is_int3) {
                int3_run++;
                if (int3_run == IVF_SUSPICIOUS_INT3_RUN) {
                    char detail[64];
                    snprintf(detail, 64, "run of %d+ INT3 — padding or breakpoint spray", int3_run);
                    ivf_add(addr - (uint64_t)(int3_run-1), IVF_SUSPICIOUS_INT3, "int3", detail);
                }
            } else {
                int3_run = 0;
            }

            if (is_uncond) after_uncond = 1;
            off += (size_t)(len > 0 ? len : 1);
        }
    }

    if (g_nivf == 0) {
        fprintf(out, "%s  No suspicious instructions found — all code appears valid.%s\n\n", CG, CR);
        return;
    }

    fprintf(out, "  %s%-8s  %-20s  %-16s  %s%s\n", CM, "Category", "Address", "Mnemonic", "Detail", CR);
    { int j; for(j=0;j<72;j++) fprintf(out,"\u2500"); fprintf(out,"\n"); }

    int n_invalid = 0, n_priv = 0, n_nop = 0, n_dead = 0, n_int3 = 0;

    for (i = 0; i < g_nivf; i++) {
        ivf_finding_t *f = &g_ivf[i];
        const char *cat_col, *cat_str;

        switch (f->kind) {
            case IVF_INVALID:
                cat_col = CR2; cat_str = "INVALID "; n_invalid++; break;
            case IVF_PRIVILEGED:
                cat_col = CO;  cat_str = "PRIV    "; n_priv++; break;
            case IVF_SUSPICIOUS_NOP:
                cat_col = CD;  cat_str = "NOP-RUN "; n_nop++; break;
            case IVF_SUSPICIOUS_INT3:
                cat_col = CO;  cat_str = "INT3-RUN"; n_int3++; break;
            case IVF_DEAD_AFTER_UNCOND:
                cat_col = CR2; cat_str = "DEAD    "; n_dead++; break;
            default:
                cat_col = CD;  cat_str = "OTHER   "; break;
        }

        fprintf(out, "  %s%-8s%s  %s0x%016llx%s  %s%-16s%s  %s%s%s\n",
                cat_col, cat_str, CR,
                CB, (unsigned long long)f->addr, CR,
                CM, f->mnem, CR,
                CD, f->detail, CR);
    }

    fprintf(out, "\n");
    fprintf(out, "%s  Summary: %sinvalid=%d%s  %sprivileged=%d%s  "
                 "%sdead-bytes=%d%s  %snop-runs=%d%s  %sint3-runs=%d%s%s\n\n",
            CD,
            CR2, n_invalid, CD,
            CO,  n_priv,    CD,
            CR2, n_dead,    CD,
            CD,  n_nop,     CD,
            CO,  n_int3,    CD,
            CR);
}
