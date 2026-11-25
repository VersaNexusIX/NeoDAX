#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <time.h>
#include "dax.h"
#include "dax_guard.h"
#include "x86.h"
#include "arm64.h"
#include "riscv.h"

extern dax_igrp_t dax_classify_x86(const char *m);
extern dax_igrp_t dax_classify_arm64(const char *m);

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

    DAX_GUARD_BIN(bin);
    if (!opts || !out) return;

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        size_t         off;
        int            printed_header = 0;
        double         sec_max = 0.0, sec_sum = 0.0;
        int            sec_n   = 0;

        if (sec->size < (uint64_t)ENT_WINDOW) continue;
        if (sec->offset > bin->size) continue;
        if (sec->size > bin->size - sec->offset) continue;  /* overflow-safe */

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
    snprintf(out->mnem, 32, "%s", insn.mnemonic);
    snprintf(out->ops, 128, "%.127s", insn.operands);
    mnem = insn.mnemonic;

    if (strcmp(mnem,"bl")==0 || strcmp(mnem,"blr")==0 || strcmp(mnem,"blraa")==0) {
        out->is_call = 1;
        if (out->ops[0]=='0') sscanf(out->ops,"0x%llx",(unsigned long long*)&out->branch_target);
    } else if (strcmp(mnem,"b")==0) {
        out->is_uncond_branch = 1;
        if (out->ops[0]=='0') sscanf(out->ops,"0x%llx",(unsigned long long*)&out->branch_target);
    } else if (strcmp(mnem,"br")==0) {
        
        out->is_uncond_branch = 1;
        out->branch_target = 0;
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
    snprintf(out->mnem, 32, "%s", insn.mnemonic);
    snprintf(out->ops, 128, "%.127s", insn.ops);

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
    (void)CB; (void)CM; (void)CO2; (void)CD;
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

    for (int i = 0; i < bin->nsymbols && i < DAX_MAX_SYMBOLS && q->size < RDA_MAX_QUEUE/2; i++) {
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
    DAX_GUARD_BIN(bin);
    if (!opts || !out) return;
    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        if (sec->type != SEC_TYPE_CODE) continue;
        if (sec->size == 0 || sec->offset > bin->size) continue;
        if (sec->size > bin->size - sec->offset) continue;
        dax_rda_section(bin, sec, sec->vaddr, opts, out);
    }
}

#define IVF_SUSPICIOUS_NOP_RUN  8
#define IVF_SUSPICIOUS_INT3_RUN 3

typedef enum {
    IVF_INVALID = 0,
    IVF_PRIVILEGED,
    IVF_SUSPICIOUS_NOP,
    IVF_SUSPICIOUS_INT3,
    IVF_MISALIGNED,
    IVF_DEAD_AFTER_UNCOND,
    IVF_INDIRECT_BRANCH,
    IVF_COMPUTED_JUMP,
    IVF_SMC_PATTERN,
    IVF_OPAQUE_SYSREG,
    IVF_DATA_IN_CODE,
    IVF_OVERLAPPING_INSN,
    
    IVF_OPAQUE_CONST,        
    IVF_OPAQUE_STACK,        
    IVF_THUNK_CHAIN,         
    IVF_RET_TRAMPOLINE,      
    IVF_HASH_DISPATCH,       
    IVF_ANTI_DEBUG_TIMING,   
    IVF_ASLR_PROBE,          
    IVF_REGISTER_ALIAS,      
    IVF_JUMP_TABLE,          
    IVF_OPAQUE_MUL_PARITY,  
    IVF_OPAQUE_SAME_REG,    
    IVF_TAINT_PROPAGATION,  
    IVF_STACK_PIVOT,        
    IVF_CONST_BRANCH,       
    IVF_MISALIGNED_DATA,    
    IVF_VM_DISPATCH,        
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
    snprintf(g_ivf[g_nivf].mnem, 32, "%s", mnem);
    snprintf(g_ivf[g_nivf].detail, 64, "%.63s", detail);
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

static int ivf_addr_is_exec(dax_binary_t *bin, uint64_t addr) {
    int i;
    for (i = 0; i < bin->nsections; i++) {
        dax_section_t *s = &bin->sections[i];
        if (s->type != SEC_TYPE_CODE) continue;
        if (addr >= s->vaddr && addr < s->vaddr + s->size) return 1;
    }
    return 0;
}

typedef struct {
    uint64_t dispatch_pc;   
    uint64_t table_base;    
    int      n_handlers;    
    uint64_t handlers[32];  
} vm_info_t;

static int dax_detect_vm(dax_binary_t *bin, int func_idx, vm_info_t *vm_out) {
    if (!bin || func_idx < 0 || func_idx >= bin->nfunctions) return 0;
    dax_func_t *fn = &bin->functions[func_idx];

    
    int si;
    uint8_t *code = NULL; size_t csz = 0; uint64_t base = 0;
    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *s = &bin->sections[si];
        if (fn->start >= s->vaddr && fn->start < s->vaddr + s->size &&
            s->offset + s->size <= bin->size) {
            code = bin->data + s->offset; csz = s->size; base = s->vaddr; break;
        }
    }
    if (!code) return 0;

    size_t fn_start_off = (size_t)(fn->start - base);
    size_t fn_end_off   = (fn->end > fn->start && fn->end <= base+csz)
                          ? (size_t)(fn->end - base) : fn_start_off + 512;
    if (fn_end_off > csz) fn_end_off = csz;

    int score = 0;
    int sig_ip_inc = 0, sig_bytecode = 0, sig_modulo = 0;
    int sig_table = 0, sig_indirect = 0, sig_loop = 0;
    uint64_t table_base = 0;
    uint64_t br_pc = 0;

    uint64_t adrp_val[32] = {0}; 
    uint64_t add_val[32]  = {0};
    int      reg_known[32]= {0};

    size_t off = fn_start_off;
    while (off + 4 <= fn_end_off) {
        uint32_t raw = (uint32_t)code[off]|(code[off+1]<<8)|
                       (code[off+2]<<16)|(code[off+3]<<24);
        uint64_t addr = base + off;
        a64_insn_t insn; a64_decode(raw, addr, &insn);
        const char *m = insn.mnemonic, *ops = insn.operands;

        
        if (!strcmp(m,"adrp")) {
            char r[16]=""; uint64_t pg=0;
            sscanf(ops, "%15[^,], 0x%llx", r, (unsigned long long*)&pg);
            int ri = (r[0]=='x'||r[0]=='w') ? atoi(r+1) : -1;
            if (ri>=0&&ri<32) { adrp_val[ri]=pg; reg_known[ri]=1; add_val[ri]=0; }
        }
        
        if (!strcmp(m,"add")) {
            char r1[16]="",r2[16]="",imm[32]="";
            sscanf(ops,"%15[^,], %15[^,], %31s",r1,r2,imm);
            int d=(r1[0]=='x'||r1[0]=='w')?atoi(r1+1):-1;
            int s=(r2[0]=='x'||r2[0]=='w')?atoi(r2+1):-1;
            if (d>=0&&d<32&&s>=0&&s<32&&reg_known[s]&&imm[0]=='#') {
                uint64_t ov=(uint64_t)strtoull(imm+1,NULL,0);
                add_val[d]=adrp_val[s]+ov; reg_known[d]=2;
            }
        }

        
        if (!strcmp(m,"add")) {
            char r1[16]="",r2[16]="",i3[16]="";
            sscanf(ops,"%15[^,], %15[^,], %15s",r1,r2,i3);
            if (!strcmp(r1,r2) && (i3[0]=='#'||i3[0]=='0'))
                sig_ip_inc = 1;
        }

        
        if (!strcmp(m,"ldrb") || !strcmp(m,"ldrh")) {
            
            if (strstr(ops,"uxtx")||strstr(ops,"sxtx")||strstr(ops,"lsl"))
                sig_bytecode = 1;
            else if (strchr(ops,'[') && strchr(ops,','))
                sig_bytecode = 1;
        }

        
        if (!strcmp(m,"and") || !strcmp(m,"sbfm") || !strcmp(m,"ubfm"))
            sig_modulo = 1;
        if (!strcmp(m,"udiv") || !strcmp(m,"sdiv"))
            sig_modulo = 1;

        
        if (!strcmp(m,"ldr") && strstr(ops,"uxtx #3")) {
            
            char bname[16]=""; const char *bp=strchr(ops,'[');
            if (bp) {
                bp++;
                int bi=0;
                while(*bp&&*bp!=','&&*bp!=']'&&bi<15)bname[bi++]=*bp++;
                bname[bi]='\0';
                int bri=(bname[0]=='x'||bname[0]=='w')?atoi(bname+1):-1;
                if (bri>=0&&bri<32&&reg_known[bri]>=2) {
                    table_base = add_val[bri];
                    sig_table  = 1;
                }
            }
        }

        
        if (!strcmp(m,"br") && ops[0]=='x') {
            sig_indirect = 1; br_pc = addr;
        }

        
        if (!strncmp(m,"b.",2)||!strcmp(m,"b")||!strcmp(m,"cbnz")||!strcmp(m,"cbz")) {
            const char *tp=strrchr(ops,'0');
            if (tp && tp[1]=='x') {
                uint64_t tgt=strtoull(tp,NULL,16);
                if (tgt >= fn->start && tgt < addr) sig_loop = 1;
            }
        }

        off += 4;
    }

    score = sig_ip_inc + sig_bytecode + sig_modulo +
            sig_table + sig_indirect + sig_loop;
    if (score < 4) return 0;

    
    if (vm_out) {
        vm_out->dispatch_pc = br_pc;
        vm_out->table_base  = table_base;
        vm_out->n_handlers  = 0;
        if (table_base > 0) {
            int ei;
            for (ei = 0; ei < 32; ei++) {
                uint64_t eaddr = table_base + (uint64_t)(ei * 8);
                int si2;
                for (si2 = 0; si2 < bin->nsections && si2 < DAX_MAX_SECTIONS; si2++) {
                    dax_section_t *s2 = &bin->sections[si2];
                    if (eaddr < s2->vaddr || eaddr+8 > s2->vaddr+s2->size) continue;
                    if (s2->offset+s2->size > bin->size) continue;
                    uint8_t *p = bin->data+s2->offset+(eaddr-s2->vaddr);
                    uint64_t v = (uint64_t)p[0]|((uint64_t)p[1]<<8)|
                                 ((uint64_t)p[2]<<16)|((uint64_t)p[3]<<24)|
                                 ((uint64_t)p[4]<<32)|((uint64_t)p[5]<<40)|
                                 ((uint64_t)p[6]<<48)|((uint64_t)p[7]<<56);
                    if (bin->is_pie && v > 0 && v < bin->image_size) v += bin->base;
                    
                    if (!ivf_addr_is_exec(bin, v)) goto done_handlers;
                    vm_out->handlers[vm_out->n_handlers++] = v;
                    if (vm_out->n_handlers >= 32) goto done_handlers;
                    break;
                }
            }
            done_handlers:;
        }
    }
    return score;
}

void dax_ivf_scan(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int    c    = opts ? opts->color : 1;
    int    si, i;
    (void)((!bin->is_pie && bin->os != DAX_PLAT_WINDOWS)); /* user_space unused */

    const char *CR  = c ? COL_RESET    : "";
    const char *CB  = c ? COL_ADDR     : "";
    const char *CM  = c ? COL_MNEM     : "";
    const char *CD  = c ? COL_COMMENT  : "";
    const char *CY  = c ? COL_LABEL    : "";
    const char *CR2 = c ? "\033[0;31m" : "";
    const char *CO  = c ? "\033[0;33m" : "";
    const char *CG  = c ? "\033[0;32m" : "";

    DAX_GUARD_BIN(bin);
    if (!opts || !out) return;

    g_nivf = 0;

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                 " INSTRUCTION VALIDITY FILTER "
                 "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n");
    if (c) fprintf(out, "%s", CR);
    fprintf(out, "\n");

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
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
            int      len         = 0;
            int      is_nop      = 0, is_int3     = 0, is_uncond   = 0;
            int      is_invalid  = 0, is_indirect = 0, is_sysreg   = 0;
            int      is_str_exec = 0;
            int      is_mul      = 0, is_br_reg   = 0;
            int      is_cmp      = 0, is_tst      = 0, is_rdtsc    = 0;
            int      is_adrp     = 0, is_32bit_wr = 0;

            if (bin->arch == ARCH_ARM64) {
                if (off + 4 > csz) break;
                uint32_t raw = (uint32_t)(code[off])|(code[off+1]<<8)|
                               (code[off+2]<<16)|(code[off+3]<<24);
                a64_insn_t insn; a64_decode(raw, addr, &insn);
                snprintf(mnem, 32, "%s", insn.mnemonic);
                snprintf(ops, 256, "%.255s", insn.operands);
                len         = 4;
                is_nop      = (strcmp(mnem,"nop")==0);
                is_invalid  = (strcmp(mnem,"??")==0 || strcmp(mnem,"dw")==0);
                is_uncond   = (strcmp(mnem,"b")==0  || strcmp(mnem,"br")==0 ||
                               strncmp(mnem,"ret",3)==0);
                
                is_indirect = ((!strcmp(mnem,"br") || !strcmp(mnem,"blr")) &&
                               ops[0]=='x');
                is_sysreg   = (!strcmp(mnem,"mrs") || !strcmp(mnem,"msr"));
                is_str_exec = (!strcmp(mnem,"str") || !strcmp(mnem,"strb") ||
                               !strcmp(mnem,"strh")|| !strcmp(mnem,"stur"));
                is_mul      = (!strcmp(mnem,"mul") || !strcmp(mnem,"madd") ||
                               !strcmp(mnem,"umulh")|| !strcmp(mnem,"smulh"));
                is_br_reg   = (!strcmp(mnem,"br") && ops[0]=='x');
                is_cmp      = (!strcmp(mnem,"cmp") || !strcmp(mnem,"cmn"));
                
                is_tst      = (!strcmp(mnem,"tst") || !strcmp(mnem,"ands"));
                is_adrp     = (!strcmp(mnem,"adrp"));
                
                is_32bit_wr = (mnem[0]!='b' && ops[0]=='w' && ops[1]>'0' && ops[1]<='9');
                
                is_rdtsc    = (is_sysreg && (strstr(ops,"cntvct")!=NULL ||
                               strstr(ops,"CNTVCT")!=NULL ||
                               strstr(ops,"pmccntr")!=NULL));
            } else if (bin->arch == ARCH_RISCV64) {
                rv_insn_t insn;
                len = rv_decode(code + off, csz - off, addr, &insn);
                if (len <= 0) { len = 1; is_invalid = 1; strcpy(mnem,"??"); }
                else {
                    snprintf(mnem, 32, "%s", insn.mnemonic);
                    snprintf(ops, 256, "%.255s", insn.operands);
                    is_nop     = (!strcmp(mnem,"nop") || !strcmp(mnem,"c.nop"));
                    is_uncond  = (!strcmp(mnem,"j") || !strcmp(mnem,"jalr") ||
                                  !strcmp(mnem,"ret") || !strcmp(mnem,"c.j") ||
                                  !strcmp(mnem,"c.jr") || !strcmp(mnem,"c.jalr"));
                    is_invalid = (!strcmp(mnem,"??") || !strcmp(mnem,"c.illegal"));
                    is_indirect= ((!strcmp(mnem,"jalr")||!strcmp(mnem,"c.jalr")||
                                   !strcmp(mnem,"c.jr")) && ops[0]!='z');
                    is_sysreg  = (!strncmp(mnem,"csr",3));
                    is_mul     = (!strncmp(mnem,"mul",3)||!strncmp(mnem,"div",3)||
                                  !strncmp(mnem,"rem",3));
                    is_cmp     = 0;
                    is_rdtsc   = (is_sysreg && (strstr(ops,"cycle")!=NULL ||
                                  strstr(ops,"instret")!=NULL || strstr(ops,"time")!=NULL));
                }
            } else {
                x86_insn_t insn;
                len = x86_decode(code + off, csz - off, addr, &insn);
                if (len <= 0) { len = 1; is_invalid = 1; strcpy(mnem,"??"); }
                else {
                    snprintf(mnem, 32, "%s", insn.mnemonic);
                    snprintf(ops, 256, "%.255s", insn.ops);
                    is_nop      = (strcmp(mnem,"nop")==0);
                    is_int3     = (strcmp(mnem,"int3")==0 || strcmp(mnem,"int")==0);
                    is_uncond   = (strcmp(mnem,"jmp")==0 || strcmp(mnem,"ret")==0 ||
                                   strcmp(mnem,"retq")==0);
                    is_invalid  = (strcmp(mnem,"??")==0);
                    is_indirect = (!strcmp(mnem,"jmp")||!strcmp(mnem,"call")) &&
                                  (ops[0]=='*'||ops[0]=='r'||ops[0]=='e');
                }
            }

            
            if (after_uncond) {
                dax_func_t   *fn  = dax_func_find(bin, addr);
                dax_symbol_t *sym = dax_sym_find(bin, addr);
                if (!fn && !sym) {
                    dead_count++;
                    if (dead_count <= 8) {
                        char detail[64];
                        if (is_invalid)
                            snprintf(detail,64,"data 0x%02x%02x%02x%02x after branch",
                                     code[off],
                                     (off+1<csz)?code[off+1]:0,
                                     (off+2<csz)?code[off+2]:0,
                                     (off+3<csz)?code[off+3]:0);
                        else
                            snprintf(detail,64,"unreachable instruction after branch");
                        ivf_add(addr, IVF_DEAD_AFTER_UNCOND, mnem, detail);
                    }
                    off += (size_t)len;
                    continue;
                }
            }
            after_uncond = 0; dead_count = 0;

            
            if (is_invalid) {
                char detail[64];
                uint32_t r32 = (uint32_t)(code[off]) |
                    ((off+1<csz)?(uint32_t)(code[off+1])<<8:0)  |
                    ((off+2<csz)?(uint32_t)(code[off+2])<<16:0) |
                    ((off+3<csz)?(uint32_t)(code[off+3])<<24:0);
                
                int is_embedded_const = 0;
                if (!strcmp(mnem,"dw") && off >= 4) {
                    uint32_t prw = (uint32_t)(code[off-4])|(code[off-3]<<8)|
                                   (code[off-2]<<16)|(code[off-1]<<24);
                    a64_insn_t pri; a64_decode(prw, addr-4, &pri);
                    
                    if (!strcmp(pri.mnemonic,"movz")||!strcmp(pri.mnemonic,"movk")||
                        !strcmp(pri.mnemonic,"adr") ||!strcmp(pri.mnemonic,"adrp"))
                        is_embedded_const = 1;
                }
                if (is_embedded_const) {
                    snprintf(detail,64,"0x%08x — embedded constant/obfuscated encoding", r32);
                    ivf_add(addr, IVF_INVALID, "embedded", detail);
                } else {
                    snprintf(detail,64,"bytes: 0x%08x", r32);
                    ivf_add(addr, IVF_INVALID, mnem, detail);
                }
            }

            
            if (!is_invalid) {
                int is_priv = (bin->arch == ARCH_ARM64)
                              ? is_privileged_arm64(mnem)
                              : is_privileged_x86(mnem);
                if (is_priv && bin->os != DAX_PLAT_WINDOWS) {
                    char detail[64];
                    snprintf(detail,64,"privileged instruction in user-mode ELF");
                    ivf_add(addr, IVF_PRIVILEGED, mnem, detail);
                }
            }

            
            if (is_indirect && !is_invalid) {
                char detail[64];
                if (bin->arch == ARCH_ARM64)
                    snprintf(detail,64,"target=%s — static target unknown", ops);
                else
                    snprintf(detail,64,"computed target");
                ivf_add(addr, IVF_INDIRECT_BRANCH, mnem, detail);
            }

            
            if (is_sysreg && bin->arch == ARCH_ARM64 &&
                bin->os != DAX_PLAT_WINDOWS) {
                int is_opaque = 0;
                if (off + 12 <= csz) {
                    uint32_t r1 = (uint32_t)(code[off+4])|(code[off+5]<<8)|
                                  (code[off+6]<<16)|(code[off+7]<<24);
                    uint32_t r2 = (uint32_t)(code[off+8])|(code[off+9]<<8)|
                                  (code[off+10]<<16)|(code[off+11]<<24);
                    a64_insn_t n1, n2;
                    a64_decode(r1,addr+4,&n1); a64_decode(r2,addr+8,&n2);
                    if ((!strcmp(n1.mnemonic,"tst")||!strcmp(n1.mnemonic,"cmp")) &&
                        n2.mnemonic[0]=='b' && n2.mnemonic[1]=='.')
                        is_opaque = 1;
                }
                char detail[64];
                if (is_opaque)
                    snprintf(detail,64,"mrs→tst/cmp→b.cond: opaque predicate pattern");
                else
                    snprintf(detail,64,"sysreg read in userspace — likely anti-analysis");
                ivf_add(addr, IVF_OPAQUE_SYSREG, mnem, detail);
            }

            /* ── SMC Pattern Detection (ARM64) ─────────────────────────────────
             * Upgraded: multi-look backward, detects:
             *   1. str/strb/strh with base from adr/adrp into exec region
             *   2. store to self-modifying address derived from PC-relative load
             *   3. xor-then-store: eor + str to exec addr (XOR mutation stub)
             *   4. repeated stores to same exec base (multi-patch loop)      */
            if (is_str_exec && bin->arch == ARCH_ARM64 && !is_invalid && off >= 4) {
                int smc_confirmed = 0;
                char smc_detail[128] = "";

                /* extract store destination base register */
                char str_dst_base[16] = "";
                {
                    const char *bp = strchr(ops, '[');
                    if (bp) {
                        bp++;
                        int bi = 0;
                        while (*bp && *bp != ',' && *bp != ']' && bi < 15)
                            str_dst_base[bi++] = *bp++;
                        str_dst_base[bi] = '\0';
                    }
                }

                /* extract stored source register */
                char str_src_reg[16] = "";
                {
                    const char *sp = ops;
                    int bi = 0;
                    while (*sp && *sp != ',' && bi < 15) str_src_reg[bi++] = *sp++;
                    str_src_reg[bi] = '\0';
                }

                /* look back up to 8 instructions for adr/adrp to exec region */
                int look;
                for (look = 1; look <= 8 && (int)off >= look*4; look++) {
                    uint32_t prw = (uint32_t)(code[off-look*4])  |(code[off-look*4+1]<<8)|
                                              (code[off-look*4+2]<<16)|(code[off-look*4+3]<<24);
                    a64_insn_t pri; a64_decode(prw, addr-(uint64_t)(look*4), &pri);

                    /* pattern 1: adr/adrp dst → exec target */
                    if (!strcmp(pri.mnemonic,"adr") || !strcmp(pri.mnemonic,"adrp")) {
                        char adr_dst[16] = "";
                        { const char *p=pri.operands; int bi=0;
                          while(*p&&*p!=','&&bi<15){adr_dst[bi++]=*p++;} adr_dst[bi]='\0'; }
                        if (str_dst_base[0] && adr_dst[0] &&
                            !strcmp(adr_dst, str_dst_base)) {
                            uint64_t adr_tgt = 0;
                            const char *tp = strstr(pri.operands, "0x");
                            if (tp) adr_tgt = strtoull(tp, NULL, 16);
                            if (adr_tgt > 0 && ivf_addr_is_exec(bin, adr_tgt)) {
                                smc_confirmed = 1;
                                snprintf(smc_detail, sizeof(smc_detail),
                                         "str→adr-derived exec addr 0x%llx — confirmed code mutation",
                                         (unsigned long long)adr_tgt);
                            }
                        }
                        if (look == 1) break; /* first adr found, stop */
                    }

                    /* pattern 2: eor/eon before store → XOR-mutation stub */
                    if ((!strcmp(pri.mnemonic,"eor")||!strcmp(pri.mnemonic,"eon")) &&
                        str_src_reg[0]) {
                        char eor_dst[16]="";
                        { const char *p=pri.operands; int bi=0;
                          while(*p&&*p!=','&&bi<15){eor_dst[bi++]=*p++;} eor_dst[bi]='\0'; }
                        if (!strcmp(eor_dst, str_src_reg)) {
                            /* eor produced the value we're storing — check if dest is exec */
                            /* look further back for adrp that set the base */
                            int look2;
                            for (look2 = look+1; look2 <= look+6 && (int)off >= look2*4; look2++) {
                                uint32_t pw2=(uint32_t)(code[off-look2*4])|(code[off-look2*4+1]<<8)|
                                             (code[off-look2*4+2]<<16)|(code[off-look2*4+3]<<24);
                                a64_insn_t pi2; a64_decode(pw2, addr-(uint64_t)(look2*4), &pi2);
                                if (!strcmp(pi2.mnemonic,"adrp")||!strcmp(pi2.mnemonic,"adr")) {
                                    uint64_t t2=0;
                                    const char *tp2=strstr(pi2.operands,"0x");
                                    if (tp2) t2=strtoull(tp2,NULL,16);
                                    if (t2>0 && ivf_addr_is_exec(bin,t2)) {
                                        smc_confirmed = 1;
                                        snprintf(smc_detail, sizeof(smc_detail),
                                                 "eor+str to exec region — XOR mutation stub (target ~0x%llx)",
                                                 (unsigned long long)t2);
                                    }
                                    break;
                                }
                            }
                            if (!smc_confirmed) {
                                /* eor+str without confirmed target — still suspicious */
                                smc_confirmed = 1;
                                snprintf(smc_detail, sizeof(smc_detail),
                                         "eor→str sequence: XOR-key mutation of stored word");
                            }
                        }
                    }
                }

                /* pattern 3: check if store destination is inside a known poly region */
                if (!smc_confirmed && str_dst_base[0]) {
                    int pri2;
                    for (pri2 = 0; pri2 < bin->npoly_regions; pri2++) {
                        dax_poly_region_t *pr = &bin->poly_regions[pri2];
                        if (addr >= pr->start && addr <= pr->end) {
                            smc_confirmed = 1;
                            snprintf(smc_detail, sizeof(smc_detail),
                                     "store inside poly region 0x%llx-0x%llx — in-place mutation",
                                     (unsigned long long)pr->start,
                                     (unsigned long long)pr->end);
                            break;
                        }
                    }
                }

                /* pattern 4: check emulator real-time SMC log */
                if (!smc_confirmed) {
                    int esi;
                    for (esi = 0; esi < bin->nemu_smc; esi++) {
                        if (bin->emu_smc_write_pc[esi] == addr) {
                            smc_confirmed = 1;
                            snprintf(smc_detail, sizeof(smc_detail),
                                     "confirmed by emulator: str@0x%llx patches exec 0x%llx",
                                     (unsigned long long)addr,
                                     (unsigned long long)bin->emu_smc_target[esi]);
                            break;
                        }
                    }
                }

                if (smc_confirmed) {
                    ivf_add(addr, IVF_SMC_PATTERN, mnem,
                            smc_detail[0] ? smc_detail :
                            "str to exec-derived address — code mutation");
                }
            }

            /* ── SMC: emulator-confirmed writes not yet in symexec log ── */
            if (!is_str_exec && bin->arch == ARCH_ARM64 && !is_invalid) {
                int esi2;
                for (esi2 = 0; esi2 < bin->nemu_smc; esi2++) {
                    if (bin->emu_smc_write_pc[esi2] == addr) {
                        char edet[96];
                        snprintf(edet, sizeof(edet),
                                 "emulator SMC: this instruction patches exec 0x%llx",
                                 (unsigned long long)bin->emu_smc_target[esi2]);
                        ivf_add(addr, IVF_SMC_PATTERN, mnem, edet);
                        break;
                    }
                }
            }

            

            
            {
                
                int is_subs_same = 0;
                if (!strcmp(mnem,"subs")||!strcmp(mnem,"sub")) {
                    char _s1[16]="",_s2[16]=""; const char *_p=ops;
                    {while(*_p&&*_p!=',')_p++;} if(*_p==','){_p++; while(*_p==' ')_p++;}
                    {int _i=0;while(*_p&&*_p!=','&&_i<15){_s1[_i++]=*_p++;}_s1[_i]='\0';}
                    if(*_p==','){_p++; while(*_p==' ')_p++;}
                    {int _i=0;while(*_p&&*_p!=','&&_i<15){_s2[_i++]=*_p++;}_s2[_i]='\0';}
                    is_subs_same=(_s1[0]&&_s2[0]&&!strcmp(_s1,_s2));
                    if (is_subs_same)
                        ivf_add(addr, IVF_OPAQUE_CONST, mnem,
                                "subs xN,xA,xA: always zero — opaque zero subtraction");
                }
            }
            if ((is_cmp || is_tst) && bin->arch == ARCH_ARM64 && !is_invalid) {
                char o1[32]="", o2[32]="";
                const char *p2=ops; char *d=o1; int j=0;
                while(*p2&&*p2!=','&&j<31){*d++=*p2++;j++;} *d='\0';
                if(*p2==','){p2++; while(*p2==' ')p2++; d=o2; j=0;
                    while(*p2&&*p2!=','&&j<31){*d++=*p2++;j++;} *d='\0';}
                
                const char *o2s=o2; if(*o2s=='#')o2s++;
                if (o1[0]&&o2[0]&&!strcmp(o1,o2)) {
                    ivf_add(addr, IVF_OPAQUE_CONST, mnem,
                            "tautology: cmp/tst xN,xN — always equal, branch is opaque");
                }
                
                if (off >= 4) {
                    uint32_t pr = (uint32_t)(code[off-4])|(code[off-3]<<8)|
                                  (code[off-2]<<16)|(code[off-1]<<24);
                    a64_insn_t pi; a64_decode(pr, addr-4, &pi);
                    if (!strcmp(pi.mnemonic,"eor")) {
                        char pe1[16]="",pe2[16]="",pe3[16]="";
                        const char *pp=pi.operands; char *pd=pe1; int pj=0;
                        while(*pp&&*pp!=','&&pj<15){*pd++=*pp++;pj++;} *pd='\0'; if(*pp==',')pp++;
                        {while(*pp==' ')pp++;} pd=pe2; pj=0;
                        while(*pp&&*pp!=','&&pj<15){*pd++=*pp++;pj++;} *pd='\0'; if(*pp==',')pp++;
                        {while(*pp==' ')pp++;} pd=pe3; pj=0;
                        while(*pp&&*pp!=','&&pj<15){*pd++=*pp++;pj++;} *pd='\0';
                        if (pe2[0]&&pe3[0]&&!strcmp(pe2,pe3))
                            ivf_add(addr-4, IVF_OPAQUE_CONST, "eor",
                                    "eor xN,xA,xA — always zero, downstream cmp is opaque");
                    }
                }
            }

            
            if (is_cmp && bin->arch == ARCH_ARM64 && !is_invalid && off >= 12) {
                uint32_t r1=(uint32_t)(code[off-12])|(code[off-11]<<8)|
                            (code[off-10]<<16)|(code[off-9]<<24);
                uint32_t r2=(uint32_t)(code[off-8])|(code[off-7]<<8)|
                            (code[off-6]<<16)|(code[off-5]<<24);
                uint32_t r3=(uint32_t)(code[off-4])|(code[off-3]<<8)|
                            (code[off-2]<<16)|(code[off-1]<<24);
                a64_insn_t p1,p2,p3;
                a64_decode(r1,addr-12,&p1); a64_decode(r2,addr-8,&p2); a64_decode(r3,addr-4,&p3);
                if ((!strcmp(p1.mnemonic,"str")||!strcmp(p1.mnemonic,"stur")) &&
                    (!strcmp(p2.mnemonic,"ldr")||!strcmp(p2.mnemonic,"ldur")) &&
                    (!strcmp(p3.mnemonic,"cmp")||!strcmp(p3.mnemonic,"tst"))) {
                    
                    const char *soff=strstr(p1.operands,"sp,");
                    const char *loff=strstr(p2.operands,"sp,");
                    if (soff&&loff&&!strcmp(soff,loff))
                        ivf_add(addr-12, IVF_OPAQUE_STACK, p1.mnemonic,
                                "str→ldr same sp offset→cmp: stack round-trip opaque predicate");
                }
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid && !strcmp(mnem,"bl")) {
                uint64_t tgt=0;
                if (ops[0]=='0') sscanf(ops,"0x%llx",(unsigned long long*)&tgt);
                if (tgt && tgt > addr && tgt <= addr+8)
                    ivf_add(addr, IVF_THUNK_CHAIN, mnem,
                            "bl to pc+N: thunk / get-PC trick");
            }
            
            if (bin->arch == ARCH_X86_64 && !is_invalid && !strcmp(mnem,"call")) {
                uint64_t tgt=0;
                if (ops[0]=='0') sscanf(ops,"0x%llx",(unsigned long long*)&tgt);
                if (tgt && tgt == addr+5)
                    ivf_add(addr, IVF_THUNK_CHAIN, mnem,
                            "call $+5: classic x86 get-PC thunk");
            }

            
            if (is_mul && bin->arch == ARCH_ARM64 && !is_invalid) {
                
                int ha;
                int found_ldr=0, found_br=0;
                for (ha=1; ha<=6 && off+(size_t)(ha*4)+4<=csz; ha++) {
                    uint32_t hr=(uint32_t)(code[off+ha*4])|(code[off+ha*4+1]<<8)|
                                (code[off+ha*4+2]<<16)|(code[off+ha*4+3]<<24);
                    a64_insn_t hi; a64_decode(hr,addr+(uint64_t)(ha*4),&hi);
                    if (!strcmp(hi.mnemonic,"ldr")&&strstr(hi.operands,"x13,")!=NULL) found_ldr=1;
                    if (!strcmp(hi.mnemonic,"ldr")&&(strstr(hi.operands,"uxtx")!=NULL||
                        strstr(hi.operands,"lsl")!=NULL)) found_ldr=1;
                    if (!strcmp(hi.mnemonic,"br")&&hi.operands[0]=='x') found_br=1;
                }
                if (found_ldr && found_br)
                    ivf_add(addr, IVF_HASH_DISPATCH, mnem,
                            "mul→ldr[table,xN]→br: hash-based dispatch table (computed switch)");
            }

            
            if (is_rdtsc && bin->arch == ARCH_ARM64) {
                int found_cmp=0;
                int ta;
                for (ta=1; ta<=4 && off+(size_t)(ta*4)+4<=csz; ta++) {
                    uint32_t tr=(uint32_t)(code[off+ta*4])|(code[off+ta*4+1]<<8)|
                                (code[off+ta*4+2]<<16)|(code[off+ta*4+3]<<24);
                    a64_insn_t ti; a64_decode(tr,addr+(uint64_t)(ta*4),&ti);
                    if (!strcmp(ti.mnemonic,"sub")||!strcmp(ti.mnemonic,"cmp")||
                        !strcmp(ti.mnemonic,"subs")) found_cmp=1;
                }
                ivf_add(addr, IVF_ANTI_DEBUG_TIMING, mnem,
                        found_cmp ? "cntvct_el0→sub/cmp: timing-based anti-debug probe"
                                  : "cntvct_el0 read in userspace — potential timing probe");
            }
            
            if (bin->arch == ARCH_X86_64 && !is_invalid && !strcmp(mnem,"rdtsc")) {
                ivf_add(addr, IVF_ANTI_DEBUG_TIMING, mnem,
                        "rdtsc: timing-based anti-debug or entropy source");
            }

            if (bin->arch == ARCH_X86_64 && !is_invalid) {
                if (!strcmp(mnem,"cpuid")) {
                    int found_cmp=0;
                    size_t xa; x86_insn_t xi;
                    for (xa=off;;) {
                        int xl=x86_decode(code+xa,csz-xa,addr+(xa-off),&xi);
                        if (xl<=0||xa-off>32) break;
                        xa+=(size_t)xl;
                        if (!strcmp(xi.mnemonic,"cmp")||!strcmp(xi.mnemonic,"test")) { found_cmp=1; break; }
                    }
                    ivf_add(addr, IVF_ANTI_DEBUG_TIMING, mnem,
                            found_cmp ? "cpuid→cmp/test: hypervisor/sandbox detection"
                                      : "cpuid: CPU feature fingerprinting — possible sandbox probe");
                }

                if ((!strcmp(mnem,"xor")||!strcmp(mnem,"sub")) && ops[0]) {
                    char x1[32]="",x2[32]="";
                    const char *xp=ops; char *xd=x1; int xj=0;
                    while(*xp&&*xp!=','&&xj<31){*xd++=*xp++;xj++;} *xd='\0';
                    if (*xp==',') {
                        xp++; while(*xp==' ')xp++; xd=x2; xj=0;
                        while(*xp&&xj<31){*xd++=*xp++;xj++;}
                        *xd='\0';
                    }
                    if (x1[0]&&x2[0]&&!strcmp(x1,x2)) {
                        size_t xa2=off; x86_insn_t xi2;
                        int found_jcc=0;
                        for(;xa2-off<32;){
                            int xl=x86_decode(code+xa2,csz-xa2,addr+(xa2-off),&xi2);
                            if (xl<=0) break;
                            xa2+=(size_t)xl;
                            if (xi2.mnemonic[0]=='j'&&strcmp(xi2.mnemonic,"jmp")) { found_jcc=1; break; }
                        }
                        if (found_jcc)
                            ivf_add(addr, IVF_OPAQUE_CONST, mnem,
                                    "xor/sub reg,reg → jcc: always-zero opaque conditional branch");
                    }
                }

                if (!strcmp(mnem,"mov") && strstr(ops,"[") && strstr(ops,"esp") &&
                    !strstr(ops,"ebp")) {
                    ivf_add(addr, IVF_STACK_PIVOT, mnem,
                            "mov [esp+N],val without frame: possible stack frame manipulation");
                }

                if (!strcmp(mnem,"int") && ops[0]=='3') {
                    if (off>=1 && code[off-1]==0xEB) {
                        ivf_add(addr, IVF_MISALIGNED_DATA, mnem,
                                "jmp+1 skips over int3: anti-debugger byte-sequence trick");
                    }
                }

                if ((!strcmp(mnem,"push")&&strstr(ops,"ebp"))||
                    (!strcmp(mnem,"push")&&strstr(ops,"rbp"))) {
                    size_t xa3=off; x86_insn_t xi3;
                    int xl3=x86_decode(code+xa3,csz-xa3,addr+(xa3-off),&xi3);
                    if(xl3>0 && (!strcmp(xi3.mnemonic,"call")||!strcmp(xi3.mnemonic,"jmp"))) {
                        uint64_t tgt3=0;
                        if(xi3.ops[0]=='0') sscanf(xi3.ops,"0x%llx",(unsigned long long*)&tgt3);
                        if(tgt3 && !ivf_addr_is_exec(bin,tgt3))
                            ivf_add(addr, IVF_INDIRECT_BRANCH, mnem,
                                    "push rbp then call/jmp to non-exec addr: plt/import stub");
                    }
                }

                if (is_mul) {
                    size_t xa4=off; x86_insn_t xi4; int found_idx=0;
                    for(;xa4-off<40;){
                        int xl=x86_decode(code+xa4,csz-xa4,addr+(xa4-off),&xi4);
                        if (xl<=0) break;
                        xa4+=(size_t)xl;
                        if (strstr(xi4.ops,"[") && strstr(xi4.ops,"*")) { found_idx=1; break; }
                    }
                    if(found_idx)
                        ivf_add(addr, IVF_HASH_DISPATCH, mnem,
                                "mul→jmp[base+idx*scale]: x86 hash-indexed dispatch table");
                }

                if (!strcmp(mnem,"nop")&&off+1<csz) {
                    x86_insn_t xi5;
                    int xl5=x86_decode(code+off,csz-off,addr,&xi5);
                    if(xl5>1)
                        ivf_add(addr, IVF_SUSPICIOUS_NOP, mnem,
                                "multi-byte NOP: alignment or anti-disasm padding");
                }

                if (!strcmp(mnem,"lea") && strstr(ops,"rip")) {
                    if (off>=5) {
                        x86_insn_t xi6;
                        int xl6=x86_decode(code+off-5,csz-(off-5),addr-5,&xi6);
                        if(xl6>0 && !strcmp(xi6.mnemonic,"call"))
                            ivf_add(addr, IVF_THUNK_CHAIN, mnem,
                                    "call+lea rip: x86-64 get-PC pattern (PIC base)");
                    }
                }
            }

            
            if (is_adrp && bin->arch == ARCH_ARM64 && !is_invalid) {
                
                if (strstr(ops,"0x0000000000000000")!=NULL || strstr(ops,"0x0 ")!=NULL ||
                    !strcmp(ops+strspn(ops,"x0123456789abcdef ,"),"")) {
                    if (off+8<=csz) {
                        uint32_t ar1=(uint32_t)(code[off+4])|(code[off+5]<<8)|
                                     (code[off+6]<<16)|(code[off+7]<<24);
                        a64_insn_t ai; a64_decode(ar1,addr+4,&ai);
                        if (!strcmp(ai.mnemonic,"ldr")&&strstr(ai.operands,"x0,")!=NULL)
                            ivf_add(addr, IVF_ASLR_PROBE, mnem,
                                    "adrp 0+ldr: reading own load address — ASLR probe or self-check");
                    }
                }
            }

            
            if (is_32bit_wr && bin->arch == ARCH_ARM64 && !is_invalid && off >= 4) {
                uint32_t pr=(uint32_t)(code[off-4])|(code[off-3]<<8)|
                            (code[off-2]<<16)|(code[off-1]<<24);
                a64_insn_t pi; a64_decode(pr,addr-4,&pi);
                
                if (pi.operands[0]=='x' && pi.operands[1]==ops[1]) {
                    ivf_add(addr, IVF_REGISTER_ALIAS, mnem,
                            "w-reg write after x-reg: 32-bit alias to truncate/hide value");
                }
            }

            
            if (is_br_reg && bin->arch == ARCH_ARM64 && !is_invalid && off >= 4) {
                uint32_t pr=(uint32_t)(code[off-4])|(code[off-3]<<8)|
                            (code[off-2]<<16)|(code[off-1]<<24);
                a64_insn_t pi; a64_decode(pr,addr-4,&pi);
                if (!strcmp(pi.mnemonic,"ldr") && strstr(pi.operands,"x30")!=NULL)
                    ivf_add(addr, IVF_RET_TRAMPOLINE, mnem,
                            "ldr x30→br xN: return trampoline — disguised ret for CFG confusion");
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                strncmp(mnem,"b.",2)==0) {
                uint64_t tgt3=0;
                if (ops[0]=='0') sscanf(ops,"0x%llx",(unsigned long long*)&tgt3);
                
                if (tgt3 == addr + 4)
                    ivf_add(addr, IVF_OPAQUE_CONST, mnem,
                            "b.cond to next insn: always-fall opaque conditional");
                
                if (tgt3 && tgt3 > addr && tgt3 <= addr+8 && off+8<=csz) {
                    uint32_t skip_raw=(uint32_t)(code[off+4])|(code[off+5]<<8)|
                                      (code[off+6]<<16)|(code[off+7]<<24);
                    a64_insn_t skip_i; a64_decode(skip_raw,addr+4,&skip_i);
                    
                    if (!strcmp(skip_i.mnemonic,"nop")||!strcmp(skip_i.mnemonic,"hint"))
                        ivf_add(addr, IVF_OPAQUE_CONST, mnem,
                                "b.cond skips nop/hint: trivial opaque guard");
                }
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                !strcmp(mnem,"movz") && off+12<=csz) {
                uint32_t n1r=(uint32_t)(code[off+4])|(code[off+5]<<8)|
                             (code[off+6]<<16)|(code[off+7]<<24);
                uint32_t n2r=(uint32_t)(code[off+8])|(code[off+9]<<8)|
                             (code[off+10]<<16)|(code[off+11]<<24);
                a64_insn_t n1i,n2i;
                a64_decode(n1r,addr+4,&n1i); a64_decode(n2r,addr+8,&n2i);
                if (!strcmp(n1i.mnemonic,"movk")) {
                    
                    int leads_to_br=0; int la;
                    for(la=2;la<=5&&off+(size_t)(la*4)+4<=csz;la++) {
                        uint32_t lar=(uint32_t)(code[off+la*4])|(code[off+la*4+1]<<8)|
                                     (code[off+la*4+2]<<16)|(code[off+la*4+3]<<24);
                        a64_insn_t lai; a64_decode(lar,addr+(uint64_t)(la*4),&lai);
                        if (!strcmp(lai.mnemonic,"br")||!strcmp(lai.mnemonic,"blr"))
                            { leads_to_br=1; break; }
                    }
                    if (leads_to_br)
                        ivf_add(addr, IVF_INDIRECT_BRANCH, mnem,
                                "movz+movk chain→br: assembled constant indirect branch");
                }
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                (!strcmp(mnem,"br")||!strcmp(mnem,"blr")) && ops[0]=='x' &&
                bin->nresolved_indirect > 0) {
                int ri2;
                for (ri2=0; ri2<bin->nresolved_indirect; ri2++) {
                    if (bin->resolved_indirect_from[ri2]==addr) {
                        char det[64];
                        snprintf(det,64,"symexec resolved → 0x%llx",
                                 (unsigned long long)bin->resolved_indirect_to[ri2]);
                        ivf_add(addr, IVF_INDIRECT_BRANCH, mnem, det);
                        break;
                    }
                }
            }

            
            if (bin->nsmc_patches > 0) {
                int pi3;
                for (pi3=0; pi3<bin->nsmc_patches; pi3++) {
                    if (bin->smc_write_pc[pi3]==addr) {
                        char det[96];
                        a64_insn_t new_insn;
                        a64_decode(bin->smc_new_word[pi3],bin->smc_target_addr[pi3],&new_insn);
                        snprintf(det,sizeof(det),"confirmed SMC write -> 0x%llx patches to %s",
                                 (unsigned long long)bin->smc_target_addr[pi3],
                                 new_insn.mnemonic);
                        ivf_add(addr, IVF_SMC_PATTERN, mnem, det);
                        break;
                    }
                    if (bin->smc_target_addr[pi3]==addr) {
                        char det[64];
                        a64_insn_t new_insn;
                        a64_decode(bin->smc_new_word[pi3],addr,&new_insn);
                        snprintf(det,64,"patched by 0x%llx: %s → %s",
                                 (unsigned long long)bin->smc_write_pc[pi3],
                                 mnem, new_insn.mnemonic);
                        ivf_add(addr, IVF_SMC_PATTERN, mnem, det);
                        break;
                    }
                }
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid) {
                dax_func_t *this_fn = dax_func_find(bin, addr);
                if (this_fn) {
                    int fi3;
                    for (fi3=0; fi3<bin->nfunctions; fi3++) {
                        uint64_t other = bin->functions[fi3].start;
                        if (other!=addr && other>addr-4 && other<addr+4) {
                            ivf_add(addr, IVF_OVERLAPPING_INSN, mnem,
                                    "overlapping function entry — misaligned or trampoline");
                            break;
                        }
                    }
                }
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                !strcmp(mnem,"ldr") && strstr(ops,"uxtx") && off+8<=csz) {
                uint32_t n1r=(uint32_t)(code[off+4])|(code[off+5]<<8)|
                             (code[off+6]<<16)|(code[off+7]<<24);
                a64_insn_t n1i; a64_decode(n1r,addr+4,&n1i);
                int br_next=(!strcmp(n1i.mnemonic,"br")&&n1i.operands[0]=='x');
                if (!br_next && off+12<=csz) {
                    uint32_t n2r=(uint32_t)(code[off+8])|(code[off+9]<<8)|
                                 (code[off+10]<<16)|(code[off+11]<<24);
                    a64_insn_t n2i; a64_decode(n2r,addr+8,&n2i);
                    br_next=(!strcmp(n2i.mnemonic,"br")&&n2i.operands[0]=='x');
                }
                if (br_next)
                    ivf_add(addr, IVF_JUMP_TABLE, mnem,
                            "ldr xN,[base,idx,uxtx]+br: computed jump table dispatch");
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid && is_mul && off+8<=csz) {
                uint32_t n1r=(uint32_t)(code[off+4])|(code[off+5]<<8)|
                             (code[off+6]<<16)|(code[off+7]<<24);
                a64_insn_t n1i; a64_decode(n1r,addr+4,&n1i);
                
                if (!strcmp(n1i.mnemonic,"add")) {
                    char mp2[16]="",mp3[16]="";
                    const char *mp=ops;
                    { while(*mp&&*mp!=',')mp++; } if(*mp==','){mp++; while(*mp==' ')mp++;}
                    { int j2=0; char *d2=mp2; while(*mp&&*mp!=','&&j2<15){*d2++=*mp++;j2++;} *d2='\0'; }
                    if(*mp==','){mp++; { while(*mp==' ')mp++; } }
                    { int j2=0; char *d2=mp3; while(*mp&&*mp!=','&&j2<15){*d2++=*mp++;j2++;} *d2='\0'; }
                    if (mp2[0]&&mp3[0]&&!strcmp(mp2,mp3))
                        ivf_add(addr, IVF_OPAQUE_MUL_PARITY, mnem,
                                "mul xA,xB,xB+add: x*(x+1) parity opaque predicate pattern");
                }
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                (is_cmp||!strcmp(mnem,"sub")||!strcmp(mnem,"subs"))) {
                char oo2[16]="",oo3[16]="";
                const char *p3=ops;
                { while(*p3&&*p3!=',')p3++; } if(*p3==','){p3++; while(*p3==' ')p3++;}
                { int j3=0; char *d3=oo2; while(*p3&&*p3!=','&&j3<15){*d3++=*p3++;j3++;} *d3='\0'; }
                if(*p3==','){p3++; { while(*p3==' ')p3++; } }
                { int j3=0; char *d3=oo3; while(*p3&&*p3!=','&&j3<15){*d3++=*p3++;j3++;} *d3='\0'; }
                if (oo2[0]&&oo3[0]&&!strcmp(oo2,oo3)&&
                    (!strcmp(mnem,"sub")||!strcmp(mnem,"subs")))
                    ivf_add(addr, IVF_OPAQUE_SAME_REG, mnem,
                            "sub xN,xA,xA: always zero — opaque zero-value");
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                (!strcmp(mnem,"mov")||!strcmp(mnem,"add"))&&
                ops[0]=='s'&&ops[1]=='p'&&ops[2]==',') {
                
                const char *src_start=ops+3;
                while(*src_start==' ')src_start++;
                if (src_start[0]=='x'||src_start[0]=='w')
                    ivf_add(addr, IVF_STACK_PIVOT, mnem,
                            "mov sp,xN: stack pivot — SP set from general register");
            }

            
            if (is_invalid && bin->arch == ARCH_ARM64 && !after_uncond) {
                
                if (off >= 4) {
                    uint32_t pr=(uint32_t)(code[off-4])|(code[off-3]<<8)|
                                (code[off-2]<<16)|(code[off-1]<<24);
                    a64_insn_t pi; a64_decode(pr,addr-4,&pi);
                    dax_igrp_t pg=dax_classify_arm64(pi.mnemonic);
                    if (pg!=IGRP_BRANCH&&pg!=IGRP_RET) {
                        char det[64];
                        uint32_t raw_w=(uint32_t)(code[off])|(code[off+1]<<8)|
                                       (code[off+2]<<16)|(code[off+3]<<24);
                        snprintf(det,64,"0x%08x not after branch — anti-disasm data",raw_w);
                        ivf_add(addr, IVF_MISALIGNED_DATA, mnem, det);
                    }
                }
            }

            
            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                (!strcmp(mnem,"autia")||!strcmp(mnem,"autib")||
                 !strcmp(mnem,"autia1716")||!strcmp(mnem,"autib1716")||
                 !strcmp(mnem,"autiasp")||!strcmp(mnem,"autiaz")||
                 !strcmp(mnem,"autibsp")||!strcmp(mnem,"autibz"))) {
                char det[64];
                snprintf(det,64,"PAC auth instruction in userspace — CFI bypass possible");
                ivf_add(addr, IVF_PRIVILEGED, mnem, det);
            }

            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                (!strcmp(mnem,"paciza")||!strcmp(mnem,"pacizb")||
                 !strcmp(mnem,"pacdza")||!strcmp(mnem,"pacdzb"))) {
                char det[64];
                snprintf(det,64,"PAC signing with zero key — weak pointer authentication");
                ivf_add(addr, IVF_OPAQUE_CONST, mnem, det);
            }

            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                !strcmp(mnem,"xpaclri") && off >= 4) {
                uint32_t pr=(uint32_t)(code[off-4])|(code[off-3]<<8)|
                            (code[off-2]<<16)|(code[off-1]<<24);
                a64_insn_t pi; a64_decode(pr,addr-4,&pi);
                if (!strncmp(pi.mnemonic,"ldr",3)||!strncmp(pi.mnemonic,"ldp",3))
                    ivf_add(addr, IVF_RET_TRAMPOLINE, mnem,
                            "xpaclri after load: strip PAC then indirect branch — CFI stripping");
            }

            if (bin->arch == ARCH_ARM64 && !is_invalid && off+8<=csz) {
                uint32_t n1r=(uint32_t)(code[off+4])|(code[off+5]<<8)|
                             (code[off+6]<<16)|(code[off+7]<<24);
                a64_insn_t n1i; a64_decode(n1r,addr+4,&n1i);
                if (!strcmp(mnem,"lsr") && !strcmp(n1i.mnemonic,"lsl")) {
                    char op_rd[16]="",op_rd2[16]="";
                    const char *p1=ops,*p2=n1i.operands;
                    { int j=0; while(*p1&&*p1!=','&&j<15){op_rd[j++]=*p1++;} op_rd[j]='\0'; }
                    { int j=0; while(*p2&&*p2!=','&&j<15){op_rd2[j++]=*p2++;} op_rd2[j]='\0'; }
                    if (op_rd[0]&&!strcmp(op_rd,op_rd2))
                        ivf_add(addr, IVF_OPAQUE_CONST, mnem,
                                "lsr+lsl same reg/amount: double shift to hide value via bit masking");
                }
            }

            if (bin->arch == ARCH_ARM64 && !is_invalid && off+16<=csz) {
                uint32_t seq[3];
                a64_insn_t si_arr[3];
                int k2;
                for (k2=0;k2<3;k2++) {
                    seq[k2]=(uint32_t)(code[off+4+k2*4])|(code[off+5+k2*4]<<8)|
                            (code[off+6+k2*4]<<16)|(code[off+7+k2*4]<<24);
                    a64_decode(seq[k2],addr+4+(uint64_t)(k2*4),&si_arr[k2]);
                }
                if (!strcmp(mnem,"bl") &&
                    !strcmp(si_arr[0].mnemonic,"mov") && si_arr[0].operands[0]=='x' &&
                    !strcmp(si_arr[1].mnemonic,"blr")) {
                    ivf_add(addr, IVF_INDIRECT_BRANCH, mnem,
                            "bl→mov xN,x30→blr: call-site return hijack via LR manipulation");
                }
                (void)seq;
            }

            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                !strcmp(mnem,"eor") && off+4<=csz) {
                char e_dst[16]="",e_s1[16]="",e_s2[16]="";
                const char *ep=ops; char *ed=e_dst; int ej=0;
                while(*ep&&*ep!=','&&ej<15){*ed++=*ep++;ej++;} *ed='\0';
                if (*ep==',') ep++;
                while (*ep==' ') ep++;
                ed=e_s1; ej=0;
                while(*ep&&*ep!=','&&ej<15){*ed++=*ep++;ej++;} *ed='\0';
                if (*ep==',') ep++;
                while (*ep==' ') ep++;
                ed=e_s2; ej=0;
                while(*ep&&*ep!=','&&ej<15){*ed++=*ep++;ej++;} *ed='\0';
                if (e_s1[0]&&e_s2[0]&&!strcmp(e_s1,e_s2)) {
                    uint32_t nr2=(uint32_t)(code[off+4])|(code[off+5]<<8)|
                                 (code[off+6]<<16)|(code[off+7]<<24);
                    a64_insn_t ni2; a64_decode(nr2,addr+4,&ni2);
                    if (!strcmp(ni2.mnemonic,"cbnz")||!strcmp(ni2.mnemonic,"cbz")||
                        !strncmp(ni2.mnemonic,"b.",2)) {
                        ivf_add(addr, IVF_OPAQUE_CONST, mnem,
                                "eor xN,xA,xA → cbz/cbnz: zero-EOR opaque branch on constant zero");
                    }
                }
            }

            if (bin->arch == ARCH_ARM64 && !is_invalid &&
                !strcmp(mnem,"csel") && off+4<=csz) {
                char cs1[16]="",cs2[16]="",cs3[16]="";
                const char *cp=ops; char *cd=cs1; int cj=0;
                while(*cp&&*cp!=','&&cj<15){*cd++=*cp++;cj++;} *cd='\0';
                if (*cp==',') cp++;
                while (*cp==' ') cp++;
                cd=cs2; cj=0;
                while(*cp&&*cp!=','&&cj<15){*cd++=*cp++;cj++;} *cd='\0';
                if (*cp==',') cp++;
                while (*cp==' ') cp++;
                cd=cs3; cj=0;
                while(*cp&&*cp!=','&&cj<15){*cd++=*cp++;cj++;} *cd='\0';
                if (cs1[0]&&cs2[0]&&cs3[0]&&!strcmp(cs2,cs3))
                    ivf_add(addr, IVF_OPAQUE_CONST, mnem,
                            "csel xD,xA,xA,cond: both arms identical — opaque select");
            }

            if (bin->arch == ARCH_ARM64 && !is_invalid && off>=8 &&
                !strcmp(mnem,"bl")) {
                uint32_t p1r=(uint32_t)(code[off-8])|(code[off-7]<<8)|
                             (code[off-6]<<16)|(code[off-5]<<24);
                uint32_t p2r=(uint32_t)(code[off-4])|(code[off-3]<<8)|
                             (code[off-2]<<16)|(code[off-1]<<24);
                a64_insn_t pi1,pi2;
                a64_decode(p1r,addr-8,&pi1); a64_decode(p2r,addr-4,&pi2);
                if (!strcmp(pi1.mnemonic,"stp") && strstr(pi1.operands,"x29, x30") &&
                    !strcmp(pi2.mnemonic,"mov") && strstr(pi2.operands,"x29, sp")) {
                    uint64_t tgt4=0;
                    if (ops[0]=='0') sscanf(ops,"0x%llx",(unsigned long long*)&tgt4);
                    if (tgt4 && !ivf_addr_is_exec(bin, tgt4))
                        ivf_add(addr, IVF_INDIRECT_BRANCH, mnem,
                                "proper frame setup then bl to non-exec addr: import stub or lazy binding");
                }
            }

            if (bin->arch == ARCH_RISCV64 && !is_invalid) {
                if (is_indirect) {
                    char det[64];
                    snprintf(det,64,"jalr/c.jr — indirect branch, target computed at runtime: %s",ops);
                    ivf_add(addr, IVF_INDIRECT_BRANCH, mnem, det);
                }

                if (is_rdtsc) {
                    int found_cmp = 0;
                    size_t ta;
                    for (ta=1; ta<=6 && off+(ta*2)+2<=csz; ta++) {
                        rv_insn_t ti;
                        int tl = rv_decode(code+off+ta*2, csz-off-ta*2, addr+ta*2, &ti);
                        if (tl <= 0) break;
                        if (!strcmp(ti.mnemonic,"sub")||!strcmp(ti.mnemonic,"bltu")||
                            !strcmp(ti.mnemonic,"blt")) found_cmp=1;
                    }
                    ivf_add(addr, IVF_ANTI_DEBUG_TIMING, mnem,
                            found_cmp ? "CSR cycle/instret read → compare: timing anti-debug probe"
                                      : "CSR cycle/time read in userspace — potential timing probe");
                }

                if (is_sysreg && off+4<=csz) {
                    rv_insn_t n1; rv_decode(code+off+2, csz-off-2, addr+2, &n1);
                    if (!strncmp(n1.mnemonic,"b",1) && strlen(n1.mnemonic)>=3)
                        ivf_add(addr, IVF_OPAQUE_SYSREG, mnem,
                                "csrr → branch: opaque predicate via CSR read");
                }

                if (!strcmp(mnem,"auipc") && off+4<=csz) {
                    rv_insn_t n1; int nl = rv_decode(code+off, csz-off, addr, &n1);
                    if (nl > 0 && !strcmp(n1.mnemonic,"add") && off+nl+2<=csz) {
                        rv_insn_t n2; rv_decode(code+off+nl, csz-off-nl, addr+nl, &n2);
                        if (!strcmp(n2.mnemonic,"jalr") || !strcmp(n2.mnemonic,"c.jalr"))
                            ivf_add(addr, IVF_THUNK_CHAIN, mnem,
                                    "auipc+add+jalr: position-independent indirect call (get-PC thunk)");
                    }
                }

                if (!strncmp(mnem,"amo",3)) {
                    char det[64];
                    snprintf(det,64,"atomic op %s — possible lock-free anti-tamper or data race",mnem);
                    ivf_add(addr, IVF_DATA_IN_CODE, mnem, det);
                }

                if ((!strcmp(mnem,"mul")||!strcmp(mnem,"mulh")) && off+4<=csz) {
                    rv_insn_t n1; int nl=rv_decode(code+off,csz-off,addr,&n1);
                    if (nl>0 && (!strcmp(n1.mnemonic,"jalr")||!strcmp(n1.mnemonic,"c.jr")))
                        ivf_add(addr, IVF_HASH_DISPATCH, mnem,
                                "mul→jalr: hash-multiply then indirect branch — dispatch table via hash");
                }

                if (is_invalid && !after_uncond && off >= 2) {
                    char det[96];
                    snprintf(det,96,"0x%02x%02x -- invalid encoding not after branch, possible anti-disasm",
                             code[off], (off+1<csz)?code[off+1]:0);
                    ivf_add(addr, IVF_MISALIGNED_DATA, mnem, det);
                }
            }

            if (is_nop) {
                nop_run++;
                if (nop_run == IVF_SUSPICIOUS_NOP_RUN) {
                    char detail[64];
                    snprintf(detail,64,"run of %d+ NOPs — anti-disasm or alignment padding",
                             nop_run);
                    ivf_add(addr-(uint64_t)(nop_run-1)*4,
                            IVF_SUSPICIOUS_NOP, "nop", detail);
                }
            } else { nop_run = 0; }

            
            if (is_int3) {
                int3_run++;
                if (int3_run == IVF_SUSPICIOUS_INT3_RUN) {
                    char detail[64];
                    snprintf(detail,64,"run of %d+ INT3 — padding or breakpoint spray",
                             int3_run);
                    ivf_add(addr-(uint64_t)(int3_run-1),
                            IVF_SUSPICIOUS_INT3, "int3", detail);
                }
            } else { int3_run = 0; }

            if (is_uncond) after_uncond = 1;
            if (dax_func_find(bin, addr+(uint64_t)len) ||
                dax_sym_find(bin,  addr+(uint64_t)len))
                after_uncond = 0;

            off += (size_t)(len > 0 ? len : 1);
        }
    }

    if (g_nivf == 0) {
        fprintf(out, "%s  No suspicious instructions found — all code appears valid.%s\n\n", CG, CR);
        return;
    }

    fprintf(out, "  %s%-10s  %-20s  %-16s  %s%s\n", CM, "Category", "Address", "Mnemonic", "Detail", CR);
    { int j; for(j=0;j<84;j++) fprintf(out,"\u2500"); fprintf(out,"\n"); }

    int n_invalid=0, n_priv=0, n_nop=0, n_dead=0, n_int3=0,
        n_indirect=0, n_smc=0, n_opaque=0;

    for (i = 0; i < g_nivf; i++) {
        ivf_finding_t *f = &g_ivf[i];
        const char *cat_col, *cat_str;

        switch (f->kind) {
            case IVF_INVALID:
                cat_col=CR2; cat_str="INVALID   "; n_invalid++; break;
            case IVF_PRIVILEGED:
                cat_col=CO;  cat_str="PRIV      "; n_priv++;   break;
            case IVF_SUSPICIOUS_NOP:
                cat_col=CD;  cat_str="NOP-RUN   "; n_nop++;    break;
            case IVF_SUSPICIOUS_INT3:
                cat_col=CO;  cat_str="INT3-RUN  "; n_int3++;   break;
            case IVF_DEAD_AFTER_UNCOND:
                cat_col=CR2; cat_str="DEAD      "; n_dead++;   break;
            case IVF_INDIRECT_BRANCH:
                cat_col=CY;  cat_str="INDIRECT  "; n_indirect++; break;
            case IVF_COMPUTED_JUMP:
                cat_col=CY;  cat_str="COMPUTED  "; n_indirect++; break;
            case IVF_SMC_PATTERN:
                cat_col=CR2; cat_str="SMC       "; n_smc++;
                bin->obf_score_smc++;                           break;
            case IVF_OPAQUE_SYSREG:
                cat_col=CO;  cat_str="OPAQUE    "; n_opaque++;
                bin->obf_score_opaque++;                        break;
            case IVF_DATA_IN_CODE:
                cat_col=CR2; cat_str="DATA/CODE "; n_invalid++; break;
            case IVF_OPAQUE_CONST:
                cat_col=CO;  cat_str="OPAQUE-C  "; n_opaque++; break;
            case IVF_OPAQUE_STACK:
                cat_col=CO;  cat_str="OPAQUE-S  "; n_opaque++; break;
            case IVF_THUNK_CHAIN:
                cat_col=CY;  cat_str="THUNK     "; n_indirect++; break;
            case IVF_RET_TRAMPOLINE:
                cat_col=CR2; cat_str="TRAMPOLINE"; n_indirect++; break;
            case IVF_HASH_DISPATCH:
                cat_col=CY;  cat_str="HASH-DISP "; n_indirect++; break;
            case IVF_ANTI_DEBUG_TIMING:
                cat_col=CO;  cat_str="ANTIDEBUG "; n_opaque++;
                bin->obf_score_antidebug++;                     break;
            case IVF_ASLR_PROBE:
                cat_col=CY;  cat_str="ASLR-PROB "; n_opaque++; break;
            case IVF_REGISTER_ALIAS:
                cat_col=CD;  cat_str="REG-ALIAS "; break;
            case IVF_JUMP_TABLE:
                cat_col=CY;  cat_str="JUMP-TBL  "; n_indirect++; break;
            case IVF_OPAQUE_MUL_PARITY:
                cat_col=CO;  cat_str="OPAQUE-MP "; n_opaque++;
                bin->obf_score_opaque++;            break;
            case IVF_OPAQUE_SAME_REG:
                cat_col=CO;  cat_str="OPAQUE-SR "; n_opaque++;
                bin->obf_score_opaque++;            break;
            case IVF_TAINT_PROPAGATION:
                cat_col=CD;  cat_str="TAINT     "; break;
            case IVF_STACK_PIVOT:
                cat_col=CR2; cat_str="STK-PIVOT "; n_indirect++; break;
            case IVF_CONST_BRANCH:
                cat_col=CO;  cat_str="CONST-BR  "; n_opaque++;  break;
            case IVF_MISALIGNED_DATA:
                cat_col=CR2; cat_str="MISALIGN  "; n_invalid++; break;
            default:
                cat_col=CD;  cat_str="OTHER     "; break;
        }

        fprintf(out, "  %s%-10s%s  %s0x%016llx%s  %s%-16s%s  %s%s%s\n",
                cat_col, cat_str, CR,
                CB, (unsigned long long)f->addr, CR,
                CM, f->mnem, CR,
                CD, f->detail, CR);
    }

    fprintf(out, "\n");
    fprintf(out, "%s  Summary:%s", CD, CR);
    if (n_invalid)  fprintf(out, "  %sinvalid=%d%s",    CR2, n_invalid,  CR);
    if (n_priv)     fprintf(out, "  %spriv=%d%s",       CO,  n_priv,     CR);
    if (n_dead)     fprintf(out, "  %sdead=%d%s",       CR2, n_dead,     CR);
    if (n_indirect) fprintf(out, "  %sindirect=%d%s",   CY,  n_indirect, CR);
    if (n_smc)      fprintf(out, "  %sSMC=%d%s",        CR2, n_smc,      CR);
    if (n_opaque)   fprintf(out, "  %sopaque=%d%s",     CO,  n_opaque,   CR);
    if (n_nop)      fprintf(out, "  %snop-runs=%d%s",   CD,  n_nop,      CR);
    if (n_int3)     fprintf(out, "  %sint3-runs=%d%s",  CO,  n_int3,     CR);
    fprintf(out, "\n");

    
    if (bin->nresolved_indirect > 0) {
        int ri;
        fprintf(out, "%s  Resolved indirect branches (from symexec):%s\n", CY, CR);
        for (ri = 0; ri < bin->nresolved_indirect; ri++) {
            fprintf(out, "    %s0x%016llx%s  br → %s0x%016llx%s\n",
                    CB, (unsigned long long)bin->resolved_indirect_from[ri], CR,
                    CG, (unsigned long long)bin->resolved_indirect_to[ri], CR);
        }
        fprintf(out, "\n");
    }

    
    if (bin->nsmc_patches > 0) {
        int pi2;
        fprintf(out, "%s  SMC patches (from symexec simulation):%s\n", CR2, CR);
        for (pi2 = 0; pi2 < bin->nsmc_patches; pi2++) {
            a64_insn_t oi, ni;
            a64_decode(bin->smc_old_word[pi2], bin->smc_target_addr[pi2], &oi);
            a64_decode(bin->smc_new_word[pi2], bin->smc_target_addr[pi2], &ni);
            fprintf(out, "    %s0x%016llx%s  [%s0x%08x%s %s%-8s%s] → [%s0x%08x%s %s%-8s%s]\n",
                    CB, (unsigned long long)bin->smc_target_addr[pi2], CR,
                    CD, bin->smc_old_word[pi2], CR, CM, oi.mnemonic, CR,
                    CG, bin->smc_new_word[pi2], CR, CG, ni.mnemonic, CR);
        }
        fprintf(out, "\n");
    }

    /* ── Emulator real-time SMC log ── */
    if (bin->nemu_smc > 0) {
        int ei;
        fprintf(out, "%s  SMC writes (emulator real-time capture):%s\n", CR2, CR);
        for (ei = 0; ei < bin->nemu_smc; ei++) {
            fprintf(out, "    write@%s0x%016llx%s → exec %s0x%016llx%s\n",
                    CB, (unsigned long long)bin->emu_smc_write_pc[ei], CR,
                    CG, (unsigned long long)bin->emu_smc_target[ei],   CR);
        }
        fprintf(out, "\n");
    }

    /* ── Mutation chains (addresses written multiple times) ── */
    if (bin->nsmc_chains > 0) {
        int ci2;
        fprintf(out, "%s  SMC mutation chains (addr written ≥2×):%s\n", CR2, CR);
        for (ci2 = 0; ci2 < bin->nsmc_chains; ci2++) {
            fprintf(out, "    %s0x%016llx%s  patched %s%d×%s — probable polymorphic loop\n",
                    CB, (unsigned long long)bin->smc_chain_addr[ci2], CR,
                    CR2, bin->smc_chain_count[ci2], CR);
        }
        fprintf(out, "\n");
    }

    
    {
        int total_score = bin->obf_score_smc * 3 +
                          bin->obf_score_opaque * 2 +
                          bin->obf_score_indirect +
                          bin->obf_score_antidebug * 2;
        const char *grade_col, *grade;
        if      (total_score == 0)  { grade_col=CG;  grade="CLEAN   — no obfuscation detected"; }
        else if (total_score <= 3)  { grade_col=CG;  grade="LOW     — minimal obfuscation"; }
        else if (total_score <= 8)  { grade_col=CO;  grade="MEDIUM  — moderate obfuscation"; }
        else if (total_score <= 16) { grade_col=CO;  grade="HIGH    — heavily obfuscated"; }
        else                        { grade_col=CR2; grade="EXTREME — professional obfuscation/packer"; }
        fprintf(out, "%s  Obfuscation score: %d  [%s%s%s]%s\n",
                CD, total_score, grade_col, grade, CD, CR);
        fprintf(out, "%s  Components:%s",CD,CR);
        if (bin->obf_score_smc)       fprintf(out, "  SMC×3=%d",    bin->obf_score_smc*3);
        if (bin->obf_score_opaque)    fprintf(out, "  opaque×2=%d", bin->obf_score_opaque*2);
        if (bin->obf_score_indirect)  fprintf(out, "  indirect=%d", bin->obf_score_indirect);
        if (bin->obf_score_antidebug) fprintf(out, "  antidebug×2=%d", bin->obf_score_antidebug*2);
        if (total_score==0) fprintf(out,"  none");
        fprintf(out, "\n");
    }

    
    {
        int vm_found = 0;
        int fi;
        for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
            vm_info_t vm; memset(&vm, 0, sizeof(vm));
            int score = dax_detect_vm(bin, fi, &vm);
            if (score < 4) continue;
            if (!vm_found) {
                fprintf(out, "\n");
                if (c) fprintf(out, "%s", COL_FUNC);
                fprintf(out, "  ══════════════ VM DISPATCH DETECTION ══════════════\n");
                if (c) fprintf(out, "%s", COL_RESET);
                vm_found = 1;
            }
            const char *CB = c ? "\033[1;34m" : "";
            const char *CY = c ? "\033[1;33m" : "";
            const char *CG = c ? "\033[1;32m" : "";
            const char *CR2= c ? COL_RESET    : "";
            fprintf(out, "\n  %s[VM_DISPATCH]%s  func=%s%s%s  score=%d/6\n",
                    CY, CR2, CB, bin->functions[fi].name[0]
                    ? bin->functions[fi].name : "?", CR2, score);
            if (vm.dispatch_pc)
                fprintf(out, "    dispatch br  : %s0x%016llx%s\n",
                        CB, (unsigned long long)vm.dispatch_pc, CR2);
            if (vm.table_base)
                fprintf(out, "    table base   : %s0x%016llx%s\n",
                        CB, (unsigned long long)vm.table_base, CR2);
            if (vm.n_handlers > 0) {
                int hi;
                fprintf(out, "    handlers (%d) :", vm.n_handlers);
                for (hi = 0; hi < vm.n_handlers; hi++) {
                    
                    dax_symbol_t *sym = dax_sym_find(bin, vm.handlers[hi]);
                    dax_func_t   *fn2 = dax_func_find(bin, vm.handlers[hi]);
                    const char *label = sym ? (sym->demangled[0]?sym->demangled:sym->name)
                                            : (fn2 ? fn2->name : NULL);
                    fprintf(out, "\n      [%d] %s0x%llx%s", hi,
                            CG, (unsigned long long)vm.handlers[hi], CR2);
                    if (label && label[0])
                        fprintf(out, " <%s>", label);
                }
                fprintf(out, "\n");
            }
            
            if (vm.dispatch_pc && vm.n_handlers > 0 && bin->nresolved_indirect < 128) {
                int hi;
                for (hi = 0; hi < vm.n_handlers && bin->nresolved_indirect < 128; hi++) {
                    int dup = 0, di;
                    for (di = 0; di < bin->nresolved_indirect; di++)
                        if (bin->resolved_indirect_from[di] == vm.dispatch_pc &&
                            bin->resolved_indirect_to[di]   == vm.handlers[hi])
                            { dup = 1; break; }
                    if (!dup) {
                        bin->resolved_indirect_from[bin->nresolved_indirect] = vm.dispatch_pc;
                        bin->resolved_indirect_to[bin->nresolved_indirect]   = vm.handlers[hi];
                        bin->nresolved_indirect++;
                    }
                }
            }
        }
        if (!vm_found) {
            
        }
    }

    {
        int i2;
        int has_chains = 0;
        for (i2 = 0; i2 < g_nivf; i2++) {
            ivf_finding_t *f = &g_ivf[i2];
            if (f->kind != IVF_INDIRECT_BRANCH && f->kind != IVF_HASH_DISPATCH &&
                f->kind != IVF_RET_TRAMPOLINE  && f->kind != IVF_THUNK_CHAIN    &&
                f->kind != IVF_VM_DISPATCH      && f->kind != IVF_JUMP_TABLE     &&
                f->kind != IVF_SMC_PATTERN)
                continue;
            if (!has_chains) {
                fprintf(out, "\n");
                if (c) fprintf(out, "%s", COL_FUNC);
                fprintf(out,
                    "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                    " CONTROL FLOW MOVEMENT TRACE "
                    "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n");
                if (c) fprintf(out, "%s", COL_RESET);
                fprintf(out, "\n  %sWhat is the code doing at each suspicious transfer?%s\n\n",
                        CD, CR);
                has_chains = 1;
            }

            dax_func_t   *fn_ctx  = dax_func_find(bin, f->addr);
            dax_symbol_t *sym_ctx = dax_sym_find(bin,  f->addr);
            const char *ctx_name  = fn_ctx  ? fn_ctx->name
                                  : sym_ctx ? (sym_ctx->demangled[0] ? sym_ctx->demangled : sym_ctx->name)
                                  : NULL;

            fprintf(out, "  %s0x%016llx%s", CB, (unsigned long long)f->addr, CR);
            if (ctx_name && ctx_name[0])
                fprintf(out, "  %s<%s>%s", CY, ctx_name, CR);
            fprintf(out, "\n");

            switch (f->kind) {
            case IVF_INDIRECT_BRANCH:
                fprintf(out, "    %sWHAT:%s  Indirect branch — target computed at runtime%s\n", CM, CR, CR);
                fprintf(out, "    %sWHY:%s   The destination is not fixed in the binary. "
                        "May be a vtable call, function pointer, dispatch table, or obfuscated jump.%s\n", CM, CR, CR);
                if (strstr(f->detail, "symexec resolved"))
                    fprintf(out, "    %sRESOLVED:%s %s%s%s\n", CG, CR, CG, f->detail, CR);
                else
                    fprintf(out, "    %sSTATUS:%s  Unresolved — run with -P (symbolic exec) to attempt resolution%s\n", CO, CR, CR);
                break;
            case IVF_THUNK_CHAIN:
                fprintf(out, "    %sWHAT:%s  get-PC thunk — function calls itself+N to read instruction pointer%s\n", CM, CR, CR);
                fprintf(out, "    %sWHY:%s   Classic position-independent code trick. "
                        "The return address on stack becomes the PC value, "
                        "then used as base for ASLR-aware address calculation.%s\n", CM, CR, CR);
                fprintf(out, "    %sMOVEMENT:%s  call → push ret-addr → pop into reg → use as base → indirect jump%s\n", CY, CR, CR);
                break;
            case IVF_RET_TRAMPOLINE:
                fprintf(out, "    %sWHAT:%s  Return trampoline — ldr x30 then br xN disguises a function return%s\n", CM, CR, CR);
                fprintf(out, "    %sWHY:%s   Confuses CFG reconstruction tools that track real `ret` instructions. "
                        "The code transfers control like a ret but looks like an indirect branch.%s\n", CM, CR, CR);
                fprintf(out, "    %sMOVEMENT:%s  load link-reg from memory → branch to it → CFG sees indirect, not ret%s\n", CY, CR, CR);
                break;
            case IVF_HASH_DISPATCH:
                fprintf(out, "    %sWHAT:%s  Hash-based dispatch — value hashed/multiplied → used as table index → indirect jump%s\n", CM, CR, CR);
                fprintf(out, "    %sWHY:%s   Common in VM interpreters and obfuscators. "
                        "The opcode (bytecode value) is hashed and used to index a handler table.%s\n", CM, CR, CR);
                fprintf(out, "    %sMOVEMENT:%s  load-bytecode → mul/hash → ldr handler[hash] → br handler%s\n", CY, CR, CR);
                break;
            case IVF_JUMP_TABLE:
                fprintf(out, "    %sWHAT:%s  Computed jump table — ldr with scaled index → br%s\n", CM, CR, CR);
                fprintf(out, "    %sWHY:%s   Switch statement compiled to a jump table. "
                        "Each case maps to a handler address stored in a read-only table.%s\n", CM, CR, CR);
                fprintf(out, "    %sMOVEMENT:%s  bounds-check → load table[index * ptr_size] → br target%s\n", CY, CR, CR);
                break;
            case IVF_SMC_PATTERN:
                fprintf(out, "    %sWHAT:%s  Self-modifying code — writing to executable memory%s\n", CM, CR, CR);
                fprintf(out, "    %sWHY:%s   The code is rewriting its own instructions at runtime. "
                        "Could be: unpacking (decrypting code into place), "
                        "anti-debug patching, or mutation obfuscation.%s\n", CM, CR, CR);
                if (strstr(f->detail, "confirmed"))
                    fprintf(out, "    %sCONFIRMED:%s symexec traced the write — see SMC patches above%s\n", CR2, CR, CR);
                else
                    fprintf(out, "    %sMOVEMENT:%s  str to adr-derived exec addr → instruction cache invalidate → execute patched code%s\n", CY, CR, CR);
                break;
            case IVF_VM_DISPATCH:
                fprintf(out, "    %sWHAT:%s  VM dispatcher — bytecode interpreter main loop detected%s\n", CM, CR, CR);
                fprintf(out, "    %sWHY:%s   A full virtual machine is running inside this binary. "
                        "Real logic is hidden inside bytecode — static analysis of native code "
                        "reveals only the VM infrastructure, not the actual program logic.%s\n", CM, CR, CR);
                fprintf(out, "    %sMOVEMENT:%s  fetch-opcode → increment-IP → decode → hash/index → dispatch → execute-handler → loop%s\n", CY, CR, CR);
                break;
            default:
                break;
            }

            {
                int xr;
                for (xr = 0; xr < bin->nxrefs && xr < DAX_MAX_XREFS; xr++) {
                    if (bin->xrefs[xr].to == f->addr) {
                        dax_func_t *caller_fn = dax_func_find(bin, bin->xrefs[xr].from);
                        fprintf(out, "    %sCALLED FROM:%s  0x%016llx%s%s%s%s\n",
                                CD, CR,
                                (unsigned long long)bin->xrefs[xr].from,
                                caller_fn && caller_fn->name[0] ? "  <" : "",
                                caller_fn && caller_fn->name[0] ? caller_fn->name : "",
                                caller_fn && caller_fn->name[0] ? ">" : "",
                                CR);
                        break;
                    }
                }
            }
            fprintf(out, "\n");
        }
    }
    fprintf(out, "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * dax_poly_map — Polymorphic Obfuscation Mapping
 *
 * Scans every code section for clusters of anomalies that together signal
 * polymorphic code:
 *   • high ratio of indirect branches in a small window
 *   • NOP sleds interleaved with active code (junk insertion)
 *   • opcode substitution signature: several instructions with the same
 *     semantic output but different encodings within N bytes
 *   • mutating constants: sequences of movz/movk that produce values that
 *     could be arithmetic transforms of a simpler constant (obfuscated imm)
 *   • dead code density > threshold after unconditional branches
 *
 * Detected regions are stored in bin->poly_regions[] and printed.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define POLY_WINDOW       48      /* bytes per analysis window — tighter for ARM64 */
#define POLY_SCORE_THRESH  3      /* minimum score to flag as polymorphic           */

/* ── poly_entropy8 — 8-byte windowed Shannon entropy approximation ── */
static int poly_entropy8(const uint8_t *buf, size_t n) {
    if (n == 0) return 0;
    int freq[256] = {0};
    size_t i;
    for (i = 0; i < n; i++) freq[buf[i]]++;
    /* return count of distinct byte values — cheap entropy proxy */
    int distinct = 0;
    for (i = 0; i < 256; i++) if (freq[i]) distinct++;
    return distinct;
}

/* ── poly_is_xor_mutation ─────────────────────────────────────────────────────
 * Detect XOR-based polymorphic decryption loops:
 *   ldr/ldrb  rN, [base + off]
 *   eor       rN, rN, key
 *   str/strb  rN, [base + off]
 * Returns 1 if the pattern is found in the window.                            */
static int poly_is_xor_mutation(const uint8_t *code, size_t off, size_t csz, uint64_t base) {
    int xor_count = 0, load_count = 0, store_count = 0;
    size_t wend = off + 48;
    if (wend > csz) wend = csz;
    size_t woff = off;
    while (woff + 4 <= wend) {
        uint32_t raw = (uint32_t)code[woff]|(code[woff+1]<<8)|
                       (code[woff+2]<<16)|(code[woff+3]<<24);
        a64_insn_t insn; a64_decode(raw, base + woff, &insn);
        const char *m = insn.mnemonic;
        if (!strncmp(m,"ldr",3)||!strncmp(m,"ldur",4)) load_count++;
        if (!strncmp(m,"str",3)||!strncmp(m,"stur",4)) store_count++;
        if (!strcmp(m,"eor")||!strcmp(m,"eon"))         xor_count++;
        woff += 4;
    }
    return (xor_count >= 1 && load_count >= 1 && store_count >= 1) ? 1 : 0;
}

/* ── poly_is_hash_chain ───────────────────────────────────────────────────────
 * Detect hash/checksum mutation chains: sequences of
 *   add / mul / ror / lsl / eor applied to the same dest register.
 * Returns count of chained operations.                                        */
static int poly_hash_chain_depth(const uint8_t *code, size_t off, size_t csz, uint64_t base) {
    size_t wend = off + 64;
    if (wend > csz) wend = csz;
    size_t woff = off;
    int chain_reg = -1, depth = 0;
    while (woff + 4 <= wend) {
        uint32_t raw = (uint32_t)code[woff]|(code[woff+1]<<8)|
                       (code[woff+2]<<16)|(code[woff+3]<<24);
        a64_insn_t insn; a64_decode(raw, base + woff, &insn);
        const char *m = insn.mnemonic;
        const char *o = insn.operands;
        int rd = -1;
        if ((o[0]=='x'||o[0]=='w') && o[1]>='0' && o[1]<='9') rd = atoi(o+1);
        int is_arith = (!strcmp(m,"add")||!strcmp(m,"mul")||!strcmp(m,"ror")||
                        !strcmp(m,"lsl")||!strcmp(m,"lsr")||!strcmp(m,"eor")||
                        !strcmp(m,"orr")||!strcmp(m,"and")||!strcmp(m,"madd")||
                        !strcmp(m,"umulh")||!strcmp(m,"smulh")||!strcmp(m,"extr")||
                        !strcmp(m,"ror"));
        if (is_arith && rd >= 0) {
            if (chain_reg < 0) { chain_reg = rd; depth = 1; }
            else if (rd == chain_reg) depth++;
            else { if (depth >= 3) break; chain_reg = rd; depth = 1; }
        }
        woff += 4;
    }
    return depth;
}

void dax_poly_map(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int c = opts ? opts->color : 1;
    int si;

    const char *CTitle = c ? "\033[1;36m"  : "";
    const char *CAddr  = c ? "\033[1;34m"  : "";
    const char *CWarn  = c ? "\033[1;33m"  : "";
    const char *CGood  = c ? "\033[1;32m"  : "";
    const char *CDim   = c ? "\033[0;90m"  : "";
    const char *CRed   = c ? "\033[1;31m"  : "";
    const char *CR     = c ? "\033[0m"     : "";

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", CTitle);
    fprintf(out, "  ══════════════ POLYMORPHIC OBFUSCATION MAP ══════════════\n");
    if (c) fprintf(out, "%s", CR);
    fprintf(out, "\n");

    bin->npoly_regions = 0;
    int total_flagged = 0;

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        if (sec->type != SEC_TYPE_CODE) continue;
        if (sec->size == 0 || sec->offset + sec->size > bin->size) continue;

        uint8_t  *code = bin->data + sec->offset;
        size_t    csz  = sec->size;
        uint64_t  base = sec->vaddr;

        fprintf(out, "  %ssection%s  %-16s  %s0x%llx%s .. %s0x%llx%s  (%zu bytes)\n",
                CDim, CR,
                sec->name[0] ? sec->name : "?",
                CAddr, (unsigned long long)base, CR,
                CAddr, (unsigned long long)(base + csz), CR,
                csz);

        size_t off = 0;
        int    region_open = 0;
        uint64_t region_start = 0;
        int    region_score   = 0;
        char   region_techniques[512] = "";
        char   region_obfuscator[48]  = "";

        while (off < csz) {
            size_t   wend  = off + POLY_WINDOW;
            if (wend > csz) wend = csz;
            uint64_t waddr = base + off;

            int score            = 0;
            int n_indirect       = 0;
            int n_nop            = 0;
            int n_dead           = 0;
            int n_movk_chain     = 0;
            int n_identical_op   = 0;
            int n_opaque         = 0;
            int n_xor_arith      = 0;    /* eor/eon used in arithmetic context */
            int n_ror_extr       = 0;    /* ror/extr — rotation obf */
            int n_data_dep_br    = 0;    /* tbz/tbnz on computed regs */
            int n_antidebug      = 0;    /* mrs/msr sysreg in window */
            int n_subst_chain    = 0;    /* reg written then same reg as src */
            int last_was_uncond  = 0;
            int prev_output_reg  = -1;
            int prev_mnem_hash   = 0;

            size_t woff = off;
            while (woff < wend) {
                uint64_t addr = base + woff;
                char  m[32]="", ops[128]="";
                int   len = 4;

                if (bin->arch == ARCH_ARM64) {
                    if (woff + 4 > csz) break;
                    uint32_t raw = (uint32_t)code[woff]|(code[woff+1]<<8)|
                                   (code[woff+2]<<16)|(code[woff+3]<<24);
                    a64_insn_t insn; a64_decode(raw, addr, &insn);
                    snprintf(m, 32, "%s", insn.mnemonic);
                    snprintf(ops, 128, "%.127s", insn.operands);
                    len = 4;

                    if (!strcmp(m,"nop"))                       n_nop++;
                    if ((!strcmp(m,"br")||!strcmp(m,"blr"))
                        && ops[0]=='x')                         n_indirect++;
                    if (last_was_uncond) {
                        dax_func_t *ff = dax_func_find(bin, addr);
                        if (!ff)                                n_dead++;
                    }
                    last_was_uncond = (!strcmp(m,"b")||!strcmp(m,"br")||
                                       !strncmp(m,"ret",3));

                    if (!strcmp(m,"movk"))                      n_movk_chain++;
                    if (!strcmp(m,"mrs")||!strcmp(m,"msr"))     n_antidebug++;
                    if (!strcmp(m,"eor")||!strcmp(m,"eon"))     n_xor_arith++;
                    if (!strcmp(m,"ror")||!strcmp(m,"extr"))    n_ror_extr++;
                    if (!strcmp(m,"tbz")||!strcmp(m,"tbnz")) {
                        /* data-dependent branch: check if tested reg was recently computed */
                        char tbreg[8]="";
                        const char *tp=ops; int ti=0;
                        while(*tp&&*tp!=','&&ti<7){tbreg[ti++]=*tp++;} tbreg[ti]='\0';
                        int tbr=-1;
                        if ((tbreg[0]=='x'||tbreg[0]=='w')&&tbreg[1]>='0')
                            tbr=atoi(tbreg+1);
                        if (tbr>=0 && tbr==prev_output_reg) n_data_dep_br++;
                    }

                    /* substitution chain: same dest written consecutively */
                    int dreg = -1;
                    if (ops[0]=='x'||ops[0]=='w')
                        dreg = atoi(ops+1);
                    if (dreg >= 0 && dreg == prev_output_reg &&
                        strcmp(m,"nop")!=0)                     n_identical_op++;

                    /* substitution chain: source == previous dest (def-use chain of depth≥2) */
                    {
                        const char *p2 = strchr(ops,',');
                        if (p2) {
                            p2++; while(*p2==' ')p2++;
                            int sreg=-1;
                            if((*p2=='x'||*p2=='w')&&p2[1]>='0') sreg=atoi(p2+1);
                            if (sreg>=0 && sreg==prev_output_reg) n_subst_chain++;
                        }
                    }

                    /* simple mnemonic hash to detect opaque repetition */
                    int mh = (int)(m[0]*7 + m[1]*3 + m[2]);
                    if (mh == prev_mnem_hash && !strcmp(m,"mrs")) n_opaque++;
                    prev_mnem_hash = mh;
                    prev_output_reg = dreg;

                } else if (bin->arch == ARCH_RISCV64) {
                    rv_insn_t ri;
                    len = rv_decode(code+woff, csz-woff, addr, &ri);
                    if (len <= 0) { len = 2; woff += 2; continue; }
                    snprintf(m, 32, "%s", ri.mnemonic);
                    snprintf(ops, 128, "%.127s", ri.operands);
                    if (!strcmp(m,"nop")||!strcmp(m,"c.nop"))   n_nop++;
                    if (!strcmp(m,"jalr")||!strcmp(m,"c.jalr")||
                        !strcmp(m,"c.jr"))                      n_indirect++;
                    if (!strncmp(m,"xor",3))                    n_xor_arith++;
                    if (!strncmp(m,"ror",3))                    n_ror_extr++;
                    last_was_uncond = (!strcmp(m,"j")||!strcmp(m,"jalr")||
                                       !strcmp(m,"ret"));
                    if (last_was_uncond) n_dead++;

                } else {
                    x86_insn_t xi;
                    len = x86_decode(code+woff, csz-woff, addr, &xi);
                    if (len <= 0) { len = 1; woff++; continue; }
                    snprintf(m, 32, "%s", xi.mnemonic);
                    snprintf(ops, 128, "%.127s", xi.ops);
                    if (!strcmp(m,"nop"))                       n_nop++;
                    if ((!strcmp(m,"jmp")||!strcmp(m,"call"))&&
                        (ops[0]=='*'||ops[0]=='r'))             n_indirect++;
                    if (!strcmp(m,"xor")||!strcmp(m,"xorps"))   n_xor_arith++;
                    if (!strcmp(m,"ror")||!strcmp(m,"rol"))      n_ror_extr++;
                    last_was_uncond = (!strcmp(m,"jmp")||!strcmp(m,"ret")||
                                       !strcmp(m,"retq"));
                }
                woff += (size_t)len;
            }

            /* ── XOR-mutation and hash-chain passes (ARM64 only) ── */
            int has_xor_mut   = 0;
            int hash_depth    = 0;
            int byte_entropy  = 0;
            if (bin->arch == ARCH_ARM64 && wend > off) {
                has_xor_mut  = poly_is_xor_mutation(code, off, csz, base);
                hash_depth   = poly_hash_chain_depth(code, off, csz, base);
                byte_entropy = poly_entropy8(code + off, wend - off);
            }

            /* ── Scoring ── */
            if (n_indirect    >= 2) score += 2;
            if (n_indirect    >= 4) score += 1; /* extra for dense indirect */
            if (n_nop         >= 4) score += 1;
            if (n_dead        >= 3) score += 2;
            if (n_movk_chain  >= 3) score += 1;
            if (n_movk_chain  >= 6) score += 1; /* very dense const obf */
            if (n_opaque      >= 2) score += 2;
            if (n_identical_op>= 2) score += 1;
            if (n_xor_arith   >= 2) score += 1;
            if (n_xor_arith   >= 4) score += 1; /* saturated XOR */
            if (n_ror_extr    >= 2) score += 1;
            if (n_data_dep_br >= 1) score += 1; /* data-dep branch = obf gate */
            if (n_antidebug   >= 1) score += 1;
            if (n_subst_chain >= 3) score += 1;
            if (has_xor_mut)        score += 3; /* XOR mutation loop = strong signal */
            if (hash_depth    >= 4) score += 2; /* deep arithmetic chain */
            if (hash_depth    >= 8) score += 1;
            if (byte_entropy  >= 220) score += 1; /* near-random bytes in code = packed */

            if (score >= POLY_SCORE_THRESH) {
                if (!region_open) {
                    region_open  = 1;
                    region_start = waddr;
                    region_score = 0;
                    region_techniques[0] = '\0';
                    region_obfuscator[0] = '\0';
                }
                if (score > region_score) region_score = score;

                /* build technique string */
                char tbuf[512] = "";
                if (n_indirect    >= 2)  strncat(tbuf, "indirect-dispatch ",    500);
                if (n_nop         >= 4)  strncat(tbuf, "nop-junk ",             500);
                if (n_dead        >= 3)  strncat(tbuf, "dead-code ",            500);
                if (n_movk_chain  >= 3)  strncat(tbuf, "const-obfuscation ",    500);
                if (n_opaque      >= 2)  strncat(tbuf, "opaque-predicate ",     500);
                if (n_identical_op>= 2)  strncat(tbuf, "opcode-subst ",         500);
                if (n_xor_arith   >= 2)  strncat(tbuf, "xor-arith ",            500);
                if (n_ror_extr    >= 2)  strncat(tbuf, "rotation-obf ",         500);
                if (n_data_dep_br >= 1)  strncat(tbuf, "data-dep-branch ",      500);
                if (n_antidebug   >= 1)  strncat(tbuf, "antidebug-gate ",       500);
                if (n_subst_chain >= 3)  strncat(tbuf, "subst-chain ",          500);
                if (has_xor_mut)         strncat(tbuf, "xor-mutation-loop ",    500);
                if (hash_depth    >= 4)  strncat(tbuf, "hash-chain ",           500);
                if (byte_entropy  >= 220)strncat(tbuf, "high-entropy ",         500);
                if (tbuf[0] && !region_techniques[0])
                    snprintf(region_techniques, 512, "%.511s", tbuf);
                else if (tbuf[0]) {
                    size_t _cur = strlen(region_techniques);
                    if (_cur < 511)
                        snprintf(region_techniques + _cur, 512 - _cur, "%.511s", tbuf);
                }

                /* ── Obfuscator fingerprint (more granular) ── */
                if (has_xor_mut && n_movk_chain >= 3)
                    snprintf(region_obfuscator, 48, "%s", "XOR-poly/custom-packer");
                else if (n_opaque >= 2 && n_movk_chain >= 3)
                    snprintf(region_obfuscator, 48, "%s", "OLLVM/Hikari");
                else if (n_indirect >= 3 && n_dead >= 3)
                    snprintf(region_obfuscator, 48, "%s", "custom-VM");
                else if (has_xor_mut && n_ror_extr >= 2)
                    snprintf(region_obfuscator, 48, "%s", "XOR+ROR self-decrypt");
                else if (n_antidebug >= 2 && n_data_dep_br >= 1)
                    snprintf(region_obfuscator, 48, "%s", "antidebug+opaque-gate");
                else if (hash_depth >= 6)
                    snprintf(region_obfuscator, 48, "%s", "hash-chain/Tigress");
                else if (n_nop >= 8)
                    snprintf(region_obfuscator, 48, "%s", "NOP-packer");
                else if (n_movk_chain >= 5)
                    snprintf(region_obfuscator, 48, "%s", "const-obf/split-imm");
                else if (byte_entropy >= 220)
                    snprintf(region_obfuscator, 48, "%s", "packed/encrypted");
                else
                    snprintf(region_obfuscator, 48, "%s", "unknown");

                off += POLY_WINDOW;
                total_flagged++;
                continue;
            }

            /* score dropped — close any open region */
            if (region_open) {
                uint64_t rend = waddr;

                if (bin->npoly_regions < DAX_POLY_MAX) {
                    dax_poly_region_t *pr = &bin->poly_regions[bin->npoly_regions++];
                    pr->start          = region_start;
                    pr->end            = rend;
                    pr->mutation_score = region_score > 10 ? 10 : region_score;
                    snprintf(pr->technique, 64, "%.63s", region_techniques);
                    snprintf(pr->obfuscator, 32, "%.31s", region_obfuscator);
                }

                const char *scol = region_score >= 7 ? CRed :
                                   region_score >= 4 ? CWarn : CGood;
                fprintf(out, "\n  %s[POLY]%s  0x%llx .. 0x%llx  (%llu bytes)\n",
                        scol, CR,
                        (unsigned long long)region_start,
                        (unsigned long long)rend,
                        (unsigned long long)(rend - region_start));
                fprintf(out, "    %sscore%s      %s%d/10%s\n",
                        CDim, CR, scol, region_score > 10 ? 10 : region_score, CR);
                fprintf(out, "    %stechniques%s  %s%s%s\n",
                        CDim, CR, CWarn,
                        region_techniques[0] ? region_techniques : "?", CR);
                fprintf(out, "    %sobfuscator%s  %s%s%s\n",
                        CDim, CR, CGood,
                        region_obfuscator[0] ? region_obfuscator : "?", CR);

                region_open = 0;
            }

            off += (bin->arch == ARCH_ARM64 || bin->arch == ARCH_RISCV64) ? 4 : 1;
        }

        /* close trailing region */
        if (region_open && bin->npoly_regions < DAX_POLY_MAX) {
            dax_poly_region_t *pr = &bin->poly_regions[bin->npoly_regions++];
            pr->start          = region_start;
            pr->end            = base + csz;
            pr->mutation_score = region_score > 10 ? 10 : region_score;
            snprintf(pr->technique, 64, "%.63s", region_techniques);
            snprintf(pr->obfuscator, 32, "%.31s", region_obfuscator);

            const char *scol = region_score >= 7 ? CRed :
                               region_score >= 4 ? CWarn : CGood;
            fprintf(out, "\n  %s[POLY]%s  0x%llx .. 0x%llx\n",
                    scol, CR,
                    (unsigned long long)region_start,
                    (unsigned long long)(base + csz));
            fprintf(out, "    %sscore%s  %s%d/10%s\n",
                    CDim, CR, scol, region_score > 10 ? 10 : region_score, CR);
            fprintf(out, "    %stechniques%s  %s%s%s\n",
                    CDim, CR, CWarn,
                    region_techniques[0] ? region_techniques : "?", CR);
            fprintf(out, "    %sobfuscator%s  %s%s%s\n",
                    CDim, CR, CGood,
                    region_obfuscator[0] ? region_obfuscator : "?", CR);
        }
    }

    if (bin->npoly_regions == 0) {
        fprintf(out, "  %s(no polymorphic regions detected)%s\n", CDim, CR);
    } else {
        fprintf(out, "\n  %s── Summary: %d polymorphic region(s) detected across %d window(s) ──%s\n",
                CDim, bin->npoly_regions, total_flagged, CR);
    }
    fprintf(out, "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * dax_aire_analyze — Assisted Intelligence Reverse Engineering
 *
 * Post-processes all prior analysis results stored in dax_binary_t and
 * emits structured, human-readable insights with confidence levels.
 *
 * Rule engine categories:
 *   vm-dispatch  — VM interpreter infrastructure
 *   poly         — polymorphic / self-mutating sections
 *   anti-debug   — timing / sysreg / int3 anti-debugging
 *   smc          — self-modifying code
 *   packer       — packed/encrypted payload
 *   func-purpose — guesses function purpose from call graph + strings
 *   arch-oddity  — unexpected patterns for the target architecture
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ─────────────────────────────────────────────────────────────────────────────
 * AIRE internal helpers
 * ─────────────────────────────────────────────────────────────────────────────*/

/*
 * aire_insight_t (extended) — stored in bin->aire_insights[].
 * insight[0..255]  = what AIRE observed / why it matters
 * The action field lives right after insight in our layout via a second
 * write into the same slot separated by \n — we print them differently.
 */

static void aire_add(dax_binary_t *bin, uint64_t addr,
                     const char *category, int confidence,
                     const char *fmt, ...) {
    if (bin->naire_insights >= DAX_AIRE_MAX) return;
    dax_aire_insight_t *ins = &bin->aire_insights[bin->naire_insights++];
    ins->addr       = addr;
    ins->confidence = confidence < 0 ? 0 : confidence > 100 ? 100 : confidence;
    snprintf(ins->category, 32, "%.31s", category);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ins->insight, 1023, fmt, ap);
    va_end(ap);
}

/*
 * aire_score — multi-factor weighted confidence.
 * Each factor is a 0/1 boolean weighted by its diagnostic power.
 * Returns 0-100 clamped.
 */
typedef struct {
    int dispatch_count;    /* resolved indirect dispatches in function  */
    int obf_total;         /* total obfuscation score                   */
    int has_loop;          /* back-edge detected in function            */
    int has_bytecode_load; /* ldrb/ldrh with shift in function          */
    int has_ip_increment;  /* add Xn, Xn, #N pattern                   */
    int has_jump_table;    /* ldr [base, idx, lsl#3] pattern            */
    int smc_count;         /* number of SMC patches                     */
    int entropy_high;      /* section entropy >= 7.0                    */
    int poly_score;        /* highest poly mutation score               */
    int ncallers;          /* how many callers this function has        */
    int func_size;         /* bytes                                     */
    int antidebug_score;
    int indirect_score;
} aire_factors_t;

static int aire_score(const int *weights, const int *flags, int n) {
    int raw = 0, maxw = 0, k;
    for (k = 0; k < n; k++) {
        if (flags[k]) raw += weights[k];
        maxw += weights[k];
    }
    if (maxw == 0) return 0;
    int s = (raw * 100) / maxw;
    return s > 100 ? 100 : s;
}

/* Count how many xrefs go TO a given address */
static int aire_count_callers(dax_binary_t *bin, uint64_t addr) {
    int n = 0, i;
    if (!bin || !bin->xrefs || bin->nxrefs <= 0) return 0;
    for (i = 0; i < bin->nxrefs && i < DAX_MAX_XREFS; i++)
        if (bin->xrefs[i].to == addr) n++;
    return n;
}

/* Count how many xrefs FROM a given function range go to external targets */
static int aire_count_callees(dax_binary_t *bin, dax_func_t *fn) {
    int n = 0, i;
    if (!bin || !bin->xrefs || !fn || bin->nxrefs <= 0) return 0;
    for (i = 0; i < bin->nxrefs && i < DAX_MAX_XREFS; i++) {
        if (bin->xrefs[i].from >= fn->start && bin->xrefs[i].from < fn->end) {
            /* callees that land inside a different function */
            dax_func_t *tgt = dax_func_find(bin, bin->xrefs[i].to);
            if (tgt && tgt->start != fn->start) n++;
        }
    }
    return n;
}

/* Scan function bytes for a specific signal — returns count of occurrences */
static int aire_scan_fn(dax_binary_t *bin, dax_func_t *fn,
                        int sig_ldrb, int sig_ip_inc, int sig_mul) {
    int si;
    uint8_t *code = NULL; size_t csz = 0; uint64_t base = 0;
    if (!bin || !fn || !bin->data) return 0;
    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *s = &bin->sections[si];
        if (s->size == 0 || s->offset > bin->size) continue;
        if (s->size > bin->size - s->offset) continue;
        if (fn->start >= s->vaddr && fn->start < s->vaddr + s->size) {
            code = bin->data + s->offset; csz = s->size; base = s->vaddr;
            break;
        }
    }
    if (!code || fn->end <= fn->start) return 0;
    if (fn->start < base) return 0;

    size_t start_off = (size_t)(fn->start - base);
    size_t end_off   = (fn->end > fn->start && fn->end <= base + csz)
                       ? (size_t)(fn->end - base) : start_off + 256;
    if (end_off > csz) end_off = csz;

    int count = 0;
    size_t off = start_off;
    while (off + 4 <= end_off) {
        uint32_t raw = (uint32_t)code[off]|(code[off+1]<<8)|
                       (code[off+2]<<16)|(code[off+3]<<24);
        a64_insn_t insn; a64_decode(raw, base+off, &insn);
        const char *m = insn.mnemonic, *ops = insn.operands;
        if (!m || !ops) { off += 4; continue; }

        if (sig_ldrb && (!strcmp(m,"ldrb")||!strcmp(m,"ldrh")) &&
            (strstr(ops,"uxtx")||strstr(ops,"sxtx")||strstr(ops,"lsl")))
            count++;
        if (sig_ip_inc && !strcmp(m,"add")) {
            char r1[16]="", r2[16]="", r3[16]="";
            sscanf(ops, "%15[^,], %15[^,], %15s", r1, r2, r3);
            if (strcmp(r1,r2)==0 && r3[0]=='#') count++;
        }
        if (sig_mul && (!strcmp(m,"mul")||!strcmp(m,"umulh")||
                        !strcmp(m,"smulh")||!strcmp(m,"madd")))
            count++;
        off += 4;
    }
    return count;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * AIRE — main analysis function
 * ─────────────────────────────────────────────────────────────────────────────*/
void dax_aire_analyze(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int c = opts ? opts->color : 1;
    int fi, i;

    const char *CTitle  = c ? "\033[1;36m"  : "";
    const char *CAddr   = c ? "\033[1;34m"  : "";
    const char *CConf   = c ? "\033[1;32m"  : "";
    const char *CWarn   = c ? "\033[1;33m"  : "";
    const char *CRed    = c ? "\033[1;31m"  : "";
    const char *CDim    = c ? "\033[0;90m"  : "";
    const char *CMag    = c ? "\033[1;35m"  : "";
    const char *CCyan   = c ? "\033[1;36m"  : "";
    const char *CAction = c ? "\033[1;32m"  : "";
    const char *CR      = c ? "\033[0m"     : "";

    /* ── AIRE Memory: load previous analysis for this binary ── */
    aire_memory_t mem;
    memset(&mem, 0, sizeof(mem));
    aire_memory_entry_t *prev = NULL;

    FILE *mfp = fopen(AIRE_MEMORY_FILE, "rb");
    if (mfp) {
        if (fread(&mem, sizeof(aire_memory_t), 1, mfp) != 1)
            memset(&mem, 0, sizeof(mem)); /* ignore partial read */
        fclose(mfp);
        /* find entry matching this binary by SHA-256 */
        for (i = 0; i < mem.count && i < AIRE_MEMORY_MAX_ENTRIES; i++) {
            if (strcmp(mem.entries[i].sha256, bin->sha256) == 0) {
                prev = &mem.entries[i];
                break;
            }
        }
    }

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", CTitle);
    fprintf(out,
        "  ══════════════════════════════════════════════════════════\n"
        "  AIRE — Assisted Intelligence Reverse Engineering\n"
        "  ══════════════════════════════════════════════════════════\n");
    if (c) fprintf(out, "%s", CR);
    fprintf(out, "\n");

    bin->naire_insights = 0;

    /* ── Memory recall: show what AIRE remembers about this binary ── */
    if (prev) {
        fprintf(out, "  %s┌─ Memory ────────────────────────────────────────────┐%s\n", CDim, CR);
        fprintf(out, "  %s│%s  Binary seen %s%d time(s)%s — last: %s%s%s\n",
                CDim, CR, CConf, prev->run_count, CR, CDim, prev->timestamp, CR);
        if (prev->summary[0])
            fprintf(out, "  %s│%s  Last finding: %s%s%s\n",
                    CDim, CR, CWarn, prev->summary, CR);
        if (prev->last_cmd[0])
            fprintf(out, "  %s│%s  Last command: %s%s%s\n",
                    CDim, CR, CCyan, prev->last_cmd, CR);
        fprintf(out, "  %s└─────────────────────────────────────────────────────┘%s\n\n", CDim, CR);
    }

    /* pre-compute global obfuscation score */
    int obf_total = bin->obf_score_smc * 3 + bin->obf_score_opaque * 2 +
                    bin->obf_score_indirect + bin->obf_score_antidebug * 2;

    /* pre-compute max poly score across all regions */
    int max_poly_score = 0;
    for (i = 0; i < bin->npoly_regions; i++)
        if (bin->poly_regions[i].mutation_score > max_poly_score)
            max_poly_score = bin->poly_regions[i].mutation_score;

    /* pre-compute highest section entropy */
    double max_ent = 0.0;
    uint64_t max_ent_vaddr = 0;
    const char *max_ent_name = "?";
    {
        int si;
        for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
            dax_section_t *sec = &bin->sections[si];
            if (sec->size <= 256 || sec->offset + sec->size > bin->size) continue;
            uint32_t freq[256] = {0}; size_t bi;
            uint8_t *buf = bin->data + sec->offset;
            for (bi = 0; bi < sec->size; bi++) freq[buf[bi]]++;
            double ent = 0.0;
            for (bi = 0; bi < 256; bi++) {
                if (freq[bi] > 0) {
                    double p = (double)freq[bi] / (double)sec->size;
                    ent -= p * log2(p);
                }
            }
            if (ent > max_ent) {
                max_ent = ent; max_ent_vaddr = sec->vaddr;
                max_ent_name = sec->name[0] ? sec->name : "?";
            }
        }
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 1 — VM Interpreter Loop Detection (multi-factor)
     * Weights: dispatch_count, bytecode load, IP increment, jump table,
     *          back-edge loop, obf score, call fan-in
     * ====================================================================*/
    for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
        dax_func_t *fn = &bin->functions[fi];
        if (!fn->name[0]) continue;

        int dispatch_count = 0;
        for (i = 0; i < bin->nresolved_indirect; i++)
            if (bin->resolved_indirect_from[i] >= fn->start &&
                bin->resolved_indirect_from[i] <  fn->end)
                dispatch_count++;

        int ldrb_count  = aire_scan_fn(bin, fn, 1, 0, 0);
        int ip_inc      = aire_scan_fn(bin, fn, 0, 1, 0);
        int mul_count   = aire_scan_fn(bin, fn, 0, 0, 1);
        int ncallers    = aire_count_callers(bin, fn->start);
        int ncallees    = aire_count_callees(bin, fn);
        int func_size   = (fn->end > fn->start) ? (int)(fn->end - fn->start) : 0;

        /* VM signal flags */
        int f_dispatch   = (dispatch_count >= 2)  ? 1 : 0;
        int f_bytecode   = (ldrb_count >= 1)       ? 1 : 0;
        int f_ip_inc     = (ip_inc >= 1)            ? 1 : 0;
        int f_obf        = (obf_total >= 8)         ? 1 : 0;
        int f_big        = (func_size >= 128)       ? 1 : 0;
        int f_fanout     = (ncallees >= 4)          ? 1 : 0;
        int f_hub        = (ncallers >= 2)          ? 1 : 0;

        /* weights — dispatch and bytecode load are strongest signals */
        int flags[7]   = { f_dispatch, f_bytecode, f_ip_inc, f_obf,
                           f_big, f_fanout, f_hub };
        int weights[7] = { 35,         25,         20,       10,
                           4,          4,          2 };
        int conf = aire_score(weights, flags, 7);
        if (conf < 40) continue;  /* below threshold */

        /* build interpretation string */
        char why[512] = "";
        if (f_dispatch)
            strncat(why, "resolved indirect dispatch", 511);
        if (f_bytecode) {
            if (why[0]) strncat(why, " + ", 511);
            strncat(why, "bytecode-load (ldrb/ldrh with shift)", 511);
        }
        if (f_ip_inc) {
            if (why[0]) strncat(why, " + ", 511);
            strncat(why, "IP-increment pattern (add Rn,Rn,#N)", 511);
        }

        /* fingerprint VM family */
        const char *vm_family = "unknown VM protection";
        const char *vm_detail = "";
        if (f_dispatch && f_bytecode && f_ip_inc) {
            vm_family = "fetch-decode-execute interpreter";
            vm_detail = "Classic VM loop structure: fetch opcode from stream "
                        "(ldrb with IP register), increment IP, index into "
                        "handler dispatch table, execute handler, repeat.";
        } else if (f_dispatch && f_obf && obf_total >= 16) {
            vm_family = "professional VM-protector (VMProtect/Themida/LLVM-obf)";
            vm_detail = "Extreme obfuscation score combined with dispatch "
                        "strongly suggests a commercial VM protector. The "
                        "visible native code is only the VM shell — real "
                        "program logic is hidden inside encrypted bytecode.";
        } else if (f_dispatch && mul_count >= 3) {
            vm_family = "hash-dispatch VM";
            vm_detail = "Multiply-heavy + indirect dispatch suggests handler "
                        "selection via hash or CRC of the opcode rather than "
                        "a direct jump table — harder to reconstruct statically.";
        } else if (f_fanout && f_big) {
            vm_family = "large dispatcher / central decode hub";
            vm_detail = "Large function with many callees but few callers — "
                        "likely the central decode/dispatch function that all "
                        "VM handler paths pass through.";
        }

        /* evasion purpose */
        const char *evasion = (obf_total >= 8)
            ? "Designed to prevent static signature detection and to "
              "make reverse engineering require full dynamic execution "
              "of the bytecode VM."
            : "Likely used to hide control flow from static analysis tools "
              "by encoding logic as interpreted bytecode instead of native code.";

        /* action suggestion */
        const char *action;
        if (f_dispatch && f_bytecode && f_ip_inc)
            action = "ACTION  Run '--emulate' on this function to trace the "
                     "bytecode fetch/dispatch loop concretely. Then run "
                     "'vmtrace' to see every opcode dispatched. Use '-P' "
                     "(symbolic execution) to map all reachable handler paths.";
        else if (obf_total >= 16)
            action = "ACTION  Attach Frida/PIN to intercept the dispatch "
                     "point at runtime and log (opcode, handler_pc) pairs. "
                     "Static analysis of this function alone is insufficient.";
        else
            action = "ACTION  Use '-P --poly' to further characterise this "
                     "region, then 'step init' in the interactive shell to "
                     "walk through the dispatch logic instruction-by-instruction.";

        aire_add(bin, fn->start, "vm-dispatch", conf,
                 "[%s]\n"
                 "  WHY     %s\n"
                 "  SIGNALS %s (%d dispatches, %d bytecode-loads, "
                 "ip-inc=%d, size=%d bytes, callees=%d)\n"
                 "  EVASION %s\n"
                 "  %s",
                 vm_family, vm_detail,
                 why[0] ? why : "indirect-dispatch",
                 dispatch_count, ldrb_count, ip_inc, func_size, ncallees,
                 evasion, action);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 2 — Polymorphic / Mutated Code Regions (multi-factor)
     * ====================================================================*/
    for (i = 0; i < bin->npoly_regions; i++) {
        dax_poly_region_t *pr = &bin->poly_regions[i];

        /* multi-factor confidence */
        int f_score_hi   = (pr->mutation_score >= 7) ? 1 : 0;
        int f_score_med  = (pr->mutation_score >= 4) ? 1 : 0;
        int f_ollvm      = (strstr(pr->obfuscator,"OLLVM") ||
                            strstr(pr->obfuscator,"Hikari")) ? 1 : 0;
        int f_vm_obf     = (strstr(pr->obfuscator,"custom VM")) ? 1 : 0;
        int f_indirect   = (strstr(pr->technique,"indirect")) ? 1 : 0;
        int f_opaque     = (strstr(pr->technique,"opaque")) ? 1 : 0;
        int f_junk       = (strstr(pr->technique,"nop-junk") ||
                            strstr(pr->technique,"dead-code")) ? 1 : 0;
        int f_const      = (strstr(pr->technique,"const-obfuscation")) ? 1 : 0;
        int f_subst      = (strstr(pr->technique,"opcode-subst")) ? 1 : 0;
        int f_large      = ((pr->end - pr->start) >= 512) ? 1 : 0;

        int flags[10]   = { f_score_hi, f_score_med, f_ollvm, f_vm_obf,
                            f_indirect, f_opaque, f_junk, f_const,
                            f_subst, f_large };
        int weights[10] = { 25, 15, 15, 15, 10, 10, 5, 5, 5, 5 };
        int conf = 30 + (aire_score(weights, flags, 10) * 65) / 100;
        if (conf > 95) conf = 95;

        /* technique explanation */
        char tech_explain[512] = "";
        if (f_ollvm)
            strncat(tech_explain,
                "Control Flow Flattening (CFF): all basic blocks are "
                "dispatched via a central switch variable — no direct "
                "edges between logic blocks, only through the switch. "
                "Bogus Control Flow (BCF) adds always-false branches to "
                "pollute the CFG. ", 511);
        if (f_vm_obf)
            strncat(tech_explain,
                "Custom VM layer: each indirect branch is a handler call "
                "for a virtual instruction. Reconstruct the bytecode "
                "format by tracing the fetch-decode loop. ", 511);
        if (f_opaque)
            strncat(tech_explain,
                "Opaque predicates: system register reads (CNTVCT/PMCCNTR) "
                "produce values used in conditions that are always-true or "
                "always-false at runtime, but appear branching statically. ", 511);
        if (f_junk)
            strncat(tech_explain,
                "Junk insertion: NOPs and unreachable code after unconditional "
                "branches pad the function to break pattern-matching signatures "
                "and confuse linear disassemblers. ", 511);
        if (f_const)
            strncat(tech_explain,
                "Constant obfuscation: immediate values are never loaded as "
                "single literals — split across movz/movk chains to prevent "
                "string/constant search from finding magic numbers. ", 511);
        if (f_subst)
            strncat(tech_explain,
                "Opcode substitution: semantically equivalent instruction "
                "sequences replace simple operations to defeat opcode-level "
                "signature matching. ", 511);
        if (!tech_explain[0])
            strncat(tech_explain,
                "Multiple structural anomalies detected in this region.", 511);

        /* evasion purpose */
        const char *evasion_purpose;
        if (f_ollvm)
            evasion_purpose = "Primary goal: defeat CFG-based decompilers "
                "(Hex-Rays, Ghidra). Flattened CFG breaks dominator tree "
                "reconstruction, making decompiled output unintelligible.";
        else if (f_vm_obf)
            evasion_purpose = "Primary goal: hide program logic from static "
                "analysis entirely. Native code only reveals the VM "
                "infrastructure — actual semantics live in bytecode.";
        else if (f_opaque)
            evasion_purpose = "Primary goal: confuse symbolic execution and "
                "constraint solvers by introducing hardware-dependent values "
                "that cannot be resolved without emulation.";
        else
            evasion_purpose = "Primary goal: evade static signature detection "
                "by structurally mutating code while preserving semantics.";

        /* action */
        const char *action;
        if (f_ollvm)
            action = "ACTION  Run symbolic execution ('-P') on this region — "
                     "NeoDAX resolves opaque predicates and can simplify the "
                     "flattened CFG. Also try '-C' (CFG view) to visualise "
                     "the abnormal switch structure.";
        else if (f_vm_obf)
            action = "ACTION  This region is likely a VM entrypoint or "
                     "handler cluster. Run 'step init' here in the interactive "
                     "shell to trace execution. Use 'vmtrace' after 'run' "
                     "to recover the handler dispatch sequence.";
        else if (f_opaque)
            action = "ACTION  Run '-P' to let symbolic execution fold the "
                     "opaque predicates. After folding, re-run '-C' and '-D' "
                     "(decompile) on this region for cleaner output.";
        else
            action = "ACTION  Run '--poly' for full region map, then '-I' "
                     "(emulate) to observe runtime behaviour of this area.";

        aire_add(bin, pr->start, "poly", conf,
                 "[%s — score %d/10]\n"
                 "  REGION  0x%llx .. 0x%llx (%llu bytes)\n"
                 "  SIGNALS %s\n"
                 "  EXPLAIN %s\n"
                 "  EVASION %s\n"
                 "  %s",
                 pr->obfuscator, pr->mutation_score,
                 (unsigned long long)pr->start, (unsigned long long)pr->end,
                 (unsigned long long)(pr->end - pr->start),
                 pr->technique[0] ? pr->technique : "?",
                 tech_explain, evasion_purpose, action);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 3 — Self-Modifying Code
     * ====================================================================*/
    if (bin->nsmc_patches > 0) {
        int conf = 70 + bin->nsmc_patches * 5;
        if (conf > 97) conf = 97;

        const char *smc_evasion =
            "SMC makes static analysis reflect a different binary than what "
            "actually executes. Signature scanners see the unpatched bytes; "
            "the real code only appears after the patch is applied at runtime. "
            "This is a classic anti-AV and anti-debugger technique.";

        const char *smc_action =
            "ACTION  Attach Frida and hook mprotect() to intercept the patch "
            "moment. Dump the patched .text page immediately after the write "
            "to capture the real instruction stream. In NeoDAX: run 'poly' to "
            "see which .text regions are flagged as write targets.";

        aire_add(bin, bin->smc_target_addr[0], "smc", conf,
                 "[self-modifying code — %d patch site(s)]\n"
                 "  FIRST   patch site 0x%llx\n"
                 "  EXPLAIN The binary uses mprotect/VirtualProtect to make "
                 ".text writable, writes new instruction bytes, then restores "
                 "RX permissions. Static analysis captures only the pre-patch "
                 "state — the bytes you see are NOT what the CPU executes.\n"
                 "  EVASION %s\n"
                 "  %s",
                 bin->nsmc_patches,
                 (unsigned long long)bin->smc_target_addr[0],
                 smc_evasion, smc_action);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 4 — Anti-Debug / Anti-Analysis (multi-factor)
     * ====================================================================*/
    if (bin->obf_score_antidebug >= 1) {
        int f_timing   = (bin->obf_score_antidebug >= 2) ? 1 : 0;
        int f_sysreg   = (bin->obf_score_opaque    >= 2) ? 1 : 0;
        int f_indirect = (bin->obf_score_indirect  >= 2) ? 1 : 0;
        int f_smc      = (bin->nsmc_patches > 0)         ? 1 : 0;

        int flags[4]   = { f_timing, f_sysreg, f_indirect, f_smc };
        int weights[4] = { 40,       30,       20,          10 };
        int conf = 55 + (aire_score(flags, weights, 4) * 40) / 100;
        if (conf > 95) conf = 95;

        char techniques[256] = "";
        if (f_timing)
            strncat(techniques, "timing-check (CNTVCT_EL0/rdtsc) ", 255);
        if (f_sysreg)
            strncat(techniques, "sysreg-opaque-predicate ", 255);
        if (f_indirect)
            strncat(techniques, "indirect-branch-confusion ", 255);
        if (f_smc)
            strncat(techniques, "SMC-based-anti-dump ", 255);

        const char *antidebug_explain =
            f_timing
            ? "Timing attacks measure execution time of a tight loop using "
              "the hardware counter register (CNTVCT_EL0). Under a debugger "
              "or emulator, the loop takes orders of magnitude longer — the "
              "binary detects this and alters execution or crashes."
            : "Sysreg reads produce hardware-dependent values that are used "
              "as conditions. These values differ between emulators, debuggers, "
              "and bare hardware, enabling environment detection.";

        const char *antidebug_action =
            "ACTION  Patch the anti-debug checks before attaching: in "
            "interactive shell use 'seek' to find the CNTVCT/timing "
            "comparison and NOP the conditional branch. Alternatively "
            "use Frida's Stalker to skip the check at runtime. "
            "Then re-run '-I' (emulate) which neutralises timing side-channels.";

        aire_add(bin, bin->base, "anti-debug", conf,
                 "[anti-debug/anti-analysis — %d technique(s)]\n"
                 "  SIGNALS %s\n"
                 "  EXPLAIN %s\n"
                 "  EVASION Goal: detect and respond to debugging, emulation, "
                 "or sandboxed execution environments to prevent dynamic analysis.\n"
                 "  %s",
                 f_timing + f_sysreg + f_indirect + f_smc,
                 techniques[0] ? techniques : "unknown",
                 antidebug_explain, antidebug_action);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 5 — High Entropy (Packed / Encrypted)
     * ====================================================================*/
    if (max_ent >= 6.5) {
        int f_extreme  = (max_ent >= 7.5) ? 1 : 0;
        int f_high     = (max_ent >= 7.0) ? 1 : 0;
        int f_med      = (max_ent >= 6.5) ? 1 : 0;
        int f_smc      = (bin->nsmc_patches > 0) ? 1 : 0;
        int f_stripped = bin->is_stripped;

        int flags[5]   = { f_extreme, f_high, f_med, f_smc, f_stripped };
        int weights[5] = { 35, 25, 20, 15, 5 };
        int conf = aire_score(flags, weights, 5);
        if (conf < 40) conf = 40;

        const char *pack_type;
        const char *pack_explain;
        if (max_ent >= 7.8)
            pack_type = "encrypted payload (AES/XOR-256 or compressed)";
        else if (max_ent >= 7.0)
            pack_type = "packed/compressed code section";
        else
            pack_type = "elevated entropy — possible partial packing";

        pack_explain = (max_ent >= 7.0)
            ? "True random-looking data: no discernible byte frequency bias. "
              "This is the expected output of a cipher (AES-CTR, ChaCha20) or "
              "a compressor (LZMA/zlib at high compression). The CPU never "
              "executes these bytes directly — a small, low-entropy stub "
              "decrypts or decompresses this region into executable memory "
              "before jumping to it."
            : "Slightly elevated entropy. Could be an optimised binary, "
              "resource data, or lightly obfuscated code section.";

        const char *pack_action =
            (max_ent >= 7.0)
            ? "ACTION  Find the unpacker stub: locate the function with the "
              "lowest entropy that calls mprotect/VirtualAlloc and jumps into "
              "the high-entropy region. Set a breakpoint at the end of the "
              "stub (after the decrypt loop) and dump the decrypted buffer. "
              "In NeoDAX: run '-R' (recursive descent) from the entry point "
              "to find the loader function, then '-I' to emulate it."
            : "ACTION  Run '-e' (entropy scan) for per-region breakdown, "
              "then '-I' on the lowest-entropy function near this section "
              "to find the decoder stub.";

        aire_add(bin, max_ent_vaddr, "packer", conf,
                 "[%s]\n"
                 "  SECTION %s at 0x%llx — entropy %.4f bits/byte\n"
                 "  EXPLAIN %s\n"
                 "  EVASION Prevents static disassembly and signature scanning "
                 "of the real payload. The binary is effectively two programs: "
                 "a loader stub (visible, low-entropy) and the real code "
                 "(invisible until runtime decryption).\n"
                 "  %s",
                 pack_type,
                 max_ent_name, (unsigned long long)max_ent_vaddr, max_ent,
                 pack_explain, pack_action);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 6 — Function Purpose (multi-factor heuristics)
     * ====================================================================*/
    for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
        dax_func_t *fn = &bin->functions[fi];
        if (!fn->name[0]) continue;

        int ncallers  = aire_count_callers(bin, fn->start);
        int ncallees  = aire_count_callees(bin, fn);
        int func_size = (fn->end > fn->start) ? (int)(fn->end - fn->start) : 0;
        int mul_count = aire_scan_fn(bin, fn, 0, 0, 1);
        int ldrb_c    = aire_scan_fn(bin, fn, 1, 0, 0);

        /* Trampoline / decode glue: tiny, many callers, few callees */
        if (ncallers >= 5 && func_size > 0 && func_size < 64 && ncallees <= 2) {
            aire_add(bin, fn->start, "func-purpose", 72,
                     "[probable decode/dispatch trampoline]\n"
                     "  FUNC    '%s' (%d bytes, %d callers, %d callee(s))\n"
                     "  EXPLAIN Very small function called from many sites. "
                     "This pattern is typical of: (1) a shared opcode decode "
                     "stub that VM handlers call to fetch the next instruction, "
                     "(2) a bounds-check wrapper, or (3) a hook/trampoline that "
                     "redirects control flow.\n"
                     "  EVASION Centralising control flow through a tiny shared "
                     "stub makes CFG-based analysis harder — edges fan in from "
                     "everywhere, obscuring the real call graph structure.\n"
                     "  ACTION  Cross-reference all callers with 'xr 0x%llx' "
                     "and check if they all pass an opcode/index argument — "
                     "that confirms this is a decode hub.",
                     fn->name, func_size, ncallers, ncallees,
                     (unsigned long long)fn->start);
        }

        /* Crypto / hash round: large stripped fn, multiply-heavy */
        if (!strncmp(fn->name, "sub_", 4) && func_size >= 256 &&
            mul_count >= 4) {
            int conf = 50 + (mul_count > 10 ? 30 : mul_count * 3);
            if (conf > 88) conf = 88;
            aire_add(bin, fn->start, "func-purpose", conf,
                     "[probable crypto/hash function]\n"
                     "  FUNC    '%s' (%d bytes, %d multiply/umulh/madd insns)\n"
                     "  EXPLAIN High multiply density in a large stripped "
                     "function is a strong indicator of: AES MixColumns, "
                     "SHA-2/SHA-3 compression, GHASH (GCM), Poly1305 MAC, "
                     "or a custom hash round. Multiplication-heavy code is "
                     "also consistent with RSA/ECC field arithmetic.\n"
                     "  EVASION Stripped symbol name hides the algorithm. "
                     "Algorithm identification requires either dynamic "
                     "analysis (input/output correlation) or side-channel "
                     "recognition of the constant operands.\n"
                     "  ACTION  Run '-I' (emulate) with known test vectors "
                     "and compare output in x0 to known hash/cipher outputs. "
                     "Look for magic constants (SHA-256 uses 0x6a09e667, "
                     "AES S-box starts 0x63...) in the immediate operands.",
                     fn->name, func_size, mul_count);
        }

        /* Bytecode handler: medium size, 1-2 callers (the dispatch loop) */
        if (ncallers >= 1 && ncallers <= 3 && func_size >= 32 &&
            func_size < 256 && ldrb_c == 0 && ncallees <= 4) {
            /* only flag if there's a VM-ish function nearby */
            int vm_context = 0;
            int vi2;
            for (vi2 = 0; vi2 < bin->nresolved_indirect && !vm_context; vi2++)
                if (bin->resolved_indirect_to[vi2] == fn->start) vm_context = 1;
            if (vm_context) {
                aire_add(bin, fn->start, "func-purpose", 68,
                         "[probable VM bytecode handler]\n"
                         "  FUNC    '%s' (%d bytes, called from %d dispatch site(s))\n"
                         "  EXPLAIN This function is a target of resolved indirect "
                         "dispatch — a VM interpreter loop jumps to it as a handler "
                         "for a specific bytecode opcode. Its size and fan-in pattern "
                         "are consistent with implementing a single virtual instruction "
                         "(e.g. VM_PUSH, VM_ADD, VM_JMP).\n"
                         "  EVASION Each handler is isolated — understanding one "
                         "handler does not reveal the full instruction set. Full "
                         "coverage requires tracing all dispatcher paths.\n"
                         "  ACTION  Run 'vmtrace' after emulating the interpreter "
                         "loop to see which opcode value dispatches to this handler. "
                         "Name this function after the opcode it implements.",
                         fn->name, func_size, ncallers);
            }
        }
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 7 — Architecture / Structural Oddities
     * ====================================================================*/
    if (bin->arch == ARCH_ARM64) {
        int f_high_indirect = (bin->obf_score_indirect >= 3) ? 1 : 0;
        int f_high_opaque   = (bin->obf_score_opaque   >= 3) ? 1 : 0;
        int f_high_obf      = (obf_total >= 12)               ? 1 : 0;
        int f_stripped      = bin->is_stripped;

        int flags7[4]   = { f_high_indirect, f_high_opaque, f_high_obf, f_stripped };
        int weights7[4] = { 35, 25, 25, 15 };
        int conf7 = aire_score(flags7, weights7, 4);

        if (conf7 >= 35) {
            char arch_signals[256] = "";
            if (f_high_indirect)
                strncat(arch_signals, "indirect-branch density anomaly ", 255);
            if (f_high_opaque)
                strncat(arch_signals, "opaque-predicate density anomaly ", 255);
            if (f_high_obf)
                strncat(arch_signals, "extreme-overall-obf-score ", 255);
            if (f_stripped)
                strncat(arch_signals, "stripped-symbols ", 255);

            const char *arch_explain =
                (f_high_indirect && f_high_opaque)
                ? "ARM64 binaries compiled natively use computed jumps only for "
                  "switch tables (adrp+add+ldr+br sequence). This binary shows "
                  "both high indirect-branch density AND sysreg-based opaque "
                  "predicates — neither pattern appears in normal ARM64 code. "
                  "Together they are the fingerprint of an LLVM-based obfuscator "
                  "(OLLVM, Hikari, Armariris) applied before compilation."
                : "ARM64 indirect branch density is significantly above normal "
                  "for non-switch-table code. Likely cause: VM dispatch loop, "
                  "runtime code patching, or JIT-compiled code region.";

            const char *arch_action =
                (f_high_indirect && f_high_opaque)
                ? "ACTION  Run '-P' (symbolic execution) — NeoDAX specifically "
                  "folds sysreg-based opaque predicates. Follow with '-C' (CFG) "
                  "and '-D' (decompile) on the affected functions for cleaner "
                  "pseudo-C output with the bogus branches removed."
                : "ACTION  Run '-V' (IVF) for the full indirect-branch list, "
                  "then '-W' (switch detect) to filter out legitimate switch "
                  "tables. Remaining 'br Xn' instructions are suspicious.";

            aire_add(bin, bin->base, "arch-oddity", conf7,
                     "[ARM64 structural anomaly]\n"
                     "  SIGNALS %s\n"
                     "  EXPLAIN %s\n"
                     "  EVASION ARM64-specific obfuscation exploits the fact that "
                     "many analysis tools assume ARM64 binaries follow ABI calling "
                     "conventions and switch-only indirect branches.\n"
                     "  %s",
                     arch_signals[0] ? arch_signals : "?",
                     arch_explain, arch_action);
        }
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 8 — Cross-correlation: multiple techniques together
     * Detect when SMC + poly + anti-debug appear simultaneously —
     * this combination is the hallmark of a professional protection layer.
     * ====================================================================*/
    {
        int layers = (bin->nsmc_patches > 0 ? 1 : 0) +
                     (bin->npoly_regions > 0 ? 1 : 0) +
                     (bin->obf_score_antidebug >= 2 ? 1 : 0) +
                     (max_ent >= 7.0 ? 1 : 0) +
                     (bin->obf_score_indirect >= 3 ? 1 : 0);

        if (layers >= 3) {
            int conf = 60 + layers * 6;
            if (conf > 97) conf = 97;

            const char *layer_verdict;
            if (layers >= 5)
                layer_verdict = "EXTREME — all major protection layers present. "
                    "This binary uses every available obfuscation category "
                    "simultaneously. Likely a commercial packer/protector "
                    "(Themida, VMProtect Pro, custom) applied to already-"
                    "obfuscated code.";
            else if (layers >= 4)
                layer_verdict = "SEVERE — four protection layers active. "
                    "Professional-grade protection. Consider dynamic analysis "
                    "as the primary approach rather than static RE.";
            else
                layer_verdict = "HIGH — three protection layers active. "
                    "Deliberate multi-layered protection design.";

            aire_add(bin, bin->base, "multi-layer", conf,
                     "[multi-layer protection system — %d/%d layers active]\n"
                     "  VERDICT %s\n"
                     "  LAYERS  %s%s%s%s%s\n"
                     "  EXPLAIN Presence of multiple independent protection "
                     "techniques is not accidental — each layer defeats a "
                     "different class of analysis tool. SMC defeats static "
                     "disassembly; polymorphism defeats signatures; anti-debug "
                     "defeats dynamic analysis; encryption defeats memory "
                     "forensics; indirect dispatch defeats CFG reconstruction.\n"
                     "  ACTION  Recommended approach order:\n"
                     "    1. Run '-e' to find encrypted sections (highest entropy first)\n"
                     "    2. Run '-I' to emulate the unpacker/loader stub\n"
                     "    3. Run '-P' to fold opaque predicates in unpacked code\n"
                     "    4. Run '--poly --aire' on the unpacked dump\n"
                     "    5. Use Frida to hook dispatch points identified by vmtrace",
                     layers, 5,
                     layer_verdict,
                     bin->nsmc_patches     > 0 ? "SMC "              : "",
                     bin->npoly_regions    > 0 ? "polymorphic-code " : "",
                     bin->obf_score_antidebug>=2?"anti-debug "       : "",
                     max_ent              >= 7.0?"encrypted-section ": "",
                     bin->obf_score_indirect>=3 ?"indirect-dispatch " : "");
        }
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 9 — DSA-powered: Opaque Predicate Detection
     * Uses dax_dsa_aire_signals() to find phi nodes where one arm has
     * zero observed frequency — definitive opaque predicate evidence.
     * ====================================================================*/
    for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
        dax_func_t *fn = &bin->functions[fi];
        if (!fn->name[0]) continue;
        int func_size = (fn->end > fn->start) ? (int)(fn->end-fn->start) : 0;
        if (func_size < 16) continue;

        int sig = dax_dsa_aire_signals(bin, fi, NULL, NULL);
        if (!(sig & 0x01)) continue;   /* no opaque predicate signal */

        int conf = 72 + (bin->obf_score_opaque * 4);
        if (conf > 94) conf = 94;

        aire_add(bin, fn->start, "opaque-pred", conf,
                 "[DSA-confirmed opaque predicate in '%s']\n"
                 "  EXPLAIN DSA (Dynamic Single Assignment) traced the concrete\n"
                 "  execution path and found a dynamic-phi node where one\n"
                 "  incoming arm has observed frequency = 0. This means a branch\n"
                 "  that appears conditional in static disassembly is actually\n"
                 "  unconditional at runtime — a classic opaque predicate.\n"
                 "  The dead arm contains junk or misleading instructions placed\n"
                 "  specifically to confuse decompilers and CFG-based tools.\n"
                 "  EVASION Opaque predicates make symbolic execution expensive:\n"
                 "  solvers must prove the predicate is always-true/false, which\n"
                 "  requires modelling the full input domain. DSA short-circuits\n"
                 "  this by observing actual branch frequency.\n"
                 "  ACTION  Run 'dsa %s' in interactive shell to see the full\n"
                 "  phi-node map. Dead-arm defs are tagged OPAQUE-DEAD.\n"
                 "  Then run '-P' (symexec) — NeoDAX will fold the predicates\n"
                 "  and prune the dead arms from the CFG automatically.",
                 fn->name, fn->name);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 10 — DSA-powered: Crypto Algorithm Identification
     * Detects known crypto constants in runtime-observed def values.
     * ====================================================================*/
    for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
        dax_func_t *fn = &bin->functions[fi];
        if (!fn->name[0]) continue;
        int func_size = (fn->end > fn->start) ? (int)(fn->end-fn->start) : 0;
        if (func_size < 32) continue;

        const char *cnames[4] = {NULL,NULL,NULL,NULL};
        int ncrypto = 0;
        int sig = dax_dsa_aire_signals(bin, fi, cnames, &ncrypto);
        if (!(sig & 0x04)) continue;

        int conf = 65 + ncrypto * 8;
        if (conf > 92) conf = 92;

        char clist[256] = "";
        for (int ci = 0; ci < ncrypto && ci < 4; ci++) {
            if (cnames[ci]) {
                if (clist[0]) strncat(clist, "; ", 255);
                strncat(clist, cnames[ci], 255);
            }
        }

        aire_add(bin, fn->start, "crypto-id", conf,
                 "[DSA crypto constant identification in '%s']\n"
                 "  CONSTS  %s\n"
                 "  EXPLAIN DSA traced concrete definition values and matched\n"
                 "  %d known cryptographic constant(s). These constants uniquely\n"
                 "  identify the algorithm family — they appear in the algorithm\n"
                 "  spec and cannot be changed without breaking compatibility.\n"
                 "  EVASION Stripping symbols hides the function name but cannot\n"
                 "  hide the constants; DSA finds them regardless of obfuscation.\n"
                 "  ACTION  Run 'dsa %s' to see which def sites hold the constants.\n"
                 "  Cross-reference with known test vectors using '-I' (emulate)\n"
                 "  to confirm the algorithm and key schedule.",
                 fn->name, clist[0] ? clist : "see dsa output",
                 ncrypto, fn->name);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 11 — DSA-powered: Induction Variable / Loop Structure
     * ====================================================================*/
    for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
        dax_func_t *fn = &bin->functions[fi];
        if (!fn->name[0]) continue;
        int func_size = (fn->end > fn->start) ? (int)(fn->end-fn->start) : 0;
        if (func_size < 16) continue;

        int sig = dax_dsa_aire_signals(bin, fi, NULL, NULL);
        if (!(sig & 0x50)) continue;   /* 0x10=induction, 0x40=loop-ctr */

        int conf = 60 + ((sig & 0x10) ? 15 : 0) + ((sig & 0x40) ? 10 : 0);
        if (conf > 88) conf = 88;

        const char *loop_type = (sig & 0x40) ? "counted loop (++counter)"
                                             : "induction-variable loop (+delta)";

        aire_add(bin, fn->start, "loop-struct", conf,
                 "[DSA loop structure in '%s' — %s]\n"
                 "  EXPLAIN DSA observed a register whose value changes by a\n"
                 "  constant delta across loop iterations. This is the classic\n"
                 "  signature of a for/while loop with a simple induction variable.\n"
                 "  In obfuscated code, CFF (control-flow flattening) hides loops\n"
                 "  behind switch dispatchers — DSA sees through the dispatcher\n"
                 "  because the loop counter increment is observable dynamically.\n"
                 "  ACTION  Run 'loops %s' to see NeoDAX loop detection output.\n"
                 "  Use 'dsa %s' to identify the induction variable register\n"
                 "  and its delta — this tells you the loop bounds.",
                 fn->name, loop_type, fn->name, fn->name);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 12 — String Decryption Stub Detection
     * Heuristic: small function, many callers, reads from .rodata,
     * has XOR/ADD with a key register, writes to stack/heap.
     * ====================================================================*/
    for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
        dax_func_t *fn = &bin->functions[fi];
        if (!fn->name[0]) continue;
        int func_size = (fn->end > fn->start) ? (int)(fn->end-fn->start) : 0;
        if (func_size < 16 || func_size > 512) continue;

        int ncallers = aire_count_callers(bin, fn->start);
        if (ncallers < 3) continue;

        /* Scan for XOR/EOR and LDRB in same function */
        int has_xor  = 0, has_ldrb = 0;
        {
            uint8_t *code = NULL; size_t csz = 0; uint64_t base = 0;
            for (int si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
                dax_section_t *s = &bin->sections[si];
                if (fn->start >= s->vaddr && fn->start < s->vaddr + s->size &&
                    s->offset + s->size <= bin->size) {
                    code = bin->data + s->offset; csz = s->size; base = s->vaddr;
                    break;
                }
            }
            if (code && fn->end > fn->start) {
                size_t so2 = (size_t)(fn->start - base);
                size_t eo2 = (fn->end <= base+csz) ? (size_t)(fn->end-base) : so2+256;
                if (eo2 > csz) eo2 = csz;
                if (bin->arch == ARCH_ARM64) {
                    for (size_t of2 = so2; of2+4 <= eo2; of2 += 4) {
                        uint32_t raw = (uint32_t)code[of2]|(code[of2+1]<<8)|
                                       (code[of2+2]<<16)|(code[of2+3]<<24);
                        a64_insn_t insn; a64_decode(raw, base+of2, &insn);
                        if (!strcmp(insn.mnemonic,"eor")||!strcmp(insn.mnemonic,"xor"))
                            has_xor = 1;
                        if (!strcmp(insn.mnemonic,"ldrb")||!strcmp(insn.mnemonic,"ldrh"))
                            has_ldrb = 1;
                    }
                }
            }
        }

        if (!has_xor || !has_ldrb) continue;

        int conf = 55 + (ncallers > 8 ? 20 : ncallers * 2);
        if (conf > 88) conf = 88;

        aire_add(bin, fn->start, "str-decrypt", conf,
                 "[probable string decryption stub '%s']\n"
                 "  FUNC    %d bytes, %d caller(s), XOR+LDRB pattern\n"
                 "  EXPLAIN Small function called from many sites that reads\n"
                 "  bytes (ldrb) and XORs them — the hallmark of a simple\n"
                 "  per-character XOR cipher used to hide string literals\n"
                 "  from static string search. Each call site passes a\n"
                 "  different encrypted buffer and key.\n"
                 "  EVASION Runtime-only plaintext: grep, strings(1), and\n"
                 "  YARA rules on raw bytes all fail because the plaintext\n"
                 "  never appears in the binary image on disk.\n"
                 "  ACTION  Set a breakpoint at the function exit in Frida and\n"
                 "  log the output buffer for each of the %d call sites.\n"
                 "  In NeoDAX: run '-I' (emulate) on each call site with the\n"
                 "  appropriate x0/x1 arguments to recover all strings.",
                 fn->name, func_size, ncallers, ncallers);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 13 — Return-Oriented Programming / Call Graph Anomaly
     * Detects when the tail-call density is abnormally high — a sign of
     * ROP gadget chains or compiler-generated trampoline obfuscation.
     * ====================================================================*/
    {
        int tail_calls = 0, total_branches = 0;
        for (i = 0; i < bin->nxrefs && i < DAX_MAX_XREFS; i++) {
            if (bin->xrefs[i].is_call) total_branches++;
            /* A tail-call xref lands inside a function but at a non-start addr */
            dax_func_t *tgt = dax_func_find(bin, bin->xrefs[i].to);
            if (tgt && bin->xrefs[i].to != tgt->start &&
                bin->xrefs[i].is_call) tail_calls++;
        }
        if (total_branches > 10) {
            int pct = (tail_calls * 100) / total_branches;
            if (pct >= 25) {
                int conf = 50 + (pct > 60 ? 30 : pct / 2);
                if (conf > 90) conf = 90;
                aire_add(bin, bin->base, "rop-like", conf,
                         "[abnormal tail-call / mid-function branch density]\n"
                         "  SIGNALS %d/%d call-xrefs land mid-function (%d%%)\n"
                         "  EXPLAIN Normal compiled code calls functions at\n"
                         "  their entry points. Mid-function branches from call\n"
                         "  sites indicate: (1) ROP/JOP gadget chains, (2) split\n"
                         "  functions from an aggressive code-layout obfuscator,\n"
                         "  (3) manually crafted assembly stubs that chain into\n"
                         "  the middle of other functions to reuse code.\n"
                         "  EVASION Defeats call-graph-based function boundary\n"
                         "  detection and makes decompiler output unreliable.\n"
                         "  ACTION  Run 'callgraph' to visualise the anomalous\n"
                         "  edges. Use 'xrefs-to <addr>' for each mid-function\n"
                         "  target to see all sources of the anomalous branches.",
                         tail_calls, total_branches, pct);
            }
        }
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 14 — Symbol Confusion / Name Collision
     * Multiple functions with the same name prefix but different sizes —
     * a code-duplication obfuscation that defeats cross-reference analysis.
     * ====================================================================*/
    {
        /* Count name prefix collisions */
        int collisions = 0;
        for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
            dax_func_t *fn = &bin->functions[fi];
            if (!fn->name[0] || strncmp(fn->name, "sub_", 4) != 0) continue;
            for (int fj = fi+1; fj < bin->nfunctions && fj < DAX_MAX_FUNCTIONS; fj++) {
                dax_func_t *fn2 = &bin->functions[fj];
                if (fn2->end == fn->end && fn2->start != fn->start &&
                    fn2->name[0]) collisions++;
            }
        }
        (void)collisions;
        /* Also check for functions whose size is exactly 4/8 (thunks) */
        int thunk_count = 0;
        for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
            int sz = (bin->functions[fi].end > bin->functions[fi].start)
                   ? (int)(bin->functions[fi].end - bin->functions[fi].start) : 0;
            if (sz == 4 || sz == 8) thunk_count++;
        }
        if (thunk_count > bin->nfunctions / 4 && thunk_count > 5) {
            int conf = 55 + (thunk_count > 20 ? 25 : thunk_count);
            if (conf > 88) conf = 88;
            aire_add(bin, bin->base, "thunk-forest", conf,
                     "[abnormal thunk density — %d/%d functions are 4/8-byte stubs]\n"
                     "  EXPLAIN %d functions are exactly 4 or 8 bytes — the size\n"
                     "  of a single branch/ret instruction. This 'thunk forest'\n"
                     "  pattern appears in: (1) import trampoline tables, (2)\n"
                     "  LLVM-obfuscated binaries where each 'function' is a\n"
                     "  single indirect branch to a real handler, (3) manually\n"
                     "  constructed call-forwarding layers.\n"
                     "  EVASION Each thunk is a separate CFG node — tools that\n"
                     "  analyse function-level call graphs see hundreds of tiny\n"
                     "  nodes instead of the real function topology.\n"
                     "  ACTION  Run 'afl' to list all functions with size < 16.\n"
                     "  Trace each thunk's single branch target to reconstruct\n"
                     "  the real call graph. Use 'callgraph' to visualise.",
                     thunk_count, bin->nfunctions, thunk_count);
        }
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 15 — Heap Spray / Allocation Anomaly
     * Detects repeated mmap/malloc calls in a tight loop — a signal of
     * runtime code generation, JIT compilers, or heap-based shellcode.
     * ====================================================================*/
    {
        int alloc_xrefs = 0;
        const char *alloc_names[] = {"malloc","calloc","mmap","VirtualAlloc",
                                     "HeapAlloc","valloc","mprotect",NULL};
        for (i = 0; i < bin->nsymbols && i < DAX_MAX_SYMBOLS; i++) {
            const char *sn = bin->symbols[i].name;
            for (int ai = 0; alloc_names[ai]; ai++) {
                if (strstr(sn, alloc_names[ai])) {
                    /* Count xrefs to this symbol */
                    for (int xi = 0; xi < bin->nxrefs && xi < DAX_MAX_XREFS; xi++)
                        if (bin->xrefs[xi].to == bin->symbols[i].address)
                            alloc_xrefs++;
                    break;
                }
            }
        }
        if (alloc_xrefs >= 5) {
            int conf = 45 + (alloc_xrefs > 15 ? 30 : alloc_xrefs * 2);
            if (conf > 88) conf = 88;
            aire_add(bin, bin->base, "runtime-alloc", conf,
                     "[high runtime allocation density — %d alloc call-sites]\n"
                     "  EXPLAIN %d call sites to memory allocation functions.\n"
                     "  High allocation density in a non-server binary suggests:\n"
                     "  (1) a JIT compiler generating native code at runtime,\n"
                     "  (2) a VM interpreter allocating handler code per opcode,\n"
                     "  (3) a packer that allocates and decrypts payload regions\n"
                     "  one block at a time to defeat memory forensics.\n"
                     "  EVASION Heap-allocated code regions are harder to capture\n"
                     "  than .text patches — they appear and disappear dynamically.\n"
                     "  ACTION  Hook malloc/mmap with Frida and log every allocation\n"
                     "  ≥ 1 page (4096 bytes) with PROT_EXEC. Dump each such region\n"
                     "  immediately after allocation for static analysis.",
                     alloc_xrefs, alloc_xrefs);
        }
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 16 — DSA Key Material Detection
     * Defs tagged DSA_TAG_KEY_MATERIAL in any function — likely key schedule,
     * round key expansion, or cipher initialisation.
     * ====================================================================*/
    for (fi = 0; fi < bin->nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
        dax_func_t *fn = &bin->functions[fi];
        if (!fn->name[0]) continue;
        int func_size = (fn->end > fn->start) ? (int)(fn->end-fn->start) : 0;
        if (func_size < 32) continue;

        int sig = dax_dsa_aire_signals(bin, fi, NULL, NULL);
        if (!(sig & 0x20)) continue;

        int conf = 58 + (func_size > 256 ? 15 : func_size / 16);
        if (conf > 87) conf = 87;

        aire_add(bin, fn->start, "key-material", conf,
                 "[DSA key-material defs in '%s']\n"
                 "  EXPLAIN DSA traced definition values and found registers\n"
                 "  holding high-entropy 64-bit constants (many bits set in both\n"
                 "  upper and lower 32 bits). These are characteristic of:\n"
                 "  encryption key bytes, round-key material expanded from a\n"
                 "  master key, nonce values, or XOR mask sequences.\n"
                 "  Unlike crypto-const (known constants), key material is\n"
                 "  input-dependent — different each run or per session.\n"
                 "  EVASION Key material in registers is invisible to static\n"
                 "  analysis and to file-level YARA rules.\n"
                 "  ACTION  Run 'dsa %s' and look for DEF entries tagged\n"
                 "  'key-material'. Set a watchpoint on those registers at the\n"
                 "  def site to capture the key during execution.",
                 fn->name, fn->name);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * RULE 17 — Control-Flow Flattening Metric
     * Ratio of blocks to unique predecessors — CFF creates a star topology
     * where one central dispatcher has N predecessors but only 1 successor
     * pattern per block.
     * ====================================================================*/
    {
        if (bin->nblocks > 4) {
            int max_preds = 0;
            uint64_t hub_addr = 0;
            int hub_fi = -1;
            for (i = 0; i < bin->nblocks; i++) {
                if (bin->blocks[i].npred > max_preds) {
                    max_preds = bin->blocks[i].npred;
                    hub_addr  = bin->blocks[i].start;
                    hub_fi    = bin->blocks[i].func_idx;
                }
            }
            /* CFF hub: many predecessors, 1-2 successors */
            if (max_preds >= 6) {
                int hub_succ = (hub_fi >= 0) ? 0 : 0;
                for (i = 0; i < bin->nblocks; i++)
                    if (bin->blocks[i].start == hub_addr) {
                        hub_succ = bin->blocks[i].nsucc; break;
                    }
                int conf = 55 + (max_preds > 12 ? 25 : max_preds * 2);
                if (conf > 90) conf = 90;
                const char *fn_name = (hub_fi >= 0 && hub_fi < bin->nfunctions && hub_fi < DAX_MAX_FUNCTIONS)
                                      ? bin->functions[hub_fi].name : "?";
                aire_add(bin, hub_addr, "cff-hub", conf,
                         "[CFF dispatcher hub at 0x%llx in '%s']\n"
                         "  SIGNALS %d predecessors, %d successors\n"
                         "  EXPLAIN A basic block with %d incoming edges and\n"
                         "  only %d outgoing edges is the signature of a\n"
                         "  control-flow flattening dispatcher. All logic blocks\n"
                         "  loop back to this hub which routes them to the next\n"
                         "  block via a switch variable — eliminating all direct\n"
                         "  block-to-block edges from the original CFG.\n"
                         "  EVASION Decompilers produce a single giant loop with\n"
                         "  a switch — semantically correct but unreadable.\n"
                         "  ACTION  Run 'cfg %s' to visualise the star topology.\n"
                         "  Use '-P' to let symexec compute the switch variable\n"
                         "  values and recover direct block edges.",
                         (unsigned long long)hub_addr, fn_name,
                         max_preds, hub_succ, max_preds, hub_succ, fn_name);
            }
        }
    }

    /* ══════════════════════════════════════════════════════════════════════
     * PRINT
     * ====================================================================*/
    if (bin->naire_insights == 0) {
        fprintf(out, "  %s(AIRE: no significant patterns detected — "
                "binary appears unobfuscated)%s\n\n", CDim, CR);
        return;
    }

    /* sort by confidence descending */
    for (i = 0; i < bin->naire_insights - 1; i++) {
        int j;
        for (j = 0; j < bin->naire_insights - 1 - i; j++) {
            if (bin->aire_insights[j].confidence <
                bin->aire_insights[j+1].confidence) {
                dax_aire_insight_t tmp  = bin->aire_insights[j];
                bin->aire_insights[j]   = bin->aire_insights[j+1];
                bin->aire_insights[j+1] = tmp;
            }
        }
    }

    for (i = 0; i < bin->naire_insights; i++) {
        dax_aire_insight_t *ins = &bin->aire_insights[i];

        /* category colour */
        const char *catcol =
            !strcmp(ins->category,"vm-dispatch")  ? CRed   :
            !strcmp(ins->category,"poly")          ? CWarn  :
            !strcmp(ins->category,"smc")           ? CRed   :
            !strcmp(ins->category,"anti-debug")    ? CWarn  :
            !strcmp(ins->category,"packer")        ? CMag   :
            !strcmp(ins->category,"func-purpose")  ? CCyan  :
            !strcmp(ins->category,"arch-oddity")   ? CWarn  :
            !strcmp(ins->category,"multi-layer")   ? CRed   :
            CDim;

        /* confidence bar */
        char bar[22]; int b;
        int filled = ins->confidence / 5;
        for (b = 0; b < 20; b++) bar[b] = b < filled ? '#' : '.';
        bar[20] = '\0';

        fprintf(out, "  %s╔═[%s]%s  %s0x%llx%s  "
                "%sconfidence %d%%%s  %s[%s]%s\n",
                catcol, ins->category, CR,
                CAddr,  (unsigned long long)ins->addr, CR,
                CConf,  ins->confidence, CR,
                CDim, bar, CR);

        /* print structured lines: indent all, colour ACTION lines */
        const char *p = ins->insight;
        while (*p) {
            /* find end of line */
            const char *nl = strchr(p, '\n');
            int linelen = nl ? (int)(nl - p) : (int)strlen(p);

            /* trim leading spaces for sub-lines */
            const char *line = p;
            while (*line == ' ') line++;
            int indent = (int)(line - p);

            /* detect ACTION lines for green highlight */
            int is_action = (strncmp(line, "ACTION", 6) == 0);

            if (is_action)
                fprintf(out, "  %s║  %s%.*s%s\n",
                        catcol, CAction, linelen - indent, line, CR);
            else
                fprintf(out, "  %s║%s  %s%.*s%s\n",
                        catcol, CR, CDim, linelen - indent, line, CR);

            p += linelen;
            if (*p == '\n') p++;
        }
        fprintf(out, "  %s╚══%s\n\n", catcol, CR);
    }

    /* ── Context-aware focus banner ────────────────────────────────────────
     * Count dominant category across all insights, then emit a focused
     * "you are looking at a X binary" line so the analyst knows what matters.
     * ─────────────────────────────────────────────────────────────────────*/
    int cnt_vm=0, cnt_smc=0, cnt_poly=0, cnt_ad=0, cnt_pack=0,
        cnt_func=0, cnt_odd=0, cnt_multi=0,
        cnt_opq=0, cnt_crypt=0, cnt_loop=0, cnt_strdec=0,
        cnt_rop=0, cnt_thunk=0, cnt_alloc=0, cnt_key=0, cnt_cff=0;
    for (i = 0; i < bin->naire_insights; i++) {
        const char *cat = bin->aire_insights[i].category;
        if      (!strcmp(cat,"vm-dispatch"))  cnt_vm++;
        else if (!strcmp(cat,"smc"))          cnt_smc++;
        else if (!strcmp(cat,"poly"))         cnt_poly++;
        else if (!strcmp(cat,"anti-debug"))   cnt_ad++;
        else if (!strcmp(cat,"packer"))       cnt_pack++;
        else if (!strcmp(cat,"func-purpose")) cnt_func++;
        else if (!strcmp(cat,"arch-oddity"))  cnt_odd++;
        else if (!strcmp(cat,"multi-layer"))  cnt_multi++;
        else if (!strcmp(cat,"opaque-pred"))  cnt_opq++;
        else if (!strcmp(cat,"crypto-id"))    cnt_crypt++;
        else if (!strcmp(cat,"loop-struct"))  cnt_loop++;
        else if (!strcmp(cat,"str-decrypt"))  cnt_strdec++;
        else if (!strcmp(cat,"rop-like"))     cnt_rop++;
        else if (!strcmp(cat,"thunk-forest")) cnt_thunk++;
        else if (!strcmp(cat,"runtime-alloc"))cnt_alloc++;
        else if (!strcmp(cat,"key-material")) cnt_key++;
        else if (!strcmp(cat,"cff-hub"))      cnt_cff++;
    }

    /* pick dominant category */
    const char *dom_cat   = "general";
    const char *dom_label = "general analysis";
    const char *dom_col   = CDim;
    int dom_max = 0;
#define _DOM(cnt,cat,label,col) \
    if ((cnt) > dom_max) { dom_max=(cnt); dom_cat=(cat); dom_label=(label); dom_col=(col); }
    _DOM(cnt_vm,    "vm-dispatch",  "VM interpreter / dispatch loop",   CRed)
    _DOM(cnt_smc,   "smc",          "self-modifying code (SMC)",        CRed)
    _DOM(cnt_poly,  "poly",         "polymorphic / self-mutating code", CWarn)
    _DOM(cnt_ad,    "anti-debug",   "anti-debugging techniques",        CWarn)
    _DOM(cnt_pack,  "packer",       "packed / encrypted payload",       CMag)
    _DOM(cnt_func,  "func-purpose", "function-purpose identification",  CCyan)
    _DOM(cnt_odd,   "arch-oddity",  "architecture oddities",            CWarn)
    _DOM(cnt_multi, "multi-layer",  "multi-layer obfuscation",          CRed)
    _DOM(cnt_opq,   "opaque-pred",  "DSA-confirmed opaque predicates",  CWarn)
    _DOM(cnt_crypt, "crypto-id",    "DSA crypto algorithm identified",  CCyan)
    _DOM(cnt_loop,  "loop-struct",  "DSA loop / induction variable",    CCyan)
    _DOM(cnt_strdec,"str-decrypt",  "string decryption stubs",          CMag)
    _DOM(cnt_rop,   "rop-like",     "ROP/JOP-like branch anomaly",      CRed)
    _DOM(cnt_thunk, "thunk-forest", "thunk forest / trampoline layer",  CWarn)
    _DOM(cnt_alloc, "runtime-alloc","runtime allocation density",       CMag)
    _DOM(cnt_key,   "key-material", "DSA key material detected",        CMag)
    _DOM(cnt_cff,   "cff-hub",      "CFF dispatcher hub (OLLVM-style)", CRed)
#undef _DOM

    fprintf(out, "  %s┌─ Context ───────────────────────────────────────────┐%s\n", CDim, CR);
    fprintf(out, "  %s│%s  Focus: %s%s%s\n", CDim, CR, dom_col, dom_label, CR);

    /* per-category focus tips */
    if (!strcmp(dom_cat, "vm-dispatch"))
        fprintf(out, "  %s│%s  %sThis binary uses a virtual machine interpreter. Trace%s\n"
                     "  %s│%s  %sthe dispatch loop and map opcode → handler tables.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    else if (!strcmp(dom_cat, "smc") || !strcmp(dom_cat, "poly"))
        fprintf(out, "  %s│%s  %sCode modifies itself at runtime. Run 'poly' to map%s\n"
                     "  %s│%s  %smutation regions, then 'vt' to trace execution flow.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    else if (!strcmp(dom_cat, "anti-debug"))
        fprintf(out, "  %s│%s  %sAnti-debug checks detected. Focus on timing checks%s\n"
                     "  %s│%s  %sand sysreg reads near entry/init functions.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    else if (!strcmp(dom_cat, "packer"))
        fprintf(out, "  %s│%s  %sPacked/encrypted section found. Locate the unpack%s\n"
                     "  %s│%s  %sstub and set a breakpoint at OEP after decryption.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    else if (!strcmp(dom_cat, "opaque-pred"))
        fprintf(out, "  %s│%s  %sDSA found dead-arm phi nodes — opaque predicates.%s\n"
                     "  %s│%s  %sRun 'dsa <func>' then '-P' to fold them out.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    else if (!strcmp(dom_cat, "crypto-id"))
        fprintf(out, "  %s│%s  %sDSA identified cryptographic constants. Use '-I'%s\n"
                     "  %s│%s  %swith known test vectors to confirm the algorithm.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    else if (!strcmp(dom_cat, "cff-hub"))
        fprintf(out, "  %s│%s  %sControl-flow flattening detected. The CFG has a%s\n"
                     "  %s│%s  %sstar-shaped dispatcher — run '-P' to recover it.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    else if (!strcmp(dom_cat, "str-decrypt"))
        fprintf(out, "  %s│%s  %sString decryption stubs found. Hook each call site%s\n"
                     "  %s│%s  %swith Frida to extract all plaintext strings.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    else if (!strcmp(dom_cat, "rop-like"))
        fprintf(out, "  %s│%s  %sROP-like mid-function branches detected. Trace the%s\n"
                     "  %s│%s  %schain with 'callgraph' to reconstruct real flow.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    else if (!strcmp(dom_cat, "key-material"))
        fprintf(out, "  %s│%s  %sDSA found key material in register defs. Run 'dsa'%s\n"
                     "  %s│%s  %son flagged functions and watchpoint the def sites.%s\n",
                     CDim, CR, CDim, CR, CDim, CR, CDim, CR);
    fprintf(out, "  %s└─────────────────────────────────────────────────────┘%s\n\n", CDim, CR);

    /* ── Next-step guide ────────────────────────────────────────────────────
     * Suggest the most useful follow-up command based on dominant category.
     * ─────────────────────────────────────────────────────────────────────*/
    fprintf(out, "  %s┌─ Next Steps ────────────────────────────────────────┐%s\n", CDim, CR);

    if (!strcmp(dom_cat, "vm-dispatch")) {
        fprintf(out, "  %s│%s  %s① run vt%s          — trace VM dispatch flow\n",       CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② cfg <func>%s      — build CFG for the dispatch loop\n", CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ xrefs <addr>%s    — find all opcode handler callers\n", CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "smc") || !strcmp(dom_cat, "poly")) {
        fprintf(out, "  %s│%s  %s① poly%s            — map polymorphic/SMC regions\n",   CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② run vt%s          — trace execution through mutations\n", CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ entropy%s         — identify high-entropy data blobs\n", CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "anti-debug")) {
        fprintf(out, "  %s│%s  %s① strings%s         — find anti-debug string markers\n", CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② symexec <func>%s  — symbolically execute check funcs\n",CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ xrefs <addr>%s    — trace callers of timing checks\n", CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "packer")) {
        fprintf(out, "  %s│%s  %s① entropy%s         — confirm encrypted section bounds\n",CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② run vt%s          — trace unpack stub execution\n",    CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ cfg <entry>%s     — map unpack CFG to find OEP jump\n",CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "func-purpose")) {
        fprintf(out, "  %s│%s  %s① funcs%s           — list all detected functions\n",    CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② callgraph%s       — visualise call relationships\n",   CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ decompile <func>%s — decompile key functions\n",      CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "opaque-pred")) {
        fprintf(out, "  %s│%s  %s① dsa <func>%s      — show phi nodes + dead arms\n",   CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② symexec <func>%s  — fold opaque predicates\n",        CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ cfg <func>%s      — view pruned CFG after folding\n", CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "crypto-id")) {
        fprintf(out, "  %s│%s  %s① dsa <func>%s      — list crypto constant defs\n",     CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② emulate <func>%s  — run with known test vectors\n",   CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ decompile <func>%s — read pseudo-C of key schedule\n",CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "cff-hub")) {
        fprintf(out, "  %s│%s  %s① cfg <func>%s      — visualise star-shaped CFG\n",     CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② symexec <func>%s  — recover direct block edges\n",    CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ decompile <func>%s — decompile with folded CFG\n",    CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "str-decrypt")) {
        fprintf(out, "  %s│%s  %s① strings%s         — find encrypted string refs\n",    CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② xrefs <func>%s    — trace all call sites\n",          CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ emulate <func>%s  — recover plaintext per call\n",    CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "rop-like")) {
        fprintf(out, "  %s│%s  %s① callgraph%s       — map anomalous edges\n",            CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② xrefs <addr>%s    — trace mid-function branches\n",   CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ cfg <func>%s      — reconstruct true CFG\n",          CDim,CR,CAction,CR);
    } else if (!strcmp(dom_cat, "key-material")) {
        fprintf(out, "  %s│%s  %s① dsa <func>%s      — show key-material def sites\n",   CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② emulate <func>%s  — observe key values at runtime\n", CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ decompile <func>%s — read key schedule pseudo-C\n",   CDim,CR,CAction,CR);
    } else {
        fprintf(out, "  %s│%s  %s① strings%s         — scan for meaningful strings\n",    CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s② funcs%s           — enumerate detected functions\n",   CDim,CR,CAction,CR);
        fprintf(out, "  %s│%s  %s③ entropy%s         — check section entropy levels\n",   CDim,CR,CAction,CR);
    }
    fprintf(out, "  %s└─────────────────────────────────────────────────────┘%s\n\n", CDim, CR);

    /* ── AIRE footer ─────────────────────────────────────────────────────── */
    fprintf(out, "  %s── AIRE: %d insight(s) | %d rule(s) evaluated ──%s\n\n",
            CDim, bin->naire_insights, 17, CR);

    /* ── Memory save: persist this analysis for next time ─────────────────*/
    {
        /* build summary from top insight */
        char summary[256] = "";
        int  top_conf = 0;
        uint64_t top_addr = 0;
        for (i = 0; i < bin->naire_insights; i++) {
            if (bin->aire_insights[i].confidence > top_conf) {
                top_conf = bin->aire_insights[i].confidence;
                top_addr = bin->aire_insights[i].addr;
                /* copy first line of insight as summary */
                const char *nl = strchr(bin->aire_insights[i].insight, '\n');
                int slen = nl ? (int)(nl - bin->aire_insights[i].insight)
                              : (int)strlen(bin->aire_insights[i].insight);
                if (slen > (int)sizeof(summary)-1) slen = (int)sizeof(summary)-1;
                memcpy(summary, bin->aire_insights[i].insight, (size_t)slen);
                summary[slen] = '\0';
            }
        }

        /* find or create slot */
        aire_memory_entry_t *slot = NULL;
        int found_slot = 0;
        for (i = 0; i < mem.count && i < AIRE_MEMORY_MAX_ENTRIES; i++) {
            if (strcmp(mem.entries[i].sha256, bin->sha256) == 0) {
                slot = &mem.entries[i]; found_slot = 1; break;
            }
        }
        if (!slot && mem.count < AIRE_MEMORY_MAX_ENTRIES) {
            slot = &mem.entries[mem.count++];
            memset(slot, 0, sizeof(*slot));
        }
        if (slot) {
            snprintf(slot->sha256,   sizeof(slot->sha256),   "%s", bin->sha256);
            snprintf(slot->filepath, sizeof(slot->filepath), "%.255s", bin->filepath);
            snprintf(slot->category, sizeof(slot->category), "%.31s", dom_cat);
            snprintf(slot->summary,  sizeof(slot->summary),  "%.255s", summary);
            slot->top_confidence = top_conf;
            slot->top_addr       = top_addr;
            slot->run_count      = found_slot ? slot->run_count + 1 : 1;
            /* timestamp via time() */
            {
                time_t now = time(NULL);
                struct tm *tm_info = gmtime(&now);
                strftime(slot->timestamp, sizeof(slot->timestamp),
                         "%Y-%m-%dT%H:%M:%SZ", tm_info);
            }
            /* save */
            FILE *wfp = fopen(AIRE_MEMORY_FILE, "wb");
            if (wfp) { fwrite(&mem, sizeof(aire_memory_t), 1, wfp); fclose(wfp); }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * dax_vm_trace — print the VM dispatch flow captured by the emulator.
 * g_vm_trace / g_nvm_trace are defined in emulate.c and extern'd in dax.h.
 * ═══════════════════════════════════════════════════════════════════════════ */
void dax_vm_trace(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int c = opts ? opts->color : 1;
    int vi;

    const char *CTitle = c ? "\033[1;36m"  : "";
    const char *CAddr  = c ? "\033[1;34m"  : "";
    const char *CGreen = c ? "\033[1;32m"  : "";
    const char *CYel   = c ? "\033[1;33m"  : "";
    const char *CDim   = c ? "\033[0;90m"  : "";
    const char *CRed   = c ? "\033[1;31m"  : "";
    const char *CR     = c ? "\033[0m"     : "";

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", CTitle);
    fprintf(out, "  ══════════════ VM DISPATCH FLOW TRACE ══════════════\n");
    if (c) fprintf(out, "%s", CR);

    if (g_nvm_trace == 0) {
        fprintf(out, "  %s(no VM dispatch events recorded — run 'run <func>' "
                "that contains a VM interpreter first)%s\n\n", CDim, CR);
        return;
    }

    /* header row */
    fprintf(out, "\n  %s  %-6s  %-18s  %-18s  %-12s  %-12s  %s%s\n",
            CDim,
            "step", "dispatch@", "handler@",
            "opcode(x0)", "vm_ip(x1)", "handler_name",
            CR);
    fprintf(out, "  %s  %s  %s  %s  %s  %s  %s%s\n",
            CDim,
            "──────", "──────────────────",
            "──────────────────", "────────────",
            "────────────", "──────────────────────────────────────",
            CR);

    uint64_t prev_dispatch = 0;
    int      prev_step     = -1;

    for (vi = 0; vi < g_nvm_trace; vi++) {
        dax_vm_dispatch_entry_t *vd = &g_vm_trace[vi];

        /* detect dispatch PC change — signals handler returned to loop */
        if (prev_dispatch != 0 && vd->dispatch_pc != prev_dispatch) {
            fprintf(out, "  %s  │   ↳ dispatch PC changed: 0x%llx → 0x%llx%s\n",
                    CDim,
                    (unsigned long long)prev_dispatch,
                    (unsigned long long)vd->dispatch_pc,
                    CR);
        }

        /* detect step gap — possible path the emulator didn't trace */
        if (prev_step >= 0 && vd->step_no - prev_step > 50) {
            fprintf(out, "  %s  │   … %d steps skipped (no dispatch) …%s\n",
                    CDim, vd->step_no - prev_step, CR);
        }

        /* resolve handler label from binary if not already stored */
        const char *lbl = vd->handler_name[0] ? vd->handler_name : NULL;
        if (!lbl && bin) {
            dax_func_t   *fn2 = dax_func_find(bin, vd->handler_pc);
            dax_symbol_t *sym = dax_sym_find(bin, vd->handler_pc);
            if (sym && sym->name[0])
                lbl = sym->demangled[0] ? sym->demangled : sym->name;
            else if (fn2 && fn2->name[0])
                lbl = fn2->name;
        }

        fprintf(out, "  %s  %-6d%s  %s0x%016llx%s  %s0x%016llx%s"
                "  %s0x%08llx%s    %s0x%08llx%s",
                CDim,   vd->step_no,                       CR,
                CAddr,  (unsigned long long)vd->dispatch_pc, CR,
                CGreen, (unsigned long long)vd->handler_pc,  CR,
                CYel,   (unsigned long long)vd->opcode_val,  CR,
                CDim,   (unsigned long long)vd->ip_val,      CR);

        if (lbl)
            fprintf(out, "  %s<%s>%s", CGreen, lbl, CR);

        fprintf(out, "\n");

        prev_dispatch = vd->dispatch_pc;
        prev_step     = vd->step_no;
    }

    /* summary */
    fprintf(out, "\n  %s  ── %d dispatch event(s) total", CDim, g_nvm_trace);

    /* count unique handlers */
    int unique = 0, hi, hj;
    uint64_t seen[VM_DISPATCH_MAX];
    for (hi = 0; hi < g_nvm_trace; hi++) {
        int dup = 0;
        for (hj = 0; hj < unique; hj++)
            if (seen[hj] == g_vm_trace[hi].handler_pc) { dup = 1; break; }
        if (!dup) seen[unique++] = g_vm_trace[hi].handler_pc;
    }
    fprintf(out, "  |  %d unique handler(s)%s\n\n", unique, CR);

    /* unique handler list */
    if (unique > 0) {
        fprintf(out, "  %sUnique handlers:%s\n", CDim, CR);
        for (hi = 0; hi < unique; hi++) {
            const char *lbl2 = NULL;
            if (bin) {
                dax_func_t   *fn3 = dax_func_find(bin, seen[hi]);
                dax_symbol_t *sy3 = dax_sym_find(bin, seen[hi]);
                if (sy3 && sy3->name[0])
                    lbl2 = sy3->demangled[0] ? sy3->demangled : sy3->name;
                else if (fn3 && fn3->name[0])
                    lbl2 = fn3->name;
            }
            /* count how many times this handler was dispatched */
            int hits = 0, hk;
            for (hk = 0; hk < g_nvm_trace; hk++)
                if (g_vm_trace[hk].handler_pc == seen[hi]) hits++;

            const char *hcol = hits >= 5 ? CRed : hits >= 2 ? CYel : CGreen;
            fprintf(out, "    %s[%2d calls]%s  %s0x%llx%s  %s%s%s\n",
                    hcol, hits, CR,
                    CAddr, (unsigned long long)seen[hi], CR,
                    CGreen, lbl2 ? lbl2 : "?", CR);
        }
        fprintf(out, "\n");
    }
}
