#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"

#define SYM_MAX_VARS   64
#define SYM_MAX_PATH   32
#define SYM_MAX_INSNS  4096
#define SYM_MAX_CONSTRAINTS 128

typedef enum {
    SV_CONCRETE = 0,
    SV_SYMBOLIC,
    SV_EXPR
} sym_vkind_t;

typedef enum {
    SEXPR_ADD = 0, SEXPR_SUB, SEXPR_AND, SEXPR_OR, SEXPR_XOR,
    SEXPR_SHL, SEXPR_SHR, SEXPR_MUL, SEXPR_NOT, SEXPR_NEG,
    SEXPR_CONST, SEXPR_VAR, SEXPR_EQ, SEXPR_NE, SEXPR_LT, SEXPR_LE,
    SEXPR_EXTRACT, SEXPR_CONCAT, SEXPR_UNDEF
} sexpr_op_t;

typedef struct sym_expr sym_expr_t;
struct sym_expr {
    sexpr_op_t  op;
    uint64_t    val;
    int         left;
    int         right;
    char        name[24];
    uint8_t     bits;
};

#define SYM_EXPR_POOL 1024
static sym_expr_t g_pool[SYM_EXPR_POOL];
static int        g_npool = 0;

static int sexpr_alloc(void) {
    if (g_npool >= SYM_EXPR_POOL) return 0;
    memset(&g_pool[g_npool], 0, sizeof(sym_expr_t));
    return g_npool++;
}

static int sexpr_const(uint64_t v, uint8_t bits) {
    int idx = sexpr_alloc();
    g_pool[idx].op   = SEXPR_CONST;
    g_pool[idx].val  = v;
    g_pool[idx].bits = bits;
    return idx;
}

static int sexpr_var(const char *name, uint8_t bits) {
    int idx = sexpr_alloc();
    g_pool[idx].op   = SEXPR_VAR;
    g_pool[idx].bits = bits;
    strncpy(g_pool[idx].name, name, 23);
    return idx;
}

static int sexpr_binop(sexpr_op_t op, int l, int r, uint8_t bits) {
    int idx = sexpr_alloc();
    g_pool[idx].op    = op;
    g_pool[idx].left  = l;
    g_pool[idx].right = r;
    g_pool[idx].bits  = bits;
    return idx;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
static void sexpr_print(int idx, char *buf, size_t bufsz) {
    if (bufsz < 4 || idx < 0 || idx >= g_npool) {
        snprintf(buf, bufsz, "?");
        return;
    }
    sym_expr_t *e = &g_pool[idx];
    char l[256], r[256];

    switch (e->op) {
        case SEXPR_CONST:
            snprintf(buf, bufsz, "0x%llx", (unsigned long long)e->val);
            return;
        case SEXPR_VAR:
            snprintf(buf, bufsz, "%s", e->name);
            return;
        case SEXPR_ADD:
            sexpr_print(e->left,l,sizeof(l)); sexpr_print(e->right,r,sizeof(r));
            snprintf(buf,bufsz,"(%s + %s)",l,r); return;
        case SEXPR_SUB:
            sexpr_print(e->left,l,sizeof(l)); sexpr_print(e->right,r,sizeof(r));
            snprintf(buf,bufsz,"(%s - %s)",l,r); return;
        case SEXPR_AND:
            sexpr_print(e->left,l,sizeof(l)); sexpr_print(e->right,r,sizeof(r));
            snprintf(buf,bufsz,"(%s & %s)",l,r); return;
        case SEXPR_OR:
            sexpr_print(e->left,l,sizeof(l)); sexpr_print(e->right,r,sizeof(r));
            snprintf(buf,bufsz,"(%s | %s)",l,r); return;
        case SEXPR_SHL:
            sexpr_print(e->left,l,sizeof(l)); sexpr_print(e->right,r,sizeof(r));
            snprintf(buf,bufsz,"(%s << %s)",l,r); return;
        case SEXPR_SHR:
            sexpr_print(e->left,l,sizeof(l)); sexpr_print(e->right,r,sizeof(r));
            snprintf(buf,bufsz,"(%s >> %s)",l,r); return;
        case SEXPR_XOR:
            sexpr_print(e->left,l,sizeof(l)); sexpr_print(e->right,r,sizeof(r));
            snprintf(buf,bufsz,"(%s ^ %s)",l,r); return;
        case SEXPR_NOT:
            sexpr_print(e->left,l,sizeof(l));
            snprintf(buf,bufsz,"~%s",l); return;
        case SEXPR_NEG:
            sexpr_print(e->left,l,sizeof(l));
            snprintf(buf,bufsz,"-%s",l); return;
        default:
            snprintf(buf,bufsz,"expr(%d)",idx); return;
    }
}
#pragma GCC diagnostic pop

typedef struct {
    int       expr_idx;
    int       is_concrete;
    uint64_t  concrete;
    uint8_t   bits;
} sym_val_t;

static void sv_make_const(sym_val_t *v, uint64_t c, uint8_t bits) {
    v->is_concrete = 1;
    v->concrete    = c;
    v->bits        = bits;
    v->expr_idx    = sexpr_const(c, bits);
}

static void sv_make_sym(sym_val_t *v, const char *name, uint8_t bits) {
    v->is_concrete = 0;
    v->bits        = bits;
    v->expr_idx    = sexpr_var(name, bits);
}

#define MAX_SYM_REGS 32

typedef struct {
    sym_val_t regs[MAX_SYM_REGS];
    uint64_t  pc;
    int       path_id;
    int       insn_count;
    int       flags_zf;
    int       flags_nf;
    int       flags_cf;
    int       flags_expr;
} sym_state_t;

static void sym_state_init_arm64(sym_state_t *s, uint64_t pc) {
    int i;
    char name[16];
    memset(s, 0, sizeof(*s));
    s->pc = pc;
    for (i = 0; i < 32; i++) {
        snprintf(name, sizeof(name), "x%d", i);
        sv_make_sym(&s->regs[i], name, 64);
    }
    sv_make_const(&s->regs[31], 0, 64);
}

static void sym_state_init_x86(sym_state_t *s, uint64_t pc) {
    static const char *names[] = {
        "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
        "r8","r9","r10","r11","r12","r13","r14","r15"
    };
    int i;
    memset(s, 0, sizeof(*s));
    s->pc = pc;
    for (i = 0; i < 16; i++)
        sv_make_sym(&s->regs[i], names[i], 64);
    sv_make_const(&s->regs[4], 0x7fff0000ULL, 64);
}

static int arm64_reg_idx(const char *name) {
    if (!name || !name[0]) return -1;
    if (name[0]=='x'||name[0]=='w') {
        int n = atoi(name+1);
        if (n >= 0 && n <= 30) return n;
    }
    if (strcmp(name,"sp")==0||strcmp(name,"wsp")==0) return 31;
    if (strcmp(name,"xzr")==0||strcmp(name,"wzr")==0) return 31;
    if (strcmp(name,"lr")==0) return 30;
    if (strcmp(name,"fp")==0) return 29;
    return -1;
}

static int x86_reg_idx(const char *name) {
    static const char *r64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                  "r8","r9","r10","r11","r12","r13","r14","r15"};
    static const char *r32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
    static const char *r16[] = {"ax","cx","dx","bx","sp","bp","si","di"};
    static const char *r8[]  = {"al","cl","dl","bl"};
    int i;
    for (i=0;i<16;i++) if(strcmp(name,r64[i])==0) return i;
    for (i=0;i<8;i++)  if(strcmp(name,r32[i])==0) return i;
    for (i=0;i<8;i++)  if(strcmp(name,r16[i])==0) return i;
    for (i=0;i<4;i++)  if(strcmp(name,r8[i])==0)  return i;
    if (strncmp(name,"r",1)==0 && strlen(name)>=2) {
        int n = atoi(name+1);
        if (n>=8&&n<=15) return n;
    }
    return -1;
}

static sym_val_t sym_apply_binop(sym_val_t *a, sym_val_t *b, sexpr_op_t op) {
    sym_val_t result;
    result.bits = a->bits;
    if (a->is_concrete && b->is_concrete) {
        uint64_t v = 0;
        switch (op) {
            case SEXPR_ADD: v = a->concrete + b->concrete; break;
            case SEXPR_SUB: v = a->concrete - b->concrete; break;
            case SEXPR_AND: v = a->concrete & b->concrete; break;
            case SEXPR_OR:  v = a->concrete | b->concrete; break;
            case SEXPR_XOR: v = a->concrete ^ b->concrete; break;
            case SEXPR_SHL: v = a->concrete << (b->concrete & 63); break;
            case SEXPR_SHR: v = a->concrete >> (b->concrete & 63); break;
            case SEXPR_MUL: v = a->concrete * b->concrete; break;
            default: v = 0; break;
        }
        if (a->bits == 32) v &= 0xFFFFFFFF;
        sv_make_const(&result, v, a->bits);
    } else {
        result.is_concrete = 0;
        result.expr_idx    = sexpr_binop(op, a->expr_idx, b->expr_idx, a->bits);
    }
    return result;
}

typedef struct {
    uint64_t  addr;
    char      reg[16];
    char      expr[128];
    int       is_concrete;
    uint64_t  concrete_val;
} sym_result_t;

typedef struct {
    sym_result_t results[SYM_MAX_VARS];
    int          nresults;
    uint64_t     entry_pc;
    int          steps;
    char         path_condition[256];
} sym_analysis_t;

static void step_arm64(sym_state_t *s, const char *mnem, const char *ops,
                        sym_analysis_t *out) {
    char a1[64]="", a2[64]="", a3[64]="";
    int  nfields = 0;
    {
        const char *p = ops;
        char *bufs[3] = {a1, a2, a3};
        int   sizes[3] = {64, 64, 64};
        while (*p && nfields < 3) {
            while (*p == ' ') p++;
            char *dst = bufs[nfields];
            int   max = sizes[nfields] - 1;
            int   j   = 0;
            while (*p && *p != ',' && j < max) { *dst++ = *p++; j++; }
            *dst = '\0';
            nfields++;
            if (*p == ',') p++;
        }
    }

    int dst_reg = arm64_reg_idx(a1);
    int src1    = arm64_reg_idx(a2);
    int src2    = arm64_reg_idx(a3);

    if (strcmp(mnem,"mov")==0 || strcmp(mnem,"movz")==0) {
        if (dst_reg >= 0) {
            if (src1 >= 0) {
                s->regs[dst_reg] = s->regs[src1];
                s->regs[dst_reg].bits = (a1[0]=='w') ? 32 : 64;
            } else {
                uint64_t imm = 0;
                if (a2[0]=='#') imm = (uint64_t)strtoull(a2+1,NULL,0);
                else             imm = (uint64_t)strtoull(a2,NULL,0);
                sv_make_const(&s->regs[dst_reg], imm, (a1[0]=='w')?32:64);
            }
        }
    } else if (strcmp(mnem,"add")==0 || strcmp(mnem,"adds")==0) {
        if (dst_reg >= 0 && src1 >= 0) {
            sym_val_t b;
            if (src2 >= 0) b = s->regs[src2];
            else {
                uint64_t imm = 0;
                const char *ip = a3;
                if (*ip=='#') ip++;
                if (strncmp(ip,"0x",2)==0) imm=(uint64_t)strtoull(ip,NULL,16);
                else imm=(uint64_t)strtoull(ip,NULL,0);
                sv_make_const(&b, imm, s->regs[src1].bits);
            }
            s->regs[dst_reg] = sym_apply_binop(&s->regs[src1], &b, SEXPR_ADD);
        }
    } else if (strcmp(mnem,"sub")==0 || strcmp(mnem,"subs")==0) {
        if (dst_reg >= 0 && src1 >= 0) {
            sym_val_t b;
            if (src2 >= 0) b = s->regs[src2];
            else {
                uint64_t imm=0; const char *ip=a3; if(*ip=='#')ip++;
                imm=(uint64_t)strtoull(ip,NULL,0);
                sv_make_const(&b,imm,s->regs[src1].bits);
            }
            s->regs[dst_reg] = sym_apply_binop(&s->regs[src1], &b, SEXPR_SUB);
        }
    } else if (strcmp(mnem,"and")==0 || strcmp(mnem,"ands")==0) {
        if (dst_reg>=0 && src1>=0 && src2>=0)
            s->regs[dst_reg] = sym_apply_binop(&s->regs[src1],&s->regs[src2],SEXPR_AND);
    } else if (strcmp(mnem,"orr")==0) {
        if (dst_reg>=0 && src1>=0 && src2>=0)
            s->regs[dst_reg] = sym_apply_binop(&s->regs[src1],&s->regs[src2],SEXPR_OR);
    } else if (strcmp(mnem,"eor")==0) {
        if (dst_reg>=0 && src1>=0) {
            if (src2>=0)
                s->regs[dst_reg] = sym_apply_binop(&s->regs[src1],&s->regs[src2],SEXPR_XOR);
            else {
                uint64_t imm=0; const char *ip=a3; if(*ip=='#')ip++;
                imm=(uint64_t)strtoull(ip,NULL,16);
                sym_val_t b; sv_make_const(&b,imm,s->regs[src1].bits);
                s->regs[dst_reg] = sym_apply_binop(&s->regs[src1],&b,SEXPR_XOR);
            }
        }
    } else if (strcmp(mnem,"lsl")==0) {
        if (dst_reg>=0&&src1>=0) {
            sym_val_t b;
            uint64_t imm=0; const char *ip=a3; if(*ip=='#')ip++;
            imm=(uint64_t)strtoull(ip,NULL,0);
            sv_make_const(&b,imm,8);
            s->regs[dst_reg]=sym_apply_binop(&s->regs[src1],&b,SEXPR_SHL);
        }
    } else if (strcmp(mnem,"lsr")==0||strcmp(mnem,"asr")==0) {
        if (dst_reg>=0&&src1>=0) {
            sym_val_t b;
            uint64_t imm=0; const char *ip=a3; if(*ip=='#')ip++;
            imm=(uint64_t)strtoull(ip,NULL,0);
            sv_make_const(&b,imm,8);
            s->regs[dst_reg]=sym_apply_binop(&s->regs[src1],&b,SEXPR_SHR);
        }
    }
}

void dax_symexec_func(dax_binary_t *bin, int func_idx,
                      dax_opts_t *opts, FILE *out) {
    int          c   = opts ? opts->color : 1;
    dax_func_t  *fn;
    uint8_t     *code;
    size_t       sz;
    uint64_t     base;
    int          si;
    sym_state_t  state;
    size_t       off;
    int          steps = 0;

    const char *CY = c ? COL_LABEL   : "";
    const char *CB = c ? COL_ADDR    : "";
    const char *CG = c ? COL_SECTION : "";
    const char *CD = c ? COL_COMMENT : "";
    const char *CR = c ? COL_RESET   : "";
    const char *CM = c ? COL_MNEM    : "";
    const char *CP = c ? COL_PURPLE : "";

    if (!bin || func_idx < 0 || func_idx >= bin->nfunctions) return;
    fn = &bin->functions[func_idx];

    code = NULL; sz = 0; base = 0;
    for (si = 0; si < bin->nsections; si++) {
        dax_section_t *sec = &bin->sections[si];
        if (fn->start >= sec->vaddr && fn->start < sec->vaddr + sec->size &&
            sec->offset + sec->size <= bin->size) {
            code = bin->data + sec->offset;
            sz   = (size_t)sec->size;
            base = sec->vaddr;
            break;
        }
    }
    if (!code) return;

    g_npool = 0;

    if (bin->arch == ARCH_ARM64)
        sym_state_init_arm64(&state, fn->start);
    else
        sym_state_init_x86(&state, fn->start);

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                 " SYMBOLIC EXECUTION: %s "
                 "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n",
                 fn->name);
    if (c) fprintf(out, "%s", CR);
    fprintf(out, "\n");
    fprintf(out, "%s  Entry state: all registers symbolic (input values)%s\n", CD, CR);
    fprintf(out, "\n");

    off = (size_t)(fn->start - base);
    size_t fn_end = (fn->end > fn->start && fn->end <= base + sz)
                    ? (size_t)(fn->end - base) : off + 256;

    while (off < fn_end && off < sz && steps < SYM_MAX_INSNS) {
        uint64_t addr = base + off;
        char mnem[32] = "", ops[256] = "";
        int  len = 0;

        if (bin->arch == ARCH_ARM64) {
            if (off + 4 > sz) break;
            uint32_t raw = (uint32_t)(code[off])|(code[off+1]<<8)|
                           (code[off+2]<<16)|(code[off+3]<<24);
            a64_insn_t insn; a64_decode(raw, addr, &insn);
            strncpy(mnem, insn.mnemonic, 31);
            strncpy(ops,  insn.operands, 255);
            len = 4;
        } else {
            x86_insn_t insn;
            len = x86_decode(code + off, fn_end - off, addr, &insn);
            if (len <= 0) { off++; continue; }
            strncpy(mnem, insn.mnemonic, 31);
            strncpy(ops,  insn.ops, 255);
        }

        state.pc = addr;
        step_arm64(&state, mnem, ops, NULL);

        fprintf(out, "  %s0x%016llx%s  %s%-10s%s %s%s%s\n",
                CB, (unsigned long long)addr, CR, CM, mnem, CR, CD, ops, CR);

        {
            int di = arm64_reg_idx(ops);
            if (di < 0) {
                char tmp[64] = "";
                const char *p = ops;
                int j = 0;
                while (*p && *p != ',' && j < 63) { tmp[j++] = *p++; }
                tmp[j] = '\0';
                di = arm64_reg_idx(tmp);
            }
            if (di >= 0 && di < MAX_SYM_REGS) {
                char expr_str[512];
                sexpr_print(state.regs[di].expr_idx, expr_str, sizeof(expr_str));
                if (state.regs[di].is_concrete) {
                    fprintf(out, "  %s  → %s%s = 0x%llx%s\n",
                            CD, CP,
                            state.regs[di].bits==32?ops:ops,
                            (unsigned long long)state.regs[di].concrete,
                            CR);
                } else {
                    char regname[16];
                    strncpy(regname, ops, 15);
                    {char *cm=strchr(regname,','); if(cm)*cm='\0';}
                    fprintf(out, "  %s  → %s%s%s = %s%s%s\n",
                            CD, CY, regname, CR, CG, expr_str, CR);
                }
            }
        }

        off += (size_t)len;
        steps++;

        dax_igrp_t grp = (bin->arch == ARCH_ARM64)
                         ? dax_classify_arm64(mnem)
                         : dax_classify_x86(mnem);
        if (grp == IGRP_RET) {
            fprintf(out, "\n%s  [RET] Symbolic return value: %s%s%s\n",
                    CD, CG,
                    state.regs[0].is_concrete
                        ? "concrete" : "symbolic",
                    CR);
            if (state.regs[0].is_concrete) {
                fprintf(out, "%s         = 0x%llx%s\n", CP,
                        (unsigned long long)state.regs[0].concrete, CR);
            } else {
                char expr_str[512];
                sexpr_print(state.regs[0].expr_idx, expr_str, sizeof(expr_str));
                fprintf(out, "%s         = %s%s\n", CP, expr_str, CR);
            }
            break;
        }
    }

    fprintf(out, "\n%s  Symbolic execution completed: %d steps%s\n", CD, steps, CR);
    fprintf(out, "\n");
}

void dax_symexec_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i;
    if (!bin || !opts || !out) return;
    for (i = 0; i < bin->nfunctions; i++)
        dax_symexec_func(bin, i, opts, out);
}
