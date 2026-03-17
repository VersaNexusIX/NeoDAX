#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"

static uint64_t decomp_parse_imm(const char *s) {
    if (!s || !s[0]) return 0;
    if (s[0] == '#') s++;
    if (strncmp(s, "0x", 2) == 0) return (uint64_t)strtoull(s, NULL, 16);
    return (uint64_t)strtoull(s, NULL, 0);
}

#define SSA_MAX_VARS   512
#define SSA_MAX_STMTS  2048
#define DECOMP_MAX_STMTS 2048

extern dax_igrp_t dax_classify_x86(const char *m);
extern dax_igrp_t dax_classify_arm64(const char *m);

/* ────────────────────────────────────────────────────────────────────
 *  SSA Variable
 * ──────────────────────────────────────────────────────────────────── */
typedef struct {
    char     base[16];
    int      version;
    uint8_t  bits;
    int      is_phi;
    int      phi_srcs[4];
    int      nphi;
} ssa_var_t;

/* ────────────────────────────────────────────────────────────────────
 *  SSA Statement kinds
 * ──────────────────────────────────────────────────────────────────── */
typedef enum {
    SSA_ASSIGN = 0,
    SSA_ADD, SSA_SUB, SSA_AND, SSA_OR, SSA_XOR,
    SSA_SHL, SSA_SHR, SSA_MUL, SSA_NOT, SSA_NEG,
    SSA_LOAD, SSA_STORE,
    SSA_CALL, SSA_RET, SSA_BRANCH, SSA_PHI,
    SSA_CMP, SSA_UNDEF, SSA_NOP, SSA_CAST
} ssa_op_t;

typedef struct {
    ssa_op_t  op;
    int       dst;
    int       src1;
    int       src2;
    uint64_t  imm;
    int       has_imm;
    uint64_t  addr;
    char      label[32];
} ssa_stmt_t;

/* ────────────────────────────────────────────────────────────────────
 *  SSA Context
 * ──────────────────────────────────────────────────────────────────── */
typedef struct {
    ssa_var_t   vars[SSA_MAX_VARS];
    int         nvars;
    ssa_stmt_t  stmts[SSA_MAX_STMTS];
    int         nstmts;
    int         version_map[64];
    char        last_cmp_src1[16];
    char        last_cmp_src2[16];
    int         last_cmp_imm;
    uint64_t    last_cmp_immval;
} ssa_ctx_t;

static int ssa_find_var(ssa_ctx_t *ctx, const char *base) {
    int i;
    for (i = ctx->nvars - 1; i >= 0; i--)
        if (strcmp(ctx->vars[i].base, base) == 0)
            return i;
    return -1;
}

static int ssa_new_var(ssa_ctx_t *ctx, const char *base, uint8_t bits) {
    int i;
    int ver = 0;
    for (i = 0; i < ctx->nvars; i++)
        if (strcmp(ctx->vars[i].base, base) == 0)
            ver = ctx->vars[i].version + 1;

    if (ctx->nvars >= SSA_MAX_VARS) return ctx->nvars - 1;
    i = ctx->nvars++;
    strncpy(ctx->vars[i].base, base, 15);
    ctx->vars[i].version = ver;
    ctx->vars[i].bits    = bits;
    return i;
}

static int ssa_get_var(ssa_ctx_t *ctx, const char *base) {
    int idx = ssa_find_var(ctx, base);
    if (idx < 0) idx = ssa_new_var(ctx, base, 64);
    return idx;
}

static void ssa_emit(ssa_ctx_t *ctx, ssa_op_t op, int dst,
                     int src1, int src2, uint64_t imm, int has_imm,
                     uint64_t addr) {
    if (ctx->nstmts >= SSA_MAX_STMTS) return;
    ssa_stmt_t *s = &ctx->stmts[ctx->nstmts++];
    s->op      = op;
    s->dst     = dst;
    s->src1    = src1;
    s->src2    = src2;
    s->imm     = imm;
    s->has_imm = has_imm;
    s->addr    = addr;
}

static const char *ssa_var_name(ssa_ctx_t *ctx, int idx, char *buf, size_t bsz) {
    if (idx < 0 || idx >= ctx->nvars) {
        snprintf(buf, bsz, "?"); return buf;
    }
    if (ctx->vars[idx].version == 0)
        snprintf(buf, bsz, "%s", ctx->vars[idx].base);
    else
        snprintf(buf, bsz, "%s_%d", ctx->vars[idx].base, ctx->vars[idx].version);
    return buf;
}

static void parse_arm64_operands(const char *ops,
                                  char *a1, char *a2, char *a3,
                                  size_t sz) {
    const char *p = ops;
    char *bufs[3] = {a1, a2, a3};
    int k;
    a1[0]=a2[0]=a3[0]='\0';
    for (k = 0; k < 3; k++) {
        while (*p == ' ') p++;
        char *d = bufs[k]; int j = 0;
        while (*p && *p != ',' && j < (int)sz-1) { *d++ = *p++; j++; }
        *d = '\0';
        if (*p == ',') p++;
    }
}

static void ssa_lift_arm64_insn(ssa_ctx_t *ctx, const char *mnem,
                                  const char *ops, uint64_t addr) {
    char a1[64]="", a2[64]="", a3[64]="";
    parse_arm64_operands(ops, a1, a2, a3, 64);

    uint8_t is32 = (a1[0] == 'w') ? 32 : 64;

    /* Strip 'w' prefix for reg lookup */
    char rb1[16]="", rb2[16]="", rb3[16]="";
    {
        const char *s = a1; if(*s=='w'||*s=='x') s++;
        snprintf(rb1,16,"r%s",s);
        s=a2; if(*s=='w'||*s=='x') s++;
        snprintf(rb2,16,"r%s",s);
        s=a3; if(*s=='w'||*s=='x') s++;
        snprintf(rb3,16,"r%s",s);
    }
    if (strcmp(a1,"xzr")==0||strcmp(a1,"wzr")==0) rb1[0]='\0';
    if (strcmp(a2,"xzr")==0||strcmp(a2,"wzr")==0) { snprintf(rb2,16,"0"); }
    if (strcmp(a3,"xzr")==0||strcmp(a3,"wzr")==0) { snprintf(rb3,16,"0"); }

    if (strcmp(mnem,"mov")==0||strcmp(mnem,"movz")==0||strcmp(mnem,"movn")==0) {
        if (!rb1[0]) return;
        int dst = ssa_new_var(ctx, rb1, is32);
        if (a2[0]=='#') {
            ssa_emit(ctx, SSA_ASSIGN, dst, -1, -1, decomp_parse_imm(a2), 1, addr);
        } else if (rb2[0]) {
            int src = ssa_get_var(ctx, rb2);
            ssa_emit(ctx, SSA_ASSIGN, dst, src, -1, 0, 0, addr);
        }
    } else if (strcmp(mnem,"add")==0||strcmp(mnem,"adds")==0) {
        if (!rb1[0]) return;
        int dst  = ssa_new_var(ctx, rb1, is32);
        int src1 = rb2[0] ? ssa_get_var(ctx,rb2) : -1;
        if (a3[0]=='#') {
            ssa_emit(ctx,SSA_ADD,dst,src1,-1,decomp_parse_imm(a3),1,addr);
        } else if (rb3[0]) {
            int src2=ssa_get_var(ctx,rb3);
            ssa_emit(ctx,SSA_ADD,dst,src1,src2,0,0,addr);
        }
    } else if (strcmp(mnem,"sub")==0||strcmp(mnem,"subs")==0) {
        if (!rb1[0]) return;
        int dst=ssa_new_var(ctx,rb1,is32);
        int src1=rb2[0]?ssa_get_var(ctx,rb2):-1;
        if (a3[0]=='#') {
            ssa_emit(ctx,SSA_SUB,dst,src1,-1,decomp_parse_imm(a3),1,addr);
        } else if (rb3[0]) {
            ssa_emit(ctx,SSA_SUB,dst,src1,ssa_get_var(ctx,rb3),0,0,addr);
        }
    } else if (strcmp(mnem,"and")==0||strcmp(mnem,"ands")==0) {
        int dst=ssa_new_var(ctx,rb1,is32);
        if (a3[0]=='#') ssa_emit(ctx,SSA_AND,dst,ssa_get_var(ctx,rb2),-1,decomp_parse_imm(a3),1,addr);
        else ssa_emit(ctx,SSA_AND,dst,ssa_get_var(ctx,rb2),ssa_get_var(ctx,rb3),0,0,addr);
    } else if (strcmp(mnem,"orr")==0) {
        int dst=ssa_new_var(ctx,rb1,is32);
        ssa_emit(ctx,SSA_OR,dst,ssa_get_var(ctx,rb2),ssa_get_var(ctx,rb3),0,0,addr);
    } else if (strcmp(mnem,"eor")==0) {
        int dst=ssa_new_var(ctx,rb1,is32);
        if (a3[0]=='#') ssa_emit(ctx,SSA_XOR,dst,ssa_get_var(ctx,rb2),-1,decomp_parse_imm(a3),1,addr);
        else ssa_emit(ctx,SSA_XOR,dst,ssa_get_var(ctx,rb2),ssa_get_var(ctx,rb3),0,0,addr);
    } else if (strcmp(mnem,"lsl")==0) {
        int dst=ssa_new_var(ctx,rb1,is32);
        ssa_emit(ctx,SSA_SHL,dst,ssa_get_var(ctx,rb2),-1,decomp_parse_imm(a3),1,addr);
    } else if (strcmp(mnem,"lsr")==0||strcmp(mnem,"asr")==0) {
        int dst=ssa_new_var(ctx,rb1,is32);
        ssa_emit(ctx,SSA_SHR,dst,ssa_get_var(ctx,rb2),-1,decomp_parse_imm(a3),1,addr);
    } else if (strcmp(mnem,"cmp")==0||strcmp(mnem,"cmn")==0) {
        strncpy(ctx->last_cmp_src1, rb1, 15);
        strncpy(ctx->last_cmp_src2, a2[0]=='#'?"#":rb2, 15);
        ctx->last_cmp_imm    = (a2[0]=='#');
        ctx->last_cmp_immval = decomp_parse_imm(a2);
        int src1=ssa_get_var(ctx,rb1);
        int src2=a2[0]=='#'?-1:ssa_get_var(ctx,rb2);
        ssa_emit(ctx,SSA_CMP,ssa_new_var(ctx,"flags",8),src1,src2,
                 ctx->last_cmp_immval,ctx->last_cmp_imm,addr);
    } else if (strcmp(mnem,"ldr")==0||strcmp(mnem,"ldrb")==0||strcmp(mnem,"ldrh")==0||
               strcmp(mnem,"ldrsw")==0) {
        int dst=ssa_new_var(ctx,rb1,is32);
        int base2=rb2[0]?ssa_get_var(ctx,rb2):-1;
        ssa_emit(ctx,SSA_LOAD,dst,base2,-1,0,0,addr);
    } else if (strcmp(mnem,"str")==0||strcmp(mnem,"strb")==0||strcmp(mnem,"strh")==0) {
        int src=rb1[0]?ssa_get_var(ctx,rb1):-1;
        int base2=rb2[0]?ssa_get_var(ctx,rb2):-1;
        ssa_emit(ctx,SSA_STORE,-1,src,base2,0,0,addr);
    } else if (strcmp(mnem,"bl")==0) {
        uint64_t tgt=0; if(a1[0]=='0') sscanf(a1,"0x%llx",(unsigned long long*)&tgt);
        int dst=ssa_new_var(ctx,"r0",32);
        ssa_emit(ctx,SSA_CALL,dst,-1,-1,tgt,1,addr);
    } else if (strcmp(mnem,"ret")==0||strncmp(mnem,"ret",3)==0) {
        int src=ssa_get_var(ctx,"r0");
        ssa_emit(ctx,SSA_RET,-1,src,-1,0,0,addr);
    } else if (strcmp(mnem,"b")==0||strncmp(mnem,"b.",2)==0||strcmp(mnem,"cbz")==0||strcmp(mnem,"cbnz")==0) {
        uint64_t tgt=0;
        const char *tp=ops; if(strncmp(mnem,"b.",2)==0||strcmp(mnem,"cbz")==0||strcmp(mnem,"cbnz")==0) {
            const char *comma=strrchr(ops,','); if(comma) tp=comma+1; while(*tp==' ')tp++;
        }
        if(tp[0]=='0') sscanf(tp,"0x%llx",(unsigned long long*)&tgt);
        ssa_emit(ctx,SSA_BRANCH,-1,-1,-1,tgt,1,addr);
    } else {
        ssa_emit(ctx,SSA_NOP,-1,-1,-1,0,0,addr);
    }
}

static const char *ssa_op_str(ssa_op_t op) {
    switch(op){
        case SSA_ADD:    return "+";
        case SSA_SUB:    return "-";
        case SSA_AND:    return "&";
        case SSA_OR:     return "|";
        case SSA_XOR:    return "^";
        case SSA_SHL:    return "<<";
        case SSA_SHR:    return ">>";
        case SSA_MUL:    return "*";
        default:         return "op";
    }
}

void dax_ssa_lift_func(dax_binary_t *bin, int func_idx,
                       dax_opts_t *opts, FILE *out) {
    int          c  = opts ? opts->color : 1;
    dax_func_t  *fn;
    uint8_t     *code;
    size_t       sz, off;
    uint64_t     base;
    int          si;
    ssa_ctx_t   *ctx;

    const char *CY = c ? COL_LABEL   : "";
    const char *CB = c ? COL_ADDR    : "";
    const char *CG = c ? COL_SECTION : "";
    const char *CD = c ? COL_COMMENT : "";
    const char *CR = c ? COL_RESET   : "";
    const char *CM = c ? COL_MNEM    : "";
    const char *CP = c ? "\033[0;35m" : "";
    const char *CO = c ? COL_OPS     : "";

    if (!bin||func_idx<0||func_idx>=bin->nfunctions) return;
    fn = &bin->functions[func_idx];

    code=NULL;sz=0;base=0;
    for (si=0;si<bin->nsections;si++) {
        dax_section_t *sec=&bin->sections[si];
        if (fn->start>=sec->vaddr&&fn->start<sec->vaddr+sec->size&&
            sec->offset+sec->size<=bin->size) {
            code=bin->data+sec->offset; sz=(size_t)sec->size; base=sec->vaddr; break;
        }
    }
    if (!code) return;

    ctx = (ssa_ctx_t *)calloc(1, sizeof(ssa_ctx_t));
    if (!ctx) return;

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                 " SSA FORM: %s "
                 "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n",
                 fn->name);
    if (c) fprintf(out, "%s", CR);
    fprintf(out, "\n");

    off = (size_t)(fn->start - base);
    size_t fn_end = (fn->end > fn->start && fn->end <= base + sz)
                    ? (size_t)(fn->end - base) : off + 512;

    while (off < fn_end && off < sz) {
        uint64_t addr = base + off;
        char mnem[32]="", ops[256]="";
        int len = 0;

        if (bin->arch == ARCH_ARM64) {
            if (off + 4 > sz) break;
            uint32_t raw=(uint32_t)(code[off])|(code[off+1]<<8)|(code[off+2]<<16)|(code[off+3]<<24);
            a64_insn_t insn; a64_decode(raw,addr,&insn);
            strncpy(mnem,insn.mnemonic,31); strncpy(ops,insn.operands,255);
            len=4;
        } else {
            x86_insn_t insn;
            len=x86_decode(code+off,fn_end-off,addr,&insn);
            if(len<=0){off++;continue;}
            strncpy(mnem,insn.mnemonic,31); strncpy(ops,insn.ops,255);
        }

        if (bin->arch == ARCH_ARM64)
            ssa_lift_arm64_insn(ctx, mnem, ops, addr);

        off += (size_t)len;
    }

    {
        int i;
        for (i = 0; i < ctx->nstmts; i++) {
            ssa_stmt_t *s = &ctx->stmts[i];
            char dstbuf[32]="",s1buf[32]="",s2buf[32]="";
            ssa_var_name(ctx, s->dst,  dstbuf, sizeof(dstbuf));
            ssa_var_name(ctx, s->src1, s1buf,  sizeof(s1buf));
            ssa_var_name(ctx, s->src2, s2buf,  sizeof(s2buf));

            fprintf(out, "  %s0x%llx%s  ", CB, (unsigned long long)s->addr, CR);

            switch(s->op) {
                case SSA_ASSIGN:
                    if (s->has_imm)
                        fprintf(out,"%s%s%s = %s0x%llx%s\n",CY,dstbuf,CR,CO,(unsigned long long)s->imm,CR);
                    else
                        fprintf(out,"%s%s%s = %s%s%s\n",CY,dstbuf,CR,CP,s1buf,CR);
                    break;
                case SSA_ADD: case SSA_SUB: case SSA_AND:
                case SSA_OR:  case SSA_XOR: case SSA_SHL: case SSA_SHR:
                    if (s->has_imm)
                        fprintf(out,"%s%s%s = %s%s%s %s%s%s %s0x%llx%s\n",
                                CY,dstbuf,CR,CP,s1buf,CR,CM,ssa_op_str(s->op),CR,
                                CO,(unsigned long long)s->imm,CR);
                    else
                        fprintf(out,"%s%s%s = %s%s%s %s%s%s %s%s%s\n",
                                CY,dstbuf,CR,CP,s1buf,CR,CM,ssa_op_str(s->op),CR,CP,s2buf,CR);
                    break;
                case SSA_LOAD:
                    fprintf(out,"%s%s%s = %sload%s[%s%s%s]\n",
                            CY,dstbuf,CR,CM,CR,CP,s1buf,CR);
                    break;
                case SSA_STORE:
                    fprintf(out,"%sstore%s[%s%s%s] ← %s%s%s\n",
                            CM,CR,CP,s2buf,CR,CP,s1buf,CR);
                    break;
                case SSA_CMP:
                    if (s->has_imm)
                        fprintf(out,"%sflags%s = %scmp%s(%s%s%s, %s0x%llx%s)\n",
                                CY,CR,CM,CR,CP,s1buf,CR,CO,(unsigned long long)s->imm,CR);
                    else
                        fprintf(out,"%sflags%s = %scmp%s(%s%s%s, %s%s%s)\n",
                                CY,CR,CM,CR,CP,s1buf,CR,CP,s2buf,CR);
                    break;
                case SSA_CALL:
                    fprintf(out,"%s%s%s = %scall%s 0x%llx\n",
                            CY,dstbuf,CR,CM,CR,(unsigned long long)s->imm);
                    break;
                case SSA_RET:
                    fprintf(out,"%sret%s %s%s%s\n",CM,CR,CP,s1buf,CR);
                    break;
                case SSA_BRANCH:
                    fprintf(out,"%sbranch%s → 0x%llx\n",CM,CR,(unsigned long long)s->imm);
                    break;
                case SSA_NOP:
                    fprintf(out,"%snop%s\n",CD,CR);
                    break;
                default:
                    fprintf(out,"...\n");
            }
        }
    }

    fprintf(out, "\n%s  %d SSA statements generated from %s%s\n",
            CD, ctx->nstmts, fn->name, CR);
    fprintf(out, "\n");
    free(ctx);
}

void dax_ssa_lift_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i;
    if (!bin||!opts||!out) return;
    for (i = 0; i < bin->nfunctions; i++)
        dax_ssa_lift_func(bin, i, opts, out);
}

/* ────────────────────────────────────────────────────────────────────
 *  Decompiler — pattern-based pseudo-C from SSA
 * ──────────────────────────────────────────────────────────────────── */

typedef enum {
    IR_ASSIGN=0, IR_ADD, IR_SUB, IR_AND, IR_OR, IR_XOR,
    IR_SHL, IR_SHR, IR_LOAD, IR_STORE, IR_CALL, IR_RET,
    IR_IF, IR_WHILE, IR_BREAK, IR_NOP
} ir_op_t;

typedef struct ir_node ir_node_t;
struct ir_node {
    ir_op_t   op;
    char      dst[32];
    char      src1[32];
    char      src2[32];
    uint64_t  imm;
    int       has_imm;
    uint64_t  addr;
    int       indent;
};

#define MAX_IR 512
static ir_node_t g_ir[MAX_IR];
static int       g_nir = 0;

static void emit_ir(ir_op_t op, const char *dst,
                    const char *src1, const char *src2,
                    uint64_t imm, int has_imm, uint64_t addr, int indent) {
    if (g_nir >= MAX_IR) return;
    ir_node_t *n = &g_ir[g_nir++];
    n->op      = op;
    n->imm     = imm;
    n->has_imm = has_imm;
    n->addr    = addr;
    n->indent  = indent;
    strncpy(n->dst,  dst  ? dst  : "", 31);
    strncpy(n->src1, src1 ? src1 : "", 31);
    strncpy(n->src2, src2 ? src2 : "", 31);
}

static void lift_to_ir_arm64(const char *mnem, const char *ops,
                               uint64_t addr, int indent) {
    char a1[64]="",a2[64]="",a3[64]="";
    {
        const char *p=ops;
        char *bufs[3]={a1,a2,a3};
        int k;
        for(k=0;k<3;k++){
            while(*p==' ')p++;
            char *d=bufs[k]; int j=0;
            while(*p&&*p!=','&&j<63){*d++=*p++;j++;}
            *d='\0'; if(*p==',')p++;
        }
    }

    char dst[32]="",s1[32]="",s2[32]="",s3[32]="";
    strncpy(dst,a1,31); strncpy(s1,a2,31); strncpy(s2,a3,31);

    if (strcmp(mnem,"mov")==0||strcmp(mnem,"movz")==0) {
        if (a2[0]=='#') emit_ir(IR_ASSIGN,dst,NULL,NULL,decomp_parse_imm(a2),1,addr,indent);
        else            emit_ir(IR_ASSIGN,dst,s1,NULL,0,0,addr,indent);
    } else if (strcmp(mnem,"add")==0||strcmp(mnem,"adds")==0) {
        if (a3[0]=='#') emit_ir(IR_ADD,dst,s1,NULL,decomp_parse_imm(a3),1,addr,indent);
        else            emit_ir(IR_ADD,dst,s1,s2,0,0,addr,indent);
    } else if (strcmp(mnem,"sub")==0||strcmp(mnem,"subs")==0) {
        if (a3[0]=='#') emit_ir(IR_SUB,dst,s1,NULL,decomp_parse_imm(a3),1,addr,indent);
        else            emit_ir(IR_SUB,dst,s1,s2,0,0,addr,indent);
    } else if (strcmp(mnem,"and")==0||strcmp(mnem,"ands")==0) {
        if (a3[0]=='#') emit_ir(IR_AND,dst,s1,NULL,decomp_parse_imm(a3),1,addr,indent);
        else            emit_ir(IR_AND,dst,s1,s2,0,0,addr,indent);
    } else if (strcmp(mnem,"orr")==0) {
        emit_ir(IR_OR,dst,s1,s2,0,0,addr,indent);
    } else if (strcmp(mnem,"eor")==0) {
        if (a3[0]=='#') emit_ir(IR_XOR,dst,s1,NULL,decomp_parse_imm(a3),1,addr,indent);
        else            emit_ir(IR_XOR,dst,s1,s2,0,0,addr,indent);
    } else if (strcmp(mnem,"lsl")==0) {
        emit_ir(IR_SHL,dst,s1,NULL,decomp_parse_imm(a3),1,addr,indent);
    } else if (strcmp(mnem,"lsr")==0||strcmp(mnem,"asr")==0) {
        emit_ir(IR_SHR,dst,s1,NULL,decomp_parse_imm(a3),1,addr,indent);
    } else if (strcmp(mnem,"ldr")==0||strcmp(mnem,"ldrb")==0||strcmp(mnem,"ldrsw")==0) {
        emit_ir(IR_LOAD,dst,s1,NULL,0,0,addr,indent);
    } else if (strcmp(mnem,"str")==0||strcmp(mnem,"strb")==0) {
        emit_ir(IR_STORE,s2,s1,NULL,0,0,addr,indent);
    } else if (strcmp(mnem,"bl")==0) {
        uint64_t tgt=0; if(a1[0]=='0')sscanf(a1,"0x%llx",(unsigned long long*)&tgt);
        emit_ir(IR_CALL,"result",a1,NULL,tgt,1,addr,indent);
    } else if (strcmp(mnem,"ret")==0||strncmp(mnem,"ret",3)==0) {
        emit_ir(IR_RET,NULL,dst[0]?dst:"w0",NULL,0,0,addr,indent);
    } else if (strcmp(mnem,"b")==0) {
        emit_ir(IR_NOP,NULL,a1,NULL,0,0,addr,indent);
    } else if (strncmp(mnem,"b.",2)==0) {
        char cond[8]="";
        strncpy(cond,mnem+2,7);
        char ifcond[64]="";
        if (strcmp(cond,"eq")==0) snprintf(ifcond,64,"flags == 0");
        else if (strcmp(cond,"ne")==0) snprintf(ifcond,64,"flags != 0");
        else if (strcmp(cond,"lt")==0) snprintf(ifcond,64,"flags < 0");
        else if (strcmp(cond,"le")==0) snprintf(ifcond,64,"flags <= 0");
        else if (strcmp(cond,"gt")==0) snprintf(ifcond,64,"flags > 0");
        else if (strcmp(cond,"ge")==0) snprintf(ifcond,64,"flags >= 0");
        else snprintf(ifcond,64,"cond_%s",cond);
        emit_ir(IR_IF,NULL,ifcond,a1,0,0,addr,indent);
    } else {
        emit_ir(IR_NOP,NULL,mnem,ops,0,0,addr,indent);
    }
}

void dax_decompile_func(dax_binary_t *bin, int func_idx,
                        dax_opts_t *opts, FILE *out) {
    int          c  = opts ? opts->color : 1;
    dax_func_t  *fn;
    uint8_t     *code;
    size_t       sz, off;
    uint64_t     base;
    int          si;
    int          indent = 1;

    const char *CY = c ? COL_LABEL    : "";
    const char *CB = c ? COL_ADDR     : "";
    const char *CG = c ? COL_SECTION  : "";
    const char *CD = c ? COL_COMMENT  : "";
    const char *CR = c ? COL_RESET    : "";
    const char *CM = c ? COL_MNEM     : "";
    const char *CP = c ? "\033[0;35m" : "";
    const char *CO = c ? COL_OPS      : "";
    const char *CK = c ? COL_GRP_CALL : "";

    if (!bin||func_idx<0||func_idx>=bin->nfunctions) return;
    fn = &bin->functions[func_idx];

    code=NULL;sz=0;base=0;
    for (si=0;si<bin->nsections;si++) {
        dax_section_t *sec=&bin->sections[si];
        if (fn->start>=sec->vaddr&&fn->start<sec->vaddr+sec->size&&
            sec->offset+sec->size<=bin->size) {
            code=bin->data+sec->offset; sz=(size_t)sec->size; base=sec->vaddr; break;
        }
    }
    if (!code) return;

    g_nir = 0;

    off = (size_t)(fn->start - base);
    size_t fn_end = (fn->end > fn->start && fn->end <= base + sz)
                    ? (size_t)(fn->end - base) : off + 512;

    while (off < fn_end && off < sz) {
        uint64_t addr = base + off;
        char mnem[32]="",ops[256]="";
        int len = 0;

        if (bin->arch == ARCH_ARM64) {
            if (off + 4 > sz) break;
            uint32_t raw=(uint32_t)(code[off])|(code[off+1]<<8)|(code[off+2]<<16)|(code[off+3]<<24);
            a64_insn_t insn; a64_decode(raw,addr,&insn);
            strncpy(mnem,insn.mnemonic,31); strncpy(ops,insn.operands,255);
            len=4;
        } else {
            x86_insn_t insn;
            len=x86_decode(code+off,fn_end-off,addr,&insn);
            if(len<=0){off++;continue;}
            strncpy(mnem,insn.mnemonic,31); strncpy(ops,insn.ops,255);
        }

        if (bin->arch == ARCH_ARM64)
            lift_to_ir_arm64(mnem, ops, addr, indent);

        off += (size_t)len;
    }

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                 " DECOMPILED: %s "
                 "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n",
                 fn->name);
    if (c) fprintf(out, "%s", CR);

    fprintf(out, "\n%sint32_t %s%s%s(", CD, CK, fn->name, CR);

    dax_symbol_t *sym = dax_sym_find(bin, fn->start);
    if (sym && sym->demangled[0])
        fprintf(out, "%sint arg0%s", CP, CR);
    else
        fprintf(out, "%sint arg0%s", CP, CR);
    fprintf(out, ") {\n");

    {
        int i;
        for (i = 0; i < g_nir; i++) {
            ir_node_t *n = &g_ir[i];
            int ind = n->indent;
            int j;
            for (j=0;j<ind*2+2;j++) fprintf(out," ");

            switch(n->op) {
                case IR_ASSIGN:
                    if (n->has_imm)
                        fprintf(out,"%s%s%s = %s0x%llx%s;\n",
                                CY,n->dst,CR,CO,(unsigned long long)n->imm,CR);
                    else
                        fprintf(out,"%s%s%s = %s%s%s;\n",
                                CY,n->dst,CR,CP,n->src1,CR);
                    break;
                case IR_ADD:
                    if (n->has_imm)
                        fprintf(out,"%s%s%s = %s%s%s + %s0x%llx%s;\n",
                                CY,n->dst,CR,CP,n->src1,CR,CO,(unsigned long long)n->imm,CR);
                    else
                        fprintf(out,"%s%s%s = %s%s%s + %s%s%s;\n",
                                CY,n->dst,CR,CP,n->src1,CR,CP,n->src2,CR);
                    break;
                case IR_SUB:
                    if (n->has_imm)
                        fprintf(out,"%s%s%s = %s%s%s - %s0x%llx%s;\n",
                                CY,n->dst,CR,CP,n->src1,CR,CO,(unsigned long long)n->imm,CR);
                    else
                        fprintf(out,"%s%s%s = %s%s%s - %s%s%s;\n",
                                CY,n->dst,CR,CP,n->src1,CR,CP,n->src2,CR);
                    break;
                case IR_AND:
                    if (n->has_imm)
                        fprintf(out,"%s%s%s = %s%s%s & %s0x%llx%s;\n",
                                CY,n->dst,CR,CP,n->src1,CR,CO,(unsigned long long)n->imm,CR);
                    else
                        fprintf(out,"%s%s%s = %s%s%s & %s%s%s;\n",
                                CY,n->dst,CR,CP,n->src1,CR,CP,n->src2,CR);
                    break;
                case IR_OR:
                    fprintf(out,"%s%s%s = %s%s%s | %s%s%s;\n",
                            CY,n->dst,CR,CP,n->src1,CR,CP,n->src2,CR);
                    break;
                case IR_XOR:
                    if (n->has_imm)
                        fprintf(out,"%s%s%s = %s%s%s ^ %s0x%llx%s;\n",
                                CY,n->dst,CR,CP,n->src1,CR,CO,(unsigned long long)n->imm,CR);
                    else
                        fprintf(out,"%s%s%s = %s%s%s ^ %s%s%s;\n",
                                CY,n->dst,CR,CP,n->src1,CR,CP,n->src2,CR);
                    break;
                case IR_SHL:
                    fprintf(out,"%s%s%s = %s%s%s << %s%llu%s;\n",
                            CY,n->dst,CR,CP,n->src1,CR,CO,(unsigned long long)n->imm,CR);
                    break;
                case IR_SHR:
                    fprintf(out,"%s%s%s = %s%s%s >> %s%llu%s;\n",
                            CY,n->dst,CR,CP,n->src1,CR,CO,(unsigned long long)n->imm,CR);
                    break;
                case IR_LOAD:
                    fprintf(out,"%s%s%s = %s*%s%s%s;\n",
                            CY,n->dst,CR,CM,CR,CP,n->src1);
                    fprintf(out,"%s",CR);
                    break;
                case IR_STORE:
                    fprintf(out,"%s*%s%s%s = %s%s%s;\n",
                            CM,CR,CP,n->dst,CP,n->src1,CR);
                    break;
                case IR_CALL: {
                    const char *sym_target = NULL;
                    uint64_t tgt = n->imm;
                    dax_symbol_t *cs = dax_sym_find(bin, tgt);
                    if (cs) sym_target = cs->demangled[0] ? cs->demangled : cs->name;
                    if (sym_target)
                        fprintf(out,"%sresult%s = %s%s%s();\n",
                                CY,CR,CK,sym_target,CR);
                    else
                        fprintf(out,"%sresult%s = %scall%s(0x%llx);\n",
                                CY,CR,CK,CR,(unsigned long long)tgt);
                    break;
                }
                case IR_RET:
                    fprintf(out,"%sreturn%s %s%s%s;\n",CM,CR,CP,n->src1,CR);
                    break;
                case IR_IF:
                    fprintf(out,"%sif%s (%s%s%s) %s→%s 0x%s\n",
                            CM,CR,CG,n->src1,CR,CD,CR,n->src2);
                    break;
                case IR_NOP:
                    if (n->src2[0])
                        fprintf(out,"%s/* %s %s */%s\n",CD,n->src1,n->src2,CR);
                    break;
                default:
                    break;
            }
        }
    }

    fprintf(out, "}\n");
    fprintf(out, "\n");
}

void dax_decompile_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i;
    if (!bin||!opts||!out) return;
    for (i = 0; i < bin->nfunctions; i++)
        dax_decompile_func(bin, i, opts, out);
}
