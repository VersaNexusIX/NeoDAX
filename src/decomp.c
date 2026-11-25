/*
 * decomp.c — NR: NeoDAX Representation
 *
 * NR is NeoDAX's native program IR, superseding the old SSA form.
 * Designed for reverse-engineering: preserves address annotations,
 * models obfuscation artefacts explicitly, and tracks inter-function
 * relationships across the entire binary.
 *
 * Key upgrades over old SSA layer
 * ─────────────────────────────────
 *  1. Richer opcodes: MUL/DIV/ROL/ROR/CAST/SEXT/ZEXT/PHI/UNDEF/
 *                     MEMCPY/SYSCALL/INDIRECT_CALL
 *  2. Inter-function linkage: every NR_CALL carries callee_func_idx
 *     resolved against bin->functions[]; callee name embedded inline.
 *  3. Program-level NR module: cross-function call graph + SMC flags.
 *  4. Type inference: ptr/u8/u16/u32/u64/bool on every NR_Var.
 *  5. Decompiler: type-aware locals, loop hints, condition inversion,
 *     resolved call sites with callee summary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "dax.h"
#include "dax_guard.h"
#include "x86.h"
#include "arm64.h"
#include "riscv.h"

extern dax_igrp_t dax_classify_x86(const char *m);
extern dax_igrp_t dax_classify_arm64(const char *m);

/* ═══════════════════════════════════════════════════════════════════
 * §1  NR opcodes and types
 * ═══════════════════════════════════════════════════════════════════ */

typedef enum {
    NR_ASSIGN=0,
    NR_LOAD, NR_STORE, NR_MEMCPY,
    NR_ADD, NR_SUB, NR_MUL, NR_DIV, NR_NEG,
    NR_AND, NR_OR, NR_XOR, NR_NOT,
    NR_SHL, NR_SHR, NR_ROL, NR_ROR,
    NR_CAST, NR_SEXT, NR_ZEXT,
    NR_CMP, NR_BRANCH, NR_COND_BR,
    NR_PHI, NR_UNDEF,
    NR_CALL, NR_INDIRECT_CALL, NR_SYSCALL, NR_RET,
    NR_NOP, NR_LABEL
} nr_op_t;

typedef enum {
    NRT_UNKNOWN=0,
    NRT_BOOL,
    NRT_U8, NRT_U16, NRT_U32, NRT_U64,
    NRT_PTR, NRT_PTR_CODE, NRT_FLAGS
} nr_type_t;

#define NR_MAX_VARS    768
#define NR_MAX_STMTS  3072
#define NR_MAX_CALLS   256

typedef struct {
    char      base[20];
    int       version;
    nr_type_t type;
    uint8_t   bits;
    uint64_t  def_addr;
    int       func_idx;
} nr_var_t;

typedef struct {
    nr_op_t   op;
    int       dst, src1, src2, src3;
    uint64_t  imm;
    int       has_imm;
    uint64_t  addr;
    int       callee_func_idx;
    char      callee_name[48];
    char      cond[12];
    uint64_t  branch_target;
} nr_stmt_t;

typedef struct {
    nr_var_t   vars[NR_MAX_VARS];
    int        nvars;
    nr_stmt_t  stmts[NR_MAX_STMTS];
    int        nstmts;
    int        version_map[64];
    char       last_cmp_lhs[20];
    char       last_cmp_rhs[20];
    int        last_cmp_rhs_imm;
    uint64_t   last_cmp_rhs_val;
    int        func_idx;
} nr_ctx_t;

typedef struct {
    int      caller_func;
    int      callee_func;
    uint64_t call_site;
    char     callee_name[48];
} nr_call_edge_t;

/* ═══════════════════════════════════════════════════════════════════
 * §2  Operand parsing helpers
 * ═══════════════════════════════════════════════════════════════════ */

static uint64_t nr_parse_imm(const char *s) {
    if (!s||!s[0]) return 0;
    if (s[0]=='#') s++;
    if (!strncmp(s,"0x",2)) return (uint64_t)strtoull(s,NULL,16);
    return (uint64_t)strtoull(s,NULL,0);
}

static void nr_parse_ops(const char *ops,
                          char *a1,char *a2,char *a3,char *a4,int sz) {
    const char *p=ops;
    char *bufs[4]={a1,a2,a3,a4};
    int k;
    for(k=0;k<4;k++){
        bufs[k][0]='\0';
        while(*p==' ')p++;
        char *d=bufs[k]; int j=0;
        if(*p=='['){
            while(*p&&*p!=']'&&j<sz-1)*d++=*p++,j++;
            if(*p==']')*d++=*p++,j++;
        } else {
            while(*p&&*p!=','&&j<sz-1)*d++=*p++,j++;
        }
        *d='\0';
        if(*p==',')p++;
    }
}

static void nr_strip_bracket(const char *in, char *out, int sz) {
    const char *p=in;
    if(*p=='[')p++;
    int i=0;
    while(*p&&*p!=','&&*p!=']'&&i<sz-1)out[i++]=*p++;
    out[i]='\0';
    while(i>0&&out[i-1]==' ')out[--i]='\0';
}

static void nr_reg_base(const char *reg, char *base, int sz) {
    if(!reg||!reg[0]){base[0]='\0';return;}
    if(!strcmp(reg,"xzr")||!strcmp(reg,"wzr")||!strcmp(reg,"zero"))
        {strncpy(base,"zero",sz-1);base[sz-1]='\0';return;}
    if(!strcmp(reg,"sp")||!strcmp(reg,"wsp"))
        {strncpy(base,"sp",sz-1);base[sz-1]='\0';return;}
    if(!strcmp(reg,"lr")||!strcmp(reg,"x30"))
        {strncpy(base,"r30",sz-1);base[sz-1]='\0';return;}
    if(!strcmp(reg,"fp")||!strcmp(reg,"x29"))
        {strncpy(base,"r29",sz-1);base[sz-1]='\0';return;}
    const char *s=reg;
    if(*s=='x'||*s=='w')s++;
    snprintf(base,sz,"r%s",s);
}

/* ═══════════════════════════════════════════════════════════════════
 * §3  NR variable table
 * ═══════════════════════════════════════════════════════════════════ */

static int nr_find_latest(nr_ctx_t *ctx, const char *base) {
    int i, found=-1;
    for(i=0;i<ctx->nvars;i++)
        if(!strcmp(ctx->vars[i].base,base))found=i;
    return found;
}

static int nr_new_var(nr_ctx_t *ctx,const char *base,uint8_t bits,uint64_t def_addr){
    if(ctx->nvars>=NR_MAX_VARS)return ctx->nvars-1;
    nr_var_t *v=&ctx->vars[ctx->nvars];
    strncpy(v->base,base,19);v->base[19]='\0';
    int ver=0,i;
    for(i=0;i<ctx->nvars;i++)
        if(!strcmp(ctx->vars[i].base,base))ver=ctx->vars[i].version+1;
    v->version=ver; v->bits=bits; v->def_addr=def_addr; v->func_idx=ctx->func_idx;
    v->type=(bits==64)?NRT_U64:(bits==32)?NRT_U32:(bits==16)?NRT_U16:NRT_U8;
    return ctx->nvars++;
}

static int nr_get_var(nr_ctx_t *ctx, const char *base){
    int idx=nr_find_latest(ctx,base);
    if(idx<0)return nr_new_var(ctx,base,64,0);
    return idx;
}

static void nr_emit(nr_ctx_t *ctx,nr_op_t op,
                     int dst,int src1,int src2,
                     uint64_t imm,int has_imm,uint64_t addr){
    if(ctx->nstmts>=NR_MAX_STMTS)return;
    nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
    memset(s,0,sizeof(*s));
    s->op=op; s->dst=dst; s->src1=src1; s->src2=src2; s->src3=-1;
    s->imm=imm; s->has_imm=has_imm; s->addr=addr; s->callee_func_idx=-1;
}

/* ═══════════════════════════════════════════════════════════════════
 * §4  Resolve call target → function index
 * ═══════════════════════════════════════════════════════════════════ */

static int nr_resolve_call(dax_binary_t *bin,uint64_t tgt,char *name_out,int nsz){
    if(!bin||!tgt){name_out[0]='\0';return -1;}
    int fi;
    for(fi=0;fi<bin->nfunctions;fi++){
        if(bin->functions[fi].start==tgt){
            const char *n=bin->functions[fi].name;
            strncpy(name_out,n[0]?n:"<unnamed>",nsz-1);
            name_out[nsz-1]='\0';
            return fi;
        }
    }
    dax_symbol_t *sym=dax_sym_find(bin,tgt);
    if(sym){
        const char *n=sym->demangled[0]?sym->demangled:sym->name;
        strncpy(name_out,n[0]?n:"<extern>",nsz-1);
        name_out[nsz-1]='\0';
        return -1;
    }
    snprintf(name_out,nsz,"sub_0x%llx",(unsigned long long)tgt);
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════
 * §5  ARM64 → NR lift (single instruction)
 * ═══════════════════════════════════════════════════════════════════ */

static void nr_lift_arm64(nr_ctx_t *ctx,dax_binary_t *bin,
                           const char *mnem,const char *ops,uint64_t addr){
    char a1[64]="",a2[64]="",a3[64]="",a4[64]="";
    nr_parse_ops(ops,a1,a2,a3,a4,64);
    char b1[20]="",b2[20]="",b3[20]="";
    nr_reg_base(a1,b1,20); nr_reg_base(a2,b2,20); nr_reg_base(a3,b3,20);
    uint8_t w=(a1[0]=='w')?32:64;

#define DST  nr_new_var(ctx,b1,w,addr)
#define S1   nr_get_var(ctx,b2)
#define S2   nr_get_var(ctx,b3)
#define I2   nr_parse_imm(a2)
#define I3   nr_parse_imm(a3)

    if(!strcmp(mnem,"mov")||!strcmp(mnem,"movz")||!strcmp(mnem,"movn")){
        if(!b1[0])return;
        int d=DST;
        if(a2[0]=='#') nr_emit(ctx,NR_ASSIGN,d,-1,-1,I2,1,addr);
        else if(b2[0]) nr_emit(ctx,NR_ASSIGN,d,S1,-1,0,0,addr);

    } else if(!strcmp(mnem,"movk")){
        if(!b1[0])return;
        int prev=nr_get_var(ctx,b1), d=DST;
        nr_emit(ctx,NR_OR,d,prev,-1,I2,1,addr);

    } else if(!strcmp(mnem,"add")||!strcmp(mnem,"adds")){
        if(!b1[0])return;
        int d=DST,s1=S1;
        if(a3[0]=='#') nr_emit(ctx,NR_ADD,d,s1,-1,I3,1,addr);
        else           nr_emit(ctx,NR_ADD,d,s1,S2,0,0,addr);

    } else if(!strcmp(mnem,"sub")||!strcmp(mnem,"subs")){
        if(!b1[0])return;
        int d=DST,s1=S1;
        if(a3[0]=='#') nr_emit(ctx,NR_SUB,d,s1,-1,I3,1,addr);
        else           nr_emit(ctx,NR_SUB,d,s1,S2,0,0,addr);

    } else if(!strcmp(mnem,"neg")||!strcmp(mnem,"negs")){
        if(!b1[0])return; nr_emit(ctx,NR_NEG,DST,S1,-1,0,0,addr);

    } else if(!strcmp(mnem,"mul")||!strcmp(mnem,"madd")||!strcmp(mnem,"mneg")||
              !strcmp(mnem,"umulh")||!strcmp(mnem,"smulh")){
        if(!b1[0])return; nr_emit(ctx,NR_MUL,DST,S1,S2,0,0,addr);

    } else if(!strcmp(mnem,"udiv")||!strcmp(mnem,"sdiv")){
        if(!b1[0])return; nr_emit(ctx,NR_DIV,DST,S1,S2,0,0,addr);

    } else if(!strcmp(mnem,"and")||!strcmp(mnem,"ands")){
        if(!b1[0])return;
        int d=DST,s1=S1;
        if(a3[0]=='#') nr_emit(ctx,NR_AND,d,s1,-1,I3,1,addr);
        else           nr_emit(ctx,NR_AND,d,s1,S2,0,0,addr);

    } else if(!strcmp(mnem,"orr")){
        if(!b1[0])return; nr_emit(ctx,NR_OR,DST,S1,S2,0,0,addr);

    } else if(!strcmp(mnem,"eor")||!strcmp(mnem,"eon")){
        if(!b1[0])return;
        int d=DST,s1=S1;
        if(a3[0]=='#') nr_emit(ctx,NR_XOR,d,s1,-1,I3,1,addr);
        else           nr_emit(ctx,NR_XOR,d,s1,S2,0,0,addr);

    } else if(!strcmp(mnem,"mvn")||!strcmp(mnem,"not")){
        if(!b1[0])return; nr_emit(ctx,NR_NOT,DST,S1,-1,0,0,addr);

    } else if(!strcmp(mnem,"lsl")){
        if(!b1[0])return;
        int d=DST,s1=S1;
        if(a3[0]=='#') nr_emit(ctx,NR_SHL,d,s1,-1,I3,1,addr);
        else           nr_emit(ctx,NR_SHL,d,s1,S2,0,0,addr);

    } else if(!strcmp(mnem,"lsr")||!strcmp(mnem,"asr")){
        if(!b1[0])return;
        int d=DST,s1=S1;
        if(a3[0]=='#') nr_emit(ctx,NR_SHR,d,s1,-1,I3,1,addr);
        else           nr_emit(ctx,NR_SHR,d,s1,S2,0,0,addr);

    } else if(!strcmp(mnem,"ror")||!strcmp(mnem,"extr")){
        if(!b1[0])return;
        int d=DST,s1=S1;
        if(a3[0]=='#')       nr_emit(ctx,NR_ROR,d,s1,-1,I3,1,addr);
        else if(a4[0]=='#')  nr_emit(ctx,NR_ROR,d,s1,S2,I3,1,addr);
        else                 nr_emit(ctx,NR_ROR,d,s1,S2,0,0,addr);

    } else if(!strcmp(mnem,"sxtb")||!strcmp(mnem,"sxth")||!strcmp(mnem,"sxtw")){
        if(!b1[0])return;
        uint8_t from=!strcmp(mnem,"sxtb")?8:!strcmp(mnem,"sxth")?16:32;
        int d=DST; nr_emit(ctx,NR_SEXT,d,S1,-1,from,1,addr);
        if(d>=0&&d<ctx->nvars)ctx->vars[d].type=NRT_U64;

    } else if(!strcmp(mnem,"uxtb")||!strcmp(mnem,"uxth")){
        if(!b1[0])return;
        uint8_t from=!strcmp(mnem,"uxtb")?8:16;
        int d=DST; nr_emit(ctx,NR_ZEXT,d,S1,-1,from,1,addr);

    } else if(!strcmp(mnem,"adr")||!strcmp(mnem,"adrp")){
        if(!b1[0])return;
        uint64_t tgt=0;
        const char *tp=strstr(a2,"0x"); if(tp)tgt=strtoull(tp,NULL,16);
        int d=nr_new_var(ctx,b1,64,addr);
        nr_emit(ctx,NR_ASSIGN,d,-1,-1,tgt,1,addr);
        if(d>=0&&d<ctx->nvars)ctx->vars[d].type=NRT_PTR;

    } else if(!strncmp(mnem,"ldr",3)||!strncmp(mnem,"ldur",4)||!strncmp(mnem,"ldp",3)){
        if(!b1[0])return;
        char bbase[20]=""; nr_strip_bracket(a2,bbase,20);
        char bb[20]=""; nr_reg_base(bbase,bb,20);
        int d=nr_new_var(ctx,b1,w,addr);
        int s1=bb[0]?nr_get_var(ctx,bb):-1;
        nr_emit(ctx,NR_LOAD,d,s1,-1,0,0,addr);

    } else if(!strncmp(mnem,"str",3)||!strncmp(mnem,"stur",4)||!strncmp(mnem,"stp",3)){
        char bbase[20]="";
        nr_strip_bracket(!strncmp(mnem,"stp",3)?a3:a2,bbase,20);
        char bb[20]=""; nr_reg_base(bbase,bb,20);
        int src=b1[0]?nr_get_var(ctx,b1):-1;
        int base2=bb[0]?nr_get_var(ctx,bb):-1;
        nr_emit(ctx,NR_STORE,-1,src,base2,0,0,addr);

    } else if(!strcmp(mnem,"cmp")||!strcmp(mnem,"cmn")||!strcmp(mnem,"tst")){
        strncpy(ctx->last_cmp_lhs,b1[0]?b1:"r0",19);
        if(a2[0]=='#'){
            ctx->last_cmp_rhs_imm=1;
            ctx->last_cmp_rhs_val=nr_parse_imm(a2);
            ctx->last_cmp_rhs[0]='#';ctx->last_cmp_rhs[1]='\0';
        } else {
            ctx->last_cmp_rhs_imm=0;
            strncpy(ctx->last_cmp_rhs,b2[0]?b2:"r0",19);
        }
        int flags=nr_new_var(ctx,"flags",8,addr);
        if(flags>=0&&flags<ctx->nvars)ctx->vars[flags].type=NRT_FLAGS;
        int lhs=nr_get_var(ctx,ctx->last_cmp_lhs);
        int rhs=ctx->last_cmp_rhs_imm?-1:nr_get_var(ctx,ctx->last_cmp_rhs);
        nr_emit(ctx,NR_CMP,flags,lhs,rhs,ctx->last_cmp_rhs_val,ctx->last_cmp_rhs_imm,addr);

    } else if(!strcmp(mnem,"b")){
        uint64_t tgt=0;
        const char *tp=strstr(a1,"0x");if(tp)tgt=strtoull(tp,NULL,16);
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_BRANCH;s->dst=-1;s->src1=-1;s->src2=-1;s->src3=-1;
            s->callee_func_idx=-1;s->addr=addr;s->branch_target=tgt;s->has_imm=1;
        }

    } else if(!strcmp(mnem,"br")){
        int src=b1[0]?nr_get_var(ctx,b1):-1;
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_BRANCH;s->dst=-1;s->src1=src;s->src2=-1;s->src3=-1;
            s->callee_func_idx=-1;s->addr=addr;
        }

    } else if(!strncmp(mnem,"b.",2)||!strcmp(mnem,"cbz")||!strcmp(mnem,"cbnz")||
               !strcmp(mnem,"tbz")||!strcmp(mnem,"tbnz")){
        const char *cond_str=mnem+2;
        uint64_t tgt=0;
        const char *tp=strrchr(ops,',');if(tp)tp++;else tp=ops;
        while(*tp==' ')tp++;
        if(tp[0]=='0')tgt=strtoull(tp,NULL,16);
        int flags=nr_get_var(ctx,"flags");
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_COND_BR;s->dst=-1;s->src1=flags;s->src2=-1;s->src3=-1;
            s->callee_func_idx=-1;s->addr=addr;s->branch_target=tgt;
            if(!strcmp(mnem,"cbz"))       strncpy(s->cond,"eq",11);
            else if(!strcmp(mnem,"cbnz")) strncpy(s->cond,"ne",11);
            else if(!strcmp(mnem,"tbz"))  strncpy(s->cond,"tbit0",11);
            else if(!strcmp(mnem,"tbnz")) strncpy(s->cond,"tbit1",11);
            else strncpy(s->cond,cond_str[0]?cond_str:"??",11);
        }

    } else if(!strcmp(mnem,"bl")){
        uint64_t tgt=0;
        const char *tp=strstr(a1,"0x");if(tp)tgt=strtoull(tp,NULL,16);
        char cn[48]=""; int cfi=nr_resolve_call(bin,tgt,cn,48);
        int d=nr_new_var(ctx,"r0",64,addr);
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_CALL;s->dst=d;s->src1=-1;s->src2=-1;s->src3=-1;
            s->imm=tgt;s->has_imm=1;s->addr=addr;s->callee_func_idx=cfi;
            strncpy(s->callee_name,cn[0]?cn:"<extern>",47);
        }

    } else if(!strcmp(mnem,"blr")){
        int fn_ptr=b1[0]?nr_get_var(ctx,b1):-1;
        int d=nr_new_var(ctx,"r0",64,addr);
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_INDIRECT_CALL;s->dst=d;s->src1=fn_ptr;s->src2=-1;s->src3=-1;
            s->addr=addr;s->callee_func_idx=-1;
            strncpy(s->callee_name,"<indirect>",47);
        }

    } else if(!strcmp(mnem,"mrs")||!strcmp(mnem,"msr")){
        int d=b1[0]?nr_new_var(ctx,b1,64,addr):-1;
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_SYSCALL;s->dst=d;s->src1=-1;s->src2=-1;s->src3=-1;
            s->addr=addr;s->callee_func_idx=-1;
            snprintf(s->callee_name,47,"sysreg:%s",a2[0]?a2:a1);
        }

    } else if(!strcmp(mnem,"svc")){
        int d=nr_new_var(ctx,"r0",64,addr);
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_SYSCALL;s->dst=d;s->src1=-1;s->src2=-1;s->src3=-1;
            s->imm=nr_parse_imm(a1);s->has_imm=1;s->addr=addr;s->callee_func_idx=-1;
            strncpy(s->callee_name,"syscall",47);
        }

    } else if(!strncmp(mnem,"ret",3)||!strcmp(mnem,"eret")){
        int src=nr_get_var(ctx,"r0");
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_RET;s->dst=-1;s->src1=src;s->src2=-1;s->src3=-1;s->addr=addr;
        }

    } else if(!strcmp(mnem,"nop")||!strcmp(mnem,"??")){
        nr_emit(ctx,NR_NOP,-1,-1,-1,0,0,addr);
    } else {
        nr_emit(ctx,NR_NOP,-1,-1,-1,0,0,addr);
    }

#undef DST
#undef S1
#undef S2
#undef I2
#undef I3
}

/* ═══════════════════════════════════════════════════════════════════
 * §6  RISC-V → NR lift
 * ═══════════════════════════════════════════════════════════════════ */

static void nr_lift_riscv(nr_ctx_t *ctx,dax_binary_t *bin,
                           const char *mnem,const char *ops,uint64_t addr){
    char a1[64]="",a2[64]="",a3[64]="",a4[64]="";
    nr_parse_ops(ops,a1,a2,a3,a4,64);
    char b1[20]="",b2[20]="",b3[20]="";
    nr_reg_base(a1,b1,20);nr_reg_base(a2,b2,20);nr_reg_base(a3,b3,20);
    uint8_t w=64;
    (void)a4;

#define RD   nr_new_var(ctx,b1,w,addr)
#define RS1  nr_get_var(ctx,b2)
#define RS2  nr_get_var(ctx,b3)
#define RI3  nr_parse_imm(a3)

    if(!strcmp(mnem,"add")||!strcmp(mnem,"addw")){
        if(!b1[0])return; nr_emit(ctx,NR_ADD,RD,RS1,RS2,0,0,addr);
    } else if(!strcmp(mnem,"addi")||!strcmp(mnem,"addiw")){
        if(!b1[0])return; nr_emit(ctx,NR_ADD,RD,RS1,-1,RI3,1,addr);
    } else if(!strcmp(mnem,"sub")||!strcmp(mnem,"subw")){
        if(!b1[0])return; nr_emit(ctx,NR_SUB,RD,RS1,RS2,0,0,addr);
    } else if(!strcmp(mnem,"mul")||!strcmp(mnem,"mulw")){
        if(!b1[0])return; nr_emit(ctx,NR_MUL,RD,RS1,RS2,0,0,addr);
    } else if(!strcmp(mnem,"div")||!strcmp(mnem,"divu")||
              !strcmp(mnem,"divw")||!strcmp(mnem,"divuw")){
        if(!b1[0])return; nr_emit(ctx,NR_DIV,RD,RS1,RS2,0,0,addr);
    } else if(!strcmp(mnem,"and")){
        if(!b1[0])return; nr_emit(ctx,NR_AND,RD,RS1,RS2,0,0,addr);
    } else if(!strcmp(mnem,"andi")){
        if(!b1[0])return; nr_emit(ctx,NR_AND,RD,RS1,-1,RI3,1,addr);
    } else if(!strcmp(mnem,"or")){
        if(!b1[0])return; nr_emit(ctx,NR_OR,RD,RS1,RS2,0,0,addr);
    } else if(!strcmp(mnem,"ori")){
        if(!b1[0])return; nr_emit(ctx,NR_OR,RD,RS1,-1,RI3,1,addr);
    } else if(!strcmp(mnem,"xor")){
        if(!b1[0])return; nr_emit(ctx,NR_XOR,RD,RS1,RS2,0,0,addr);
    } else if(!strcmp(mnem,"xori")){
        if(!b1[0])return; nr_emit(ctx,NR_XOR,RD,RS1,-1,RI3,1,addr);
    } else if(!strncmp(mnem,"sll",3)||!strncmp(mnem,"slli",4)){
        if(!b1[0])return;
        if(isdigit((unsigned char)a3[0]))
            nr_emit(ctx,NR_SHL,RD,RS1,-1,RI3,1,addr);
        else nr_emit(ctx,NR_SHL,RD,RS1,RS2,0,0,addr);
    } else if(!strncmp(mnem,"srl",3)||!strncmp(mnem,"sra",3)||
               !strncmp(mnem,"srli",4)||!strncmp(mnem,"srai",4)){
        if(!b1[0])return;
        if(isdigit((unsigned char)a3[0]))
            nr_emit(ctx,NR_SHR,RD,RS1,-1,RI3,1,addr);
        else nr_emit(ctx,NR_SHR,RD,RS1,RS2,0,0,addr);
    } else if(!strcmp(mnem,"ld")||!strcmp(mnem,"lw")||!strcmp(mnem,"lh")||
               !strcmp(mnem,"lb")||!strcmp(mnem,"lwu")||!strcmp(mnem,"lhu")||
               !strcmp(mnem,"lbu")){
        if(!b1[0])return;
        char bbase[20]="";nr_strip_bracket(a2,bbase,20);
        char bb[20]="";nr_reg_base(bbase,bb,20);
        nr_emit(ctx,NR_LOAD,RD,bb[0]?nr_get_var(ctx,bb):-1,-1,0,0,addr);
    } else if(!strcmp(mnem,"sd")||!strcmp(mnem,"sw")||!strcmp(mnem,"sh")||!strcmp(mnem,"sb")){
        char bbase[20]="";nr_strip_bracket(a2,bbase,20);
        char bb[20]="";nr_reg_base(bbase,bb,20);
        nr_emit(ctx,NR_STORE,-1,b1[0]?nr_get_var(ctx,b1):-1,
                bb[0]?nr_get_var(ctx,bb):-1,0,0,addr);
    } else if(!strcmp(mnem,"jal")||!strcmp(mnem,"call")){
        uint64_t tgt=0;
        const char *tp=strstr(ops,"0x");if(tp)tgt=strtoull(tp,NULL,16);
        char cn[48]="";int cfi=nr_resolve_call(bin,tgt,cn,48);
        int d=nr_new_var(ctx,"r10",64,addr);
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_CALL;s->dst=d;s->src1=-1;s->src2=-1;s->src3=-1;
            s->imm=tgt;s->has_imm=1;s->addr=addr;s->callee_func_idx=cfi;
            strncpy(s->callee_name,cn[0]?cn:"<extern>",47);
        }
    } else if(!strcmp(mnem,"jalr")){
        int src=b1[0]?nr_get_var(ctx,b1):-1;
        int d=nr_new_var(ctx,"r10",64,addr);
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_INDIRECT_CALL;s->dst=d;s->src1=src;s->src2=-1;s->src3=-1;
            s->addr=addr;s->callee_func_idx=-1;strncpy(s->callee_name,"<indirect>",47);
        }
    } else if(!strcmp(mnem,"ret")){
        int src=nr_get_var(ctx,"r10");
        if(ctx->nstmts<NR_MAX_STMTS){
            nr_stmt_t *s=&ctx->stmts[ctx->nstmts++];
            memset(s,0,sizeof(*s));
            s->op=NR_RET;s->dst=-1;s->src1=src;s->src2=-1;s->src3=-1;s->addr=addr;
        }
    } else {
        nr_emit(ctx,NR_NOP,-1,-1,-1,0,0,addr);
    }
#undef RD
#undef RS1
#undef RS2
#undef RI3
}

/* ═══════════════════════════════════════════════════════════════════
 * §7  Helpers: type names, op symbols, var formatting
 * ═══════════════════════════════════════════════════════════════════ */

static const char *nr_type_name(nr_type_t t){
    switch(t){
        case NRT_BOOL:     return "bool";
        case NRT_U8:       return "u8";
        case NRT_U16:      return "u16";
        case NRT_U32:      return "u32";
        case NRT_U64:      return "u64";
        case NRT_PTR:      return "ptr";
        case NRT_PTR_CODE: return "fnptr";
        case NRT_FLAGS:    return "flags";
        default:           return "var";
    }
}

static const char *nr_op_sym(nr_op_t op){
    switch(op){
        case NR_ADD: return "+";
        case NR_SUB: return "-";
        case NR_MUL: return "*";
        case NR_DIV: return "/";
        case NR_AND: return "&";
        case NR_OR:  return "|";
        case NR_XOR: return "^";
        case NR_SHL: return "<<";
        case NR_SHR: return ">>";
        default:     return "?";
    }
}

static void nr_var_fmt(nr_ctx_t *ctx,int idx,char *buf,int sz){
    if(idx<0||idx>=ctx->nvars){snprintf(buf,sz,"???");return;}
    nr_var_t *v=&ctx->vars[idx];
    if(v->version==0) snprintf(buf,sz,"%s",v->base);
    else              snprintf(buf,sz,"%s_%d",v->base,v->version);
}

static void decomp_local_name(nr_ctx_t *ctx,int idx,char *buf,int sz){
    if(idx<0||idx>=ctx->nvars){snprintf(buf,sz,"???");return;}
    nr_var_t *v=&ctx->vars[idx];
    const char *pfx;
    switch(v->type){
        case NRT_PTR:case NRT_PTR_CODE: pfx="p"; break;
        case NRT_BOOL:                  pfx="b"; break;
        case NRT_FLAGS:                 pfx="flags"; break;
        case NRT_U8:                    pfx="u8_"; break;
        case NRT_U16:                   pfx="u16_"; break;
        default:                        pfx="v"; break;
    }
    const char *base=v->base;
    if(base[0]=='r'&&base[1]>='0'&&base[1]<='9')base++;
    if(v->version==0) snprintf(buf,sz,"%s%s",pfx,base);
    else              snprintf(buf,sz,"%s%s_%d",pfx,base,v->version);
}

/* ═══════════════════════════════════════════════════════════════════
 * §8  Lift one function → nr_ctx_t
 * ═══════════════════════════════════════════════════════════════════ */

static nr_ctx_t *nr_lift_func(dax_binary_t *bin,int func_idx){
    if(!bin||func_idx<0||func_idx>=bin->nfunctions)return NULL;
    dax_func_t *fn=&bin->functions[func_idx];
    uint8_t *code=NULL; size_t sz=0; uint64_t base=0;
    int si;
    for(si=0;si<bin->nsections;si++){
        dax_section_t *sec=&bin->sections[si];
        if(fn->start>=sec->vaddr&&fn->start<sec->vaddr+sec->size&&
           sec->offset+sec->size<=bin->size){
            code=bin->data+sec->offset; sz=(size_t)sec->size; base=sec->vaddr; break;
        }
    }
    if(!code)return NULL;
    nr_ctx_t *ctx=(nr_ctx_t*)calloc(1,sizeof(nr_ctx_t));
    if(!ctx)return NULL;
    ctx->func_idx=func_idx;

    size_t off=(size_t)(fn->start-base);
    size_t fn_end=(fn->end>fn->start&&fn->end<=base+sz)
                  ?(size_t)(fn->end-base):off+1024;

    while(off<fn_end&&off<sz){
        uint64_t addr=base+off;
        char mnem[32]="",ops[256]=""; int len=0;
        if(bin->arch==ARCH_ARM64){
            if(off+4>sz)break;
            uint32_t raw=(uint32_t)(code[off])|(code[off+1]<<8)|
                         (code[off+2]<<16)|(code[off+3]<<24);
            a64_insn_t insn; a64_decode(raw,addr,&insn);
            strncpy(mnem,insn.mnemonic,31); strncpy(ops,insn.operands,255);
            len=4;
            nr_lift_arm64(ctx,bin,mnem,ops,addr);
        } else if(bin->arch==ARCH_RISCV64){
            rv_insn_t insn;
            len=rv_decode(code+off,sz-off,addr,&insn);
            if(len<=0){len=2;off+=2;continue;}
            strncpy(mnem,insn.mnemonic,31); strncpy(ops,insn.operands,255);
            nr_lift_riscv(ctx,bin,mnem,ops,addr);
        } else {
            x86_insn_t insn;
            len=x86_decode(code+off,fn_end-off,addr,&insn);
            if(len<=0){len=1;off++;continue;}
            strncpy(mnem,insn.mnemonic,31); strncpy(ops,insn.ops,255);
            nr_lift_arm64(ctx,bin,mnem,ops,addr);
        }
        off+=(size_t)len;
        if(!strncmp(mnem,"ret",3)||!strcmp(mnem,"c.jr"))break;
        if(!strcmp(mnem,"br")||(!strcmp(mnem,"jalr")&&strstr(ops,"zero")))break;
        if(off<sz){
            uint64_t na=base+off;
            dax_func_t *nf=dax_func_find(bin,na);
            if(nf&&nf->start==na&&nf->start!=fn->start)break;
        }
    }
    return ctx;
}

/* ═══════════════════════════════════════════════════════════════════
 * §9  Print NR form for one function
 * ═══════════════════════════════════════════════════════════════════ */

static void nr_print_func(dax_binary_t *bin,int func_idx,
                           nr_ctx_t *ctx,dax_opts_t *opts,FILE *out){
    int c=opts?opts->color:1;
    dax_func_t *fn=&bin->functions[func_idx];

    const char *CT=c?"\033[1;36m":"";
    const char *CA=c?"\033[1;34m":"";
    const char *CV=c?"\033[1;33m":"";
    const char *CI=c?"\033[0;37m":"";
    const char *CO=c?"\033[1;35m":"";
    const char *CC=c?"\033[1;32m":"";
    const char *CX=c?"\033[1;31m":"";
    const char *CD=c?"\033[0;90m":"";
    const char *CR=c?"\033[0m":"";

    fprintf(out,"\n");
    if(c)fprintf(out,"%s",CT);
    fprintf(out,"  ══════════════ NR: %s ══════════════\n",
            fn->name[0]?fn->name:"<unnamed>");
    if(c)fprintf(out,"%s",CR);

    /* callers — inter-function linkage */
    {
        int ci,found=0;
        for(ci=0;ci<bin->nxrefs;ci++){
            if(bin->xrefs[ci].to==fn->start&&bin->xrefs[ci].is_call){
                if(!found){fprintf(out,"  %s▸ callers:%s",CD,CR);found=1;}
                dax_func_t *caller=dax_func_find(bin,bin->xrefs[ci].from);
                if(caller) fprintf(out,"  %s%s%s@%s0x%llx%s",
                                   CC,caller->name[0]?caller->name:"?",CR,
                                   CD,(unsigned long long)bin->xrefs[ci].from,CR);
                else fprintf(out,"  %s0x%llx%s",
                             CA,(unsigned long long)bin->xrefs[ci].from,CR);
            }
        }
        if(found)fprintf(out,"\n");
    }
    /* callees — inter-function linkage */
    {
        int i,found=0;
        for(i=0;i<ctx->nstmts;i++){
            nr_stmt_t *s=&ctx->stmts[i];
            if((s->op==NR_CALL||s->op==NR_INDIRECT_CALL)&&s->callee_name[0]){
                if(!found){fprintf(out,"  %s▸ callees:%s",CD,CR);found=1;}
                fprintf(out,"  %s%s%s",CC,s->callee_name,CR);
            }
        }
        if(found)fprintf(out,"\n");
    }
    /* SMC flag */
    {
        int pi;
        for(pi=0;pi<bin->nsmc_patches;pi++){
            if(bin->smc_target_addr[pi]>=fn->start&&
               bin->smc_target_addr[pi]<fn->end){
                fprintf(out,"  %s⚠ SMC-modified function%s\n",CX,CR);
                break;
            }
        }
    }
    fprintf(out,"\n");

    int i;
    for(i=0;i<ctx->nstmts;i++){
        nr_stmt_t *s=&ctx->stmts[i];
        char db[32]="",s1[32]="",s2[32]="";
        nr_var_fmt(ctx,s->dst, db, 32);
        nr_var_fmt(ctx,s->src1,s1, 32);
        nr_var_fmt(ctx,s->src2,s2, 32);
        const char *tn=(s->dst>=0&&s->dst<ctx->nvars)?
                        nr_type_name(ctx->vars[s->dst].type):"";

        fprintf(out,"  %s0x%llx%s  ",CA,(unsigned long long)s->addr,CR);

        switch(s->op){
        case NR_ASSIGN:
            if(s->has_imm)
                fprintf(out,"%s%s%s:%s%s%s = %s0x%llx%s\n",
                        CV,db,CR,CD,tn,CR,CI,(unsigned long long)s->imm,CR);
            else
                fprintf(out,"%s%s%s:%s%s%s = %s%s%s\n",
                        CV,db,CR,CD,tn,CR,CV,s1,CR);
            break;
        case NR_ADD:case NR_SUB:case NR_MUL:case NR_DIV:
        case NR_AND:case NR_OR: case NR_XOR:
        case NR_SHL:case NR_SHR:case NR_ROL:case NR_ROR:
            if(s->has_imm)
                fprintf(out,"%s%s%s = %s%s%s %s%s%s %s0x%llx%s\n",
                        CV,db,CR,CV,s1,CR,CO,nr_op_sym(s->op),CR,
                        CI,(unsigned long long)s->imm,CR);
            else
                fprintf(out,"%s%s%s = %s%s%s %s%s%s %s%s%s\n",
                        CV,db,CR,CV,s1,CR,CO,nr_op_sym(s->op),CR,CV,s2,CR);
            break;
        case NR_NEG: fprintf(out,"%s%s%s = %s-%s%s%s\n",CV,db,CR,CO,CR,CV,s1);break;
        case NR_NOT: fprintf(out,"%s%s%s = %s~%s%s%s\n",CV,db,CR,CO,CR,CV,s1);break;
        case NR_SEXT:
            fprintf(out,"%s%s%s = %ssext%s(%s%s%s, from=%llu)\n",
                    CV,db,CR,CO,CR,CV,s1,CR,(unsigned long long)s->imm);break;
        case NR_ZEXT:
            fprintf(out,"%s%s%s = %szext%s(%s%s%s, from=%llu)\n",
                    CV,db,CR,CO,CR,CV,s1,CR,(unsigned long long)s->imm);break;
        case NR_LOAD:
            fprintf(out,"%s%s%s:%s%s%s = %sload%s[%s%s%s]\n",
                    CV,db,CR,CD,tn,CR,CO,CR,CV,s1,CR);break;
        case NR_STORE:
            fprintf(out,"%sstore%s[%s%s%s] %s←%s %s%s%s\n",
                    CO,CR,CV,s2,CR,CO,CR,CV,s1,CR);break;
        case NR_CMP:
            if(s->has_imm)
                fprintf(out,"%s%s%s = %scmp%s(%s%s%s, %s0x%llx%s)\n",
                        CV,db,CR,CO,CR,CV,s1,CR,CI,(unsigned long long)s->imm,CR);
            else
                fprintf(out,"%s%s%s = %scmp%s(%s%s%s, %s%s%s)\n",
                        CV,db,CR,CO,CR,CV,s1,CR,CV,s2,CR);
            break;
        case NR_BRANCH:
            if(s->branch_target)
                fprintf(out,"%sbranch%s → %s0x%llx%s\n",
                        CO,CR,CA,(unsigned long long)s->branch_target,CR);
            else
                fprintf(out,"%sindirect_jump%s [%s%s%s]\n",CO,CR,CV,s1,CR);
            break;
        case NR_COND_BR:
            fprintf(out,"%sif%s (%s%s%s %s%s%s) %s→%s %s0x%llx%s\n",
                    CO,CR,CV,s1,CR,CX,s->cond[0]?s->cond:"?",CR,
                    CO,CR,CA,(unsigned long long)s->branch_target,CR);
            break;
        case NR_PHI:
            fprintf(out,"%s%s%s = %sφ%s(%s%s%s, %s%s%s)\n",
                    CV,db,CR,CO,CR,CV,s1,CR,CV,s2,CR);break;
        case NR_UNDEF:
            fprintf(out,"%s%s%s = %sundef%s\n",CV,db,CR,CD,CR);break;
        case NR_CALL:
            fprintf(out,"%s%s%s = %scall%s %s%s%s",
                    CV,db,CR,CO,CR,CC,s->callee_name,CR);
            if(s->callee_func_idx>=0&&s->callee_func_idx<bin->nfunctions){
                dax_func_t *cf=&bin->functions[s->callee_func_idx];
                fprintf(out," %s[→ func[%d] insns=%u loops=%s]%s",
                        CD,s->callee_func_idx,cf->insn_count,
                        cf->has_loops?"yes":"no",CR);
            } else if(s->imm) {
                fprintf(out," %s(0x%llx)%s",CD,(unsigned long long)s->imm,CR);
            }
            fprintf(out,"\n");
            break;
        case NR_INDIRECT_CALL:
            fprintf(out,"%s%s%s = %sindirect_call%s [%s%s%s] → %s%s%s\n",
                    CV,db,CR,CO,CR,CV,s1,CR,CD,s->callee_name,CR);break;
        case NR_SYSCALL:
            fprintf(out,"%s%s%s = %ssyscall%s %s%s%s",
                    CV,db,CR,CO,CR,CC,s->callee_name,CR);
            if(s->has_imm)fprintf(out," %s(#%llu)%s",CI,(unsigned long long)s->imm,CR);
            fprintf(out,"\n");
            break;
        case NR_RET:
            fprintf(out,"%sret%s %s%s%s\n",CO,CR,CV,s1,CR);break;
        case NR_NOP:
            fprintf(out,"%snop%s\n",CD,CR);break;
        default:
            fprintf(out,"...\n");break;
        }
    }
    fprintf(out,"\n  %s%d NR stmts  |  %d vars  |  func_idx=%d%s\n",
            CD,ctx->nstmts,ctx->nvars,func_idx,CR);
    fprintf(out,"\n");
}

/* ═══════════════════════════════════════════════════════════════════
 * §10  Public NR API
 * ═══════════════════════════════════════════════════════════════════ */

void dax_ssa_lift_func(dax_binary_t *bin, int func_idx, dax_opts_t *opts, FILE *out) {
    nr_ctx_t *ctx;
    DAX_GUARD_BIN(bin);
    if (!dax_func_idx_ok(bin, func_idx)) return;
    ctx = nr_lift_func(bin, func_idx);
    if (!ctx) return;
    nr_print_func(bin, func_idx, ctx, opts, out);
    free(ctx);
}

void dax_ssa_lift_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int c, i;
    DAX_GUARD_BIN(bin);
    if (!opts || !out) return;
    c = opts->color;
    fprintf(out, "\n");
    if (c) fprintf(out, "\033[1;36m");
    fprintf(out, "  ══════════════ NR — NeoDAX Representation ══════════════\n");
    if (c) fprintf(out, "\033[0m");
    for (i = 0; i < bin->nfunctions && i < DAX_MAX_FUNCTIONS; i++)
        dax_ssa_lift_func(bin, i, opts, out);
}

/* ═══════════════════════════════════════════════════════════════════
 * §11  Decompiler — pseudo-C with type inference + resolved calls
 * ═══════════════════════════════════════════════════════════════════ */

static void nr_print_program_module(dax_binary_t *bin,dax_opts_t *opts,
                                     nr_call_edge_t *edges,int nedges,FILE *out){
    int c=opts?opts->color:1;
    const char *CT=c?"\033[1;36m":"";
    const char *CC=c?"\033[1;32m":"";
    const char *CA=c?"\033[1;34m":"";
    const char *CD=c?"\033[0;90m":"";
    const char *CX=c?"\033[1;31m":"";
    const char *CR=c?"\033[0m":"";

    fprintf(out,"\n");
    if(c)fprintf(out,"%s",CT);
    fprintf(out,"  ══════════════ NR MODULE — Inter-Function Call Graph ══════════════\n");
    if(c)fprintf(out,"%s",CR);
    fprintf(out,"\n");

    int i;
    for(i=0;i<nedges;i++){
        nr_call_edge_t *e=&edges[i];
        const char *cn="?";
        if(e->caller_func>=0&&e->caller_func<bin->nfunctions)
            cn=bin->functions[e->caller_func].name;
        fprintf(out,"  %s%-24s%s  %s→%s  ",CC,cn,CR,CD,CR);
        if(e->callee_func>=0&&e->callee_func<bin->nfunctions)
            fprintf(out,"%s%-24s%s",CC,bin->functions[e->callee_func].name,CR);
        else
            fprintf(out,"%s%-24s%s",CX,e->callee_name,CR);
        fprintf(out,"  %s@ 0x%llx%s\n",CA,(unsigned long long)e->call_site,CR);
    }
    if(!nedges)fprintf(out,"  %s(no call edges resolved)%s\n",CD,CR);

    /* SMC-flagged functions */
    {
        int fi,smc_found=0;
        for(fi=0;fi<bin->nfunctions;fi++){
            dax_func_t *fn=&bin->functions[fi];
            int pi;
            for(pi=0;pi<bin->nsmc_patches;pi++){
                if(bin->smc_target_addr[pi]>=fn->start&&
                   bin->smc_target_addr[pi]<fn->end){
                    if(!smc_found){
                        fprintf(out,"\n  %sSMC-modified functions:%s\n",CX,CR);
                        smc_found=1;
                    }
                    fprintf(out,"  %s⚠%s %s%-24s%s @ 0x%llx\n",
                            CX,CR,CC,fn->name[0]?fn->name:"<?>",CR,
                            (unsigned long long)fn->start);
                    break;
                }
            }
        }
    }

    fprintf(out,"\n  %s%d call edge(s)  |  %d function(s)  |  %d SMC patch(es)%s\n",
            CD,nedges,bin->nfunctions,bin->nsmc_patches,CR);
    fprintf(out,"\n");
}

static void decomp_print_func(dax_binary_t *bin,int func_idx,
                               nr_ctx_t *ctx,dax_opts_t *opts,FILE *out){
    int c=opts?opts->color:1;
    dax_func_t *fn=&bin->functions[func_idx];

    const char *CT=c?"\033[1;36m":"";
    const char *CTy=c?"\033[0;90m":"";
    const char *CV=c?"\033[1;33m":"";
    const char *CI=c?"\033[0;37m":"";
    const char *CO=c?"\033[1;35m":"";
    const char *CC=c?"\033[1;32m":"";
    const char *CX=c?"\033[1;31m":"";
    const char *CD=c?"\033[0;90m":"";
    const char *CR=c?"\033[0m":"";

    /* signature */
    fprintf(out,"\n");
    if(c)fprintf(out,"%s",CTy);
    fprintf(out,"/* 0x%llx — %d insns",(unsigned long long)fn->start,fn->insn_count);
    {
        int ci,nc=0;
        for(ci=0;ci<bin->nxrefs;ci++)
            if(bin->xrefs[ci].to==fn->start&&bin->xrefs[ci].is_call)nc++;
        if(nc)fprintf(out,"  called_from=%d",nc);
    }
    fprintf(out," */\n");
    if(c)fprintf(out,"%s",CR);

    const char *rtype=(fn->insn_count<4)?"void":"uint64_t";
    fprintf(out,"%s%s%s %s%s%s(",
            CTy,rtype,CR,CT,fn->name[0]?fn->name:"sub",CR);
    /* argument heuristic */
    {
        int ai,nargs=0;
        for(ai=0;ai<8;ai++){
            char rn[8]; snprintf(rn,8,"r%d",ai);
            if(nr_find_latest(ctx,rn)<0)break;
            if(nargs)fprintf(out,", ");
            fprintf(out,"%suint64_t%s %sa%d%s",CTy,CR,CV,ai,CR);
            nargs++;
        }
        if(!nargs)fprintf(out,"%svoid%s",CTy,CR);
    }
    fprintf(out,") {\n");

    /* locals */
    {
        int vi,emitted=0;
        for(vi=0;vi<ctx->nvars;vi++){
            nr_var_t *v=&ctx->vars[vi];
            if(!strcmp(v->base,"zero")||!strcmp(v->base,"sp"))continue;
            if(v->base[0]=='r'&&v->base[1]>='0'&&v->base[1]<='7'&&v->version==0)continue;
            if(v->type==NRT_FLAGS)continue;
            if(!emitted){fprintf(out,"  %s/* locals */%s\n",CD,CR);emitted=1;}
            char ln[32]=""; decomp_local_name(ctx,vi,ln,32);
            fprintf(out,"  %s%s%s %s%s%s;\n",CTy,nr_type_name(v->type),CR,CV,ln,CR);
        }
        if(emitted)fprintf(out,"\n");
    }

    /* body */
    int i;
    for(i=0;i<ctx->nstmts;i++){
        nr_stmt_t *s=&ctx->stmts[i];
        char db[32]="",s1[32]="",s2[32]="";
        decomp_local_name(ctx,s->dst, db,32);
        decomp_local_name(ctx,s->src1,s1,32);
        decomp_local_name(ctx,s->src2,s2,32);

        fprintf(out,"  ");

        switch(s->op){
        case NR_ASSIGN:
            if(s->has_imm)
                fprintf(out,"%s%s%s = %s0x%llx%s;\n",
                        CV,db,CR,CI,(unsigned long long)s->imm,CR);
            else
                fprintf(out,"%s%s%s = %s%s%s;\n",CV,db,CR,CV,s1,CR);
            break;
        case NR_ADD:case NR_SUB:case NR_MUL:case NR_DIV:
        case NR_AND:case NR_OR: case NR_XOR:
        case NR_SHL:case NR_SHR:
            if(s->has_imm)
                fprintf(out,"%s%s%s = %s%s%s %s%s%s %s0x%llx%s;\n",
                        CV,db,CR,CV,s1,CR,CO,nr_op_sym(s->op),CR,
                        CI,(unsigned long long)s->imm,CR);
            else
                fprintf(out,"%s%s%s = %s%s%s %s%s%s %s%s%s;\n",
                        CV,db,CR,CV,s1,CR,CO,nr_op_sym(s->op),CR,CV,s2,CR);
            break;
        case NR_ROL:
            fprintf(out,"%s%s%s = %s__rol%s(%s%s%s, %s%llu%s);\n",
                    CV,db,CR,CO,CR,CV,s1,CR,CI,(unsigned long long)s->imm,CR);break;
        case NR_ROR:
            fprintf(out,"%s%s%s = %s__ror%s(%s%s%s, %s%llu%s);\n",
                    CV,db,CR,CO,CR,CV,s1,CR,CI,(unsigned long long)s->imm,CR);break;
        case NR_NEG:
            fprintf(out,"%s%s%s = %s-%s%s%s;\n",CV,db,CR,CO,CR,CV,s1);break;
        case NR_NOT:
            fprintf(out,"%s%s%s = %s~%s%s%s;\n",CV,db,CR,CO,CR,CV,s1);break;
        case NR_SEXT:
            fprintf(out,"%s%s%s = %s(int%llu_t)%s(%s%s%s);\n",
                    CV,db,CR,CTy,(unsigned long long)s->imm,CR,CV,s1,CR);break;
        case NR_ZEXT:
            fprintf(out,"%s%s%s = %s(uint%llu_t)%s(%s%s%s);\n",
                    CV,db,CR,CTy,(unsigned long long)s->imm,CR,CV,s1,CR);break;
        case NR_LOAD:
            fprintf(out,"%s%s%s = %s*(%s%s%s);\n",CV,db,CR,CO,CV,s1,CR);break;
        case NR_STORE:
            fprintf(out,"%s*(%s%s%s) = %s%s%s;\n",CO,CV,s2,CR,CV,s1,CR);break;
        case NR_CMP:
            if(s->has_imm)
                fprintf(out,"%s/* cmp %s%s%s, %s0x%llx%s */%s\n",
                        CD,CV,s1,CR,CI,(unsigned long long)s->imm,CD,CR);
            else
                fprintf(out,"%s/* cmp %s%s%s, %s%s%s */%s\n",
                        CD,CV,s1,CR,CV,s2,CD,CR);
            break;
        case NR_BRANCH:
            if(s->branch_target){
                /* tail-call detection */
                int tfi; int is_tail=0;
                for(tfi=0;tfi<bin->nfunctions;tfi++)
                    if(bin->functions[tfi].start==s->branch_target&&tfi!=func_idx)
                        {is_tail=1;break;}
                if(is_tail)
                    fprintf(out,"%sreturn%s %s%s%s(/*tail*/);\n",
                            CO,CR,CC,bin->functions[tfi].name,CR);
                else
                    fprintf(out,"%sgoto%s %sloc_0x%llx%s;\n",
                            CO,CR,CD,(unsigned long long)s->branch_target,CR);
            } else {
                fprintf(out,"%sgoto%s *(%s%s%s); %s/* indirect */%s\n",
                        CO,CR,CV,s1,CR,CD,CR);
            }
            break;
        case NR_COND_BR:
            fprintf(out,"%sif%s (%s%s%s %s%s%s) %sgoto%s %sloc_0x%llx%s;\n",
                    CO,CR,CV,s1,CR,CX,s->cond[0]?s->cond:"?",CR,
                    CO,CR,CD,(unsigned long long)s->branch_target,CR);
            break;
        case NR_CALL:{
            if(s->dst>=0)fprintf(out,"%s%s%s = ",CV,db,CR);
            fprintf(out,"%s%s%s(",CC,s->callee_name[0]?s->callee_name:"??",CR);
            int ai,npa=0;
            for(ai=0;ai<8;ai++){
                char rn[8]; snprintf(rn,8,"r%d",ai);
                int vi=nr_find_latest(ctx,rn); if(vi<0)break;
                char an[32]=""; decomp_local_name(ctx,vi,an,32);
                if(npa)fprintf(out,", ");
                fprintf(out,"%s%s%s",CV,an,CR);
                npa++;
            }
            fprintf(out,")");
            if(s->callee_func_idx>=0&&s->callee_func_idx<bin->nfunctions)
                fprintf(out," %s/* func[%d] */%s",CD,s->callee_func_idx,CR);
            fprintf(out,";\n");
            break;
        }
        case NR_INDIRECT_CALL:
            if(s->dst>=0)fprintf(out,"%s%s%s = ",CV,db,CR);
            fprintf(out,"((%suint64_t(*)(...)%s)%s%s%s)(); %s/* %s */%s\n",
                    CTy,CR,CV,s1,CR,CD,s->callee_name,CR);
            break;
        case NR_SYSCALL:
            if(s->dst>=0)fprintf(out,"%s%s%s = ",CV,db,CR);
            fprintf(out,"%s_syscall%s(%s\"%s\"%s",CC,CR,CI,s->callee_name,CR);
            if(s->has_imm)fprintf(out,", %s%llu%s",CI,(unsigned long long)s->imm,CR);
            fprintf(out,");\n");
            break;
        case NR_RET:
            fprintf(out,"%sreturn%s %s%s%s;\n",CO,CR,CV,s1,CR);break;
        case NR_PHI:
            fprintf(out,"%s%s%s = %sφ%s(%s%s%s, %s%s%s);\n",
                    CV,db,CR,CO,CR,CV,s1,CR,CV,s2,CR);break;
        case NR_NOP: break;
        default: break;
        }
    }
    fprintf(out,"}\n\n");
}

void dax_decompile_func(dax_binary_t *bin, int func_idx, dax_opts_t *opts, FILE *out) {
    nr_ctx_t *ctx;
    DAX_GUARD_BIN(bin);
    if (!dax_func_idx_ok(bin, func_idx)) return;
    ctx = nr_lift_func(bin, func_idx);
    if (!ctx) return;
    decomp_print_func(bin, func_idx, ctx, opts, out);
    free(ctx);
}

void dax_decompile_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int c, i;
    nr_call_edge_t *edges;
    int nedges = 0;
    DAX_GUARD_BIN(bin);
    if (!opts || !out) return;
    c = opts->color;
    fprintf(out, "\n");
    if (c) fprintf(out, "\033[1;36m");
    fprintf(out, "  ══════════════ NR DECOMPILER — Pseudo-C ══════════════\n");
    if (c) fprintf(out, "\033[0m");

    edges = (nr_call_edge_t *)calloc(NR_MAX_CALLS, sizeof(nr_call_edge_t));
    if (!edges) { dax_fault_set("calloc failed in decompile_all"); return; }

    for(i=0;i<bin->nfunctions&&i<DAX_MAX_FUNCTIONS;i++){
        nr_ctx_t *ctx=nr_lift_func(bin,i);
        if(!ctx)continue;
        /* harvest call edges for module summary */
        int j;
        for(j=0;j<ctx->nstmts&&nedges<NR_MAX_CALLS;j++){
            nr_stmt_t *s=&ctx->stmts[j];
            if(s->op==NR_CALL||s->op==NR_INDIRECT_CALL){
                nr_call_edge_t *e=&edges[nedges++];
                e->caller_func=i;
                e->callee_func=s->callee_func_idx;
                e->call_site=s->addr;
                strncpy(e->callee_name,s->callee_name,47);
            }
        }
        decomp_print_func(bin,i,ctx,opts,out);
        free(ctx);
    }
    nr_print_program_module(bin,opts,edges,nedges,out);
    free(edges);
}
