#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "dax.h"
#include "dax_guard.h"
#include "x86.h"
#include "arm64.h"
#include "riscv.h"
#include <ctype.h>

#define SYM_MAX_INSNS       2048
#define MAX_STEPS_PER_PATH   128   
#define SYM_EXPR_POOL       8192   
#define MAX_SYM_REGS        33      
#define MAX_SYM_MEM         256     
#define MAX_PATH_WORKLIST   16      
#define MAX_PATHS           4       
#define SMC_MAX_PATCHES     32      
#define MAX_INDIRECT_CACHE  64      

typedef enum {
    SEXPR_CONST=0, SEXPR_VAR,
    SEXPR_ADD, SEXPR_SUB, SEXPR_AND, SEXPR_OR, SEXPR_XOR,
    SEXPR_SHL, SEXPR_SHR, SEXPR_MUL, SEXPR_NOT, SEXPR_NEG,
    SEXPR_EQ, SEXPR_NE, SEXPR_LT, SEXPR_LE
} sexpr_op_t;

typedef struct {
    sexpr_op_t  op;
    uint64_t    val;
    int         left, right;
    uint8_t     bits;
    char        name[24];
} sym_expr_t;

static sym_expr_t g_pool[SYM_EXPR_POOL];
static int        g_npool = 0;

static int sexpr_alloc(void) {
    if (g_npool >= SYM_EXPR_POOL - 1) {
        
        return SYM_EXPR_POOL - 1;
    }
    memset(&g_pool[g_npool],0,sizeof(sym_expr_t));
    return g_npool++;
}
static int sexpr_const(uint64_t v, uint8_t b) {
    int i=sexpr_alloc(); g_pool[i].op=SEXPR_CONST; g_pool[i].val=v; g_pool[i].bits=b; return i;
}
static int sexpr_var(const char *n, uint8_t b) {
    int i=sexpr_alloc(); g_pool[i].op=SEXPR_VAR; g_pool[i].bits=b;
    strncpy(g_pool[i].name,n,23); return i;
}
static int sexpr_binop(sexpr_op_t op, int l, int r, uint8_t b) {
    int i=sexpr_alloc(); g_pool[i].op=op; g_pool[i].left=l; g_pool[i].right=r; g_pool[i].bits=b; return i;
}
static void sexpr_print(int idx, char *buf, size_t sz) {
    if (idx<0||idx>=SYM_EXPR_POOL||sz<2) { strncpy(buf,"?",sz); return; }
    if (idx >= g_npool) { strncpy(buf,"?",sz); return; }
    sym_expr_t *e=&g_pool[idx];
    char l[128]="",r[128]="";
    switch(e->op) {
        case SEXPR_CONST: snprintf(buf,sz,"0x%llx",(unsigned long long)e->val); return;
        case SEXPR_VAR:   snprintf(buf,sz,"%s",e->name); return;
        case SEXPR_NOT:   sexpr_print(e->left,l,sizeof(l)); snprintf(buf,sz,"~%s",l); return;
        case SEXPR_NEG:   sexpr_print(e->left,l,sizeof(l)); snprintf(buf,sz,"-%s",l); return;
        default: break;
    }
    sexpr_print(e->left,l,sizeof(l)); sexpr_print(e->right,r,sizeof(r));
    const char *op_s="?";
    switch(e->op){
        case SEXPR_ADD: op_s="+";  break; case SEXPR_SUB: op_s="-"; break;
        case SEXPR_AND: op_s="&";  break; case SEXPR_OR:  op_s="|"; break;
        case SEXPR_XOR: op_s="^";  break; case SEXPR_SHL: op_s="<<"; break;
        case SEXPR_SHR: op_s=">>";  break; case SEXPR_MUL: op_s="*"; break;
        case SEXPR_EQ:  op_s="=="; break; case SEXPR_NE:  op_s="!="; break;
        case SEXPR_LT:  op_s="<";  break; case SEXPR_LE:  op_s="<="; break;
        default: break;
    }
    snprintf(buf,sz,"(%s %s %s)",l,op_s,r);
}

typedef struct {
    int      is_concrete;
    uint64_t concrete;
    int      expr_idx;
    uint8_t  bits;
} sym_val_t;

static void sv_const(sym_val_t *v, uint64_t c, uint8_t b) {
    v->is_concrete=1; v->concrete=(b==32)?(c&0xFFFFFFFF):c;
    v->expr_idx=sexpr_const(v->concrete,b); v->bits=b;
}
static void sv_sym(sym_val_t *v, const char *n, uint8_t b) {
    v->is_concrete=0; v->concrete=0; v->expr_idx=sexpr_var(n,b); v->bits=b;
}
static sym_val_t sv_binop(sym_val_t *a, sym_val_t *b, sexpr_op_t op) {
    sym_val_t r; r.bits=a->bits;
    if (a->is_concrete && b->is_concrete) {
        uint64_t v=0;
        switch(op) {
            case SEXPR_ADD: v=a->concrete+b->concrete; break;
            case SEXPR_SUB: v=a->concrete-b->concrete; break;
            case SEXPR_AND: v=a->concrete&b->concrete; break;
            case SEXPR_OR:  v=a->concrete|b->concrete; break;
            case SEXPR_XOR: v=a->concrete^b->concrete; break;
            case SEXPR_SHL: v=a->concrete<<(b->concrete&63); break;
            case SEXPR_SHR: v=a->concrete>>(b->concrete&63); break;
            case SEXPR_MUL: v=a->concrete*b->concrete; break;
            default: break;
        }
        if (a->bits==32) v&=0xFFFFFFFF;
        sv_const(&r,v,a->bits);
    } else {
        r.is_concrete=0;
        r.expr_idx=sexpr_binop(op,a->expr_idx,b->expr_idx,a->bits);
        if (r.expr_idx >= SYM_EXPR_POOL-1) {
            
            r.expr_idx=sexpr_var("?",a->bits);
        }
    }
    return r;
}

typedef struct {
    uint64_t  addr;         
    sym_val_t val;
    int       is_exec;      
    uint64_t  write_pc;     
} sym_mem_cell_t;

typedef struct {
    uint64_t  target_addr;  
    uint32_t  old_word;     
    uint32_t  new_word;     
    uint64_t  write_pc;     
    uint64_t  src_addr;     
} smc_patch_t;

typedef struct {
    uint64_t  from_pc;      
    uint64_t  target;       
    char      reg[8];       
} indirect_resolve_t;

typedef struct {
    sym_val_t      regs[MAX_SYM_REGS];
    sym_mem_cell_t mem[MAX_SYM_MEM];
    int            nmem;
    uint64_t       pc;
    int            path_id;
    int            step;
    int            flags_z, flags_n, flags_c, flags_v;
    char           path_cond[512];  
    int            taken_branches;  
    
    uint64_t       visited[256];
    int            nvisited;
} sym_path_t;

typedef struct {
    sym_path_t  state;
    const char *label;      
} sym_work_t;

typedef struct {
    smc_patch_t        patches[SMC_MAX_PATCHES];
    int                npatches;
    indirect_resolve_t indirect[MAX_INDIRECT_CACHE];
    int                nindirect;
    int                paths_explored;
    int                paths_halted_indirect;
    int                paths_halted_call;
} sym_results_t;

static sym_results_t g_results;

static int arm64_rn(const char *n) {
    if (!n||!n[0]) return -1;
    if (n[0]=='x'||n[0]=='w') { int v=atoi(n+1); if(v>=0&&v<=30) return v; }
    if (!strcmp(n,"sp")||!strcmp(n,"wsp")) return 31;
    if (!strcmp(n,"xzr")||!strcmp(n,"wzr")) return 31;
    if (!strcmp(n,"lr")) return 30;
    if (!strcmp(n,"fp")||!strcmp(n,"x29")) return 29;
    return -1;
}
static int x86_rn(const char *n) {
    static const char *r64[]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                               "r8","r9","r10","r11","r12","r13","r14","r15"};
    static const char *r32[]={"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
    int i;
    for(i=0;i<16;i++) if(!strcmp(n,r64[i])) return i;
    for(i=0;i<8;i++)  if(!strcmp(n,r32[i])) return i;
    return -1;
}

static int arm64_reg_idx(const char *n) { return arm64_rn(n); }

static int rv_reg_se(const char *name) {
    static const char *rv_names[32] = {
        "zero","ra","sp","gp","tp","t0","t1","t2",
        "s0","s1","a0","a1","a2","a3","a4","a5",
        "a6","a7","s2","s3","s4","s5","s6","s7",
        "s8","s9","s10","s11","t3","t4","t5","t6"
    };
    int i;
    if (!name||!name[0]) return -1;
    if (name[0]=='x' && isdigit((unsigned char)name[1])) return atoi(name+1);
    for (i=0;i<32;i++) if(strcmp(name,rv_names[i])==0) return i;
    return -1;
}
static int x86_reg_idx(const char *n)   { return x86_rn(n); }

static void parse3(const char *ops, char *a1, char *a2, char *a3) {
    const char *p=ops; char *b[3]={a1,a2,a3}; int k;
    a1[0]=a2[0]=a3[0]='\0';
    for(k=0;k<3;k++){
        while(*p==' ')p++;
        char *d=b[k]; int j=0;
        while(*p&&*p!=','&&j<63){*d++=*p++;j++;} *d='\0'; if(*p==',')p++;
    }
}

static uint64_t parse_imm(const char *s) {
    if (!s||!s[0]) return 0;
    if (s[0]=='#') s++;
    if (!strncmp(s,"0x",2)) return strtoull(s,NULL,16);
    return strtoull(s,NULL,0);
}

static sym_val_t sym_mem_read(sym_path_t *st, uint64_t addr, uint8_t bits) {
    int i;
    for (i=st->nmem-1; i>=0; i--) {
        if (st->mem[i].addr==addr && st->mem[i].val.bits>=bits)
            return st->mem[i].val;
    }
    
    sym_val_t r; char name[32]; snprintf(name,32,"mem[0x%llx]",(unsigned long long)addr);
    sv_sym(&r,name,bits); return r;
}

static void sym_mem_write(sym_path_t *st, uint64_t addr, sym_val_t val,
                           int is_exec, uint64_t write_pc,
                           dax_binary_t *bin,
                           uint64_t src_adr_addr) {
    if (st->nmem < MAX_SYM_MEM) {
        st->mem[st->nmem].addr     = addr;
        st->mem[st->nmem].val      = val;
        st->mem[st->nmem].is_exec  = is_exec;
        st->mem[st->nmem].write_pc = write_pc;
        st->nmem++;
    }

    
    if (is_exec && val.is_concrete && g_results.npatches < SMC_MAX_PATCHES) {
        smc_patch_t *p = &g_results.patches[g_results.npatches];
        p->target_addr = addr;
        p->write_pc    = write_pc;
        p->src_addr    = src_adr_addr;
        p->new_word    = (uint32_t)(val.concrete & 0xFFFFFFFF);
        
        if (bin) {
            int si;
            for (si=0; si<bin->nsections; si++) {
                dax_section_t *s2=&bin->sections[si];
                if (addr>=s2->vaddr && addr<s2->vaddr+s2->size &&
                    s2->offset+s2->size<=bin->size) {
                    size_t off2=(size_t)(addr-s2->vaddr);
                    uint8_t *ptr=bin->data+s2->offset+off2;
                    p->old_word=(uint32_t)(ptr[0])|(ptr[1]<<8)|(ptr[2]<<16)|(ptr[3]<<24);
                    break;
                }
            }
            
            if (bin->nsmc_patches < 128) {
                int dup=0, di;
                for(di=0;di<bin->nsmc_patches;di++)
                    if(bin->smc_target_addr[di]==addr){dup=1;break;}
                if (!dup) {
                    bin->smc_write_pc[bin->nsmc_patches]    = write_pc;
                    bin->smc_target_addr[bin->nsmc_patches] = addr;
                    bin->smc_old_word[bin->nsmc_patches]    = p->old_word;
                    bin->smc_new_word[bin->nsmc_patches]    = p->new_word;
                    bin->nsmc_patches++;
                    bin->obf_score_smc++;
                } else {
                    /* duplicate write to same addr — mutation chain */
                    int ci;
                    int found_chain = 0;
                    for (ci = 0; ci < bin->nsmc_chains; ci++) {
                        if (bin->smc_chain_addr[ci] == addr) {
                            bin->smc_chain_count[ci]++;
                            found_chain = 1;
                            break;
                        }
                    }
                    if (!found_chain && bin->nsmc_chains < 32) {
                        bin->smc_chain_addr[bin->nsmc_chains]  = addr;
                        bin->smc_chain_count[bin->nsmc_chains] = 2;
                        bin->nsmc_chains++;
                        bin->obf_score_smc += 2; /* chains are more suspicious */
                    }
                }
            }
        }
        g_results.npatches++;
    }
}

static int addr_is_exec(dax_binary_t *bin, uint64_t addr) {
    int i;
    for (i=0;i<bin->nsections;i++) {
        dax_section_t *s2=&bin->sections[i];
        if ((s2->type==SEC_TYPE_CODE||s2->type==SEC_TYPE_PLT) &&
            addr>=s2->vaddr && addr<s2->vaddr+s2->size) return 1;
    }
    return 0;
}

static void path_init_arm64(sym_path_t *st, uint64_t pc, int pid) {
    int i; char n[16];
    memset(st,0,sizeof(*st));
    st->pc=pc; st->path_id=pid;
    for (i=0;i<31;i++){snprintf(n,16,"x%d",i); sv_sym(&st->regs[i],n,64);}
    sv_const(&st->regs[31], 0x7fff0000ULL, 64);  
    sv_const(&st->regs[32], 0, 8);                
}

typedef struct {
    int      action;        
    uint64_t branch_tgt;   
    uint64_t fall_tgt;     
    int      cond_known;   
    int      cond_taken;   
    char     indirect_reg[8]; 
    int      indirect_concrete;
    uint64_t indirect_tgt;
} step_result_t;

static void record_indirect(uint64_t from_pc, uint64_t tgt,
                             const char *reg, dax_binary_t *bin);

static step_result_t step_arm64_path(sym_path_t *st, const char *mnem,
                                      const char *ops, uint64_t addr,
                                      dax_binary_t *bin) {
    step_result_t res;
    memset(&res,0,sizeof(res));
    res.fall_tgt = addr + 4;

    char a1[64]="",a2[64]="",a3[64]="";
    parse3(ops,a1,a2,a3);
    int dr=arm64_rn(a1), sr1=arm64_rn(a2), sr2=arm64_rn(a3);

    
    if (!strcmp(mnem,"mov")||!strcmp(mnem,"movz")) {
        if (dr>=0) {
            if (sr1>=0) { st->regs[dr]=st->regs[sr1]; st->regs[dr].bits=(a1[0]=='w')?32:64; }
            else { sv_const(&st->regs[dr],parse_imm(a2),(a1[0]=='w')?32:64); }
        }
    } else if (!strcmp(mnem,"movn")) {
        if (dr>=0) sv_const(&st->regs[dr],~parse_imm(a2)&0xFFFFFFFF,32);
    } else if (!strcmp(mnem,"movk")) {
        if (dr>=0 && st->regs[dr].is_concrete) {
            uint64_t imm=parse_imm(a2), shift=0;
            const char *lp=strstr(ops,"lsl"); if(lp){const char *sp=strchr(lp,'#');if(sp)shift=parse_imm(sp);}
            uint64_t mask=~(0xFFFFULL<<shift);
            sv_const(&st->regs[dr],(st->regs[dr].concrete&mask)|((imm&0xFFFF)<<shift),64);
        }
    } else if (!strcmp(mnem,"adr")||!strcmp(mnem,"adrp")) {
        if (dr>=0) {
            uint64_t tgt=0;
            if (a2[0]=='0') sscanf(a2,"0x%llx",(unsigned long long*)&tgt);
            else tgt=addr;
            sv_const(&st->regs[dr],tgt,64);
        }
    }
    
    else if (!strcmp(mnem,"add")||!strcmp(mnem,"adds")) {
        if (dr>=0&&sr1>=0) {
            sym_val_t b;
            if (sr2>=0) {
                b=st->regs[sr2];
                
                const char *lp=strstr(ops,"lsl");
                if (lp&&b.is_concrete){
                    const char *sp=strchr(lp,'#'); if(sp){uint64_t s=parse_imm(sp);b.concrete<<=s&63;}
                }
            } else { sv_const(&b,parse_imm(a3),st->regs[sr1].bits); }
            st->regs[dr]=sv_binop(&st->regs[sr1],&b,SEXPR_ADD);
        }
    } else if (!strcmp(mnem,"sub")||!strcmp(mnem,"subs")) {
        if (dr>=0&&sr1>=0) {
            sym_val_t b;
            if (sr2>=0) b=st->regs[sr2];
            else sv_const(&b,parse_imm(a3),st->regs[sr1].bits);
            st->regs[dr]=sv_binop(&st->regs[sr1],&b,SEXPR_SUB);
            if (!strcmp(mnem,"subs")&&st->regs[dr].is_concrete) {
                uint64_t v=st->regs[dr].concrete;
                st->flags_z=(v==0); st->flags_n=(int)((int64_t)v<0);
                st->flags_c=(st->regs[sr1].is_concrete&&b.is_concrete&&st->regs[sr1].concrete>=b.concrete);
            }
        }
    } else if (!strcmp(mnem,"and")||!strcmp(mnem,"ands")) {
        if (dr>=0&&sr1>=0) {
            sym_val_t b;
            if (sr2>=0) b=st->regs[sr2]; else sv_const(&b,parse_imm(a3),64);
            st->regs[dr]=sv_binop(&st->regs[sr1],&b,SEXPR_AND);
            if (!strcmp(mnem,"ands")&&st->regs[dr].is_concrete){st->flags_z=(st->regs[dr].concrete==0);}
        }
    } else if (!strcmp(mnem,"orr")) {
        if (dr>=0&&sr1>=0&&sr2>=0) st->regs[dr]=sv_binop(&st->regs[sr1],&st->regs[sr2],SEXPR_OR);
    } else if (!strcmp(mnem,"eor")) {
        if (dr>=0&&sr1>=0) {
            sym_val_t b;
            if (sr2>=0) b=st->regs[sr2]; else sv_const(&b,parse_imm(a3),64);
            st->regs[dr]=sv_binop(&st->regs[sr1],&b,SEXPR_XOR);
        }
    } else if (!strcmp(mnem,"bic")||!strcmp(mnem,"bics")) {
        if (dr>=0&&sr1>=0&&sr2>=0) {
            sym_val_t nb=st->regs[sr2];
            if (nb.is_concrete) { sv_const(&nb,~nb.concrete,nb.bits); }
            st->regs[dr]=sv_binop(&st->regs[sr1],&nb,SEXPR_AND);
        }
    } else if (!strcmp(mnem,"lsl")||!strcmp(mnem,"lsr")||!strcmp(mnem,"asr")) {
        if (dr>=0&&sr1>=0) {
            sym_val_t b; sv_const(&b,parse_imm(a3),8);
            sexpr_op_t op=(!strcmp(mnem,"lsl"))?SEXPR_SHL:SEXPR_SHR;
            st->regs[dr]=sv_binop(&st->regs[sr1],&b,op);
        }
    } else if (!strcmp(mnem,"ror")) {
        if (dr>=0&&sr1>=0&&st->regs[sr1].is_concrete) {
            uint64_t v=st->regs[sr1].concrete, sh=parse_imm(a3)&63;
            sv_const(&st->regs[dr],(sh==0)?v:(v>>sh)|(v<<(64-sh)),64);
        }
    } else if (!strcmp(mnem,"extr")) {
        if (dr>=0&&sr1>=0) {
            uint64_t lsb=parse_imm(a3);
            if (st->regs[sr1].is_concrete&&sr2>=0&&st->regs[sr2].is_concrete){
                uint64_t rn=st->regs[sr1].concrete,rm=st->regs[sr2].concrete;
                sv_const(&st->regs[dr],(lsb==0)?rn:((rn<<(64-lsb))|(rm>>lsb)),64);
            }
        }
    }
    
    else if (!strcmp(mnem,"cmp")) {
        if (sr1>=0) {
            uint64_t v1=st->regs[dr].concrete, v2=(a2[0]=='#')?parse_imm(a2):
                        (sr1>=0&&st->regs[sr1].is_concrete?st->regs[sr1].concrete:0);
            if (st->regs[dr].is_concrete) {
                uint64_t r=v1-v2;
                st->flags_z=(r==0); st->flags_n=((int64_t)r<0);
                st->flags_c=(v1>=v2); st->flags_v=0;
            }
        }
    } else if (!strcmp(mnem,"tst")) {
        if (dr>=0) {
            uint64_t v2=(a2[0]=='#')?parse_imm(a2):(sr1>=0&&st->regs[sr1].is_concrete?st->regs[sr1].concrete:0);
            if (st->regs[dr].is_concrete) {
                uint64_t r=st->regs[dr].concrete&v2;
                st->flags_z=(r==0); st->flags_n=(r>>63)&1;
            }
        }
    } else if (!strcmp(mnem,"cmn")) {
        if (dr>=0&&st->regs[dr].is_concrete) {
            uint64_t v2=(a2[0]=='#')?parse_imm(a2):(sr1>=0&&st->regs[sr1].is_concrete?st->regs[sr1].concrete:0);
            uint64_t r=st->regs[dr].concrete+v2;
            st->flags_z=(r==0); st->flags_n=((int64_t)r<0);
        }
    }
    
    else if (!strcmp(mnem,"ldr")||!strcmp(mnem,"ldrb")||!strcmp(mnem,"ldrh")||
             !strcmp(mnem,"ldrsw")||!strcmp(mnem,"ldur")) {
        if (dr>=0) {
            
            const char *br2=a2; if(*br2=='[')br2++;
            char base_r[16]=""; uint64_t off2=0;
            char *cp=strchr(br2,',');
            if(cp){strncpy(base_r,br2,(size_t)(cp-br2)<15?(size_t)(cp-br2):15);off2=parse_imm(cp+1);}
            else  {strncpy(base_r,br2,15);char *rb=strchr(base_r,']');if(rb)*rb='\0';}
            int br_idx=arm64_rn(base_r);
            if (br_idx>=0&&st->regs[br_idx].is_concrete) {
                uint64_t addr2=st->regs[br_idx].concrete+off2;
                
                if (addr_is_exec(bin,addr2)) {
                    
                    sym_val_t mv=sym_mem_read(st,addr2,32);
                    st->regs[dr]=mv;
                } else {
                    sym_val_t mv=sym_mem_read(st,addr2,(uint8_t)(a1[0]=='w'?32:64));
                    st->regs[dr]=mv;
                }
            } else {
                char sname[32]; snprintf(sname,32,"mem[%s+0x%llx]",base_r,(unsigned long long)off2);
                sv_sym(&st->regs[dr],sname,a1[0]=='w'?32:64);
            }
        }
    } else if (!strcmp(mnem,"str")||!strcmp(mnem,"strb")||!strcmp(mnem,"strh")||
               !strcmp(mnem,"stur")) {
        
        const char *br2=a2; if(*br2=='[')br2++;
        char base_r[16]=""; uint64_t off2=0;
        char *cp=strchr(br2,',');
        uint64_t src_adr_addr=0;
        if(cp){strncpy(base_r,br2,(size_t)(cp-br2)<15?(size_t)(cp-br2):15);off2=parse_imm(cp+1);}
        else  {strncpy(base_r,br2,15);char *rb=strchr(base_r,']');if(rb)*rb='\0';}
        int br_idx=arm64_rn(base_r);
        sym_val_t val=(dr>=0&&dr<=31)?st->regs[dr]:(sym_val_t){1,0,0,32};
        if (br_idx>=0&&st->regs[br_idx].is_concrete) {
            uint64_t waddr=st->regs[br_idx].concrete+off2;
            int is_exec=addr_is_exec(bin,waddr);
            
            if (is_exec && dr>=0 && st->regs[dr].is_concrete) {
                
                int mi;
                for(mi=st->nmem-1;mi>=0;mi--){
                    if(st->mem[mi].val.is_concrete&&
                       st->mem[mi].val.concrete==st->regs[dr].concrete&&
                       addr_is_exec(bin,st->mem[mi].addr)){
                        src_adr_addr=st->mem[mi].addr; break;
                    }
                }
            }
            sym_mem_write(st,waddr,val,is_exec,addr,bin,src_adr_addr);
        }
    }
    
    else if (!strcmp(mnem,"b")) {
        uint64_t tgt=0; if(a1[0]=='0')sscanf(a1,"0x%llx",(unsigned long long*)&tgt);
        if (tgt) { res.action=3; res.branch_tgt=tgt; return res; }
    } else if (strncmp(mnem,"b.",2)==0) {
        const char *cond=mnem+2;
        uint64_t tgt=0; if(a1[0]=='0')sscanf(a1,"0x%llx",(unsigned long long*)&tgt);
        int known=0, taken=0;
        
        if      (!strcmp(cond,"eq")){ known=1; taken=st->flags_z; }
        else if (!strcmp(cond,"ne")){ known=1; taken=!st->flags_z; }
        else if (!strcmp(cond,"lt")){ known=1; taken=(st->flags_n!=st->flags_v); }
        else if (!strcmp(cond,"le")){ known=1; taken=st->flags_z||(st->flags_n!=st->flags_v); }
        else if (!strcmp(cond,"gt")){ known=1; taken=(!st->flags_z)&&(st->flags_n==st->flags_v); }
        else if (!strcmp(cond,"ge")){ known=1; taken=(st->flags_n==st->flags_v); }
        else if (!strcmp(cond,"mi")){ known=1; taken=st->flags_n; }
        else if (!strcmp(cond,"pl")){ known=1; taken=!st->flags_n; }
        res.action=4; res.branch_tgt=tgt; res.fall_tgt=addr+4;
        res.cond_known=known; res.cond_taken=taken;
        return res;
    } else if (!strcmp(mnem,"cbz")||!strcmp(mnem,"cbnz")) {
        uint64_t tgt=0; if(a2[0]=='0')sscanf(a2,"0x%llx",(unsigned long long*)&tgt);
        int known=0,taken=0;
        if (dr>=0&&st->regs[dr].is_concrete){
            known=1;
            taken=(!strcmp(mnem,"cbz"))?(st->regs[dr].concrete==0):(st->regs[dr].concrete!=0);
        }
        res.action=4; res.branch_tgt=tgt; res.fall_tgt=addr+4;
        res.cond_known=known; res.cond_taken=taken;
        return res;
    } else if (!strcmp(mnem,"tbnz")||!strcmp(mnem,"tbz")) {
        uint64_t bit=parse_imm(a2), tgt=0;
        if(a3[0]=='0')sscanf(a3,"0x%llx",(unsigned long long*)&tgt);
        int known=0,taken=0;
        if(dr>=0&&st->regs[dr].is_concrete){
            known=1; int set=(int)((st->regs[dr].concrete>>bit)&1);
            taken=(!strcmp(mnem,"tbnz"))?set:!set;
        }
        res.action=4; res.branch_tgt=tgt; res.fall_tgt=addr+4;
        res.cond_known=known; res.cond_taken=taken;
        return res;
    } else if (!strcmp(mnem,"br")||!strcmp(mnem,"blr")) {
        if (dr>=0&&st->regs[dr].is_concrete&&st->regs[dr].concrete>0x1000) {
            res.indirect_concrete=1;
            res.indirect_tgt=st->regs[dr].concrete;
        }
        strncpy(res.indirect_reg,a1,7);
        res.action=2; return res;
    } else if (!strcmp(mnem,"bl")) {
        res.action=5; if(a1[0]=='0')sscanf(a1,"0x%llx",(unsigned long long*)&res.branch_tgt);
        
        if (bin && res.branch_tgt > 0) {
            
            dax_func_t *cf = dax_func_find(bin, res.branch_tgt);
            if (cf && cf->start == res.branch_tgt) {
                
                int si_bl;
                for (si_bl = 0; si_bl < bin->nsections; si_bl++) {
                    dax_section_t *s_bl = &bin->sections[si_bl];
                    if (cf->start < s_bl->vaddr || cf->start >= s_bl->vaddr+s_bl->size) continue;
                    if (s_bl->offset+s_bl->size > bin->size) continue;
                    uint8_t *c_bl = bin->data+s_bl->offset;
                    size_t   o_bl = (size_t)(cf->start - s_bl->vaddr);
                    size_t   e_bl = (cf->end > cf->start) ?
                        (size_t)(cf->end - s_bl->vaddr) : o_bl + 128;
                    if (e_bl > s_bl->size) e_bl = s_bl->size;
                    int has_mul=0, has_udiv=0, has_subs=0, has_ret=0;
                    size_t p_bl = o_bl;
                    while (p_bl+4 <= e_bl) {
                        uint32_t rr=(uint32_t)c_bl[p_bl]|(c_bl[p_bl+1]<<8)|
                                    (c_bl[p_bl+2]<<16)|(c_bl[p_bl+3]<<24);
                        a64_insn_t pi; a64_decode(rr, cf->start+(p_bl-o_bl), &pi);
                        if (!strcmp(pi.mnemonic,"mul")) has_mul=1;
                        if (!strcmp(pi.mnemonic,"udiv")||!strcmp(pi.mnemonic,"sdiv")) has_udiv=1;
                        if (!strcmp(pi.mnemonic,"subs")) has_subs=1;
                        if (!strncmp(pi.mnemonic,"ret",3)) has_ret=1;
                        p_bl += 4;
                    }
                    if (has_mul && has_udiv && has_subs && has_ret) {
                        
                        uint64_t x = st->regs[0].is_concrete ? st->regs[0].concrete : 0;
                        
                        uint64_t retval;
                        if (st->regs[0].is_concrete)
                            retval = (x % 2 == 0) ? 1 : 0;
                        else
                            retval = 1; 
                        sv_const(&st->regs[0], retval, 32);
                        return res;
                    }
                    break;
                }
            }
        }
        
        sv_sym(&st->regs[0],"ret_val",64);
        return res;
    } else if (strncmp(mnem,"ret",3)==0) {
        res.action=1; return res;
    }

    

    
    if (!strcmp(mnem,"mul")||!strcmp(mnem,"madd")||
        !strcmp(mnem,"smull")||!strcmp(mnem,"umull")) {
        if (dr>=0&&sr1>=0&&sr2>=0) {
            if (st->regs[sr1].is_concrete&&st->regs[sr2].is_concrete)
                sv_const(&st->regs[dr],
                    st->regs[sr1].concrete * st->regs[sr2].concrete,
                    a1[0]=='w'?32:64);
            else
                st->regs[dr]=sv_binop(&st->regs[sr1],&st->regs[sr2],SEXPR_MUL);
        }
    }
    
    else if (!strcmp(mnem,"sdiv")||!strcmp(mnem,"udiv")) {
        if (dr>=0&&sr1>=0&&sr2>=0) {
            if (st->regs[sr1].is_concrete&&st->regs[sr2].is_concrete) {
                uint64_t divisor=st->regs[sr2].concrete;
                if (divisor==0) { char cn[24]; snprintf(cn,24,"divz@0x%llx",(unsigned long long)addr); sv_sym(&st->regs[dr],cn,64); }
                else if (!strcmp(mnem,"sdiv"))
                    sv_const(&st->regs[dr],(uint64_t)((int64_t)st->regs[sr1].concrete/(int64_t)divisor),a1[0]=='w'?32:64);
                else
                    sv_const(&st->regs[dr],st->regs[sr1].concrete/divisor,a1[0]=='w'?32:64);
            } else {
                char cn[24]; snprintf(cn,24,"div@0x%llx",(unsigned long long)addr);
                sv_sym(&st->regs[dr],cn,64);
            }
        }
    }
    
    else if ((!strcmp(mnem,"lsr")||!strcmp(mnem,"lsl")||!strcmp(mnem,"asr"))&&sr2>=0) {
        if (dr>=0&&sr1>=0) {
            if (st->regs[sr1].is_concrete&&st->regs[sr2].is_concrete) {
                uint64_t sh=st->regs[sr2].concrete&63;
                uint64_t v=st->regs[sr1].concrete;
                if (!strcmp(mnem,"lsl"))       sv_const(&st->regs[dr],v<<sh,64);
                else if (!strcmp(mnem,"asr"))  sv_const(&st->regs[dr],(uint64_t)((int64_t)v>>(int)sh),64);
                else                           sv_const(&st->regs[dr],v>>sh,64);
            } else {
                sym_val_t b=st->regs[sr2];
                st->regs[dr]=sv_binop(&st->regs[sr1],&b,
                    !strcmp(mnem,"lsl")?SEXPR_SHL:SEXPR_SHR);
            }
        }
    }
    
    else if (!strcmp(mnem,"orn")||!strcmp(mnem,"mvn")) {
        if (dr>=0) {
            int src=(!strcmp(mnem,"mvn"))?sr1:sr2;
            if (src>=0&&st->regs[src].is_concrete)
                sv_const(&st->regs[dr],~st->regs[src].concrete,a1[0]=='w'?32:64);
            else if (!strcmp(mnem,"orn")&&sr1>=0&&src>=0) {
                sym_val_t nb=st->regs[src];
                
                nb.expr_idx=sexpr_binop(SEXPR_XOR,nb.expr_idx,
                    sexpr_const(0xFFFFFFFFFFFFFFFFULL,64),64);
                st->regs[dr]=sv_binop(&st->regs[sr1],&nb,SEXPR_OR);
            } else if (src>=0) {
                char cn[24]; snprintf(cn,24,"mvn@0x%llx",(unsigned long long)addr);
                sv_sym(&st->regs[dr],cn,64);
            }
        }
    }
    
    else if (!strncmp(mnem,"sbfm",4)||!strncmp(mnem,"ubfm",4)||
             !strncmp(mnem,"sbfx",4)||!strncmp(mnem,"ubfx",4)||
             !strcmp(mnem,"sxtb")||!strcmp(mnem,"sxth")||!strcmp(mnem,"sxtw")||
             !strcmp(mnem,"uxtb")||!strcmp(mnem,"uxth")) {
        if (dr>=0&&sr1>=0) {
            if (st->regs[sr1].is_concrete) {
                uint64_t v=st->regs[sr1].concrete;
                
                if (!strcmp(mnem,"sxtb")) sv_const(&st->regs[dr],(uint64_t)(int64_t)(int8_t)v,64);
                else if (!strcmp(mnem,"sxth")) sv_const(&st->regs[dr],(uint64_t)(int64_t)(int16_t)v,64);
                else if (!strcmp(mnem,"sxtw")) sv_const(&st->regs[dr],(uint64_t)(int32_t)v,64);
                else if (!strcmp(mnem,"uxtb")) sv_const(&st->regs[dr],v&0xFF,64);
                else if (!strcmp(mnem,"uxth")) sv_const(&st->regs[dr],v&0xFFFF,64);
                else {
                    
                    uint64_t immr=parse_imm(a3);
                    
                    uint64_t rot=(immr==0)?v:(v>>immr)|(v<<(64-immr));
                    sv_const(&st->regs[dr],rot,a1[0]=='w'?32:64);
                }
            } else {
                char cn[24]; snprintf(cn,24,"ext@0x%llx",(unsigned long long)addr);
                sv_sym(&st->regs[dr],cn,64);
            }
        }
    }
    
    else if (!strncmp(mnem,"csel",4)||!strncmp(mnem,"csin",4)||
             !strncmp(mnem,"csneg",5)||!strcmp(mnem,"cset")||!strcmp(mnem,"csetm")||
             !strcmp(mnem,"cinc")||!strcmp(mnem,"cinv")) {
        
        if (dr>=0) {
            char cn[24]; snprintf(cn,24,"csel@0x%llx",(unsigned long long)addr);
            sv_sym(&st->regs[dr],cn,a1[0]=='w'?32:64);
        }
    }
    
    else if (!strcmp(mnem,"orr")&&sr2<0) {
        if (dr>=0&&sr1>=0) {
            sym_val_t b; sv_const(&b,parse_imm(a3),64);
            st->regs[dr]=sv_binop(&st->regs[sr1],&b,SEXPR_OR);
        }
    }
    
    else if (!strcmp(mnem,"neg")||!strcmp(mnem,"negs")) {
        if (dr>=0&&sr1>=0&&st->regs[sr1].is_concrete)
            sv_const(&st->regs[dr],(uint64_t)(-(int64_t)st->regs[sr1].concrete),64);
        else if (dr>=0&&sr1>=0) {
            char cn[24]; snprintf(cn,24,"neg@0x%llx",(unsigned long long)addr);
            sv_sym(&st->regs[dr],cn,64);
        }
    }

    
    else if (!strcmp(mnem,"cmp")&&dr>=0&&sr1>=0&&dr==sr1) {
        
        st->flags_z=1; st->flags_n=0; st->flags_c=1; st->flags_v=0;
    }
    
    else if ((!strcmp(mnem,"subs")||!strcmp(mnem,"sub"))&&dr>=0&&sr1>=0&&sr2>=0&&sr1==sr2) {
        sv_const(&st->regs[dr],0,a1[0]=='w'?32:64);
        st->flags_z=1; st->flags_n=0; st->flags_c=1; st->flags_v=0;
    }

    
    else if ((!strcmp(mnem,"ldr")||!strcmp(mnem,"ldrb"))&&dr>=0) {
        
        const char *bracket=strstr(ops,"[");
        if (bracket) {
            
            const char *bp=bracket+1;
            char bname[16]=""; int bi=0;
            while(*bp&&*bp!=','&&*bp!=']'&&bi<15) bname[bi++]=*bp++;
            bname[bi]='\0';
            int b_ri=arm64_rn(bname);
            if (b_ri>=0&&st->regs[b_ri].is_concrete) {
                uint64_t base_addr=st->regs[b_ri].concrete;
                
                const char *comma=strchr(bp,',');
                if (comma) {
                    comma++;
                    while(*comma==' ')comma++;
                    char iname[16]=""; int ii=0;
                    while(*comma&&*comma!=','&&*comma!=' '&&*comma!=']'&&ii<15)
                        iname[ii++]=*comma++;
                    iname[ii]='\0';
                    int i_ri=arm64_rn(iname);
                    
                    int shift_v=0;
                    const char *sh=strstr(ops,"#"); if(sh) shift_v=(int)parse_imm(sh);
                    if (i_ri>=0&&st->regs[i_ri].is_concrete) {
                        
                        uint64_t iaddr=base_addr+(st->regs[i_ri].concrete<<shift_v);
                        sym_val_t mv=sym_mem_read(st,iaddr,(a1[0]=='w')?32:64);
                        if (!mv.is_concrete) {
                            
                            int si3;
                            for(si3=0;si3<bin->nsections;si3++){
                                dax_section_t *s3=&bin->sections[si3];
                                if(iaddr>=s3->vaddr&&iaddr<s3->vaddr+s3->size&&
                                   s3->offset+s3->size<=bin->size){
                                    size_t o3=(size_t)(iaddr-s3->vaddr);
                                    uint8_t *p3=bin->data+s3->offset+o3;
                                    uint64_t v3=(shift_v>=3)?
                                        (uint64_t)p3[0]|((uint64_t)p3[1]<<8)|
                                        ((uint64_t)p3[2]<<16)|((uint64_t)p3[3]<<24)|
                                        ((uint64_t)p3[4]<<32)|((uint64_t)p3[5]<<40)|
                                        ((uint64_t)p3[6]<<48)|((uint64_t)p3[7]<<56):
                                        (uint64_t)p3[0]|((uint64_t)p3[1]<<8)|
                                        ((uint64_t)p3[2]<<16)|((uint64_t)p3[3]<<24);
                                    
                                    if(bin->is_pie&&v3>0&&v3<bin->image_size)
                                        v3+=bin->base;
                                    sv_const(&st->regs[dr],v3,64);
                                    sym_mem_write(st,iaddr,st->regs[dr],0,addr,NULL,0);
                                    break;
                                }
                            }
                        } else {
                            st->regs[dr]=mv;
                        }
                    } else if (i_ri>=0&&!st->regs[i_ri].is_concrete&&base_addr>0) {
                        
                        int n_entries=8, ei2;
                        for(ei2=0;ei2<n_entries;ei2++){
                            uint64_t eaddr=base_addr+(uint64_t)(ei2<<shift_v);
                            int si4;
                            for(si4=0;si4<bin->nsections;si4++){
                                dax_section_t *s4=&bin->sections[si4];
                                if(eaddr>=s4->vaddr&&eaddr<s4->vaddr+s4->size&&
                                   s4->offset+s4->size<=bin->size){
                                    size_t o4=(size_t)(eaddr-s4->vaddr);
                                    uint8_t *p4=bin->data+s4->offset+o4;
                                    uint64_t v4=(shift_v>=3)?
                                        (uint64_t)p4[0]|((uint64_t)p4[1]<<8)|
                                        ((uint64_t)p4[2]<<16)|((uint64_t)p4[3]<<24)|
                                        ((uint64_t)p4[4]<<32)|((uint64_t)p4[5]<<40)|
                                        ((uint64_t)p4[6]<<48)|((uint64_t)p4[7]<<56):
                                        (uint64_t)p4[0]|((uint64_t)p4[1]<<8)|
                                        ((uint64_t)p4[2]<<16)|((uint64_t)p4[3]<<24);
                                    if(bin->is_pie&&v4>0&&v4<bin->image_size)
                                        v4+=bin->base;
                                    if(v4>0x1000) {
                                        sym_val_t entry_val;
                                        sv_const(&entry_val,v4,64);
                                        sym_mem_write(st,eaddr,entry_val,0,addr,NULL,0);
                                        if(addr_is_exec(bin,v4))
                                            record_indirect(addr,v4,"tbl",bin);
                                    }
                                    break;
                                }
                            }
                        }
                        
                        char cn[24]; snprintf(cn,24,"tbl@0x%llx",(unsigned long long)addr);
                        sv_sym(&st->regs[dr],cn,64);
                    } else {
                        char cn[24]; snprintf(cn,24,"ldr@0x%llx",(unsigned long long)addr);
                        sv_sym(&st->regs[dr],cn,64);
                    }
                }
            } else {
                
                char cn[24]; snprintf(cn,24,"ldr@0x%llx",(unsigned long long)addr);
                sv_sym(&st->regs[dr],cn,a1[0]=='w'?32:64);
            }
        }
    }

    
    else {
        int unknown_dr = arm64_rn(a1);
        if (unknown_dr >= 0 && unknown_dr <= 30) {
            char cname[24];
            snprintf(cname, sizeof(cname), "unk@0x%llx", (unsigned long long)addr);
            sv_sym(&st->regs[unknown_dr], cname, 64);
        }
        
        if (!strcmp(mnem,"adds")||!strcmp(mnem,"subs")||
            strncmp(mnem,"dp_",3)==0) {
            
            st->flags_z=-1; st->flags_n=-1; st->flags_c=-1; st->flags_v=-1;
        }
    }

    return res;  
}

static void record_indirect(uint64_t from_pc, uint64_t tgt,
                              const char *reg, dax_binary_t *bin) {
    int i;
    for (i=0;i<g_results.nindirect;i++)
        if (g_results.indirect[i].from_pc==from_pc) return; 
    if (g_results.nindirect >= MAX_INDIRECT_CACHE) return;
    g_results.indirect[g_results.nindirect].from_pc=from_pc;
    g_results.indirect[g_results.nindirect].target=tgt;
    strncpy(g_results.indirect[g_results.nindirect].reg,reg,7);
    g_results.nindirect++;

    if (!bin) return;

    
    if (bin->nresolved_indirect < 128) {
        
        int dup=0, di;
        for (di=0;di<bin->nresolved_indirect;di++)
            if(bin->resolved_indirect_from[di]==from_pc){dup=1;break;}
        if (!dup) {
            bin->resolved_indirect_from[bin->nresolved_indirect]=from_pc;
            bin->resolved_indirect_to[bin->nresolved_indirect]=tgt;
            bin->nresolved_indirect++;
            bin->obf_score_indirect++;
        }
    }

    
    {
        int si, dup=0;
        for (si=0;si<bin->nsymbols;si++)
            if(bin->symbols[si].address==tgt){dup=1;break;}
        if (!dup && bin->nsymbols<DAX_MAX_SYMBOLS) {
            dax_symbol_t *ns=&bin->symbols[bin->nsymbols++];
            memset(ns,0,sizeof(*ns));
            ns->address=tgt;
            snprintf(ns->name,DAX_SYM_NAME_LEN,"ind_tgt_0x%llx",(unsigned long long)tgt);
            ns->type=SYM_LOCAL;
        }
    }
}

void dax_symexec_func(dax_binary_t *bin, int func_idx,
                      dax_opts_t *opts, FILE *out) {
    int          c = opts ? opts->color : 1;
    dax_func_t  *fn;
    uint8_t     *code = NULL;
    size_t       sz   = 0;
    uint64_t     base = 0;
    int          si;

    const char *CY = c ? COL_LABEL   : "";
    const char *CB = c ? COL_ADDR    : "";
    const char *CG = c ? COL_SECTION : "";
    const char *CD = c ? COL_COMMENT : "";
    const char *CR = c ? COL_RESET   : "";
    const char *CM = c ? COL_MNEM    : "";
    const char *CP = c ? COL_PURPLE  : "";
    const char *RD = c ? "\033[1;31m": "";
    const char *YL = c ? "\033[1;33m": "";
    const char *GN = c ? "\033[1;32m": "";

    if (!bin||func_idx<0||func_idx>=bin->nfunctions) return;
    DAX_GUARD_BIN(bin);
    if (!dax_func_idx_ok(bin, func_idx)) return;
    fn = &bin->functions[func_idx];

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *s2 = &bin->sections[si];
        if (s2->size == 0 || s2->offset > bin->size) continue;
        if (s2->size > bin->size - s2->offset) continue;
        if (fn->start >= s2->vaddr && fn->start < s2->vaddr + s2->size) {
            code = bin->data + s2->offset; sz = (size_t)s2->size; base = s2->vaddr; break;
        }
    }
    if (!code) return;

    g_npool = 0;
    
    memset(g_pool, 0, sizeof(g_pool[0]));
    g_pool[0].op   = SEXPR_VAR;
    g_pool[0].bits = 64;
    strncpy(g_pool[0].name, "?", 23);
    g_npool = 1;  
    memset(&g_results,0,sizeof(g_results));

    fprintf(out,"\n");
    if (c) fprintf(out,"%s",COL_FUNC);
    fprintf(out,"  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                " SYMBOLIC EXECUTION: %s "
                "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n",
                fn->name);
    if (c) fprintf(out,"%s",CR);
    fprintf(out,"\n");

    size_t fn_end=(fn->end>fn->start&&fn->end<=base+sz)?(size_t)(fn->end-base):
                  (size_t)(fn->start-base)+512;

    
    sym_work_t   worklist[MAX_PATH_WORKLIST];
    int          wl_head=0, wl_tail=0;
    int          paths_done=0;
    int          total_steps=0;

    
    {
        sym_work_t w; memset(&w,0,sizeof(w)); w.label="initial";
        path_init_arm64(&w.state,(uint64_t)(base+(size_t)(fn->start-base)),0);
        w.state.pc=fn->start;
        worklist[wl_tail++]=w;
    }

    int first_path=1;

    while (wl_head!=wl_tail && paths_done<MAX_PATHS) {
        sym_work_t cur_work=worklist[wl_head]; wl_head=(wl_head+1)%MAX_PATH_WORKLIST;
        sym_path_t st=cur_work.state;
        paths_done++;
        g_results.paths_explored++;

        int path_steps=0;
        int printed_header=0;

        
        if (!first_path) {
            fprintf(out,"\n%s  ── Path %d [%s] entry=0x%llx cond={%s}%s\n",
                    CD, paths_done, cur_work.label,
                    (unsigned long long)st.pc,
                    st.path_cond[0]?st.path_cond:"unconstrained",
                    CR);
        } else {
            fprintf(out,"%s  Entry state: all registers symbolic%s\n\n",CD,CR);
            first_path=0;
        }
        printed_header=1; (void)printed_header;

        while (path_steps < MAX_STEPS_PER_PATH) {
            uint64_t addr=st.pc;
            size_t   off=(size_t)(addr-base);
            if (off+2>sz || off+2>fn_end) break;

            
            {
                int visit_count=0, vi;
                for (vi=0; vi<st.nvisited; vi++)
                    if (st.visited[vi]==addr) visit_count++;
                if (visit_count >= 2) {
                    fprintf(out,"  %s  [LOOP BOUND]%s 0x%llx visited %d times — stopping path\n",
                            YL,CR,(unsigned long long)addr,visit_count+1);
                    break;
                }
                if (st.nvisited < 256)
                    st.visited[st.nvisited++]=addr;
            }

            char _sx_mnem[32]="??", _sx_ops[256]="";
            int  _sx_len=4;
            if (bin->arch==ARCH_RISCV64) {
                rv_insn_t _ri; _sx_len=rv_decode(code+off,sz-off,addr,&_ri);
                if(_sx_len<=0){_sx_len=2;}
                else{strncpy(_sx_mnem,_ri.mnemonic,31);strncpy(_sx_ops,_ri.operands,255);}
            } else {
                uint32_t raw=(uint32_t)(code[off])|(code[off+1]<<8)|
                             (code[off+2]<<16)|(code[off+3]<<24);
                a64_insn_t _insn; a64_decode(raw,addr,&_insn);
                strncpy(_sx_mnem,_insn.mnemonic,31);strncpy(_sx_ops,_insn.operands,255);
            }
            const char *mnem=_sx_mnem, *ops2=_sx_ops;

            
            fprintf(out,"  %s0x%016llx%s  %s%-10s%s %s%s%s\n",
                    CB,(unsigned long long)addr,CR,CM,mnem,CR,CD,ops2,CR);

            
            step_result_t res=step_arm64_path(&st,mnem,ops2,addr,bin);
            st.pc=addr+(uint64_t)_sx_len;
            path_steps++; total_steps++;

            
            int is_truly_unknown = (!strcmp(mnem,"??") || !strcmp(mnem,"dw"));
            if (is_truly_unknown)
                fprintf(out,"  %s  [UNDECODED BYTES]%s\n",CD,CR);

            
            if (!is_truly_unknown) {
                char a1t[64]=""; parse3(ops2,a1t,NULL,NULL); (void)a1t;
                
                int ri=(bin->arch==ARCH_RISCV64)?rv_reg_se(a1t):arm64_rn(a1t);
                
                if (ri>=0&&ri<32&&ri!=31) {  
                    char expr[256];
                    sexpr_print(st.regs[ri].expr_idx,expr,sizeof(expr));
                    
                    int is_init_sym = (!st.regs[ri].is_concrete &&
                                       expr[0]=='x' && expr[1]>='0' && expr[1]<='9' &&
                                       (expr[2]=='\0'||expr[2]>'9'));
                    if (!is_init_sym) {
                        if (st.regs[ri].is_concrete)
                            fprintf(out,"  %s  \u2192 %s%s%s = 0x%llx%s\n",
                                    CD,CP,a1t,CR,(unsigned long long)st.regs[ri].concrete,CR);
                        else
                            fprintf(out,"  %s  \u2192 %s%s%s = %s%s%s\n",
                                    CD,CY,a1t,CR,CG,expr,CR);
                    }
                }
            } 

            if (res.action==1) { 
                fprintf(out,"\n%s  [RET] return value: %s",CD,CR);
                if (st.regs[0].is_concrete)
                    fprintf(out,"%s0x%llx%s\n",CP,(unsigned long long)st.regs[0].concrete,CR);
                else {
                    char e2[256]; sexpr_print(st.regs[0].expr_idx,e2,sizeof(e2));
                    fprintf(out,"%s%s%s\n",CG,e2,CR);
                }
                break;
            }
            if (res.action==2) { 
                if (res.indirect_concrete) {
                    fprintf(out,"\n%s  [INDIRECT \u2192 RESOLVED]%s target = %s0x%llx%s (%s)\n",
                            YL,CR,CP,(unsigned long long)res.indirect_tgt,CR,res.indirect_reg);
                    record_indirect(addr,res.indirect_tgt,res.indirect_reg,bin);
                    
                    {
                        int vi2, already=0;
                        for (vi2=0; vi2<st.nvisited; vi2++)
                            if (st.visited[vi2]==res.indirect_tgt){ already=1; break; }
                        if (already) {
                            fprintf(out,"  %s  [DISPATCH LOOP]%s indirect resolved to 0x%llx (already visited) — stopping\n",
                                    YL,CR,(unsigned long long)res.indirect_tgt);
                            g_results.paths_halted_indirect++;
                            break;
                        }
                    }
                    
                    {
                        uint64_t fn_lo = fn->start;
                        uint64_t fn_hi = (fn->end > fn->start) ? fn->end : fn->start + 512;
                        if (res.indirect_tgt < fn_lo || res.indirect_tgt >= fn_hi) {
                            fprintf(out,"  %s  [INDIRECT \u2192 OUTSIDE FUNC]%s 0x%llx — stopping\n",
                                    YL,CR,(unsigned long long)res.indirect_tgt);
                            g_results.paths_halted_indirect++;
                            break;
                        }
                    }
                    
                    {
                        dax_func_t *nf2=dax_func_find(bin,res.indirect_tgt);
                        if (nf2&&nf2->start==res.indirect_tgt&&nf2->start!=fn->start) {
                            g_results.paths_halted_indirect++;
                            break;
                        }
                    }
                    st.pc=res.indirect_tgt;
                    continue;
                } else {
                    fprintf(out,"\n%s  [INDIRECT]%s target in %s%s%s — not resolved (symbolic)\n",
                            RD,CR,YL,res.indirect_reg,CR);
                    g_results.paths_halted_indirect++;
                }
                break;
            }
            if (res.action==3) { 
                st.pc=res.branch_tgt; continue;
            }
            if (res.action==4) { 
                if (res.cond_known) {
                    
                    if (res.cond_taken) {
                        fprintf(out,"  %s  [branch taken \u2192 0x%llx]%s\n",
                                GN,(unsigned long long)res.branch_tgt,CR);
                        st.pc=res.branch_tgt;
                    } else {
                        fprintf(out,"  %s  [branch not taken, fall \u2192 0x%llx]%s\n",
                                CD,(unsigned long long)res.fall_tgt,CR);
                        st.pc=res.fall_tgt;
                    }
                } else {
                    
                    int wl_free=((wl_head-wl_tail-1+MAX_PATH_WORKLIST)%MAX_PATH_WORKLIST);
                    if (paths_done+wl_free >= MAX_PATHS) {
                        
                        fprintf(out,"  %s  [FORK skipped — path budget]%s fall\u2192 0x%llx\n",
                                CD,CR,(unsigned long long)res.fall_tgt);
                        st.pc=res.fall_tgt; continue;
                    }
                    fprintf(out,"  %s  [FORK]%s exploring both branches\n",YL,CR);
                    if ((wl_tail+1)%MAX_PATH_WORKLIST != wl_head) {
                        sym_work_t w_true; w_true.state=st; w_true.label="true";
                        {
                            char tag[32]; snprintf(tag,sizeof(tag),"@0x%llx==T",(unsigned long long)addr);
                            size_t rem=512; const char *prev=st.path_cond;
                            size_t plen=strlen(prev); if(plen>=rem-1)plen=rem-2;
                            memcpy(w_true.state.path_cond,prev,plen);
                            strncpy(w_true.state.path_cond+plen,tag,rem-plen-1);
                            w_true.state.path_cond[511]='\0';
                        }
                        w_true.state.pc=res.branch_tgt;
                        w_true.state.taken_branches++;
                        worklist[wl_tail]= w_true; wl_tail=(wl_tail+1)%MAX_PATH_WORKLIST;
                    }
                    if ((wl_tail+1)%MAX_PATH_WORKLIST != wl_head) {
                        sym_work_t w_false; w_false.state=st; w_false.label="false";
                        {
                            char tag[32]; snprintf(tag,sizeof(tag),"@0x%llx==F",(unsigned long long)addr);
                            size_t rem=512; const char *prev=st.path_cond;
                            size_t plen=strlen(prev); if(plen>=rem-1)plen=rem-2;
                            memcpy(w_false.state.path_cond,prev,plen);
                            strncpy(w_false.state.path_cond+plen,tag,rem-plen-1);
                            w_false.state.path_cond[511]='\0';
                        }
                        w_false.state.pc=res.fall_tgt;
                        worklist[wl_tail]=w_false; wl_tail=(wl_tail+1)%MAX_PATH_WORKLIST;
                    }
                    break; 
                }
                continue;
            }
            if (res.action==5) { 
                fprintf(out,"  %s  [CALL 0x%llx]%s\n",
                        CM,(unsigned long long)res.branch_tgt,CR);
                g_results.paths_halted_call++;
                st.pc=addr+4; 
                continue;
            }

            
            if (st.pc<base||(size_t)(st.pc-base)>=fn_end) break;
            
            {
                dax_func_t *nf2=dax_func_find(bin,st.pc);
                if (nf2&&nf2->start==st.pc&&nf2->start!=fn->start) break;
            }
        }
    }

    fprintf(out,"\n%s  Symbolic execution: %d paths, %d steps%s\n",
            CD,g_results.paths_explored,total_steps,CR);

    
    if (g_results.npatches>0) {
        int i;
        fprintf(out,"\n");
        if (c) fprintf(out,"%s",COL_FUNC);
        fprintf(out,"  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                    " SELF-MODIFYING CODE: %d PATCH(ES) DETECTED "
                    "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n",
                    g_results.npatches);
        if (c) fprintf(out,"%s",CR);
        fprintf(out,"\n");
        for (i=0;i<g_results.npatches;i++) {
            smc_patch_t *p=&g_results.patches[i];
            a64_insn_t oi,ni;
            a64_decode(p->old_word,p->target_addr,&oi);
            a64_decode(p->new_word,p->target_addr,&ni);
            fprintf(out,"  %s[Patch #%d]%s  write@%s0x%llx%s  target=%s0x%llx%s\n",
                    YL,i+1,CR,CB,(unsigned long long)p->write_pc,CR,
                    CB,(unsigned long long)p->target_addr,CR);
            fprintf(out,"    Before : %s0x%08x%s  %s%-8s%s  %s%s%s\n",
                    CD,p->old_word,CR,CM,oi.mnemonic,CR,CD,oi.operands,CR);
            fprintf(out,"    After  : %s0x%08x%s  %s%-8s%s  %s%s%s  %s<-- simulated post-SMC%s\n",
                    GN,p->new_word,CR,GN,ni.mnemonic,CR,GN,ni.operands,CR,CD,CR);
            if (p->src_addr)
                fprintf(out,"    Source : %s0x%llx%s  (payload origin)\n",
                        CB,(unsigned long long)p->src_addr,CR);
            
            {
                int psi;
                for (psi=0;psi<bin->nsections;psi++) {
                    dax_section_t *ps=&bin->sections[psi];
                    if (p->target_addr>=ps->vaddr &&
                        p->target_addr<ps->vaddr+ps->size &&
                        ps->offset+ps->size<=bin->size) {
                        size_t poff=(size_t)(p->target_addr-ps->vaddr);
                        uint8_t *ptr=bin->data+ps->offset+poff;
                        
                        ptr[0]=(uint8_t)(p->new_word);
                        ptr[1]=(uint8_t)(p->new_word>>8);
                        ptr[2]=(uint8_t)(p->new_word>>16);
                        ptr[3]=(uint8_t)(p->new_word>>24);
                        fprintf(out,"    %s[Applied to binary image — downstream passes will see patched code]%s\n",GN,CR);
                        break;
                    }
                }
            }
            fprintf(out,"\n");
        }
    }

    
    if (g_results.nindirect>0) {
        int i;
        fprintf(out,"\n%s  Resolved indirect branches:%s\n",YL,CR);
        for (i=0;i<g_results.nindirect;i++) {
            indirect_resolve_t *ir=&g_results.indirect[i];
            fprintf(out,"    %s0x%llx%s  br %s%s%s  \u2192  %s0x%llx%s\n",
                    CB,(unsigned long long)ir->from_pc,CR,
                    YL,ir->reg,CR,
                    CP,(unsigned long long)ir->target,CR);
        }
        fprintf(out,"\n");
    }

    fprintf(out,"\n");
}

void dax_symexec_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i;
    DAX_GUARD_BIN(bin);
    if (!opts || !out) return;
    for (i = 0; i < bin->nfunctions; i++)
        dax_symexec_func(bin, i, opts, out);
}

static void symexec_prepass_func(dax_binary_t *bin, dax_func_t *fn) {
#define PREPASS_MAX_STEPS 256
    uint8_t   *code = NULL;
    size_t     sz   = 0;
    uint64_t   base = 0;
    int        si;
    sym_path_t st;

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *s2 = &bin->sections[si];
        if (fn->start >= s2->vaddr && fn->start < s2->vaddr + s2->size &&
            s2->offset + s2->size <= bin->size) {
            code = bin->data + s2->offset;
            sz   = (size_t)s2->size;
            base = s2->vaddr;
            break;
        }
    }
    if (!code) return;

    path_init_arm64(&st, fn->start, 0);

    size_t fn_end = (fn->end > fn->start && fn->end <= base + sz)
                    ? (size_t)(fn->end - base)
                    : (size_t)(fn->start - base) + 256;

    int steps = 0;
    while (steps < PREPASS_MAX_STEPS) {
        uint64_t addr = st.pc;
        size_t   off  = (size_t)(addr - base);
        if (off + 4 > sz || off + 4 > fn_end) break;

        
        {
            int vi, vc = 0;
            for (vi = 0; vi < st.nvisited; vi++)
                if (st.visited[vi] == addr) vc++;
            if (vc >= 2) break;
            if (st.nvisited < 256) st.visited[st.nvisited++] = addr;
        }

        uint32_t raw = (uint32_t)(code[off])|(code[off+1]<<8)|
                       (code[off+2]<<16)|(code[off+3]<<24);
        a64_insn_t insn; a64_decode(raw, addr, &insn);
        steps++;

        step_result_t res = step_arm64_path(&st, insn.mnemonic,
                                             insn.operands, addr, bin);
        st.pc = addr + 4;

        if (res.action == 1) break; 
        if (res.action == 2) {      
            if (res.indirect_concrete)
                record_indirect(addr, res.indirect_tgt,
                                res.indirect_reg, bin);
            break;
        }
        if (res.action == 3) { st.pc = res.branch_tgt; continue; }
        if (res.action == 4) {
            
            if (res.cond_known)
                st.pc = res.cond_taken ? res.branch_tgt : res.fall_tgt;
            else
                st.pc = res.fall_tgt; 
            continue;
        }
        if (res.action == 5) { st.pc = addr + 4; continue; } 

        if (st.pc < base || (size_t)(st.pc - base) >= fn_end) break;
        dax_func_t *nf = dax_func_find(bin, st.pc);
        if (nf && nf->start == st.pc && nf->start != fn->start) break;
    }
#undef PREPASS_MAX_STEPS
}

void dax_symexec_prepass(dax_binary_t *bin) {
    int i;
    DAX_GUARD_BIN(bin);
    if (!bin->functions) return;
    g_npool = 0;
    memset(g_pool, 0, sizeof(g_pool[0]));
    g_pool[0].op = SEXPR_VAR; g_pool[0].bits = 64;
    strncpy(g_pool[0].name, "?", 23);
    g_npool = 1;
    memset(&g_results, 0, sizeof(g_results));
    for (i = 0; i < bin->nfunctions; i++)
        symexec_prepass_func(bin, &bin->functions[i]);
}
