#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"

#define EMU_MAX_STEPS   8192
#define EMU_MEM_PAGES   64
#define EMU_PAGE_SIZE   4096
#define EMU_STACK_BASE  0x7fff0000ULL
#define EMU_STACK_SIZE  0x10000

extern dax_igrp_t dax_classify_x86(const char *m);
extern dax_igrp_t dax_classify_arm64(const char *m);

typedef struct {
    uint64_t base;
    uint8_t  data[EMU_PAGE_SIZE];
    int      used;
} emu_page_t;

typedef struct {
    uint64_t  regs[32];
    uint64_t  pc;
    uint64_t  sp;
    uint8_t   flags_z;
    uint8_t   flags_n;
    uint8_t   flags_c;
    uint8_t   flags_v;
    emu_page_t pages[EMU_MEM_PAGES];
    int        npages;
    int        steps;
    int        halted;
    char       halt_reason[64];
    uint8_t   *code_base;
    size_t     code_size;
    uint64_t   code_vaddr;
    dax_binary_t *bin;
} emu_state_t;

typedef struct {
    uint64_t  addr;
    char      mnem[32];
    char      ops[128];
    uint64_t  regs_after[32];
    uint64_t  pc_after;
} emu_trace_entry_t;

#define EMU_MAX_TRACE 512
static emu_trace_entry_t g_trace[EMU_MAX_TRACE];
static int               g_ntrace = 0;

static void emu_write8(emu_state_t *e, uint64_t addr, uint8_t val) {
    int i;
    uint64_t pg = addr & ~(uint64_t)(EMU_PAGE_SIZE - 1);
    for (i = 0; i < e->npages; i++) {
        if (e->pages[i].base == pg) {
            e->pages[i].data[addr & (EMU_PAGE_SIZE-1)] = val;
            return;
        }
    }
    if (e->npages < EMU_MEM_PAGES) {
        i = e->npages++;
        memset(&e->pages[i], 0, sizeof(emu_page_t));
        e->pages[i].base = pg;
        e->pages[i].used = 1;
        e->pages[i].data[addr & (EMU_PAGE_SIZE-1)] = val;
    }
}

static uint8_t emu_read8(emu_state_t *e, uint64_t addr) {
    int i;
    uint64_t pg = addr & ~(uint64_t)(EMU_PAGE_SIZE - 1);
    for (i = 0; i < e->npages; i++) {
        if (e->pages[i].base == pg)
            return e->pages[i].data[addr & (EMU_PAGE_SIZE-1)];
    }
    if (e->bin && e->bin->data) {
        for (i = 0; i < e->bin->nsections; i++) {
            dax_section_t *sec = &e->bin->sections[i];
            if (addr >= sec->vaddr && addr < sec->vaddr + sec->size &&
                sec->offset + sec->size <= e->bin->size) {
                return e->bin->data[sec->offset + (addr - sec->vaddr)];
            }
        }
    }
    return 0;
}

static uint32_t emu_read32(emu_state_t *e, uint64_t addr) {
    return (uint32_t)emu_read8(e,addr) | ((uint32_t)emu_read8(e,addr+1)<<8) |
           ((uint32_t)emu_read8(e,addr+2)<<16) | ((uint32_t)emu_read8(e,addr+3)<<24);
}

static uint64_t emu_read64(emu_state_t *e, uint64_t addr) {
    return (uint64_t)emu_read32(e,addr) | ((uint64_t)emu_read32(e,addr+4)<<32);
}

static void emu_write32(emu_state_t *e, uint64_t addr, uint32_t v) {
    emu_write8(e,addr,(uint8_t)v); emu_write8(e,addr+1,(uint8_t)(v>>8));
    emu_write8(e,addr+2,(uint8_t)(v>>16)); emu_write8(e,addr+3,(uint8_t)(v>>24));
}

static void emu_write64(emu_state_t *e, uint64_t addr, uint64_t v) {
    emu_write32(e,addr,(uint32_t)v); emu_write32(e,addr+4,(uint32_t)(v>>32));
}

static int arm64_rn(const char *name) {
    if (!name||!name[0]) return 31;
    if (strcmp(name,"xzr")==0||strcmp(name,"wzr")==0) return 31;
    if (strcmp(name,"sp")==0||strcmp(name,"wsp")==0)  return 31;
    if (strcmp(name,"lr")==0) return 30;
    if (strcmp(name,"fp")==0||strcmp(name,"x29")==0) return 29;
    if ((name[0]=='x'||name[0]=='w') && isdigit((unsigned char)name[1])) {
        int n=atoi(name+1);
        if(n>=0&&n<=30) return n;
    }
    return -1;
}

static uint64_t parse_arm64_imm(const char *s) {
    if (!s||!s[0]) return 0;
    if (s[0]=='#') s++;
    if (strncmp(s,"0x",2)==0) return strtoull(s,NULL,16);
    return strtoull(s,NULL,0);
}

static void parse_ops3(const char *ops, char *a1, char *a2, char *a3) {
    const char *p=ops;
    char *bufs[3]={a1,a2,a3};
    int k;
    a1[0]=a2[0]=a3[0]='\0';
    for(k=0;k<3;k++){
        while(*p==' ')p++;
        char *d=bufs[k]; int j=0;
        while(*p&&*p!=','&&j<63){*d++=*p++;j++;}
        *d='\0'; if(*p==',')p++;
    }
}

static uint64_t emu_get_reg(emu_state_t *e, const char *name) {
    int idx=arm64_rn(name);
    if(idx==31) {
        if(strcmp(name,"sp")==0||strcmp(name,"wsp")==0) return e->sp;
        return 0;
    }
    if(idx<0||idx>=32) return 0;
    uint64_t v=e->regs[idx];
    if(name[0]=='w') v&=0xFFFFFFFF;
    return v;
}

static void emu_set_reg(emu_state_t *e, const char *name, uint64_t val) {
    int idx=arm64_rn(name);
    if(idx==31){
        if(strcmp(name,"sp")==0||strcmp(name,"wsp")==0)e->sp=val;
        return;
    }
    if(idx<0||idx>=32) return;
    if(name[0]=='w') val&=0xFFFFFFFF;
    e->regs[idx]=val;
}

static int emu_step_arm64(emu_state_t *e) {
    uint32_t raw=emu_read32(e,e->pc);
    a64_insn_t insn; a64_decode(raw,e->pc,&insn);
    char a1[64]="",a2[64]="",a3[64]="";
    parse_ops3(insn.operands,a1,a2,a3);

    uint64_t next_pc=e->pc+4;
    int      branched=0;

    if (strcmp(insn.mnemonic,"mov")==0||strcmp(insn.mnemonic,"movz")==0) {
        if(a2[0]=='#') emu_set_reg(e,a1,parse_arm64_imm(a2));
        else           emu_set_reg(e,a1,emu_get_reg(e,a2));
    } else if (strcmp(insn.mnemonic,"movn")==0) {
        emu_set_reg(e,a1,~parse_arm64_imm(a2)&0xFFFFFFFF);
    } else if (strcmp(insn.mnemonic,"add")==0||strcmp(insn.mnemonic,"adds")==0) {
        uint64_t v1=emu_get_reg(e,a2);
        uint64_t v2=a3[0]=='#'?parse_arm64_imm(a3):emu_get_reg(e,a3);
        uint64_t r=v1+v2;
        if(a1[0]=='w')r&=0xFFFFFFFF;
        emu_set_reg(e,a1,r);
        if(strcmp(insn.mnemonic,"adds")==0){e->flags_z=(r==0);e->flags_n=(r>>63)&1;}
    } else if (strcmp(insn.mnemonic,"sub")==0||strcmp(insn.mnemonic,"subs")==0) {
        uint64_t v1=emu_get_reg(e,a2);
        uint64_t v2=a3[0]=='#'?parse_arm64_imm(a3):emu_get_reg(e,a3);
        uint64_t r=v1-v2;
        if(a1[0]=='w')r&=0xFFFFFFFF;
        emu_set_reg(e,a1,r);
        if(strcmp(insn.mnemonic,"subs")==0){e->flags_z=(r==0);e->flags_n=(r>>63)&1;}
    } else if (strcmp(insn.mnemonic,"and")==0||strcmp(insn.mnemonic,"ands")==0) {
        uint64_t v2=a3[0]=='#'?parse_arm64_imm(a3):emu_get_reg(e,a3);
        uint64_t r=emu_get_reg(e,a2)&v2;
        if(a1[0]=='w')r&=0xFFFFFFFF;
        emu_set_reg(e,a1,r);
        if(strcmp(insn.mnemonic,"ands")==0){e->flags_z=(r==0);e->flags_n=(r>>63)&1;}
    } else if (strcmp(insn.mnemonic,"orr")==0) {
        uint64_t r=emu_get_reg(e,a2)|emu_get_reg(e,a3);
        if(a1[0]=='w')r&=0xFFFFFFFF;
        emu_set_reg(e,a1,r);
    } else if (strcmp(insn.mnemonic,"eor")==0) {
        uint64_t v2=a3[0]=='#'?parse_arm64_imm(a3):emu_get_reg(e,a3);
        uint64_t r=emu_get_reg(e,a2)^v2;
        if(a1[0]=='w')r&=0xFFFFFFFF;
        emu_set_reg(e,a1,r);
    } else if (strcmp(insn.mnemonic,"lsl")==0) {
        uint64_t sh=a3[0]=='#'?parse_arm64_imm(a3):emu_get_reg(e,a3);
        uint64_t r=emu_get_reg(e,a2)<<(sh&63);
        if(a1[0]=='w')r&=0xFFFFFFFF;
        emu_set_reg(e,a1,r);
    } else if (strcmp(insn.mnemonic,"lsr")==0) {
        uint64_t sh=a3[0]=='#'?parse_arm64_imm(a3):emu_get_reg(e,a3);
        uint64_t r=emu_get_reg(e,a2)>>(sh&63);
        emu_set_reg(e,a1,r);
    } else if (strcmp(insn.mnemonic,"asr")==0) {
        uint64_t sh=parse_arm64_imm(a3)&63;
        int64_t  sv=(int64_t)emu_get_reg(e,a2);
        emu_set_reg(e,a1,(uint64_t)(sv>>(int)sh));
    } else if (strcmp(insn.mnemonic,"cmp")==0) {
        uint64_t v1=emu_get_reg(e,a1);
        uint64_t v2=a2[0]=='#'?parse_arm64_imm(a2):emu_get_reg(e,a2);
        uint64_t r=v1-v2;
        e->flags_z=(r==0); e->flags_n=((int64_t)r<0);
        e->flags_c=(v1>=v2); e->flags_v=0;
    } else if (strcmp(insn.mnemonic,"tst")==0) {
        uint64_t r=emu_get_reg(e,a1)&emu_get_reg(e,a2);
        e->flags_z=(r==0); e->flags_n=(r>>63)&1;
    } else if (strcmp(insn.mnemonic,"ldr")==0||strcmp(insn.mnemonic,"ldrsw")==0) {
        char base_reg[32]=""; uint64_t offset=0;
        const char *br=a2; if(*br=='[')br++;
        char *cc=strchr(br,',');
        if(cc){
            strncpy(base_reg,br,(size_t)(cc-br)<31?(size_t)(cc-br):31);
            base_reg[(size_t)(cc-br)<31?(size_t)(cc-br):31]='\0';
            offset=parse_arm64_imm(cc+1);
        } else {
            strncpy(base_reg,br,31); char *rb=strchr(base_reg,']'); if(rb)*rb='\0';
        }
        uint64_t addr2=emu_get_reg(e,base_reg)+offset;
        uint64_t val2=strcmp(insn.mnemonic,"ldrb")==0?(uint64_t)emu_read8(e,addr2):
                      strcmp(insn.mnemonic,"ldrh")==0?(uint64_t)(emu_read8(e,addr2)|((uint32_t)emu_read8(e,addr2+1)<<8)):
                      a1[0]=='w'?emu_read32(e,addr2):emu_read64(e,addr2);
        emu_set_reg(e,a1,val2);
    } else if (strcmp(insn.mnemonic,"str")==0) {
        char base_reg[32]=""; uint64_t offset=0;
        const char *br=a2; if(*br=='[')br++;
        char *cc=strchr(br,',');
        if(cc){
            strncpy(base_reg,br,(size_t)(cc-br)<31?(size_t)(cc-br):31);
            base_reg[(size_t)(cc-br)<31?(size_t)(cc-br):31]='\0';
            offset=parse_arm64_imm(cc+1);
        } else {
            strncpy(base_reg,br,31); char *rb=strchr(base_reg,']'); if(rb)*rb='\0';
        }
        uint64_t addr2=emu_get_reg(e,base_reg)+offset;
        uint64_t val2=emu_get_reg(e,a1);
        if(a1[0]=='w') emu_write32(e,addr2,(uint32_t)val2);
        else emu_write64(e,addr2,val2);
    } else if (strcmp(insn.mnemonic,"stp")==0) {
        char a4[64]=""; parse_ops3(insn.operands,a1,a2,a4);
        uint64_t addr2=emu_get_reg(e,"sp");
        const char *ba=a4; if(*ba=='[')ba++;
        char tmp_base[32]=""; uint64_t tmp_off=0;
        char *cc2=strchr(ba,',');
        if(cc2){
            strncpy(tmp_base,ba,(size_t)(cc2-ba)<31?(size_t)(cc2-ba):31);
            tmp_base[(size_t)(cc2-ba)<31?(size_t)(cc2-ba):31]='\0';
            tmp_off=parse_arm64_imm(cc2+1);
            addr2=emu_get_reg(e,tmp_base)+tmp_off;
        }
        emu_write64(e,addr2,emu_get_reg(e,a1));
        emu_write64(e,addr2+8,emu_get_reg(e,a2));
        if(strstr(a4,"!")) {
            char *rb2=strchr(tmp_base,']'); if(rb2)*rb2='\0';
            emu_set_reg(e,tmp_base,addr2);
        }
    } else if (strcmp(insn.mnemonic,"b")==0) {
        uint64_t tgt=0; if(a1[0]=='0')sscanf(a1,"0x%llx",(unsigned long long*)&tgt);
        if(tgt){next_pc=tgt;branched=1;}
    } else if (strncmp(insn.mnemonic,"b.",2)==0) {
        const char *cond=insn.mnemonic+2;
        int taken=0;
        if(strcmp(cond,"eq")==0)      taken=e->flags_z;
        else if(strcmp(cond,"ne")==0) taken=!e->flags_z;
        else if(strcmp(cond,"lt")==0) taken=e->flags_n!=e->flags_v;
        else if(strcmp(cond,"le")==0) taken=e->flags_z||(e->flags_n!=e->flags_v);
        else if(strcmp(cond,"gt")==0) taken=!e->flags_z&&(e->flags_n==e->flags_v);
        else if(strcmp(cond,"ge")==0) taken=e->flags_n==e->flags_v;
        else if(strcmp(cond,"lo")==0||strcmp(cond,"cc")==0) taken=!e->flags_c;
        else if(strcmp(cond,"hi")==0) taken=e->flags_c&&!e->flags_z;
        else if(strcmp(cond,"cs")==0||strcmp(cond,"hs")==0) taken=e->flags_c;
        else if(strcmp(cond,"mi")==0) taken=e->flags_n;
        else if(strcmp(cond,"pl")==0) taken=!e->flags_n;
        if(taken){
            uint64_t tgt2=0;
            if(a1[0]=='0')sscanf(a1,"0x%llx",(unsigned long long*)&tgt2);
            if(tgt2){next_pc=tgt2;branched=1;}
        }
    } else if (strcmp(insn.mnemonic,"cbz")==0) {
        uint64_t tgt2=0;
        if(a2[0]=='0')sscanf(a2,"0x%llx",(unsigned long long*)&tgt2);
        if(emu_get_reg(e,a1)==0&&tgt2){next_pc=tgt2;branched=1;}
    } else if (strcmp(insn.mnemonic,"cbnz")==0) {
        uint64_t tgt2=0;
        if(a2[0]=='0')sscanf(a2,"0x%llx",(unsigned long long*)&tgt2);
        if(emu_get_reg(e,a1)!=0&&tgt2){next_pc=tgt2;branched=1;}
    } else if (strcmp(insn.mnemonic,"ret")==0) {
        snprintf(e->halt_reason,sizeof(e->halt_reason),"ret w0=0x%llx",
                 (unsigned long long)e->regs[0]);
        e->halted=1; return 0;
    } else if (strcmp(insn.mnemonic,"bl")==0) {
        e->regs[30]=next_pc;
        uint64_t tgt2=0;
        if(a1[0]=='0')sscanf(a1,"0x%llx",(unsigned long long*)&tgt2);
        if(tgt2){
            next_pc=tgt2;branched=1;
            snprintf(e->halt_reason,sizeof(e->halt_reason),
                     "call to external 0x%llx",(unsigned long long)tgt2);
            e->halted=1; return 0;
        }
    } else if (strcmp(insn.mnemonic,"blr")==0) {
        e->regs[30]=next_pc;
        uint64_t tgt2=emu_get_reg(e,a1);
        snprintf(e->halt_reason,sizeof(e->halt_reason),
                 "indirect call 0x%llx",(unsigned long long)tgt2);
        e->halted=1; return 0;
    } else if (strcmp(insn.mnemonic,"br")==0) {
        next_pc=emu_get_reg(e,a1); branched=1;
    } else if (strcmp(insn.mnemonic,"ubfm")==0||strcmp(insn.mnemonic,"sbfm")==0) {
        uint64_t src2=emu_get_reg(e,a2);
        uint64_t immr=parse_arm64_imm(a3);
        uint64_t imms=parse_arm64_imm("0");
        const char *p4=strchr(insn.operands,',');
        if(p4){p4++;if((p4=strchr(p4,','))!=NULL)imms=parse_arm64_imm(++p4);}
        uint64_t mask=imms<63?(1ULL<<(imms+1))-1:~0ULL;
        emu_set_reg(e,a1,(src2>>immr)&mask);
    } else if (strcmp(insn.mnemonic,"nop")==0||
               strncmp(insn.mnemonic,"bti",3)==0||
               strcmp(insn.mnemonic,"paciaz")==0||
               strcmp(insn.mnemonic,"autiasp")==0) {
    } else {
        snprintf(e->halt_reason,sizeof(e->halt_reason),
                 "unimplemented: %s",insn.mnemonic);
        e->halted=1; return 0;
    }

    (void)branched;
    e->pc = next_pc;
    return 1;
}

void dax_emulate_func(dax_binary_t *bin, int func_idx,
                      uint64_t *init_regs, int nregs,
                      dax_opts_t *opts, FILE *out) {
    int         c  = opts ? opts->color : 1;
    dax_func_t *fn;
    int         si, i;
    emu_state_t *e;

    const char *CY = c ? COL_LABEL    : "";
    const char *CB = c ? COL_ADDR     : "";
    const char *CG = c ? COL_SECTION  : "";
    const char *CD = c ? COL_COMMENT  : "";
    const char *CR = c ? COL_RESET    : "";
    const char *CM = c ? COL_MNEM     : "";
    const char *CO = c ? COL_OPS      : "";

    if (!bin||func_idx<0||func_idx>=bin->nfunctions) return;
    fn = &bin->functions[func_idx];

    e = (emu_state_t *)calloc(1, sizeof(emu_state_t));
    if (!e) return;

    g_ntrace = 0;
    e->bin = bin;
    e->pc  = fn->start;
    e->sp  = EMU_STACK_BASE + EMU_STACK_SIZE - 0x80;

    for (si=0;si<bin->nsections;si++) {
        dax_section_t *sec=&bin->sections[si];
        if (fn->start>=sec->vaddr&&fn->start<sec->vaddr+sec->size) {
            e->code_base=bin->data+sec->offset;
            e->code_size=(size_t)sec->size;
            e->code_vaddr=sec->vaddr;
            break;
        }
    }

    if (init_regs) {
        for (i=0;i<nregs&&i<32;i++)
            e->regs[i]=init_regs[i];
    }

    fprintf(out,"\n");
    if(c)fprintf(out,"%s",COL_FUNC);
    fprintf(out,"  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
                " EMULATION: %s "
                "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n",
                fn->name);
    if(c)fprintf(out,"%s",CR);
    fprintf(out,"\n");
    fprintf(out,"  %sInitial registers:%s",CD,CR);
    for(i=0;i<(init_regs?nregs:4);i++) {
        const char *rnames[]={"w0","w1","w2","w3","w4","w5","w6","w7"};
        fprintf(out," %sx%d%s=%s0x%llx%s",CY,i,CR,CG,(unsigned long long)e->regs[i],CR);
        (void)rnames[0];
    }
    fprintf(out,"\n\n");

    while (!e->halted && e->steps < EMU_MAX_STEPS) {
        uint64_t saved_pc = e->pc;
        uint64_t saved_regs[8];
        for(i=0;i<8;i++) saved_regs[i]=e->regs[i];

        uint32_t raw=emu_read32(e,e->pc);
        a64_insn_t insn; a64_decode(raw,e->pc,&insn);

        int ok = emu_step_arm64(e);
        e->steps++;

        fprintf(out,"  %s0x%llx%s  %s%-10s%s %s%s%s",
                CB,(unsigned long long)saved_pc,CR,
                CM,insn.mnemonic,CR,
                CO,insn.operands,CR);

        int changed=0;
        for(i=0;i<8;i++) {
            if(e->regs[i]!=saved_regs[i]) {
                fprintf(out,"  %s→ x%d=0x%llx%s",CY,i,(unsigned long long)e->regs[i],CR);
                changed++;
                if(changed>=2)break;
            }
        }
        fprintf(out,"\n");

        if(!ok) break;

        if(e->pc==saved_pc&&!e->halted) {
            snprintf(e->halt_reason,sizeof(e->halt_reason),"infinite loop at 0x%llx",
                     (unsigned long long)saved_pc);
            break;
        }

        dax_func_t *cur_fn=dax_func_find(bin,e->pc);
        if(cur_fn&&cur_fn->start!=fn->start) {
            snprintf(e->halt_reason,sizeof(e->halt_reason),"jumped to %s",cur_fn->name);
            break;
        }
    }

    fprintf(out,"\n  %sEmulation complete: %d steps%s\n",CD,e->steps,CR);
    if(e->halt_reason[0])
        fprintf(out,"  %sHalted: %s%s%s\n",CD,CG,e->halt_reason,CR);
    fprintf(out,"  %sFinal register state:%s\n",CD,CR);
    for(i=0;i<8;i++)
        fprintf(out,"    %sx%d%s = %s0x%016llx%s  (%lld)\n",
                CY,i,CR,CG,(unsigned long long)e->regs[i],CR,
                (long long)e->regs[i]);
    fprintf(out,"\n");
    free(e);
}

void dax_emulate_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i;
    if (!bin||!opts||!out) return;
    for (i=0;i<bin->nfunctions&&i<4;i++) {
        uint64_t init[8]={0,1,2,3,4,5,6,7};
        dax_emulate_func(bin,i,init,4,opts,out);
    }
}
