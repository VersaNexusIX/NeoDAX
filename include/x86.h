#ifndef DAX_X86_H
#define DAX_X86_H

#include <stdint.h>
#include "dax.h"

typedef enum {
    X86_REG_NONE = -1,
    RAX=0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8,  R9,  R10, R11, R12, R13, R14, R15,
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    R8D, R9D, R10D,R11D,R12D,R13D,R14D,R15D,
    AX,  CX,  DX,  BX,  SP,  BP,  SI,  DI,
    AL,  CL,  DL,  BL,  AH,  CH,  DH,  BH,
    SPL, BPL, SIL, DIL,
    R8B, R9B, R10B,R11B,R12B,R13B,R14B,R15B,
    R8W, R9W, R10W,R11W,R12W,R13W,R14W,R15W,
    XMM0,XMM1,XMM2,XMM3,XMM4,XMM5,XMM6,XMM7,
    XMM8,XMM9,XMM10,XMM11,XMM12,XMM13,XMM14,XMM15,
    RIP, RFLAGS
} x86_reg_t;

typedef enum {
    X86_OP_NONE = 0,
    X86_OP_REG,
    X86_OP_MEM,
    X86_OP_IMM,
    X86_OP_REL
} x86_op_type_t;

typedef struct {
    x86_op_type_t   type;
    uint8_t         size;
    union {
        x86_reg_t   reg;
        int64_t     imm;
        struct {
            x86_reg_t   base;
            x86_reg_t   index;
            int         scale;
            int64_t     disp;
            uint8_t     seg;
        } mem;
    };
} x86_operand_t;

typedef struct {
    uint8_t         rex;
    uint8_t         has_rex;
    uint8_t         vex[3];
    uint8_t         has_vex;
    uint8_t         prefixes[4];
    uint8_t         nprefixes;
    uint8_t         opcode[3];
    uint8_t         opcode_len;
    uint8_t         modrm;
    uint8_t         has_modrm;
    uint8_t         sib;
    uint8_t         has_sib;
    int64_t         disp;
    uint8_t         disp_size;
    int64_t         imm;
    uint8_t         imm_size;
    char            ops[DAX_MAX_OPERANDS];
    char            mnemonic[DAX_MAX_MNEMONIC];
    uint8_t         length;
    uint64_t        address;
    int             is64;
} x86_insn_t;

extern const char *x86_reg_names_64[];
extern const char *x86_reg_names_32[];
extern const char *x86_reg_names_16[];
extern const char *x86_reg_names_8l[];
extern const char *x86_reg_names_8h[];
extern const char *x86_reg_names_xmm[];

int x86_decode(const uint8_t *buf, size_t len, uint64_t addr, x86_insn_t *insn);
void x86_format(x86_insn_t *insn, char *mnem_out, char *ops_out);

#endif
