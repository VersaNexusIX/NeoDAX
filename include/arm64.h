#ifndef DAX_ARM64_H
#define DAX_ARM64_H

#include <stdint.h>

typedef enum {
    A64_REG_X0=0, A64_REG_X1, A64_REG_X2, A64_REG_X3,
    A64_REG_X4,   A64_REG_X5, A64_REG_X6, A64_REG_X7,
    A64_REG_X8,   A64_REG_X9, A64_REG_X10,A64_REG_X11,
    A64_REG_X12,  A64_REG_X13,A64_REG_X14,A64_REG_X15,
    A64_REG_X16,  A64_REG_X17,A64_REG_X18,A64_REG_X19,
    A64_REG_X20,  A64_REG_X21,A64_REG_X22,A64_REG_X23,
    A64_REG_X24,  A64_REG_X25,A64_REG_X26,A64_REG_X27,
    A64_REG_X28,  A64_REG_FP, A64_REG_LR, A64_REG_SP,
    A64_REG_XZR = 31,
    A64_REG_NONE = -1
} a64_reg_t;

typedef enum {
    A64_SHIFT_LSL = 0,
    A64_SHIFT_LSR = 1,
    A64_SHIFT_ASR = 2,
    A64_SHIFT_ROR = 3
} a64_shift_t;

typedef enum {
    A64_EXT_UXTB=0, A64_EXT_UXTH, A64_EXT_UXTW, A64_EXT_UXTX,
    A64_EXT_SXTB,   A64_EXT_SXTH, A64_EXT_SXTW, A64_EXT_SXTX
} a64_extend_t;

typedef enum {
    A64_COND_EQ=0, A64_COND_NE, A64_COND_CS, A64_COND_CC,
    A64_COND_MI,   A64_COND_PL, A64_COND_VS, A64_COND_VC,
    A64_COND_HI,   A64_COND_LS, A64_COND_GE, A64_COND_LT,
    A64_COND_GT,   A64_COND_LE, A64_COND_AL, A64_COND_NV
} a64_cond_t;

typedef struct {
    uint32_t    raw;
    uint64_t    address;
    char        mnemonic[32];
    char        operands[128];
} a64_insn_t;

extern const char *a64_cond_str[];

int  a64_decode(uint32_t raw, uint64_t addr, a64_insn_t *insn);
void a64_reg_name(a64_reg_t r, int is32, char *out);

#endif
