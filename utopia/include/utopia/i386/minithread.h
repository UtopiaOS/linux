/*
 * Reimplementation of Apple's thread model for the Linux kernel
 * Designed via shitposting on Discord
 *
 * mach_message_t -> natual_t -> uint32_t
 */
#include <linux/types.h>

#define x86_THREAD_STATE32 1
#define x86_FLOAT_STATE32 2
#define x86_EXCEPTION_STATE32 3
#define x86_THREAD_STATE64 4
#define x86_FLOAT_STATE64 5
#define x86_EXCEPTION_STATE64 6
#define x86_THREAD_STATE 7
#define x86_FLOAT_STATE 8
#define x86_EXCEPTION_STATE 9
#define x86_DEBUG_STATE32 10
#define x86_DEBUG_STATE64 11
#define x86_DEBUG_STATE 12
#define THREAD_STATE_NONE 13

struct utopia_ymm_reg
{
    char ymm_reg[32];
};

struct utopia_fp_control
{
    unsigned short invalid : 1,
        denorm : 1,
        zdiv : 1,
        ovrfl : 1,
        undfl : 1,
        precis : 1, : 2,
        pc : 2,
#define FP_PREC_24B 0
#define FP_PREC_53B 2
#define FP_PREC_64B 3
        rc : 2,
#define FP_RND_NEAR 0
#define FP_RND_DOWN 1
#define FP_RND_UP 2
#define FP_CHOP 3
        : 1, : 3;
};

struct utopia_fp_status
{
    unsigned short invalid : 1,
        denorm : 1,
        zdiv : 1,
        ovrfl : 1,
        undfl : 1,
        precis : 1,
        stkflt : 1,
        errsumm : 1,
        c0 : 1,
        c1 : 1,
        c2 : 1,
        tos : 3,
        c3 : 1,
        busy : 1;
};

struct utopia_mmst_reg
{
    char msst_reg[10];
    char mmst_rsrv[6];
};

struct utopia_xmm_reg
{
    char xmm_reg[16];
};

struct utopia_znm_reg
{
    char zmn_reg[64];
};

struct i386_float_state
{
    int fpu_reserved[2];
    struct utopia_fp_control fpu_fcw;
    struct utopia_fp_status fpu_fsw;
    uint8_t fpu_ftw;
    uint8_t fpu_rsrv1;
    uint16_t fpu_fop;
    uint32_t fup_ip;
    uint16_t fpu_cs;
    uint16_t fpu_rsrv2;
    uint32_t fpu_dp;                  /* x87 FPU Instruction Operand(Data) Pointer offset */
    uint16_t fpu_ds;                  /* x87 FPU Instruction Operand(Data) Pointer Selector */
    uint16_t fpu_rsrv3;               /* reserved */
    uint32_t fpu_mxcsr;               /* MXCSR Register state */
    uint32_t fpu_mxcsrmask;           /* MXCSR mask */
    struct utopia_mmst_reg fpu_stmm0; /* ST0/MM0   */
    struct utopia_mmst_reg fpu_stmm1; /* ST1/MM1  */
    struct utopia_mmst_reg fpu_stmm2; /* ST2/MM2  */
    struct utopia_mmst_reg fpu_stmm3; /* ST3/MM3  */
    struct utopia_mmst_reg fpu_stmm4; /* ST4/MM4  */
    struct utopia_mmst_reg fpu_stmm5; /* ST5/MM5  */
    struct utopia_mmst_reg fpu_stmm6; /* ST6/MM6  */
    struct utopia_mmst_reg fpu_stmm7; /* ST7/MM7  */
    struct utopia_xmm_reg fpu_xmm0;   /* XMM 0  */
    struct utopia_xmm_reg fpu_xmm1;   /* XMM 1  */
    struct utopia_xmm_reg fpu_xmm2;   /* XMM 2  */
    struct utopia_xmm_reg fpu_xmm3;   /* XMM 3  */
    struct utopia_xmm_reg fpu_xmm4;   /* XMM 4  */
    struct utopia_xmm_reg fpu_xmm5;   /* XMM 5  */
    struct utopia_xmm_reg fpu_xmm6;   /* XMM 6  */
    struct utopia_xmm_reg fpu_xmm7;   /* XMM 7  */
    char fpu_rsrv4[14 * 16];          /* reserved */
    int fpu_reserved1;
};

struct x86_thread_state32
{
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
    unsigned int edi;
    unsigned int esi;
    unsigned int ebp;
    unsigned int esp;
    unsigned int ss;
    unsigned int eflags;
    unsigned int eip;
    unsigned int cs;
    unsigned int ds;
    unsigned int es;
    unsigned int fs;
    unsigned int gs;
};

struct x86_float_state64
{
    int fpu_reserved[2];
    struct utopia_fp_control fpu_fcw; /* x87 FPU control word */
    struct utopia_fp_status fpu_fsw;  /* x87 FPU status word */
    uint8_t fpu_ftw;                  /* x87 FPU tag word */
    uint8_t fpu_rsrv1;                /* reserved */
    uint16_t fpu_fop;                 /* x87 FPU Opcode */

    /* x87 FPU Instruction Pointer */
    uint32_t fpu_ip; /* offset */
    uint16_t fpu_cs; /* Selector */

    uint16_t fpu_rsrv2; /* reserved */

    /* x87 FPU Instruction Operand(Data) Pointer */
    uint32_t fpu_dp; /* offset */
    uint16_t fpu_ds; /* Selector */

    uint16_t fpu_rsrv3;               /* reserved */
    uint32_t fpu_mxcsr;               /* MXCSR Register state */
    uint32_t fpu_mxcsrmask;           /* MXCSR mask */
    struct utopia_mmst_reg fpu_stmm0; /* ST0/MM0   */
    struct utopia_mmst_reg fpu_stmm1; /* ST1/MM1  */
    struct utopia_mmst_reg fpu_stmm2; /* ST2/MM2  */
    struct utopia_mmst_reg fpu_stmm3; /* ST3/MM3  */
    struct utopia_mmst_reg fpu_stmm4; /* ST4/MM4  */
    struct utopia_mmst_reg fpu_stmm5; /* ST5/MM5  */
    struct utopia_mmst_reg fpu_stmm6; /* ST6/MM6  */
    struct utopia_mmst_reg fpu_stmm7; /* ST7/MM7  */
    struct utopia_xmm_reg fpu_xmm0;   /* XMM 0  */
    struct utopia_xmm_reg fpu_xmm1;   /* XMM 1  */
    struct utopia_xmm_reg fpu_xmm2;   /* XMM 2  */
    struct utopia_xmm_reg fpu_xmm3;   /* XMM 3  */
    struct utopia_xmm_reg fpu_xmm4;   /* XMM 4  */
    struct utopia_xmm_reg fpu_xmm5;   /* XMM 5  */
    struct utopia_xmm_reg fpu_xmm6;   /* XMM 6  */
    struct utopia_xmm_reg fpu_xmm7;   /* XMM 7  */
    struct utopia_xmm_reg fpu_xmm8;   /* XMM 8  */
    struct utopia_xmm_reg fpu_xmm9;   /* XMM 9  */
    struct utopia_xmm_reg fpu_xmm10;  /* XMM 10  */
    struct utopia_xmm_reg fpu_xmm11;  /* XMM 11 */
    struct utopia_xmm_reg fpu_xmm12;  /* XMM 12  */
    struct utopia_xmm_reg fpu_xmm13;  /* XMM 13  */
    struct utopia_xmm_reg fpu_xmm14;  /* XMM 14  */
    struct utopia_xmm_reg fpu_xmm15;  /* XMM 15  */
    char fpu_rsrv4[6 * 16];           /* reserved */
    int fpu_reserved1;
};

struct x86_thread_state64
{
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
    uint64_t cs;
    uint64_t fs;
    uint64_t gs;
};
