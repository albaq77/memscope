#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;

typedef u64 __u64;
typedef u32 __u32;
typedef u16 __u16;
typedef u8 __u8;
typedef s64 __s64;
typedef s32 __s32;
typedef s16 __s16;
typedef s8 __s8;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#if defined(__TARGET_ARCH_x86)

struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

#elif defined(__TARGET_ARCH_arm64)

struct pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};

#endif

#endif
