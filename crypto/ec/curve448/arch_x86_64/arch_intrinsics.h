/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2014-2016 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */
#ifndef __ARCH_X86_64_ARCH_INTRINSICS_H__
# define __ARCH_X86_64_ARCH_INTRINSICS_H__

# define ARCH_WORD_BITS 64

# include <openssl/e_os2.h>

/* FUTURE: autogenerate */
static __inline__ __uint128_t widemul(const uint64_t *a, const uint64_t *b)
{
    uint64_t c, d;
# ifndef __BMI2__
    __asm__ volatile
     ("movq %[a], %%rax;" "mulq %[b];":[c] "=&a"(c),[d] "=d"(d)
      :[b] "m"(*b),[a] "m"(*a)
      :"cc");
# else
    __asm__ volatile
     ("movq %[a], %%rdx;" "mulx %[b], %[c], %[d];":[c] "=r"(c),[d] "=r"(d)
      :[b] "m"(*b),[a] "m"(*a)
      :"rdx");
# endif
    return (((__uint128_t) (d)) << 64) | c;
}

static __inline__ __uint128_t widemul_rm(uint64_t a, const uint64_t *b)
{
    uint64_t c, d;
# ifndef __BMI2__
    __asm__ volatile
     ("movq %[a], %%rax;" "mulq %[b];":[c] "=&a"(c),[d] "=d"(d)
      :[b] "m"(*b),[a] "r"(a)
      :"cc");
# else
    __asm__ volatile
     ("mulx %[b], %[c], %[d];":[c] "=r"(c),[d] "=r"(d)
      :[b] "m"(*b),[a] "d"(a));
# endif
    return (((__uint128_t) (d)) << 64) | c;
}

static __inline__ __uint128_t widemul_rr(uint64_t a, uint64_t b)
{
    uint64_t c, d;
# ifndef __BMI2__
    __asm__ volatile
     ("mulq %[b];":[c] "=a"(c),[d] "=d"(d)
      :[b] "r"(b), "a"(a)
      :"cc");
# else
    __asm__ volatile
     ("mulx %[b], %[c], %[d];":[c] "=r"(c),[d] "=r"(d)
      :[b] "r"(b),[a] "d"(a));
# endif
    return (((__uint128_t) (d)) << 64) | c;
}

static __inline__ __uint128_t widemul2(const uint64_t *a, const uint64_t *b)
{
    uint64_t c, d;
# ifndef __BMI2__
    __asm__ volatile
     ("movq %[a], %%rax; "
      "addq %%rax, %%rax; " "mulq %[b];":[c] "=&a"(c),[d] "=d"(d)
      :[b] "m"(*b),[a] "m"(*a)
      :"cc");
# else
    __asm__ volatile
     ("movq %[a], %%rdx;"
      "leaq (,%%rdx,2), %%rdx;" "mulx %[b], %[c], %[d];":[c] "=r"(c),[d] "=r"(d)
      :[b] "m"(*b),[a] "m"(*a)
      :"rdx");
# endif
    return (((__uint128_t) (d)) << 64) | c;
}

static __inline__ void mac(__uint128_t * acc, const uint64_t *a,
                           const uint64_t *b)
{
    uint64_t lo = *acc, hi = *acc >> 64;

# ifdef __BMI2__
    uint64_t c, d;
    __asm__ volatile
     ("movq %[a], %%rdx; "
      "mulx %[b], %[c], %[d]; "
      "addq %[c], %[lo]; "
      "adcq %[d], %[hi]; ":[c] "=&r"(c),[d] "=&r"(d),[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "m"(*a)
      :"rdx", "cc");
# else
    __asm__ volatile
     ("movq %[a], %%rax; "
      "mulq %[b]; "
      "addq %%rax, %[lo]; " "adcq %%rdx, %[hi]; ":[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "m"(*a)
      :"rax", "rdx", "cc");
# endif

    *acc = (((__uint128_t) (hi)) << 64) | lo;
}

static __inline__ void macac(__uint128_t * acc, __uint128_t * acc2,
                             const uint64_t *a, const uint64_t *b)
{
    uint64_t lo = *acc, hi = *acc >> 64;
    uint64_t lo2 = *acc2, hi2 = *acc2 >> 64;

# ifdef __BMI2__
    uint64_t c, d;
    __asm__ volatile
     ("movq %[a], %%rdx; "
      "mulx %[b], %[c], %[d]; "
      "addq %[c], %[lo]; "
      "adcq %[d], %[hi]; "
      "addq %[c], %[lo2]; "
      "adcq %[d], %[hi2]; ":[c] "=r"(c),[d] "=r"(d),[lo] "+r"(lo),[hi] "+r"(hi),
      [lo2] "+r"(lo2),[hi2] "+r"(hi2)
      :[b] "m"(*b),[a] "m"(*a)
      :"rdx", "cc");
# else
    __asm__ volatile
     ("movq %[a], %%rax; "
      "mulq %[b]; "
      "addq %%rax, %[lo]; "
      "adcq %%rdx, %[hi]; "
      "addq %%rax, %[lo2]; "
      "adcq %%rdx, %[hi2]; ":[lo] "+r"(lo),[hi] "+r"(hi),[lo2] "+r"(lo2),
      [hi2] "+r"(hi2)
      :[b] "m"(*b),[a] "m"(*a)
      :"rax", "rdx", "cc");
# endif

    *acc = (((__uint128_t) (hi)) << 64) | lo;
    *acc2 = (((__uint128_t) (hi2)) << 64) | lo2;
}

static __inline__ void mac_rm(__uint128_t * acc, uint64_t a, const uint64_t *b)
{
    uint64_t lo = *acc, hi = *acc >> 64;

# ifdef __BMI2__
    uint64_t c, d;
    __asm__ volatile
     ("mulx %[b], %[c], %[d]; "
      "addq %[c], %[lo]; "
      "adcq %[d], %[hi]; ":[c] "=r"(c),[d] "=r"(d),[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "d"(a)
      :"cc");
# else
    __asm__ volatile
     ("movq %[a], %%rax; "
      "mulq %[b]; "
      "addq %%rax, %[lo]; " "adcq %%rdx, %[hi]; ":[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "r"(a)
      :"rax", "rdx", "cc");
# endif

    *acc = (((__uint128_t) (hi)) << 64) | lo;
}

static __inline__ void mac_rr(__uint128_t * acc, uint64_t a, const uint64_t b)
{
    uint64_t lo = *acc, hi = *acc >> 64;

# ifdef __BMI2__
    uint64_t c, d;
    __asm__ volatile
     ("mulx %[b], %[c], %[d]; "
      "addq %[c], %[lo]; "
      "adcq %[d], %[hi]; ":[c] "=r"(c),[d] "=r"(d),[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "r"(b),[a] "d"(a)
      :"cc");
# else
    __asm__ volatile
     ("mulq %[b]; "
      "addq %%rax, %[lo]; "
      "adcq %%rdx, %[hi]; ":[lo] "+r"(lo),[hi] "+r"(hi), "+a"(a)
      :[b] "r"(b)
      :"rdx", "cc");
# endif

    *acc = (((__uint128_t) (hi)) << 64) | lo;
}

static __inline__ void mac2(__uint128_t * acc, const uint64_t *a,
                            const uint64_t *b)
{
    uint64_t lo = *acc, hi = *acc >> 64;

# ifdef __BMI2__
    uint64_t c, d;
    __asm__ volatile
     ("movq %[a], %%rdx; "
      "addq %%rdx, %%rdx; "
      "mulx %[b], %[c], %[d]; "
      "addq %[c], %[lo]; "
      "adcq %[d], %[hi]; ":[c] "=r"(c),[d] "=r"(d),[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "m"(*a)
      :"rdx", "cc");
# else
    __asm__ volatile
     ("movq %[a], %%rax; "
      "addq %%rax, %%rax; "
      "mulq %[b]; "
      "addq %%rax, %[lo]; " "adcq %%rdx, %[hi]; ":[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "m"(*a)
      :"rax", "rdx", "cc");
# endif

    *acc = (((__uint128_t) (hi)) << 64) | lo;
}

static __inline__ void msb(__uint128_t * acc, const uint64_t *a,
                           const uint64_t *b)
{
    uint64_t lo = *acc, hi = *acc >> 64;
# ifdef __BMI2__
    uint64_t c, d;
    __asm__ volatile
     ("movq %[a], %%rdx; "
      "mulx %[b], %[c], %[d]; "
      "subq %[c], %[lo]; "
      "sbbq %[d], %[hi]; ":[c] "=r"(c),[d] "=r"(d),[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "m"(*a)
      :"rdx", "cc");
# else
    __asm__ volatile
     ("movq %[a], %%rax; "
      "mulq %[b]; "
      "subq %%rax, %[lo]; " "sbbq %%rdx, %[hi]; ":[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "m"(*a)
      :"rax", "rdx", "cc");
# endif
    *acc = (((__uint128_t) (hi)) << 64) | lo;
}

static __inline__ void msb2(__uint128_t * acc, const uint64_t *a,
                            const uint64_t *b)
{
    uint64_t lo = *acc, hi = *acc >> 64;
# ifdef __BMI2__
    uint64_t c, d;
    __asm__ volatile
     ("movq %[a], %%rdx; "
      "addq %%rdx, %%rdx; "
      "mulx %[b], %[c], %[d]; "
      "subq %[c], %[lo]; "
      "sbbq %[d], %[hi]; ":[c] "=r"(c),[d] "=r"(d),[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "m"(*a)
      :"rdx", "cc");
# else
    __asm__ volatile
     ("movq %[a], %%rax; "
      "addq %%rax, %%rax; "
      "mulq %[b]; "
      "subq %%rax, %[lo]; " "sbbq %%rdx, %[hi]; ":[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "m"(*a)
      :"rax", "rdx", "cc");
# endif
    *acc = (((__uint128_t) (hi)) << 64) | lo;

}

static __inline__ void mrs(__uint128_t * acc, const uint64_t *a,
                           const uint64_t *b)
{
    uint64_t c, d, lo = *acc, hi = *acc >> 64;
    __asm__ volatile
     ("movq %[a], %%rdx; "
      "mulx %[b], %[c], %[d]; "
      "subq %[lo], %[c]; "
      "sbbq %[hi], %[d]; ":[c] "=r"(c),[d] "=r"(d),[lo] "+r"(lo),[hi] "+r"(hi)
      :[b] "m"(*b),[a] "m"(*a)
      :"rdx", "cc");
    *acc = (((__uint128_t) (d)) << 64) | c;
}

static __inline__ uint64_t word_is_zero(uint64_t x)
{
    __asm__ volatile ("neg %0; sbb %0, %0;":"+r" (x));
    return ~x;
}

static inline uint64_t shrld(__uint128_t x, int n)
{
    return x >> n;
}

#endif                          /* __ARCH_X86_64_ARCH_INTRINSICS_H__ */
