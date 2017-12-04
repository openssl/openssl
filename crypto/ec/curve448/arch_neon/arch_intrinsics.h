/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2016 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef __ARCH_NEON_ARCH_INTRINSICS_H__
# define __ARCH_NEON_ARCH_INTRINSICS_H__

# define ARCH_WORD_BITS 32

static __inline__ __attribute((always_inline, unused))
uint32_t word_is_zero(uint32_t a)
{
    uint32_t ret;
    __asm__("subs %0, %1, #1;\n\tsbc %0, %0, %0": "=r"(ret): "r"(a):"cc");
    return ret;
}

static __inline__ __attribute((always_inline, unused))
uint64_t widemul(uint32_t a, uint32_t b)
{
    /*
     * Could be UMULL, but it's hard to express to CC that the registers must
     * be different
     */
    return ((uint64_t)a) * b;
}

#endif                          /* __ARCH_NEON_ARCH_INTRINSICS_H__ */
