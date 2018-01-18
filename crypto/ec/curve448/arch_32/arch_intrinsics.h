/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2016 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef __ARCH_ARCH_32_ARCH_INTRINSICS_H__
# define __ARCH_ARCH_32_ARCH_INTRINSICS_H__

# define ARCH_WORD_BITS 32

static ossl_inline uint32_t word_is_zero(uint32_t a)
{
    /* let's hope the compiler isn't clever enough to optimize this. */
    return (((uint64_t)a) - 1) >> 32;
}

static ossl_inline uint64_t widemul(uint32_t a, uint32_t b)
{
    return ((uint64_t)a) * b;
}

#endif                          /* __ARCH_ARCH_32_ARCH_INTRINSICS_H__ */
