/* Copyright (c) 2016 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#ifndef __ARCH_REF64_ARCH_INTRINSICS_H__
#define __ARCH_REF64_ARCH_INTRINSICS_H__

#define ARCH_WORD_BITS 64

static __inline__ __attribute((always_inline,unused))
uint64_t word_is_zero(uint64_t a) {
    /* let's hope the compiler isn't clever enough to optimize this. */
    return (((__uint128_t)a)-1)>>64;
}

static __inline__ __attribute((always_inline,unused))
__uint128_t widemul(uint64_t a, uint64_t b) {
    return ((__uint128_t)a) * b; 
}

#endif /* ARCH_REF64_ARCH_INTRINSICS_H__ */

