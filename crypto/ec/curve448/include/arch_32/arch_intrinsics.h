/* Copyright (c) 2016 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#ifndef __ARCH_ARCH_32_ARCH_INTRINSICS_H__
#define __ARCH_ARCH_32_ARCH_INTRINSICS_H__

#define ARCH_WORD_BITS 32

static __inline__ __attribute((always_inline,unused))
uint32_t word_is_zero(uint32_t a) {
    /* let's hope the compiler isn't clever enough to optimize this. */
    return (((uint64_t)a)-1)>>32;
}

static __inline__ __attribute((always_inline,unused))
uint64_t widemul(uint32_t a, uint32_t b) {
    return ((uint64_t)a) * b;
}

#endif /* __ARCH_ARM_32_ARCH_INTRINSICS_H__ */

