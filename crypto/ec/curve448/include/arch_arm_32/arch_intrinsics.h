/* Copyright (c) 2016 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#ifndef __ARCH_ARM_32_ARCH_INTRINSICS_H__
#define __ARCH_ARM_32_ARCH_INTRINSICS_H__

#define ARCH_WORD_BITS 32

static __inline__ __attribute((always_inline,unused))
uint32_t word_is_zero(uint32_t a) {
    uint32_t ret;
    asm("subs %0, %1, #1;\n\tsbc %0, %0, %0" : "=r"(ret) : "r"(a) : "cc");
    return ret;
}

static __inline__ __attribute((always_inline,unused))
uint64_t widemul(uint32_t a, uint32_t b) {
    /* Could be UMULL, but it's hard to express to CC that the registers must be different */
    return ((uint64_t)a) * b; 
}

#endif /* __ARCH_ARM_32_ARCH_INTRINSICS_H__ */

