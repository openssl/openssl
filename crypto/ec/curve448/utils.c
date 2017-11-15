/* Copyright (c) 2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file utils.c
 * @author Mike Hamburg
 * @brief Decaf utility functions.
 */

#include <decaf/common.h>

void decaf_bzero (
    void *s,
    size_t size
) {
#ifdef __STDC_LIB_EXT1__
    memset_s(s, size, 0, size);
#else
    const size_t sw = sizeof(decaf_word_t);
    volatile uint8_t *destroy = (volatile uint8_t *)s;
    for (; size && ((uintptr_t)destroy)%sw; size--, destroy++)
        *destroy = 0;
    for (; size >= sw; size -= sw, destroy += sw)
        *(volatile decaf_word_t *)destroy = 0;
    for (; size; size--, destroy++)
        *destroy = 0;
#endif
}

decaf_bool_t decaf_memeq (
   const void *data1_,
   const void *data2_,
   size_t size
) {
    const unsigned char *data1 = (const unsigned char *)data1_;
    const unsigned char *data2 = (const unsigned char *)data2_;
    unsigned char ret = 0;
    for (; size; size--, data1++, data2++) {
        ret |= *data1 ^ *data2;
    }
    return (((decaf_dword_t)ret) - 1) >> 8;
}
