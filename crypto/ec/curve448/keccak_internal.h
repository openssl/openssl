/**
 * @cond internal
 * @file keccak_internal.h
 * @copyright
 *   Copyright (c) 2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Keccak internal interfaces.  Will be used by STROBE once reintegrated.
 */
#ifndef __DECAF_KECCAK_INTERNAL_H__
#define __DECAF_KECCAK_INTERNAL_H__ 1

#include <stdint.h>

/* The internal, non-opaque definition of the decaf_sponge struct. */
typedef union {
    uint64_t w[25]; uint8_t b[25*8];
} kdomain_t[1];

typedef struct decaf_kparams_s {
    uint8_t position, flags, rate, start_round, pad, rate_pad, max_out, remaining;
} decaf_kparams_s, decaf_kparams_t[1];

typedef struct decaf_keccak_sponge_s {
    kdomain_t state;
    decaf_kparams_t params;
} decaf_keccak_sponge_s, decaf_keccak_sponge_t[1];

#define INTERNAL_SPONGE_STRUCT 1

void __attribute__((noinline)) keccakf(kdomain_t state, uint8_t start_round);

static inline void dokeccak (decaf_keccak_sponge_t decaf_sponge) {
    keccakf(decaf_sponge->state, decaf_sponge->params->start_round);
    decaf_sponge->params->position = 0;
}

#endif /* __DECAF_KECCAK_INTERNAL_H__ */
