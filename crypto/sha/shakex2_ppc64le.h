/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Copyright IBM Corp. 2025, 2026
 *
 * ===================================================================================
 * Written by Nimet Ozkan <nimet.ozkan@ibm.com>
 */

#ifndef OSSL_CRYPTO_SHAKE_MBX2_PPC64LE
#define OSSL_CRYPTO_SHAKE_MBX2_PPC64LE
#pragma once

#include <altivec.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHAKE128_DIGEST 128
#define SHAKE256_DIGEST 256
#define ROUNDS (2 * KECCAKl) + 12
#define STATE_SIZE 5 * 5
#define NUM_OF_STATES 2
#define KECCAK_BITS_TOTAL 1600
#define SHAKE_SUFFIX 0x1F
#define KECCAK_DOM 0x80

#define _bytes(x) ((x) / 8)
typedef __vector unsigned long long v2_u64;

/* Sponge state tracking structure matching reference implementation */
typedef struct {
    uint32_t _block_rate; /* Rate in bytes */
    uint32_t _capacity; /* Capacity in bits */
    uint32_t _digestsz; /* Digest size in bits */
    uint8_t _pad; /* Padding byte */
    uint64_t _avail; /* Available bytes for squeeze */
    uint64_t _threshold; /* Current position in absorb */
} sponge_components;

typedef struct {
    union {
        uint64_t statex2[NUM_OF_STATES][STATE_SIZE];
    } st;
    sponge_components sponge;
} shakex2_ppc64le_ctx_t;

#define get_min_bsize(a, b) ((a) < (b) ? (a) : (b))

#if defined(__PPC64__) && defined(__LITTLE_ENDIAN__)

void shakex2_config_ppc64le(shakex2_ppc64le_ctx_t *ctx, int bits);
void shakex2_absorb_ppc64le(shakex2_ppc64le_ctx_t *ctx,
    const void *data0, size_t len0,
    const void *data1, size_t len1);

int shake128x2_ppc64le(const void *seed0, size_t seed0_len,
    const void *seed1, size_t seed1_len,
    shakex2_ppc64le_ctx_t *ctx,
    uint8_t *out0, size_t out0_len,
    uint8_t *out1, size_t out1_len);

int shake128x2_squeeze_once_ppc64le(shakex2_ppc64le_ctx_t *ctx,
    uint8_t *out0, size_t out0_len,
    uint8_t *out1, size_t out1_len);

int shake256x2_ppc64le(const void *seed0, size_t seed0_len,
    const void *seed1, size_t seed1_len,
    shakex2_ppc64le_ctx_t *ctx,
    uint8_t *out0, size_t out0_len,
    uint8_t *out1, size_t out1_len);

int shake256x2_squeeze_once_ppc64le(shakex2_ppc64le_ctx_t *ctx,
    uint8_t *out0, size_t out0_len,
    uint8_t *out1, size_t out1_len);

#endif /* __PPC64__ && __LITTLE_ENDIAN__ */

#endif /* OSSL_CRYPTO_SHAKE_MBX2_PPC64LE */
