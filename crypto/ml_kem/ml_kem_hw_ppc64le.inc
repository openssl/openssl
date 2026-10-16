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

#define ML_KEM_NUM_OF_BUFF_SHAKE_X2  2
#define ML_KEM_SAMPLING_BUFSIZE_X2 (SCALAR_SAMPLING_BUFSIZE * 5)
#define ML_KEM_RANDOM_BYTES_X2     (ML_KEM_RANDOM_BYTES + ML_KEM_NUM_OF_BUFF_SHAKE_X2)

#define PROCESS_LOOP(curr, endout, in, endin, b1, b2, b3, kPrime) \
    do {                                                          \
        while (curr < endout && in < endin) {                     \
            b1 = *(in)++; b2 = *(in)++; b3 = *(in)++;             \
            if ((d = ((b2 & 0x0f) << 8) + b1) < (kPrime))         \
                *(curr)++ = d;                                    \
            if ((curr) >= (endout))                               \
                break;                                            \
            if ((d = (b3 << 4) + (b2 >> 4)) < (kPrime))           \
                *(curr)++ = d;                                    \
	}                                                         \
    } while (0)

static __owur int sample_scalar2x_ppc64le(const uint8_t *seed0, size_t seed0_len,
                                   const uint8_t *seed1, size_t seed1_len,
                                   scalar *out0, scalar *out1)
{
    uint8_t *in;
    uint16_t d;
    uint8_t b1, b2, b3;
    shakex2_ppc64le_ctx_t stx;

    uint8_t *endinx2[ML_KEM_NUM_OF_BUFF_SHAKE_X2];
    uint16_t *endoutx2[ML_KEM_NUM_OF_BUFF_SHAKE_X2];
    uint16_t *currx2[ML_KEM_NUM_OF_BUFF_SHAKE_X2];
    uint8_t buffx2[ML_KEM_NUM_OF_BUFF_SHAKE_X2][ML_KEM_SAMPLING_BUFSIZE_X2];

    currx2[0] = out0->c; endoutx2[0] = currx2[0] + DEGREE;
    currx2[1] = out1->c; endoutx2[1] = currx2[1] + DEGREE;

    endinx2[0] = buffx2[0] + sizeof(buffx2[0]);
    endinx2[1] = buffx2[1] + sizeof(buffx2[1]);

    if (!shake128x2_ppc64le(seed0, seed0_len, seed1, seed1_len, &stx, buffx2[0], sizeof(buffx2[0]), buffx2[1], sizeof(buffx2[1])))
        return 0;

    in = buffx2[0];
    PROCESS_LOOP(currx2[0], endoutx2[0], in, endinx2[0], b1, b2, b3, kPrime);
    
    in = buffx2[1];
    PROCESS_LOOP(currx2[1], endoutx2[1], in, endinx2[1], b1, b2, b3, kPrime);

    if (currx2[0] < endoutx2[0] || currx2[1] < endoutx2[1])
        return 0; /* or fallback to scalar */

    return 1;
}

static __owur int matrix_expand2x_ppc64le(EVP_MD_CTX *mdctx, ML_KEM_KEY *key)
{
    scalar *out = key->m;
    int rank = key->vinfo->rank;
    int i, j;

    uint8_t inputx2[ML_KEM_NUM_OF_BUFF_SHAKE_X2][ML_KEM_RANDOM_BYTES_X2];
    
    memcpy(inputx2[0], key->rho, ML_KEM_RANDOM_BYTES);
    memcpy(inputx2[1], key->rho, ML_KEM_RANDOM_BYTES);

    for (i = 0; i < rank; i++) {
        for (j = 0; j + 1 < rank; j += 2) {
            inputx2[0][ML_KEM_RANDOM_BYTES] = (uint8_t)i;
            inputx2[0][ML_KEM_RANDOM_BYTES + 1] = (uint8_t)j;

            inputx2[1][ML_KEM_RANDOM_BYTES] = (uint8_t)i;
            inputx2[1][ML_KEM_RANDOM_BYTES + 1] = (uint8_t)(j + 1);

            if (!sample_scalar2x_ppc64le(inputx2[0], sizeof(inputx2[0]),
                                   inputx2[1], sizeof(inputx2[1]),
                                   out, out + 1))
                return 0;

            out += 2;
        }

        if (j < rank) {
            inputx2[0][ML_KEM_RANDOM_BYTES] = (uint8_t)i;
            inputx2[0][ML_KEM_RANDOM_BYTES + 1] = (uint8_t)j;

            if (!EVP_DigestInit_ex(mdctx, key->shake128_md, NULL)
                || !EVP_DigestUpdate(mdctx, inputx2[0], sizeof(inputx2[0]))
                || !sample_scalar(out++, mdctx))
                return 0;
        }
    }

    return 1;
}

static const OSSL_ML_KEM_SAMPLE_OPS ml_kem_sample_ppc64le= {
    matrix_expand2x_ppc64le
};
