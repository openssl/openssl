/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include "slh_dsa_local.h"

/* k = 14, 17, 22, 33, 35 (number of trees) */
#define SLH_MAX_K           35
/* a = 6, 8, 9, 12 or 14  - There are (2^a) merkle trees */
#define SLH_MAX_A           9

#define SLH_MAX_K_TIMES_A      (SLH_MAX_A * SLH_MAX_K)
#define SLH_MAX_ROOTS          (SLH_MAX_K_TIMES_A * SLH_MAX_N)

static void slh_base_2b(const uint8_t *in, uint32_t b, uint32_t *out, size_t out_len);

/**
 * @brief Compute a candidatr FORS public key from a message and signature.
 * See FIPS 205 Section 8.4 Algorithm 17.
 *
 * @param sig A FORS signature of size (k * (a + 1) * n) bytes
 * @param md A message digest of size (k * a / 8) bytes
 * @param pk_seed A public key seed of size |n|
 * @param adrs An ADRS object containing
 * @param pk_out The returned
 */
void ossl_slh_fors_pk_from_sig(SLH_DSA_CTX *ctx, const uint8_t *sig,
                               const uint8_t *md, const uint8_t *pk_seed,
                               SLH_ADRS adrs, uint8_t *pk_out)
{
    SLH_ADRS_DECLARE(pk_adrs);
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_FN_DECLARE(adrsf, set_tree_index);
    SLH_ADRS_FN_DECLARE(adrsf, set_tree_height);
    SLH_HASH_FUNC_DECLARE(ctx, hashf, hctx);
    SLH_HASH_FN_DECLARE(hashf, F);
    SLH_HASH_FN_DECLARE(hashf, H);
    uint32_t i, j, aoff = 0;
    uint32_t ids[SLH_MAX_K];
    uint8_t roots[SLH_MAX_ROOTS], *node = roots;
    const SLH_DSA_PARAMS *params = ctx->params;
    uint32_t a = params->a;
    uint32_t k = params->k;
    uint32_t n = params->n;
    uint32_t two_power_a = (1 << a);

    /* Split md into k a-bit values e.g ids[0..k-1] = 12 bits each of md */
    slh_base_2b(md, a, ids, k);

    /* Compute the roots of k Merkle trees */
    for (i = 0; i < k; ++i) {
        uint32_t id = ids[i];
        uint32_t node_id = id + aoff;

        set_tree_height(adrs, 0);
        set_tree_index(adrs, node_id);
        F(hctx, pk_seed, adrs, sig, n, node);
        sig += n;

        for (j = 0; j < a; ++j) {
            set_tree_height(adrs, j + 1);
            if ((id & 1) == 0) {
                node_id >>= 1;
                set_tree_index(adrs, node_id);
                H(hctx, pk_seed, adrs, node, sig, node);
            } else {
                node_id = (node_id - 1) >> 1;
                set_tree_index(adrs, node_id);
                H(hctx, pk_seed, adrs, sig, node, node);
            }
            id >>= 1;
            sig += n;
        }
        aoff += two_power_a;
        node += n;
    }
    assert((size_t)(node - roots) <= sizeof(roots));

    /* The public key is the hash of all the roots of the k trees */
    adrsf->copy(pk_adrs, adrs);
    adrsf->set_type_and_clear(pk_adrs, SLH_ADRS_TYPE_FORS_ROOTS);
    adrsf->copy_keypair_address(pk_adrs, adrs);
    hashf->T(hctx, pk_seed, pk_adrs, roots, node - roots, pk_out);
}

/**
 * @brief Convert a byte string into a base 2^b representation
 * (See FIPS 205 Algorithm 4)
 *
 * @param in An input byte stream with a size >= |outlen * b / 8|
 * @param b The bit size to divide |in| into
 *          This is one of 6, 8, 9, 12 or 14 for FORS.
 * @param out The array of returned base-2^b integers that represents the first
 *            |outlen|*|b| bits of |in|
 * @param outlen The size of |out|
 *
 */
static void slh_base_2b(const uint8_t *in, uint32_t b, uint32_t *out, size_t out_len)
{
    size_t consumed = 0;
    uint32_t bits = 0;
    uint32_t total = 0;
    uint32_t mask = (1 << b) - 1;

    for (consumed = 0; consumed < out_len; consumed++) {
        while (bits < b) {
            total <<= 8;
            total += *in++;
            bits += 8;
        }
        bits -= b;
        *out++ = (total >> bits) & mask;
    }
}
