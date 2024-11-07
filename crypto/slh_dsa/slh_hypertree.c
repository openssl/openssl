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

#define SLH_XMSS_SIG_LEN(n, hm) ((SLH_WOTS_LEN(n) + (hm)) * (n))

/**
 * @brief Generate a Hypertree Signature
 * See FIPS 205 Section 7.1 Algorithm 12
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param msg A message of size |n|.
 * @param sk_seed The private key seed of size |n|
 * @param pk_seed The public key seed of size |n|
 * @param tree_id Index of the XMSS tree that will sign the message
 * @param leaf_id Index of the WOTS+ key within the XMSS tree that will signed the message
 * @param sig The returned Hypertree Signature (which is |d| XMSS signatures)
 * @param sig_len The size of |sig| which is (|h| + |d| * |len|) * |n|)
 * @returns 1 on success, or 0 on error.
 */
int ossl_slh_ht_sign(SLH_DSA_CTX *ctx,
                     const uint8_t *msg, const uint8_t *sk_seed,
                     const uint8_t *pk_seed,
                     uint64_t tree_id, uint32_t leaf_id,
                     uint8_t *sig, size_t sig_len)
{
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_DECLARE(adrs);
    uint8_t root[SLH_MAX_N];
    uint32_t layer, mask;
    uint32_t n = ctx->params->n;
    uint32_t d = ctx->params->d;
    uint32_t hm = ctx->params->hm;
    uint8_t *psig = sig;
    size_t xmss_sig_len = SLH_XMSS_SIG_LEN(n, hm);

    mask = (1 << hm) - 1; /* A mod 2^h = A & ((2^h - 1))) */

    adrsf->zero(adrs);
    memcpy(root, msg, n);

    for (layer = 0; layer < d; ++layer) {
        adrsf->set_layer_address(adrs, layer);
        adrsf->set_tree_address(adrs, tree_id);
        if (!ossl_slh_xmss_sign(ctx, root, sk_seed, leaf_id, pk_seed, adrs,
                                psig, xmss_sig_len))
            return 0;
        if (layer < d - 1) {
            if (!ossl_slh_xmss_pk_from_sig(ctx, leaf_id, psig, root,
                                           pk_seed, adrs, root))
                return 0;
        }
        psig += xmss_sig_len;
        leaf_id = tree_id & mask;
        tree_id >>= hm;
    }
    assert((size_t)(psig - sig) == sig_len);
    return 1;
}

/**
 * @brief Verify a Hypertree Signature
 * See FIPS 205 Section 7.2 Algorithm 13
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param msg A message of size |n| bytes
 * @param sig A HT signature of size (|h| + |d| * |len|) * |n| bytes
 * @param pk_seed SLH_DSA public key seed of size |n|
 * @param tree_id Index of the XMSS tree that signed the message
 * @param leaf_id Index of the WOTS+ key within the XMSS tree that signed the message
 * @param pk_root The known Hypertree public key of size |n|
 *
 * @returns 1 if the computed XMSS public key matches pk_root, or 0 otherwise.
 */
int ossl_slh_ht_verify(SLH_DSA_CTX *ctx, const uint8_t *msg, const uint8_t *sig,
                       const uint8_t *pk_seed, uint64_t tree_id, uint32_t leaf_id,
                       const uint8_t *pk_root)
{
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_DECLARE(adrs);
    uint8_t node[SLH_MAX_N];
    uint32_t layer, len, mask, d, n, tree_height;
    const SLH_DSA_PARAMS *params = ctx->params;

    tree_height = params->hm;
    n = params->n;
    d = params->d;
    len = SLH_XMSS_SIG_LEN(n, tree_height);
    mask = (1 << tree_height) - 1;

    adrsf->zero(adrs);
    memcpy(node, msg, n);

    for (layer = 0; layer < d; ++layer) {
        adrsf->set_layer_address(adrs, layer);
        adrsf->set_tree_address(adrs, tree_id);
        if (!ossl_slh_xmss_pk_from_sig(ctx, leaf_id, sig, node,
                                       pk_seed, adrs, node))
            return 0;
        sig += len;
        leaf_id = tree_id & mask;
        tree_id >>= tree_height;
    }
    return (memcmp(node, pk_root, n) == 0);
}
