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

/**
 * @brief Compute the root Public key of a XMSS tree.
 * See FIPS 205 Section 6.1 Algorithm 9.
 * This is a recursive function that starts at an leaf index, that calculates
 * the hash of each parent using 2 child nodes.
 *
 * @param sk_seed A private key seed
 * @param pk_seed A public key seed
 * @param n The size of |sk_seed|, |pk_seed| and |pk_out|
 * @param adrs An ADRS object containing the layer address and tree address set
 *             to the XMSS tree within which the XMSS tree is being computed.
 * @param nodeid The index of the target node being computed
 *               (which must be < 2^(hm - height)
 * @param height The height within the tree of the node being computed.
 *               (which must be <= hm) (hm is one of 3, 4, 8 or 9)
 *               At height=0 There are 2^hm leaf nodes,
 *               and the root node is at height = hm)
 * @param pk_out The generated public key of size |n|
 */
void ossl_slh_xmss_node(SLH_DSA_CTX *ctx,
                        const uint8_t *sk_seed,
                        uint32_t node_id,
                        uint32_t h,
                        const uint8_t *pk_seed,
                        SLH_ADRS adrs,
                        uint8_t *pk_out)
{
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);

    if (h == 0) {
        /* For leaf nodes generate the public key */
        adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_WOTS_HASH);
        adrsf->set_keypair_address(adrs, node_id);
        ossl_slh_wots_pk_gen(ctx, sk_seed, pk_seed, adrs, pk_out);
    } else {
        uint8_t lnode[SLH_MAX_N], rnode[SLH_MAX_N];

        ossl_slh_xmss_node(ctx, sk_seed, 2 * node_id, h - 1, pk_seed, adrs,
                           lnode);
        ossl_slh_xmss_node(ctx, sk_seed, 2 * node_id + 1, h - 1, pk_seed, adrs,
                           rnode);
        adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_TREE);
        adrsf->set_tree_height(adrs, h);
        adrsf->set_tree_index(adrs, node_id);
        ctx->hash_func->H(&ctx->hash_ctx, pk_seed, adrs, lnode, rnode, pk_out);
    }
}

/**
 * @brief Generate an XMSS signature using a message and key.
 * See FIPS 205 Section 6.2 Algorithm 10
 *
 * @param msg A message of size |n| bytes to sign
 * @param sk_seed A private key seed
 * @param pk_seed A public key seed
 * @param n The size of |msg|, |sk_seed| and |pk_seed|
 * @param adrs An ADRS object containing the layer address and tree address set
 *              to the XMSS key being used to sign the message.
 * @param node_id The index of a WOTS+ key within the XMSS tree to use for signing.
 * @param tree_height The height of the XMSS tree.
 * @param sig_out The generated XMSS signature which consists of a WOTS+
 *                 signature of size [2 * n + 3][n] followed by an authentication
 *                 path of size [tree_height[n].
 */
void ossl_slh_xmss_sign(SLH_DSA_CTX *ctx, const uint8_t *msg,
                        const uint8_t *sk_seed, uint32_t node_id,
                        const uint8_t *pk_seed, SLH_ADRS adrs,
                        uint8_t *sig, size_t sig_len)
{
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    uint32_t h, id = node_id;
    size_t n = ctx->params->n;
    uint32_t hm = ctx->params->hm;
    size_t wots_sig_len = n * SLH_WOTS_LEN(n);
    uint8_t *auth_path = sig + wots_sig_len;
/*
    size_t auth_sig_len = n * hm;
    assert(sig_len == (wots_sig_len + auth_sig_len));
*/
    for (h = 0; h < hm; ++h) {
        ossl_slh_xmss_node(ctx, sk_seed, id ^ 1, h, pk_seed, adrs, auth_path);
        id >>= 1;
        auth_path += n;
    }
    adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_WOTS_HASH);
    adrsf->set_keypair_address(adrs, node_id);
    ossl_slh_wots_sign(ctx, msg, sk_seed, pk_seed, adrs, sig, wots_sig_len);
}

/**
 * @brief Compute a candidate XMSS public key from a message and XMSS signature
 * See FIPS 205 Section 6.3 Algorithm 11
 *
 * @param sig A XMSS signature which consists of a WOTS+ signature of
 *            [2 * n + 3][n] bytes followed by an authentication path of
 *            [hm][n] bytes (where hm is the height of the XMSS tree).
 * @param msg A message of size |n| bytes
 * @param sk_seed A private key seed
 * @param pk_seed A public key seed
 * @param n The hash size size if the size of |msg|, |sk_seed| and |pk_seed|
 * @param adrs An ADRS object containing a layer address and tress address of an
 *             XMSS key used for signing the message.
 * @param node_id Must be set to the |node_id| used in xmss_sign().
 * @param tree_height The height of the XMSS tree.
 * @param pk_out The returned candidate XMSS public key of size |n|.
 */
void ossl_slh_xmss_pk_from_sig(SLH_DSA_CTX *ctx, uint32_t node_id,
                               const uint8_t *sig, const uint8_t *msg,
                               const uint8_t *pk_seed, SLH_ADRS adrs,
                               uint8_t *pk_out)
{
    SLH_HASH_FUNC_DECLARE(ctx, hashf, hctx);
    SLH_HASH_FN_DECLARE(hashf, H);
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_FN_DECLARE(adrsf, set_tree_index);
    SLH_ADRS_FN_DECLARE(adrsf, set_tree_height);
    uint32_t k;
    size_t n = ctx->params->n;
    uint32_t hm = ctx->params->hm;
    size_t wots_sig_len = n * SLH_WOTS_LEN(n);
    const uint8_t *auth_path = sig + wots_sig_len;
    uint8_t *node = pk_out;

    adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_WOTS_HASH);
    adrsf->set_keypair_address(adrs, node_id);
    ossl_slh_wots_pk_from_sig(ctx, sig, msg, pk_seed, adrs, node);

    adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_TREE);

    for (k = 0; k < hm; ++k) {
        set_tree_height(adrs, k + 1);
        if ((node_id & 1) == 0) { /* even */
            node_id >>= 1;
            set_tree_index(adrs, node_id);
            H(hctx, pk_seed, adrs, node, auth_path, node);
        } else { /* odd */
            node_id = (node_id - 1) >> 1;
            set_tree_index(adrs, node_id);
            H(hctx, pk_seed, adrs, auth_path, node, node);
        }
        auth_path += n;
    }
}
