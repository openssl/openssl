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
 * @brief Compute a candidate XMSS public key from a message and XMSS signature
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
