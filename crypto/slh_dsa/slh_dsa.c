/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "slh_dsa_local.h"
#include "slh_dsa_key.h"

#define SLH_MAX_M 49

/* (n + SLH_SIG_FORS_LEN(k, a, n) + SLH_SIG_HT_LEN(n, hm, d)) */
#define SLH_SIG_RANDOM_LEN(n)      (n)
#define SLH_SIG_FORS_LEN(k, a, n)  (n) * ((k) * (1 + (a)))
#define SLH_SIG_HT_LEN(h, d, n)    (n) * ((h) + (d) * SLH_WOTS_LEN(n))

static void get_tree_ids(const uint8_t *digest, const SLH_DSA_PARAMS *params,
                         uint64_t *tree_id, uint32_t *leaf_id);

static int slh_verify_internal(SLH_DSA_CTX *ctx, const SLH_DSA_KEY *pub,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len)
{
    SLH_HASH_FUNC_DECLARE(ctx, hashf, hctx);
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_DECLARE(adrs);
    uint8_t mdigest[SLH_MAX_M];
    uint8_t pk_fors[SLH_MAX_N];
    uint64_t tree_id;
    uint32_t leaf_id;
    const SLH_DSA_PARAMS *params = ctx->params;
    uint32_t n = params->n;
    size_t r_len = SLH_SIG_RANDOM_LEN(n);
    size_t sig_fors_len = SLH_SIG_FORS_LEN(params->k, params->a, n);
    size_t sig_ht_len = SLH_SIG_HT_LEN(params->h, params->d, n);
    const uint8_t *r, *sig_fors, *sig_ht, *md, *pk_seed, *pk_root;

    if (sig_len != (r_len + sig_fors_len + sig_ht_len))
        return 0;
    /* Exit if public key is not set */
    if (pub->key_len == 0)
        return 0;

    adrsf->zero(adrs);

    r = sig;
    sig_fors = r + r_len;
    sig_ht = sig_fors + sig_fors_len;

    pk_seed = SLH_DSA_PK_SEED(pub);
    pk_root = SLH_DSA_PK_ROOT(pub);

    hashf->H_MSG(hctx, r, pk_seed, pk_root, msg, msg_len, mdigest);
    md = mdigest;
    get_tree_ids(mdigest, params, &tree_id, &leaf_id);

    adrsf->set_tree_address(adrs, tree_id);
    adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_FORS_TREE);
    adrsf->set_keypair_address(adrs, leaf_id);
    ossl_slh_fors_pk_from_sig(ctx, sig_fors, md, pk_seed, adrs, pk_fors);
    return ossl_slh_ht_verify(ctx, pk_fors, sig_ht, pk_seed, tree_id, leaf_id, pk_root);
}

/*
 * Pure signatures M' function
 * ctx is the empty string by default.
 */
static uint8_t *msg_encode(const uint8_t *msg, size_t msg_len,
                           const uint8_t *ctx, size_t ctx_len, int encode,
                           uint8_t *tmp, size_t tmp_len, size_t *out_len)
{
    uint8_t *encoded = NULL;
    size_t encoded_len;

    if (encode == 0) {
        /* Raw message */
        *out_len = msg_len;
        return (uint8_t *)msg;
    }
    if (ctx_len > SLH_DSA_MAX_CONTEXT_STRING_LEN)
        return 0;

    /* Pure encoding */
    encoded_len = 1 + 1 + ctx_len + msg_len;
    *out_len = encoded_len;
    if (encoded_len <= tmp_len) {
        encoded = tmp;
    } else {
        encoded = OPENSSL_zalloc(encoded_len);
        if (encoded == NULL)
            return NULL;
    }
    encoded[0] = 0;
    encoded[1] = (uint8_t)ctx_len;
    memcpy(&encoded[2], ctx, ctx_len);
    memcpy(&encoded[2 + ctx_len], msg, msg_len);
    return encoded;
}

int ossl_slh_dsa_verify(SLH_DSA_CTX *slh_ctx, const SLH_DSA_KEY *pub,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *ctx, size_t ctx_len, int encode,
                        const uint8_t *sig, size_t sig_len)
{
    uint8_t *m;
    size_t m_len;
    uint8_t m_tmp[1024];
    int ret = 0;

    m = msg_encode(msg, msg_len, ctx, ctx_len, encode, m_tmp, sizeof(m_tmp),
                   &m_len);
    if (m == NULL)
        return 0;

    ret = slh_verify_internal(slh_ctx, pub, m, m_len, sig, sig_len);
    if (m != msg && m != m_tmp)
        OPENSSL_free(m);
    return ret;
}

/* FIPS 205 Algorithm 2 toInt(X, n) */
static uint64_t bytes_to_u64_be(const uint8_t *in, size_t in_len)
{
    size_t i;
    uint64_t total = 0;

    for (i = 0; i < in_len; i++)
        total = (total << 8) + *in++;
    return total;
}

/*
 * See Algorithm 19 Steps 7..10 (also Algorithm 20 Step 10..13).
 * Converts digested bytes into a tree index, and leaf index within the tree.
 * The sizes are determined by the |params| parameter set.
 */
static void get_tree_ids(const uint8_t *digest, const SLH_DSA_PARAMS *params,
                         uint64_t *tree_id, uint32_t *leaf_id)
{
    const uint8_t *tree_id_bytes, *leaf_id_bytes;
    uint32_t md_len, tree_id_len, leaf_id_len;
    uint64_t tree_id_mask, leaf_id_mask;

    md_len = ((params->k * params->a + 7) >> 3); /* 21..40 bytes */
    tree_id_len = ((params->h - params->hm + 7) >> 3); /* 7 or 8 bytes */
    leaf_id_len = ((params->hm + 7) >> 3); /* 1 or 2 bytes */

    tree_id_bytes = digest + md_len;
    leaf_id_bytes = tree_id_bytes + tree_id_len;

    assert((md_len + tree_id_len + leaf_id_len) == params->m);
    /*
     * In order to calculate A mod (2^X) where X is in the range of (54..64)
     * This is equivalent to A & (2^x - 1) which is just a sequence of X ones
     * that must fit into a 64 bit value.
     * e.g when X = 64 it would be A & (0xFFFF_FFFF_FFFF_FFFF)
     *     when X = 54 it would be A & (0x3F_FFFF_FFFF_FFFF)
     * i.e. A & (0xFFFF_FFFF_FFFF_FFFF >> (64 - X))
     */
    tree_id_mask = ((uint64_t)-1) >> (64 - (params->h - params->hm));
    leaf_id_mask = (1 << params->hm) - 1; /* max value is 0x1FF when hm = 9 */
    *tree_id = bytes_to_u64_be(tree_id_bytes, tree_id_len) & tree_id_mask;
    *leaf_id = (uint32_t)(bytes_to_u64_be(leaf_id_bytes, leaf_id_len) & leaf_id_mask);
}
