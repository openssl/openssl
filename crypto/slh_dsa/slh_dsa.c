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

/**
 * @brief SLH-DSA Signature generation
 * See FIPS 205 Section 9.2 Algorithm 19
 *
 * A signature consists of
 *   r[n] random bytes
 *   [k]*[1+a][n] FORS signature bytes
 *   [h + d*len][n] Hyper tree signature bytes
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param priv The private SLH_DSA key to use for signing.
 * @param msg The message to sign. This may be encoded beforehand.
 * @param msg_len The size of |msg|
 * @param sig The returned signature
 * @param sig_len The size of the returned |sig|
 * @param sig_size The maximum size of |sig|
 * @param opt_rand An optional random value to use of size |n|. It can be NULL.
 * @returns 1 if the signature generation succeeded or 0 otherwise.
 */
static int slh_sign_internal(SLH_DSA_CTX *ctx, const SLH_DSA_KEY *priv,
                             const uint8_t *msg, size_t msg_len,
                             uint8_t *sig, size_t *sig_len, size_t sig_size,
                             const uint8_t *opt_rand)
{
    const SLH_DSA_PARAMS *params = ctx->params;
    uint32_t n = params->n;
    size_t r_len = n;
    size_t sig_fors_len = SLH_SIG_FORS_LEN(params->k, params->a, n);
    size_t sig_ht_len = SLH_SIG_HT_LEN(params->h, params->d, n);
    size_t sig_len_expected = r_len + sig_fors_len + sig_ht_len;
    SLH_HASH_FUNC_DECLARE(ctx, hashf, hctx);
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_DECLARE(adrs);
    uint64_t tree_id;
    uint32_t leaf_id;
    uint8_t pk_fors[SLH_MAX_N];
    uint8_t m_digest[SLH_MAX_M];
    uint8_t *r = sig;
    uint8_t *sig_fors = r + r_len;
    uint8_t *sig_ht = sig_fors + sig_fors_len;
    const uint8_t *md, *pk_seed, *sk_seed;

    if (sig_len != NULL)
        *sig_len = sig_len_expected;

    if (sig == NULL)
        return (sig_len != NULL);

    if (sig_size < sig_len_expected)
        return 0;
    /* Exit if private key is not set */
    if (priv->has_priv == 0)
        return 0;

    pk_seed = SLH_DSA_PK_SEED(priv);
    sk_seed = SLH_DSA_SK_SEED(priv);

    if (opt_rand == NULL)
        opt_rand = pk_seed;

    adrsf->zero(adrs);
    /* calculate Randomness value r, and output to the signature */
    if (!hashf->PRF_MSG(hctx, SLH_DSA_SK_PRF(priv), opt_rand, msg, msg_len, r)
            /* generate a digest of size |params->m| bytes where m is (30..49) */
            || !hashf->H_MSG(hctx, r, pk_seed, SLH_DSA_PK_ROOT(priv), msg, msg_len,
                             m_digest))
        return 0;
    /* Grab selected bytes from the digest to select tree and leaf id's */
    get_tree_ids(m_digest, params, &tree_id, &leaf_id);

    adrsf->set_tree_address(adrs, tree_id);
    adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_FORS_TREE);
    adrsf->set_keypair_address(adrs, leaf_id);

    /* generate the FORS signature and append it to the signature */
    md = m_digest;
    return ossl_slh_fors_sign(ctx, md, sk_seed, pk_seed, adrs, sig_fors, sig_fors_len)
        /* Calculate the FORS public key */
        && ossl_slh_fors_pk_from_sig(ctx, sig_fors, md, pk_seed, adrs, pk_fors)
        && ossl_slh_ht_sign(ctx, pk_fors, sk_seed, pk_seed, tree_id, leaf_id,
                            sig_ht, sig_ht_len);
}

/**
 * @brief SLH-DSA Signature verification
 * See FIPS 205 Section 9.3 Algorithm 20
 *
 * A signature consists of
 *   r[n] random bytes
 *   [k]*[1+a][n] FORS signature bytes
 *   [h + d*len][n] Hyper tree signature bytes
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param pub The public SLH_DSA key to use for verification.
 * @param msg The message to verify. This may be encoded beforehand.
 * @param msg_len The size of |msg|
 * @param sig A signature to verify
 * @param sig_len The size of |sig|
 * @returns 1 if the signature verification succeeded or 0 otherwise.
 */
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

    if (!hashf->H_MSG(hctx, r, pk_seed, pk_root, msg, msg_len, mdigest))
        return 0;
    md = mdigest;
    get_tree_ids(mdigest, params, &tree_id, &leaf_id);

    adrsf->set_tree_address(adrs, tree_id);
    adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_FORS_TREE);
    adrsf->set_keypair_address(adrs, leaf_id);
    return ossl_slh_fors_pk_from_sig(ctx, sig_fors, md, pk_seed, adrs, pk_fors)
        && ossl_slh_ht_verify(ctx, pk_fors, sig_ht, pk_seed,
                              tree_id, leaf_id, pk_root);
}

/**
 * @brief Encode a message
 * See FIPS 205 Algorithm 22 Step 8 (and algorithm 24 Step 4).
 *
 * SLH_DSA pure signatures are encoded as M' = 00 || ctx_len || ctx || msg
 * Where ctx is the empty string by default and ctx_len <= 255.
 *
 * @param msg A message to encode
 * @param msg_len The size of |msg|
 * @param ctx An optional context to add to the message encoding.
 * @param ctx_len The size of |ctx|. It must be in the range 0..255
 * @param encode Use the Pure signature encoding if this is 1, and dont encode
 *               if this value is 0.
 * @param tmp A small buffer that may be used if the message is small.
 * @param tmp_len The size of |tmp|
 * @param out_len The size of the returned encoded buffer.
 * @returns A buffer containing the encoded message. If the passed in
 * |tmp| buffer is big enough to hold the encoded message then it returns |tmp|
 * otherwise it allocates memory which must be freed by the caller. If |encode|
 * is 0 then it returns |msg|. NULL is returned if there is a failure.
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
        return NULL;

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

/**
 * See FIPS 205 Section 10.2.1 Algorithm 22
 * @returns 1 on success, or 0 on error.
 */
int ossl_slh_dsa_sign(SLH_DSA_CTX *slh_ctx, const SLH_DSA_KEY *priv,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *ctx, size_t ctx_len,
                      const uint8_t *add_rand, int encode,
                      unsigned char *sig, size_t *siglen, size_t sigsize)
{
    uint8_t m_tmp[1024], *m = m_tmp;
    size_t m_len = 0;
    int ret = 0;

    if (sig != NULL) {
        m = msg_encode(msg, msg_len, ctx, ctx_len, encode, m_tmp, sizeof(m_tmp),
                       &m_len);
        if (m == NULL)
            return 0;
    }
    ret = slh_sign_internal(slh_ctx, priv, m, m_len, sig, siglen, sigsize, add_rand);
    if (m != msg && m != m_tmp)
        OPENSSL_free(m);
    return ret;
}

/**
 * See FIPS 205 Section 10.3 Algorithm 24
 * @returns 1 on success, or 0 on error.
 */
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

/* See FIPS 205 Algorithm 2 toInt(X, n) */
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
