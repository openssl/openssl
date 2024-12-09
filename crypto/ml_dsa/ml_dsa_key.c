/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include "ml_dsa_local.h"
#include "ml_dsa_key.h"
#include "ml_dsa_params.h"
#include "ml_dsa_matrix.h"

/**
 * @brief Create a new ML_DSA_KEY object
 *
 * @param libctx A OSSL_LIB_CTX object used for fetching algorithms.
 * @param alg The algorithm name associated with the key type
 * @returns The new ML_DSA_KEY object on success, or NULL on malloc failure
 */
ML_DSA_KEY *ossl_ml_dsa_key_new(OSSL_LIB_CTX *libctx, const char *alg)
{
    ML_DSA_KEY *ret;
    size_t sz;
    const ML_DSA_PARAMS *params = ossl_ml_dsa_params_get(alg);
    POLY *poly;

    if (params == NULL)
        return NULL;

    sz = sizeof(POLY) * (params->k * 3 + params->l);
    ret = OPENSSL_zalloc(sizeof(*ret) + sz);
    if (ret != NULL) {
        if (!CRYPTO_NEW_REF(&ret->references, 1)) {
            OPENSSL_free(ret);
            return NULL;
        }
        ret->libctx = libctx;
        ret->params = params;
        poly = (POLY *)((uint8_t *)ret + sizeof(*ret));
        vector_init(&ret->t0, poly, params->k);
        vector_init(&ret->t1, poly + params->k, params->k);
        vector_init(&ret->s2, poly + 2 * params->k, params->k);
        vector_init(&ret->s1, poly + 3 * params->k, params->l);
    }
    return ret;
}

/**
 * @brief Destroy a ML_DSA_KEY object
 */
void ossl_ml_dsa_key_free(ML_DSA_KEY *key)
{
    int i;

    if (key == NULL)
        return;

    CRYPTO_DOWN_REF(&key->references, &i);
    REF_PRINT_COUNT("ML_DSA_KEY", key);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    OPENSSL_free(key->pub_encoding);
    OPENSSL_free(key->priv_encoding);
    OPENSSL_free(key->propq);
    CRYPTO_FREE_REF(&key->references);
    OPENSSL_free(key);
}

/*
 * @brief Increase the reference count for a ML_DSA_KEY object.
 * @returns 1 on success or 0 otherwise.
 */
int ossl_ml_dsa_key_up_ref(ML_DSA_KEY *key)
{
    int i;

    if (CRYPTO_UP_REF(&key->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("ML_DSA_KEY", key);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

/**
 * @brief Are 2 keys equal?
 *
 * To be equal the keys must have the same key data and algorithm name.
 *
 * @param key1 A ML_DSA_KEY object
 * @param key2 A ML_DSA_KEY object
 * @param selection to select public and/or private component comparison.
 * @returns 1 if the keys are equal otherwise it returns 0.
 */
int ossl_ml_dsa_key_equal(const ML_DSA_KEY *key1, const ML_DSA_KEY *key2,
                          int selection)
{
    if (key1->params != key2->params)
        return 0;
    if (key1->pub_encoding != NULL) {
        if (key2->pub_encoding == NULL
                || memcmp(key1->pub_encoding, key1->pub_encoding,
                          key1->params->pk_len) != 0)
            return 0;
    } else if (key2->pub_encoding != NULL) {
        return 0;
    }
    if (key1->priv_encoding != NULL) {
        if (key2->priv_encoding == NULL
                || memcmp(key1->priv_encoding, key1->priv_encoding,
                          key1->params->sk_len) != 0)
            return 0;
    } else if (key2->priv_encoding != NULL) {
        return 0;
    }
    return 1;
}

int ossl_ml_dsa_key_has(const ML_DSA_KEY *key, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if (key->pub_encoding == NULL)
            return 0; /* No public key */
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                && key->priv_encoding == 0)
            return 0; /* No private key */
        return 1;
    }
    return 0;
}

/**
 * @brief Load a ML_DSA key from raw data.
 *
 * @param key An ML_DSA key to load into
 * @param params An array of parameters containing key data.
 * @param include_private Set to 1 to optionally include the private key data
 *                        if it exists.
 * @returns 1 on success, or 0 on failure.
 */
int ossl_ml_dsa_key_fromdata(ML_DSA_KEY *key, const OSSL_PARAM params[],
                             int include_private)
{
    const OSSL_PARAM *p = NULL;

    /* Private key is optional */
    if (include_private) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING
                    || !ossl_ml_dsa_sk_decode(p->data, p->data_size, key))
                return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING
                || !ossl_ml_dsa_pk_decode(p->data, p->data_size, key))
            return 0;
    }
    return 1;
}

/*
 * @brief Given a key containing private key values for rho, s1 & s2
 * generate the public value t and return the compressed values t1, t0.
 *
 * @param ctx A Object containing algorithm specific constants and hash contexts.
 * @param key A private key containing rh0, s1 & s2.
 * @param t1 The returned polynomial encoding of the 10 MSB of each coefficient
 *        of the uncompressed public key polynomial t.
 * @param t0 The returned polynomial encoding of the 13 LSB of each coefficient
 *        of the uncompressed public key polynomial t.
 * @returns 1 on success, or 0 on failure.
 */
static int public_from_private(ML_DSA_CTX *ctx, const ML_DSA_KEY *key,
                               VECTOR *t1, VECTOR *t0)
{
    const ML_DSA_PARAMS *params = ctx->params;
    POLY polys[ML_DSA_K_MAX + ML_DSA_L_MAX + ML_DSA_K_MAX * ML_DSA_L_MAX];
    MATRIX a_ntt;
    VECTOR s1_ntt;
    VECTOR t;

    vector_init(&t, polys, params->k);
    vector_init(&s1_ntt, polys + params->k, params->l);
    matrix_init(&a_ntt, polys + params->k + params->l, params->k, params->l);

    /* Using rho generate A' = A in NTT form */
    if (!ossl_ml_dsa_sample_expandA(ctx->g_ctx, key->rho, &a_ntt))
        return 0;

    /* t = NTT_inv(A' * NTT(s1)) + s2 */
    vector_copy(&s1_ntt, &key->s1);
    vector_ntt(&s1_ntt);

    ossl_ml_dsa_matrix_mult_vector(&a_ntt, &s1_ntt, &t);
    vector_ntt_inverse(&t);
    vector_add(&t, &key->s2, &t);

    /* Compress t */
    vector_power2_round(&t, t1, t0);

    /* Zeroize secret */
    vector_zero(&s1_ntt);
    return 1;
}

int ossl_ml_dsa_key_pairwise_check(const ML_DSA_KEY *key)
{
    int ret = 0;
    ML_DSA_CTX *ctx = NULL;
    VECTOR t1, t0;
    POLY polys[ML_DSA_K_MAX * 2];

    if (key->pub_encoding == NULL || key->priv_encoding == 0)
        return 0;

    ctx = ossl_ml_dsa_ctx_new(key->params->alg, key->libctx, key->propq);
    if (ctx == NULL)
        return 0;

    vector_init(&t1, polys, key->params->k);
    vector_init(&t0, polys + key->params->k, key->params->k);
    if (!public_from_private(ctx, key, &t1, &t0))
        goto err;

    ret = vector_equal(&t1, &key->t1) && vector_equal(&t0, &key->t0);
err:
    ossl_ml_dsa_ctx_free(ctx);
    return ret;
}

static int shake_xof(EVP_MD_CTX *ctx, const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t out_len)
{
    return (EVP_DigestInit_ex2(ctx, NULL, NULL) == 1
            && EVP_DigestUpdate(ctx, in, in_len) == 1
            && EVP_DigestFinalXOF(ctx, out, out_len) == 1);
}

/*
 * @brief Generate a public-private key pair from a seed.
 * See FIPS 204, Algorithm 6 ML-DSA.KeyGen_internal().
 *
 * @param entropy The input seed
 * @param entropy_len The size of entropy (Should be 32 bytes)
 *
 *
 * @returns 1 on success or 0 on failure.
 */
static int keygen_internal(ML_DSA_CTX *ctx, const uint8_t *seed, size_t seed_len,
                           ML_DSA_KEY *out)
{
    int ret = 0;
    uint8_t augmented_seed[ML_DSA_SEED_BYTES + 2];
    uint8_t expanded_seed[ML_DSA_RHO_BYTES + ML_DSA_PRIV_SEED_BYTES + ML_DSA_K_BYTES];
    const uint8_t *const rho = expanded_seed; /* p = Public Random Seed */
    const uint8_t *const priv_seed = expanded_seed + ML_DSA_RHO_BYTES;
    const uint8_t *const K = priv_seed + ML_DSA_PRIV_SEED_BYTES;
    const ML_DSA_PARAMS *params = ctx->params;

    /* augmented_seed = seed || k || l */
    memcpy(augmented_seed, seed, seed_len);
    augmented_seed[ML_DSA_SEED_BYTES] = (uint8_t)params->k;
    augmented_seed[ML_DSA_SEED_BYTES + 1] = (uint8_t)params->l;
    /* Expand the seed into p[32], p'[64], K[32] */
    if (!shake_xof(ctx->h_ctx, augmented_seed, sizeof(augmented_seed),
                   expanded_seed, sizeof(expanded_seed)))
        goto err;

    memcpy(out->rho, rho, sizeof(out->rho));
    memcpy(out->K, K, sizeof(out->K));

    ret = ossl_ml_dsa_sample_expandS(ctx->h_ctx, params->eta, priv_seed,
                                     &out->s1, &out->s2)
        && public_from_private(ctx, out, &out->t1, &out->t0)
        && ossl_ml_dsa_pk_encode(out)
        && shake_xof(ctx->h_ctx, out->pub_encoding, out->params->pk_len,
                     out->tr, sizeof(out->tr))
        && ossl_ml_dsa_sk_encode(out);
err:
    OPENSSL_cleanse(augmented_seed, sizeof(augmented_seed));
    OPENSSL_cleanse(expanded_seed, sizeof(expanded_seed));
    return ret;
}

int ossl_ml_dsa_generate_key(ML_DSA_CTX *ctx, OSSL_LIB_CTX *lib_ctx,
                             const uint8_t *entropy, size_t entropy_len,
                             ML_DSA_KEY *out)
{
    int ret = 0;
    uint8_t seed[32];
    size_t seed_len = sizeof(seed);

    if (ctx->params != out->params)
        return 0;

    if (entropy != NULL && entropy_len != 0) {
        if (entropy_len < seed_len)
            goto err;
        memcpy(seed, entropy, seed_len);
    } else {
        if (RAND_priv_bytes_ex(lib_ctx, seed, seed_len, 0) <= 0)
            goto err;
    }
    ret = keygen_internal(ctx, seed, seed_len, out);
err:
    OPENSSL_cleanse(seed, seed_len);
    return ret;
}

/**
 * @brief This is used when a ML DSA key is used for an operation.
 * This checks that the algorithm is the same (i.e. uses the same parameters)
 *
 * @param ctx Contains ML_DSA algorithm functions and constants to be used for
 *            an operation.
 * @param key A ML_DSA key to use for an operation.
 *
 * @returns 1 if the algorithm matches, or 0 otherwise.
 */
int ossl_ml_dsa_key_type_matches(ML_DSA_CTX *ctx, const ML_DSA_KEY *key)
{
    return (key->params == ctx->params);
}

/* Returns the public key data or NULL if there is no public key */
const uint8_t *ossl_ml_dsa_key_get_pub(const ML_DSA_KEY *key)
{
    return key->pub_encoding;
}

/* Returns the constant 2 * |n| which is the size of PK_SEED + PK_ROOT */
size_t ossl_ml_dsa_key_get_pub_len(const ML_DSA_KEY *key)
{
    return key->params->pk_len;
}

size_t ossl_ml_dsa_key_get_collision_strength_bits(const ML_DSA_KEY *key)
{
    return key->params->strength;
}

/* Returns the private key data or NULL if there is no private key */
const uint8_t *ossl_ml_dsa_key_get_priv(const ML_DSA_KEY *key)
{
    return key->priv_encoding;
}

size_t ossl_ml_dsa_key_get_priv_len(const ML_DSA_KEY *key)
{
    return key->params->sk_len;
}

size_t ossl_ml_dsa_key_get_sig_len(const ML_DSA_KEY *key)
{
    return key->params->sig_len;
}
void ossl_ml_dsa_key_set0_libctx(ML_DSA_KEY *key, OSSL_LIB_CTX *lib_ctx)
{
    key->libctx = lib_ctx;
}

const char *ossl_ml_dsa_key_get_name(const ML_DSA_KEY *key)
{
    return key->params->alg;
}

int ossl_ml_dsa_set_priv(ML_DSA_KEY *key, const uint8_t *priv, size_t priv_len)
{
    return 0;
}

int ossl_ml_dsa_set_pub(ML_DSA_KEY *key, const uint8_t *pub, size_t pub_len)
{
    return 0;
}
