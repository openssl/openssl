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
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include "slh_dsa_local.h"
#include "slh_dsa_key.h"
#include "internal/encoder.h"

static int slh_dsa_compute_pk_root(SLH_DSA_CTX *ctx, SLH_DSA_KEY *out,
                                   int verify);

/**
 * @brief Create a new SLH_DSA_KEY object
 *
 * @param libctx A OSSL_LIB_CTX object used for fetching algorithms.
 * @param alg The algorithm name associated with the key type
 * @returns The new SLH_DSA_KEY object on success, or NULL on malloc failure
 */
SLH_DSA_KEY *ossl_slh_dsa_key_new(OSSL_LIB_CTX *libctx, const char *alg)
{
    SLH_DSA_KEY *ret;
    const SLH_DSA_PARAMS *params = ossl_slh_dsa_params_get(alg);

    if (params == NULL)
        return NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret != NULL) {
        if (!CRYPTO_NEW_REF(&ret->references, 1)) {
            OPENSSL_free(ret);
            return NULL;
        }
        ret->libctx = libctx;
        ret->params = params;
    }
    return ret;
}

/**
 * @brief Destroy a SLH_DSA_KEY object
 */
void ossl_slh_dsa_key_free(SLH_DSA_KEY *key)
{
    int i;

    if (key == NULL)
        return;

    CRYPTO_DOWN_REF(&key->references, &i);
    REF_PRINT_COUNT("SLH_DSA_KEY", key);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    OPENSSL_cleanse(&key->priv, sizeof(key->priv) >> 1);
    OPENSSL_free(key->propq);
    CRYPTO_FREE_REF(&key->references);
    OPENSSL_free(key);
}

/*
 * @brief Increase the reference count for a SLH_DSA_KEY object.
 * @returns 1 on success or 0 otherwise.
 */
int ossl_slh_dsa_key_up_ref(SLH_DSA_KEY *key)
{
    int i;

    if (CRYPTO_UP_REF(&key->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("SLH_DSA_KEY", key);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

/**
 * @brief Are 2 keys equal?
 *
 * To be equal the keys must have the same key data and algorithm name.
 *
 * @param key1 A SLH_DSA_KEY object
 * @param key2 A SLH_DSA_KEY object
 * @param selection to select public and/or private component comparison.
 * @returns 1 if the keys are equal otherwise it returns 0.
 */
int ossl_slh_dsa_key_equal(const SLH_DSA_KEY *key1, const SLH_DSA_KEY *key2,
                           int selection)
{
    int ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        /* The parameter sets must match - i.e. The same algorithm name */
        if (key1->params != key2->params)
            return 0;
        /*
         * If both keys dont have a public key return 1
         * If only one of the keys has a public key return 0.
         */
        if (key1->pub == NULL)
            return (key2->pub == NULL);
        else if (key2->pub == NULL)
            return 0;
        /*
         * Gets here if both keys have a public key
         * Since the public key always exists with the private key, check either
         * that the private key matches (which includes the public key) OR
         * check that the public key matches depending on the selection.
         */
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            ok = ok && (key1->has_priv == key2->has_priv);
            if (key1->has_priv)
                ok = ok && (memcmp(key1->priv, key2->priv,
                                   ossl_slh_dsa_key_get_priv_len(key1)) == 0);
        } else {
            ok = ok && (memcmp(key1->pub, key2->pub,
                               ossl_slh_dsa_key_get_pub_len(key1)) == 0);
        }
    }
    return ok;
}

int ossl_slh_dsa_key_has(const SLH_DSA_KEY *key, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if (key->pub == NULL)
            return 0; /* No public key */
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                && key->has_priv == 0)
            return 0; /* No private key */
        return 1;
    }
    return 0;
}

int ossl_slh_dsa_key_pairwise_check(const SLH_DSA_KEY *key)
{
    int ret;
    SLH_DSA_CTX *ctx = NULL;

    if (key->pub == NULL || key->has_priv == 0)
        return 0;

    ctx = ossl_slh_dsa_ctx_new(key->params->alg, key->libctx, key->propq);
    if (ctx == NULL)
        return 0;
    ret = slh_dsa_compute_pk_root(ctx, (SLH_DSA_KEY *)key, 1);
    ossl_slh_dsa_ctx_free(ctx);
    return ret;
}

/**
 * @brief Load a SLH_DSA key from raw data.
 *
 * @param key An SLH_DSA key to load into
 * @param params An array of parameters containing key data.
 * @param include_private Set to 1 to optionally include the private key data
 *                        if it exists.
 * @returns 1 on success, or 0 on failure.
 */
int ossl_slh_dsa_key_fromdata(SLH_DSA_KEY *key, const OSSL_PARAM params[],
                              int include_private)
{
    size_t priv_len, key_len, data_len = 0;
    const OSSL_PARAM *param_priv = NULL, *param_pub = NULL;
    void *p;

    if (key == NULL)
        return 0;

    /* The private key consists of 4 elements SK_SEED, SK_PRF, PK_SEED and PK_ROOT */
    priv_len = ossl_slh_dsa_key_get_priv_len(key);
    /* The size of either SK_SEED + SK_PRF OR PK_SEED + PK_ROOT */
    key_len = priv_len >> 1;

    /* Private key is optional */
    if (include_private) {
        param_priv = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (param_priv != NULL) {
            p = key->priv;
            if (!OSSL_PARAM_get_octet_string(param_priv, &p, priv_len, &data_len))
                return 0;
            /* If the data read includes all 4 elements then we are finished */
            if (data_len == priv_len) {
                key->has_priv = 1;
                key->pub = SLH_DSA_PUB(key);
                return 1;
            }
            /* Otherwise it must be just SK_SEED + SK_PRF */
            if (data_len != key_len)
                goto err;
            key->has_priv = 1;
        }
    }
    /*
     * In the case where the passed in private key does not contain the public key
     * there MUST be a separate public key, since the private key cannot exist
     * without the public key elements. NOTE that this does not accept half of
     * the public key, (Keygen must be used for this case currently).
     */
    p = SLH_DSA_PUB(key);
    param_pub = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (param_pub == NULL
            || !OSSL_PARAM_get_octet_string(param_pub, &p, key_len, &data_len)
            || data_len != key_len)
        goto err;
    key->pub = p;
    return 1;
 err:
    key->pub = NULL;
    key->has_priv = 0;
    OPENSSL_cleanse(key->priv, priv_len);
    return 0;
}

/**
 * Generate the public key root from private key (seed and prf) and public key seed.
 * See FIPS 205 Section 9.1 Algorithm 18
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param out A SLH_DSA key containing the private key (seed and prf) and public key seed.
 *            The public root key is written to this key.
 * @param validate If set to 1 the computed public key is not written to the key,
 *                 but will be compared to the existing value.
 * @returns 1 if the root key is generated or compared successfully, or 0 on error.
 */
static int slh_dsa_compute_pk_root(SLH_DSA_CTX *ctx, SLH_DSA_KEY *out,
                                   int validate)
{
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_DECLARE(adrs);
    const SLH_DSA_PARAMS *params = out->params;
    size_t n = params->n;
    uint8_t pk_root[SLH_DSA_MAX_N], *dst;

    adrsf->zero(adrs);
    adrsf->set_layer_address(adrs, params->d - 1);

    dst = validate ? pk_root : SLH_DSA_PK_ROOT(out);

    /* Generate the ROOT public key */
    return ossl_slh_xmss_node(ctx, SLH_DSA_SK_SEED(out), 0, params->hm,
                              SLH_DSA_PK_SEED(out), adrs, dst, n)
        && (validate == 0 || memcmp(dst, SLH_DSA_PK_ROOT(out), n) == 0);
}

/**
 * @brief Generate a SLH_DSA keypair. The private key seed and prf as well as the
 * public key seed are generated using an approved DRBG's. The public key root is
 * calculated using these generated values.
 * See FIPS 205 Section 10.1 Algorithm 21
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param lib_ctx A library context for fetching RAND algorithms
 * @param entropy Optional entropy to use instead of using a DRBG.
 *        Required for ACVP testing. It may be NULL.
 * @param entropy_len the size of |entropy|. If set it must be at least 3 * |n|.
 * @param out An SLH_DSA key to write keypair data to.
 * @returns 1 if the key is generated or 0 otherwise.
 */
int ossl_slh_dsa_generate_key(SLH_DSA_CTX *ctx, OSSL_LIB_CTX *lib_ctx,
                              const uint8_t *entropy, size_t entropy_len,
                              SLH_DSA_KEY *out)
{
    size_t n = ctx->params->n;
    size_t secret_key_len = 2 * n; /* The length of SK_SEED + SK_PRF */
    size_t pk_seed_len = n;        /* The length of PK_SEED */
    size_t entropy_len_expected = secret_key_len + pk_seed_len;
    uint8_t *priv = SLH_DSA_PRIV(out);
    uint8_t *pub = SLH_DSA_PUB(out);

    assert(ctx->params == out->params);

    if (entropy != NULL && entropy_len != 0) {
        if (entropy_len < entropy_len_expected)
            goto err;
        memcpy(priv, entropy, entropy_len_expected);
    } else {
        if (RAND_priv_bytes_ex(lib_ctx, priv, secret_key_len, 0) <= 0
                || RAND_bytes_ex(lib_ctx, pub, pk_seed_len, 0) <= 0)
            goto err;
    }
    if (!slh_dsa_compute_pk_root(ctx, out, 0))
        goto err;
    out->pub = pub;
    out->has_priv = 1;
    return 1;
err:
    out->pub = NULL;
    out->has_priv = 0;
    OPENSSL_cleanse(priv, secret_key_len);
    return 0;
}

/**
 * @brief This is used when a SLH key is used for an operation.
 * This checks that the algorithm is the same (i.e. uses the same parameters)
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants to be used for
 *            an operation.
 * @param key A SLH_DSA key to use for an operation.
 *
 * @returns 1 if the algorithm matches, or 0 otherwise.
 */
int ossl_slh_dsa_key_type_matches(SLH_DSA_CTX *ctx, const SLH_DSA_KEY *key)
{
    return (key->params == ctx->params);
}

/* Returns the public key data or NULL if there is no public key */
const uint8_t *ossl_slh_dsa_key_get_pub(const SLH_DSA_KEY *key)
{
    return key->pub;
}

/* Returns the constant 2 * |n| which is the size of PK_SEED + PK_ROOT */
size_t ossl_slh_dsa_key_get_pub_len(const SLH_DSA_KEY *key)
{
    return 2 * key->params->n;
}

/* Returns the private key data or NULL if there is no private key */
const uint8_t *ossl_slh_dsa_key_get_priv(const SLH_DSA_KEY *key)
{
    return key->has_priv ? key->priv : NULL;
}

/*
 * Returns the constant 4 * |n| which is the size of both
 * the private and public key components.
 * SK_SEED + SK_ROOT + PK_SEED + PK_ROOT
 */
size_t ossl_slh_dsa_key_get_priv_len(const SLH_DSA_KEY *key)
{
    return 4 * key->params->n;
}

size_t ossl_slh_dsa_key_get_n(const SLH_DSA_KEY *key)
{
    return key->params->n;
}

size_t ossl_slh_dsa_key_get_sig_len(const SLH_DSA_KEY *key)
{
    return key->params->sig_len;
}
void ossl_slh_dsa_key_set0_libctx(SLH_DSA_KEY *key, OSSL_LIB_CTX *lib_ctx)
{
    key->libctx = lib_ctx;
}

const char *ossl_slh_dsa_key_get_name(const SLH_DSA_KEY *key)
{
    return key->params->alg;
}

int ossl_slh_dsa_set_priv(SLH_DSA_KEY *key, const uint8_t *priv, size_t priv_len)
{
    if (ossl_slh_dsa_key_get_priv_len(key) != priv_len)
        return 0;
    memcpy(key->priv, priv, priv_len);
    key->has_priv = 1;
    key->pub = SLH_DSA_PUB(key);
    return 1;
}

int ossl_slh_dsa_set_pub(SLH_DSA_KEY *key, const uint8_t *pub, size_t pub_len)
{
    if (ossl_slh_dsa_key_get_pub_len(key) != pub_len)
        return 0;
    key->pub = SLH_DSA_PUB(key);
    memcpy(key->pub, pub, pub_len);
    key->has_priv = 0;
    return 1;
}

int ossl_slh_dsa_key_to_text(BIO *out, const SLH_DSA_KEY *key, int selection)
{
    const char *name;

    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (ossl_slh_dsa_key_get_pub(key) == NULL) {
        /* Regardless of the |selection|, there must be a public key */
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        return 0;
    }

    name = ossl_slh_dsa_key_get_name(key);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (ossl_slh_dsa_key_get_priv(key) == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            return 0;
        }
        if (BIO_printf(out, "%s Private-Key:\n", name) <= 0)
            return 0;
        if (!ossl_bio_print_labeled_buf(out, "priv:", ossl_slh_dsa_key_get_priv(key),
                                        ossl_slh_dsa_key_get_priv_len(key)))
            return 0;
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (BIO_printf(out, "%s Public-Key:\n", name) <= 0)
            return 0;
    }

    if (!ossl_bio_print_labeled_buf(out, "pub:", ossl_slh_dsa_key_get_pub(key),
                                    ossl_slh_dsa_key_get_pub_len(key)))
        return 0;

    return 1;
}
