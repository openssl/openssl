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

static int slh_dsa_compute_pk_root(SLH_DSA_CTX *ctx, SLH_DSA_KEY *out);

/**
 * @brief Create a new SLH_DSA_KEY object
 *
 * @param libctx A OSSL_LIB_CTX object used for fetching algorithms.
 * @param alg The algrithm name associated with the key type
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

    OPENSSL_cleanse(&key->priv, sizeof(key->priv));
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
 * To be equal the keys must have the same key data.
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
        if (key1->key_len != key2->key_len)
            return 0;
        ok = (memcmp(key1->pub, key2->pub, key1->key_len) == 0);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        ok = ok && (key1->has_priv == key2->has_priv);
        if (key1->has_priv)
            ok = ok && (memcmp(key1->priv, key2->priv, key1->key_len) == 0);
    }
    return ok;
}

int ossl_slh_dsa_key_has(const SLH_DSA_KEY *key, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if (key->key_len == 0)
            return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                && key->has_priv == 0)
            return 0;
        return 1;
    }
    return 0;
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
    size_t n, key_len, len = 0;
    const OSSL_PARAM *param_priv = NULL, *param_pub = NULL;
    void *p;

    if (key == NULL)
        return 0;
    n = key->params->n;
    assert(n != 0);
    /* Both the public and private key are composed of 2 elements of size n */
    key_len = 2 * n;

    /* Private key is optional */
    if (include_private) {
        param_priv = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (param_priv == NULL)
            return 0;
    }

    /*
     * There must always be a public key, since the private key cannot exist
     * without the public key elements.
     */
    param_pub = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (param_pub == NULL)
        return 0;

    p = key->pub;
    if (!OSSL_PARAM_get_octet_string(param_pub, &p, key_len, &len))
        return 0;
    /*
     * This does not allow you to pass in just the PK SEED, this can be done
     * via key generation
     */
    if (len != key_len)
        return 0;
    if (param_priv != NULL) {
        p = key->priv;
        if (!OSSL_PARAM_get_octet_string(param_priv, &p, key_len, &len))
            return 0;
        /* This is assuming that the private component contains no public elements */
        if (len != key_len)
            goto err;
        key->has_priv = 1;
    }
    key->key_len = key_len; /* This indicates the public key is present */
    return 1;
 err:
    key->key_len = 0;
    key->has_priv = 0;
    OPENSSL_cleanse(key->priv, key_len);
    return 0;
}

/**
 * Generate the public key root from private key (seed and prf) and public key seed.
 * See FIPS 205 Section 9.1 Algorithm 18
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param out A SLH_DSA key containing the private key (seed and prf) and public key seed.
 *            The public root key is written to this key.
 * @returns 1 if the root key is generated, or 0 on error.
 */
static int slh_dsa_compute_pk_root(SLH_DSA_CTX *ctx, SLH_DSA_KEY *out)
{
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_DECLARE(adrs);
    const SLH_DSA_PARAMS *params = out->params;

    adrsf->zero(adrs);
    adrsf->set_layer_address(adrs, params->d - 1);
    /* Generate the ROOT public key */
    return ossl_slh_xmss_node(ctx, SLH_DSA_SK_SEED(out), 0, params->hm,
                              SLH_DSA_PK_SEED(out), adrs,
                              SLH_DSA_PK_ROOT(out), params->n);
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
    size_t key_len = 2 * n;

    assert(ctx->params == out->params);

    if (entropy != NULL && entropy_len != 0) {
        if (entropy_len < (key_len + n))
            goto err;
        memcpy(out->priv, entropy, key_len);
        memcpy(out->pub, entropy + key_len, n);
    } else {
        if (RAND_priv_bytes_ex(lib_ctx, out->priv, key_len, 0) <= 0
                || RAND_bytes_ex(lib_ctx, out->pub, n, 0) <= 0)
            goto err;
    }
    if (!slh_dsa_compute_pk_root(ctx, out))
        goto err;
    out->key_len = key_len;
    out->has_priv = 1;
    return 1;
err:
    out->has_priv = 0;
    out->key_len = 0;
    OPENSSL_cleanse(&out->priv, sizeof(out->priv));
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

/*
 * @returns 1 if the SLH_DSA key contains a private component, or 0 if the
 *          key is just a public key.
 */
int ossl_slh_dsa_key_is_private(const SLH_DSA_KEY *key)
{
    return key->has_priv;
}

const uint8_t *ossl_slh_dsa_key_get_pub(const SLH_DSA_KEY *key)
{
    return key->pub;
}

const uint8_t *ossl_slh_dsa_key_get_priv(const SLH_DSA_KEY *key)
{
    return key->priv;
}

size_t ossl_slh_dsa_key_get_len(const SLH_DSA_KEY *key)
{
    return key->key_len;
}

size_t ossl_slh_dsa_key_get_n(const SLH_DSA_KEY *key)
{
    return key->params->n;
}

size_t ossl_slh_dsa_key_get_sig_len(const SLH_DSA_KEY *key)
{
    return key->params->sig_len;
}
