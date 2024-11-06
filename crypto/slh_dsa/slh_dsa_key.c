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
    return ok;
}

int ossl_slh_dsa_key_has(const SLH_DSA_KEY *key, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if (key->key_len == 0)
            return 0;
        return 1;
    }
    return 0;
}

int ossl_slh_dsa_key_fromdata(SLH_DSA_KEY *key, const OSSL_PARAM params[])
{
    size_t n, key_len, len = 0;
    const OSSL_PARAM *param_pub;
    void *p;

    if (key == NULL)
        return 0;
    n = key->params->n;
    assert(n != 0);
    /* Both the public and private key are composed of 2 elements of size n */
    key_len = 2 * n;

    param_pub = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (param_pub == NULL)
        goto err;
    p = key->pub;
    if (!OSSL_PARAM_get_octet_string(param_pub, &p, key_len, &len))
        goto err;
    if (len != key_len)
        goto err;
    key->key_len = key_len; /* This indicates the public key is present */
    return 1;
 err:
    key->key_len = 0;
    return 0;
}

int ossl_slh_dsa_key_type_matches(SLH_DSA_CTX *ctx, const SLH_DSA_KEY *key)
{
    return (key->params == ctx->params);
}
