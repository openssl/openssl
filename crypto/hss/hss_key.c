/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include "crypto/hss.h"
#include <string.h>

/*
 * @brief Create an empty HSS_KEY object.
 * The key is reference counted.
 *
 * @param libctx The OSSL_LIB_CTX used for fetching algorithms
 * @param propq The property query to use when fetching algorithms
 * @returns The created HSS_KEY object if successful or NULL otherwise.
 */
HSS_KEY *ossl_hss_key_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    HSS_KEY *hsskey = OPENSSL_zalloc(sizeof(*hsskey));

    if (hsskey == NULL)
        return NULL;
    if (!CRYPTO_NEW_REF(&hsskey->references, 1)) {
        OPENSSL_free(hsskey);
        return NULL;
    }
    hsskey->libctx = libctx;
    if (propq != NULL) {
        hsskey->propq = OPENSSL_strdup(propq);
        if (hsskey->propq == NULL)
            goto err;
    }
    return hsskey;
 err:
    ossl_hss_key_free(hsskey);
    return NULL;
}

/*
 * @brief Destroys a HSS_KEY object.
 * This object is reference counted.
 */
void ossl_hss_key_free(HSS_KEY *hsskey)
{
    int i;

    if (hsskey == NULL)
        return;

    CRYPTO_DOWN_REF(&hsskey->references, &i);
    REF_PRINT_COUNT("HSS_KEY", hsskey);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    ossl_lms_key_free(hsskey->public);
    OPENSSL_free(hsskey->propq);
    CRYPTO_FREE_REF(&hsskey->references);
    OPENSSL_free(hsskey);
}

/*
 * @brief Increase the reference count for a HSS_KEY object.
 * @returns 1 on success or 0 otherwise.
 */
int ossl_hss_key_up_ref(HSS_KEY *key)
{
    int i;

    if (CRYPTO_UP_REF(&key->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("HSS_KEY", key);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

/**
 * @brief Are 2 HSS root LMS public keys equal?
 *
 * To be equal the keys must have the same LMS_PARAMS, LM_OTS_PARAMS and
 * encoded public keys and also have the same number of trees.
 *
 * @param hsskey1 A HSS_KEY object
 * @param hsskey2 A HSS_KEY object
 * @param selection Only OSSL_KEYMGMT_SELECT_PUBLIC_KEY is supported
 * @returns 1 if the keys are equal otherwise it returns 0.
 */
int ossl_hss_key_equal(const HSS_KEY *hsskey1, const HSS_KEY *hsskey2,
                       int selection)
{
    LMS_KEY *key1, *key2;

    if (hsskey1 == NULL || hsskey2 == NULL)
        return 0;

    key1 = hsskey1->public;
    key2 = hsskey2->public;
    if (key1 == NULL || key2 == NULL)
        return 0;

    return hsskey1->L == hsskey2->L && ossl_lms_key_equal(key1, key2, selection);
}

/**
 * @brief Is a HSS_KEY valid.
 *
 * @param hsskey A HSS_KEY object
 * @param selection Currently only supports |OSSL_KEYMGMT_SELECT_PUBLIC_KEY|
 * @returns 1 if a HSS_KEY contains valid key data.
 */
int ossl_hss_key_valid(const HSS_KEY *hsskey, int selection)
{
    if (hsskey == NULL || hsskey->public == NULL)
        return 0;
    if (hsskey->L < HSS_MIN_L || hsskey->L > HSS_MAX_L)
        return 0;

    return ossl_lms_key_valid(hsskey->public, selection);
}

/**
 * @brief Does a HSS_KEY object contain a root public key.
 *
 * @param key A HSS_KEY object
 * @param selection Currently only supports |OSSL_KEYMGMT_SELECT_PUBLIC_KEY|
 * @returns 1 if a HSS_KEY contains a root public key, or 0 otherwise.
 */
int ossl_hss_key_has(const HSS_KEY *hsskey, int selection)
{
    if (hsskey == NULL || hsskey->public == NULL)
        return 0;
    return ossl_lms_key_has(hsskey->public, selection);
}

const char *ossl_hss_key_get_digestname(HSS_KEY *hsskey)
{
    if (hsskey == NULL || hsskey->public == NULL)
        return NULL;
    return hsskey->public->lms_params->digestname;
}

LMS_KEY *ossl_hss_key_get_public(const HSS_KEY *hsskey)
{
    return hsskey->public;
}

int ossl_hss_key_set_public(HSS_KEY *hsskey, LMS_KEY *key)
{
    LMS_KEY *root = hsskey->public;

    if (root != NULL)
        ossl_lms_key_free(root);
    hsskey->public = key;
    return 1;
}
