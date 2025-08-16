/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
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

    hsskey->libctx = libctx;
    if (propq != NULL) {
        hsskey->propq = OPENSSL_strdup(propq);
        if (hsskey->propq == NULL)
            goto err;
    }
    return hsskey;
 err:
    OPENSSL_free(hsskey);
    return NULL;
}

/* @brief Destroys a HSS_KEY object. */
void ossl_hss_key_free(HSS_KEY *hsskey)
{
    if (hsskey == NULL)
        return;

    ossl_lms_key_free(hsskey->public);
    OPENSSL_free(hsskey->propq);
    OPENSSL_free(hsskey);
}

/**
 * @brief Duplicate a key
 *
 * @param src A HSS_KEY object to copy
 * @param selection to select public and/or private components. Only
 *                  public keys can be duplicated for HSS so this is
 *                  currently ignored.
 * @returns The duplicated key, or NULL on failure.
 */
HSS_KEY *ossl_hss_key_dup(const HSS_KEY *src, int selection)
{
    HSS_KEY *ret = NULL;

    if (src == NULL)
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;
    *ret = *src;
    ret->propq = NULL;
    ret->public = NULL;

    if (src->public != NULL) {
        ret->public = ossl_lms_key_dup(src->public);
        if (ret->public == NULL)
            goto err;
    }
    if (src->propq != NULL) {
        ret->propq = OPENSSL_strdup(src->propq);
        if (ret->propq == NULL)
            goto err;
    }
    return ret;
err:
    ossl_hss_key_free(ret);
    return NULL;
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

    key1 = hsskey1->public;
    key2 = hsskey2->public;
    if (key1 == NULL || key2 == NULL) /* Assume that this is an error */
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
    return ossl_lms_key_has(hsskey->public, selection);
}

const char *ossl_hss_key_get_digestname(HSS_KEY *hsskey)
{
    if (hsskey == NULL || hsskey->public == NULL)
        return NULL;
    return hsskey->public->lms_params->digestname;
}

int ossl_hss_key_set_public(HSS_KEY *hsskey, LMS_KEY *key)
{
    LMS_KEY *root = hsskey->public;

    if (root != NULL)
        ossl_lms_key_free(root);
    hsskey->public = key;
    return 1;
}

LMS_KEY *ossl_hss_key_get_public(const HSS_KEY *hsskey)
{
    return hsskey->public;
}
