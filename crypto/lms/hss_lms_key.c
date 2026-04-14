/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include "crypto/lms.h"
#include <string.h>

/*
 * @brief Create an empty HSS_LMS_KEY object.
 *
 * @param libctx The OSSL_LIB_CTX used for fetching algorithms
 * @param propq The property query to use when fetching algorithms
 * @returns The created HSS_LMS_KEY object if successful or NULL otherwise.
 */
HSS_LMS_KEY *ossl_hss_lms_key_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    HSS_LMS_KEY *hsskey = OPENSSL_zalloc(sizeof(*hsskey));

    if (hsskey == NULL)
        return NULL;

    hsskey->libctx = libctx;
    if (propq != NULL) {
        hsskey->propq = OPENSSL_strdup(propq);
        if (hsskey->propq == NULL)
            goto err;
    }
    hsskey->L = 1;
    hsskey->public.libctx = libctx;
    return hsskey;
err:
    OPENSSL_free(hsskey);
    return NULL;
}

/* @brief Destroys a HSS_LMS_KEY object. */
void ossl_hss_lms_key_free(HSS_LMS_KEY *hsskey)
{
    if (hsskey == NULL)
        return;

    if (hsskey->public.pub.allocated)
        OPENSSL_free(hsskey->public.pub.encoded);
    OPENSSL_free(hsskey->propq);
    OPENSSL_free(hsskey);
}

/**
 * @brief Are 2 HSS root LMS public keys equal?
 *
 * To be equal the keys must have the same LMS_PARAMS, LM_OTS_PARAMS and
 * encoded public keys and also have the same number of trees.
 *
 * @param hsskey1 A HSS_LMS_KEY object
 * @param hsskey2 A HSS_LMS_KEY object
 * @param selection Only OSSL_KEYMGMT_SELECT_PUBLIC_KEY is supported
 * @returns 1 if the keys are equal otherwise it returns 0.
 */
int ossl_hss_lms_key_equal(const HSS_LMS_KEY *hsskey1, const HSS_LMS_KEY *hsskey2,
    int selection)
{
    const LMS_KEY *key1, *key2;

    if (hsskey1 == NULL || hsskey2 == NULL) /* Assume that this is an error */
        return 0;

    key1 = &hsskey1->public;
    key2 = &hsskey2->public;
    return hsskey1->L == hsskey2->L && ossl_lms_key_equal(key1, key2, selection);
}

/**
 * @brief Is a HSS_LMS_KEY valid.
 *
 * @param hsskey A HSS_LMS_KEY object
 * @param selection Currently only supports |OSSL_KEYMGMT_SELECT_PUBLIC_KEY|
 * @returns 1 if a HSS_LMS_KEY contains valid key data.
 */
int ossl_hss_lms_key_valid(const HSS_LMS_KEY *hsskey, int selection)
{
    if (hsskey == NULL)
        return 0;
    if (hsskey->L < HSS_MIN_L || hsskey->L > HSS_MAX_L)
        return 0;

    return ossl_lms_key_valid(&hsskey->public, selection);
}

const LMS_KEY *ossl_hss_lms_key_get_public(const HSS_LMS_KEY *hsskey)
{
    return &hsskey->public;
}
