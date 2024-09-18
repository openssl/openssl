/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/hss.h>
#include "internal/common.h"
#include "crypto/hss.h"
#include "lms_local.h"

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
    if (!ossl_hss_lists_init(&hsskey->lists))
        goto err;

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

    ossl_hss_lists_free(&hsskey->lists);
    OPENSSL_free(hsskey->propq);
    CRYPTO_FREE_REF(&hsskey->references);
    OPENSSL_free(hsskey);
}
