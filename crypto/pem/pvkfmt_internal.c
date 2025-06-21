/*
 * Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include "internal/cryptlib.h"
#include <openssl/evp.h>

#include "pem_local.h"

/*
 * Create an EVP_PKEY from a type specific key.
 * This takes ownership of |key|, as long as the |evp_type| is acceptable
 * (EVP_PKEY_RSA or EVP_PKEY_DSA), even if the resulting EVP_PKEY wasn't
 * created.
 */
EVP_PKEY *evp_pkey_new0_key(void *key, int evp_type)
{
    EVP_PKEY *pkey = NULL;

    /*
     * It's assumed that if |key| is NULL, something went wrong elsewhere
     * and suitable errors are already reported.
     */
    if (key == NULL)
        return NULL;

    if (!ossl_assert(evp_type == EVP_PKEY_RSA || evp_type == EVP_PKEY_DSA)) {
        ERR_raise(ERR_LIB_PEM, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    if ((pkey = EVP_PKEY_new()) != NULL) {
        switch (evp_type) {
        case EVP_PKEY_RSA:
            if (EVP_PKEY_set1_RSA(pkey, key))
                break;
            ERR_raise(ERR_LIB_PEM, ERR_R_EVP_LIB);
            EVP_PKEY_free(pkey);
            pkey = NULL;
            break;
#ifndef OPENSSL_NO_DSA
        case EVP_PKEY_DSA:
            if (EVP_PKEY_set1_DSA(pkey, key))
                break;
            ERR_raise(ERR_LIB_PEM, ERR_R_EVP_LIB);
            EVP_PKEY_free(pkey);
            pkey = NULL;
            break;
#endif
        }
    } else {
        ERR_raise(ERR_LIB_PEM, ERR_R_EVP_LIB);
    }

    switch (evp_type) {
    case EVP_PKEY_RSA:
        RSA_free(key);
        break;
#ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
        DSA_free(key);
        break;
#endif
    }

    return pkey;
}
