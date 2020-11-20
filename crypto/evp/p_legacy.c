/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Legacy EVP_PKEY assign/set/get APIs are deprecated for public use, but
 * still ok for internal use, particularly in providers.
 */
#include "internal/deprecated.h"

#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include "crypto/types.h"
#include "crypto/evp.h"
#include "evp_local.h"

int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key)
{
    int ret = EVP_PKEY_assign_RSA(pkey, key);
    if (ret)
        RSA_up_ref(key);
    return ret;
}

RSA *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey)
{
    if (!evp_pkey_downgrade((EVP_PKEY *)pkey)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_KEY);
        return NULL;
    }
    if (pkey->type != EVP_PKEY_RSA && pkey->type != EVP_PKEY_RSA_PSS) {
        ERR_raise(ERR_LIB_EVP, EVP_R_EXPECTING_AN_RSA_KEY);
        return NULL;
    }
    return pkey->pkey.rsa;
}

RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey)
{
    RSA *ret = EVP_PKEY_get0_RSA(pkey);
    if (ret != NULL)
        RSA_up_ref(ret);
    return ret;
}
