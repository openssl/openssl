/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Helper functions for EC keys */

#include "internal/deprecated.h"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/ec.h"
#include "crypto/ec.h"
#include "crypto/ecx.h"

int ossl_ec_match_params(const EC_KEY *key1, const EC_KEY *key2)
{
    int ret;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group1 = EC_KEY_get0_group(key1);
    const EC_GROUP *group2 = EC_KEY_get0_group(key2);

    ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(key1));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = group1 != NULL
          && group2 != NULL
          && EC_GROUP_cmp(group1, group2, ctx) == 0;
    if (!ret)
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
    BN_CTX_free(ctx);
    return ret;
}

int ossl_ecx_match_params(const ECX_KEY *key1, const ECX_KEY *key2)
{
    return (key1->type == key2->type && key1->keylen == key2->keylen);
}
