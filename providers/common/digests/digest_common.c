/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "openssl/err.h"
#include "internal/digestcommon.h"
#include "internal/providercommonerr.h"

int digest_default_get_params(OSSL_PARAM params[], int blksz, int paramsz,
                              unsigned long flags)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, blksz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, paramsz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_FLAGS);
    if (p != NULL && !OSSL_PARAM_set_ulong(p, flags)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM digest_default_known_gettable_params[] = {
    { OSSL_DIGEST_PARAM_BLOCK_SIZE, OSSL_PARAM_INTEGER, NULL, sizeof(int), 0},
    { OSSL_DIGEST_PARAM_SIZE, OSSL_PARAM_INTEGER, NULL, sizeof(int), 0},
    { OSSL_DIGEST_PARAM_FLAGS, OSSL_PARAM_INTEGER, NULL,
      sizeof(unsigned long), 0},
    OSSL_PARAM_END
};
const OSSL_PARAM *digest_default_gettable_params(void)
{
    return digest_default_known_gettable_params;
}
