/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/digestcommon.h"

int ossl_digest_default_get_params(OSSL_PARAM params[], size_t blksz,
                                   size_t paramsz, unsigned long flags)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_XOF) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_ALGID_ABSENT) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SECURITY_CATEGORY_COLLISION);
    if (p != NULL) {
        int sec_category_collision = 0;

        if (paramsz != 0) {
            if (paramsz >= 64)
                sec_category_collision = 5;
            else if (paramsz >= 48)
                sec_category_collision = 4;
            else if (paramsz >= 32)
                sec_category_collision = 2;
            else
                sec_category_collision = 0;
        } else {
            if (blksz >= 168)
                sec_category_collision = 2;
            else if (blksz >= 136)
                sec_category_collision = 5;
            else
                sec_category_collision = 0;
        }

        if (!OSSL_PARAM_set_int(p, sec_category_collision)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SECURITY_CATEGORY_PREIMAGE);
    if (p != NULL) {
        int sec_category_preimage = 0;

        if (paramsz != 0) {
            if (paramsz >= 64)
                sec_category_preimage = 5;
            else if (paramsz == 48)
                sec_category_preimage = 5;
            else if (paramsz >= 32)
                sec_category_preimage = 5;
            else if (paramsz >= 28)
                sec_category_preimage = 3;
            else
                sec_category_preimage = 1;
        } else {
            if (blksz >= 168)
                sec_category_preimage = 2;
            else if (blksz >= 136)
                sec_category_preimage = 5;
            else
                sec_category_preimage = 1;
        }

        if (!OSSL_PARAM_set_int(p, sec_category_preimage)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM digest_default_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_SECURITY_CATEGORY_COLLISION, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_SECURITY_CATEGORY_PREIMAGE, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *ossl_digest_default_gettable_params(void *provctx)
{
    return digest_default_known_gettable_params;
}
