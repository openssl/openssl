/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/lms.h"

/* Refer to SP800-208 Section 4 LM-OTS parameter sets */
static const LM_OTS_PARAMS lm_ots_params[] = {
    { OSSL_LM_OTS_TYPE_SHA256_N32_W1, 32, 1, 265, "SHA256"},
    { OSSL_LM_OTS_TYPE_SHA256_N32_W2, 32, 2, 133, "SHA256"},
    { OSSL_LM_OTS_TYPE_SHA256_N32_W4, 32, 4,  67, "SHA256"},
    { OSSL_LM_OTS_TYPE_SHA256_N32_W8, 32, 8,  34, "SHA256"},
    { OSSL_LM_OTS_TYPE_SHA256_N24_W1, 24, 1, 200, "SHA256-192"},
    { OSSL_LM_OTS_TYPE_SHA256_N24_W2, 24, 2, 101, "SHA256-192"},
    { OSSL_LM_OTS_TYPE_SHA256_N24_W4, 24, 4,  51, "SHA256-192"},
    { OSSL_LM_OTS_TYPE_SHA256_N24_W8, 24, 8,  26, "SHA256-192"},
    { OSSL_LM_OTS_TYPE_SHAKE_N32_W1,  32, 1, 265, "SHAKE-256"},
    { OSSL_LM_OTS_TYPE_SHAKE_N32_W2,  32, 2, 133, "SHAKE-256"},
    { OSSL_LM_OTS_TYPE_SHAKE_N32_W4,  32, 4,  67, "SHAKE-256"},
    { OSSL_LM_OTS_TYPE_SHAKE_N32_W8,  32, 8,  34, "SHAKE-256"},
    /* SHAKE-256/192 - OpenSSL does not support this as a name */
    { OSSL_LM_OTS_TYPE_SHAKE_N24_W1,  24, 1, 200, "SHAKE-256"},
    { OSSL_LM_OTS_TYPE_SHAKE_N24_W2,  24, 2, 101, "SHAKE-256"},
    { OSSL_LM_OTS_TYPE_SHAKE_N24_W4,  24, 4,  51, "SHAKE-256"},
    { OSSL_LM_OTS_TYPE_SHAKE_N24_W8,  24, 8,  26, "SHAKE-256"},
    { 0, 0, 0, 0, NULL },
};

/**
 * @brief A getter to convert an |ots_type| into a LM_OTS_PARAMS object.
 *
 * @param ots_type The type such as OSSL_LM_OTS_TYPE_SHA256_N32_W1
 * @returns The LM_OTS_PARAMS object associated with the |ots_type|, or
 *          NULL if |ots_type| is undefined.
 */
const LM_OTS_PARAMS *ossl_lm_ots_params_get(uint32_t ots_type)
{
    const LM_OTS_PARAMS *p;

    for (p = lm_ots_params; p->lm_ots_type != 0; ++p)
        if (p->lm_ots_type == ots_type)
            return p;
    return NULL;
}
