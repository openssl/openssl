/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

int drbg_set_ctx_params(RAND_DRBG *drbg, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_get_uint64(p, &drbg->reseed_time_interval))
        return 0;
    return 1;
}

int drbg_get_ctx_params(RAND_DRBG *drbg, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, drbg->strength))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_set_uint(p, drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_set_uint64(p, drbg->reseed_time_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_request))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MIN_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->min_entropylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_entropylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MIN_NONCELEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->min_noncelen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_NONCELEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_noncelen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_PERSLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_perslen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_ADINLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_adinlen))
        return 0;
    return 1;
}

