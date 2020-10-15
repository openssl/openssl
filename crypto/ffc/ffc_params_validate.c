/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Finite Field cryptography (FFC) is used for DSA and DH.
 * This file contains methods for validation of FFC parameters.
 * It calls the same functions as the generation as the code is very similar.
 */

#include "internal/ffc.h"

/* FIPS186-4 A.2.2 Unverifiable partial validation of Generator g */
int ossl_ffc_params_validate_unverifiable_g(BN_CTX *ctx, BN_MONT_CTX *mont,
                                            const BIGNUM *p, const BIGNUM *q,
                                            const BIGNUM *g, BIGNUM *tmp,
                                            int *ret)
{
    /*
     * A.2.2 Step (1) AND
     * A.2.4 Step (2)
     * Verify that 2 <= g <= (p - 1)
     */
    if (BN_cmp(g, BN_value_one()) <= 0 || BN_cmp(g, p) >= 0) {
        *ret |= FFC_ERROR_NOT_SUITABLE_GENERATOR;
        return 0;
    }

    /*
     * A.2.2 Step (2) AND
     * A.2.4 Step (3)
     * Check g^q mod p = 1
     */
    if (!BN_mod_exp_mont(tmp, g, q, p, ctx, mont))
        return 0;
    if (BN_cmp(tmp, BN_value_one()) != 0) {
        *ret |= FFC_ERROR_NOT_SUITABLE_GENERATOR;
        return 0;
    }
    return 1;
}

int ossl_ffc_params_FIPS186_4_validate(OSSL_LIB_CTX *libctx,
                                       const FFC_PARAMS *params, int type,
                                       int *res, BN_GENCB *cb)
{
    size_t L, N;

    if (params == NULL || params->p == NULL || params->q == NULL)
        return FFC_PARAM_RET_STATUS_FAILED;

    /* A.1.1.3 Step (1..2) : L = len(p), N = len(q) */
    L = BN_num_bits(params->p);
    N = BN_num_bits(params->q);
    return ossl_ffc_params_FIPS186_4_gen_verify(libctx, (FFC_PARAMS *)params,
                                                FFC_PARAM_MODE_VERIFY, type,
                                                L, N, res, cb);
}

/* This may be used in FIPS mode to validate deprecated FIPS-186-2 Params */
int ossl_ffc_params_FIPS186_2_validate(OSSL_LIB_CTX *libctx,
                                       const FFC_PARAMS *params, int type,
                                       int *res, BN_GENCB *cb)
{
    size_t L, N;

    if (params == NULL || params->p == NULL || params->q == NULL) {
        *res = FFC_CHECK_INVALID_PQ;
        return FFC_PARAM_RET_STATUS_FAILED;
    }

    /* A.1.1.3 Step (1..2) : L = len(p), N = len(q) */
    L = BN_num_bits(params->p);
    N = BN_num_bits(params->q);
    return ossl_ffc_params_FIPS186_2_gen_verify(libctx, (FFC_PARAMS *)params,
                                                FFC_PARAM_MODE_VERIFY, type,
                                                L, N, res, cb);
}

/*
 * This does a simple check of L and N and partial g.
 * It makes no attempt to do a full validation of p, q or g since these require
 * extra parameters such as the digest and seed, which may not be available for
 * this test.
 */
int ossl_ffc_params_simple_validate(OSSL_LIB_CTX *libctx, FFC_PARAMS *params,
                                    int type)
{
    int ret, res = 0;
    int save_gindex;
    unsigned int save_flags;

    if (params == NULL)
        return 0;

    save_flags = params->flags;
    save_gindex = params->gindex;
    params->flags = FFC_PARAM_FLAG_VALIDATE_G;
    params->gindex = FFC_UNVERIFIABLE_GINDEX;

#ifndef FIPS_MODULE
    if (save_flags & FFC_PARAM_FLAG_VALIDATE_LEGACY)
        ret = ossl_ffc_params_FIPS186_2_validate(libctx, params, type, &res,
                                                 NULL);
    else
#endif
        ret = ossl_ffc_params_FIPS186_4_validate(libctx, params, type, &res,
                                                 NULL);
    params->flags = save_flags;
    params->gindex = save_gindex;
    return ret != FFC_PARAM_RET_STATUS_FAILED;
}
