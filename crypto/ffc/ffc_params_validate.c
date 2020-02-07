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
int ffc_params_validate_unverifiable_g(BN_CTX *ctx, BN_MONT_CTX *mont,
                                       const BIGNUM *p, const BIGNUM *q,
                                       const BIGNUM *g, BIGNUM *tmp, int *ret)
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

int ffc_params_FIPS186_4_validate(const FFC_PARAMS *params, int type,
                                  const EVP_MD *evpmd, int validate_flags,
                                  int *res, BN_GENCB *cb)
{
    size_t L, N;

    if (params == NULL || params->p == NULL || params->q == NULL)
        return FFC_PARAMS_RET_STATUS_FAILED;

    /* A.1.1.3 Step (1..2) : L = len(p), N = len(q) */
    L = BN_num_bits(params->p);
    N = BN_num_bits(params->q);
    return ffc_params_FIPS186_4_gen_verify(NULL, (FFC_PARAMS *)params, type, L, N,
                                           evpmd, validate_flags, res, cb);
}

/* This may be used in FIPS mode to validate deprecated FIPS-186-2 Params */
int ffc_params_FIPS186_2_validate(const FFC_PARAMS *params, int type,
                                  const EVP_MD *evpmd, int validate_flags,
                                  int *res, BN_GENCB *cb)
{
    size_t L, N;

    if (params->p == NULL || params->q == NULL) {
        *res = FFC_CHECK_INVALID_PQ;
        return FFC_PARAMS_RET_STATUS_FAILED;
    }

    /* A.1.1.3 Step (1..2) : L = len(p), N = len(q) */
    L = BN_num_bits(params->p);
    N = BN_num_bits(params->q);
    return ffc_params_FIPS186_2_gen_verify(NULL, (FFC_PARAMS *)params, type, L, N,
                                           evpmd, validate_flags, res, cb);
}
