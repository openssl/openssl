/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/params.h>
#include "crypto/rsa.h"

/*
 * The intention with the "backend" source file is to offer backend support
 * for legacy backends (EVP_PKEY_ASN1_METHOD and EVP_PKEY_METHOD) and provider
 * implementations alike.
 */

DEFINE_STACK_OF(BIGNUM)

static int collect_numbers(STACK_OF(BIGNUM) *numbers,
                           const OSSL_PARAM params[], const char *names[])
{
    const OSSL_PARAM *p = NULL;
    int i;

    if (numbers == NULL)
        return 0;

    for (i = 0; names[i] != NULL; i++){
        p = OSSL_PARAM_locate_const(params, names[i]);
        if (p != NULL) {
            BIGNUM *tmp = NULL;

            if (!OSSL_PARAM_get_BN(p, &tmp)
                || sk_BIGNUM_push(numbers, tmp) == 0)
                return 0;
        }
    }

    return 1;
}

int rsa_fromdata(RSA *rsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_n, *param_e,  *param_d;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    STACK_OF(BIGNUM) *factors = NULL, *exps = NULL, *coeffs = NULL;
    int is_private = 0;

    if (rsa == NULL)
        return 0;

    param_n = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    param_e = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    param_d = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);

    if ((param_n != NULL && !OSSL_PARAM_get_BN(param_n, &n))
        || (param_e != NULL && !OSSL_PARAM_get_BN(param_e, &e))
        || (param_d != NULL && !OSSL_PARAM_get_BN(param_d, &d)))
        goto err;

    is_private = (d != NULL);

    if (!RSA_set0_key(rsa, n, e, d))
        goto err;
    n = e = d = NULL;

    if (is_private) {
        if (!collect_numbers(factors = sk_BIGNUM_new_null(), params,
                             rsa_mp_factor_names)
            || !collect_numbers(exps = sk_BIGNUM_new_null(), params,
                                rsa_mp_exp_names)
            || !collect_numbers(coeffs = sk_BIGNUM_new_null(), params,
                                rsa_mp_coeff_names))
            goto err;

        /* It's ok if this private key just has n, e and d */
        if (sk_BIGNUM_num(factors) != 0
            && !rsa_set0_all_params(rsa, factors, exps, coeffs))
            goto err;
    }

    sk_BIGNUM_free(factors);
    sk_BIGNUM_free(exps);
    sk_BIGNUM_free(coeffs);
    return 1;

 err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    sk_BIGNUM_pop_free(factors, BN_free);
    sk_BIGNUM_pop_free(exps, BN_free);
    sk_BIGNUM_pop_free(coeffs, BN_free);
    return 0;
}

DEFINE_SPECIAL_STACK_OF_CONST(BIGNUM_const, BIGNUM)

int rsa_todata(RSA *rsa, OSSL_PARAM_BLD *bld, OSSL_PARAM params[])
{
    int ret = 0;
    const BIGNUM *rsa_d = NULL, *rsa_n = NULL, *rsa_e = NULL;
    STACK_OF(BIGNUM_const) *factors = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *exps = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *coeffs = sk_BIGNUM_const_new_null();

    if (rsa == NULL || factors == NULL || exps == NULL || coeffs == NULL)
        goto err;

    RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
    rsa_get0_all_params(rsa, factors, exps, coeffs);

    /* Check private key data integrity */
    if (rsa_d != NULL) {
        int numprimes = sk_BIGNUM_const_num(factors);
        int numexps = sk_BIGNUM_const_num(exps);
        int numcoeffs = sk_BIGNUM_const_num(coeffs);

        /*
         * It's permisssible to have zero primes, i.e. no CRT params.
         * Otherwise, there must be at least two, as many exponents,
         * and one coefficient less.
         */
        if (numprimes != 0
            && (numprimes < 2 || numexps < 2 || numcoeffs < 1))
            goto err;
    }

    if (!ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_N, rsa_n)
        || !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_E, rsa_e)
        || !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_D, rsa_d)
        || !ossl_param_build_set_multi_key_bn(bld, params, rsa_mp_factor_names,
                                              factors)
        || !ossl_param_build_set_multi_key_bn(bld, params, rsa_mp_exp_names,
                                              exps)
        || !ossl_param_build_set_multi_key_bn(bld, params, rsa_mp_coeff_names,
                                              coeffs))
        goto err;
    ret = 1;
 err:
    sk_BIGNUM_const_free(factors);
    sk_BIGNUM_const_free(exps);
    sk_BIGNUM_const_free(coeffs);
    return ret;
}
