/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include "prov/implementations.h"

static OSSL_OP_keymgmt_importkey_fn rsa_importkey;
static OSSL_OP_keymgmt_exportkey_fn rsa_exportkey;

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(BIGNUM_const)

static int collect_numbers(STACK_OF(BIGNUM) *numbers,
                           const OSSL_PARAM params[], const char *key)
{
    const OSSL_PARAM *p = NULL;

    if (numbers == NULL)
        return 0;

    for (p = params; (p = OSSL_PARAM_locate_const(p, key)) != NULL; p++) {
        BIGNUM *tmp = NULL;

        if (!OSSL_PARAM_get_BN(p, &tmp))
            return 0;
        sk_BIGNUM_push(numbers, tmp);
    }

    return 1;
}

static int params_to_key(RSA *rsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_n, *param_e,  *param_d;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    STACK_OF(BIGNUM) *factors = NULL, *exps = NULL, *coeffs = NULL;

    if (rsa == NULL)
        return 0;

    param_n = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    param_e = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    param_d = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);

    if ((param_n != NULL && !OSSL_PARAM_get_BN(param_n, &n))
        || (param_e != NULL && !OSSL_PARAM_get_BN(param_e, &e))
        || (param_d != NULL && !OSSL_PARAM_get_BN(param_d, &d)))
        goto err;

    if (!RSA_set0_key(rsa, n, e, d))
        goto err;
    n = e = d = NULL;

    if (!collect_numbers(factors = sk_BIGNUM_new_null(), params,
                         OSSL_PKEY_PARAM_RSA_FACTOR)
        || !collect_numbers(exps = sk_BIGNUM_new_null(), params,
                            OSSL_PKEY_PARAM_RSA_EXPONENT)
        || !collect_numbers(coeffs = sk_BIGNUM_new_null(), params,
                            OSSL_PKEY_PARAM_RSA_COEFFICIENT))
        goto err;

    if (!RSA_set0_all_params(rsa, factors, exps, coeffs))
        goto err;

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

static int export_numbers(OSSL_PARAM params[], const char *key,
                          STACK_OF(BIGNUM_const) *numbers)
{
    OSSL_PARAM *p = NULL;
    int i, nnum;

    if (numbers == NULL)
        return 0;

    nnum = sk_BIGNUM_const_num(numbers);

    for (p = params, i = 0;
         i < nnum && (p = OSSL_PARAM_locate(p, key)) != NULL;
         p++, i++) {
        if (!OSSL_PARAM_set_BN(p, sk_BIGNUM_const_value(numbers, i)))
            return 0;
    }

    return i;
}

static int key_to_params(RSA *rsa, OSSL_PARAM params[])
{
    int ret = 0;
    OSSL_PARAM *p;
    const BIGNUM *rsa_d = NULL, *rsa_n = NULL, *rsa_e = NULL;
    STACK_OF(BIGNUM_const) *factors = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *exps = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *coeffs = sk_BIGNUM_const_new_null();

    if (rsa == NULL || factors == NULL || exps == NULL || coeffs == NULL)
        goto err;

    RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
    RSA_get0_all_params(rsa, factors, exps, coeffs);

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N)) != NULL
        && !OSSL_PARAM_set_BN(p, rsa_n))
        goto err;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E)) != NULL
        && !OSSL_PARAM_set_BN(p, rsa_e))
        goto err;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_D)) != NULL
        && !OSSL_PARAM_set_BN(p, rsa_d))
        goto err;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_PARAMS_NUM)) != NULL
        && !OSSL_PARAM_set_uint(p, sk_BIGNUM_const_num(factors)))
        goto err;
    if (!export_numbers(params, OSSL_PKEY_PARAM_RSA_FACTOR, factors)
        || !export_numbers(params, OSSL_PKEY_PARAM_RSA_EXPONENT, exps)
        || !export_numbers(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT, coeffs))
        goto err;

    ret = 1;
 err:
    sk_BIGNUM_const_free(factors);
    sk_BIGNUM_const_free(exps);
    sk_BIGNUM_const_free(coeffs);
    return ret;
}

static void *rsa_importkey(void *provctx, const OSSL_PARAM params[])
{
    RSA *rsa;

    if ((rsa = RSA_new()) == NULL
        || !params_to_key(rsa, params)) {
        RSA_free(rsa);
        rsa = NULL;
    }
    return rsa;
}

static int rsa_exportkey(void *key, OSSL_PARAM params[])
{
    RSA *rsa = key;

    return rsa != NULL && !key_to_params(rsa, params);
}

const OSSL_DISPATCH rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_IMPORTKEY, (void (*)(void))rsa_importkey },
    { OSSL_FUNC_KEYMGMT_EXPORTKEY, (void (*)(void))rsa_exportkey },
    { OSSL_FUNC_KEYMGMT_FREEKEY, (void (*)(void))RSA_free },
    { 0, NULL }
};
