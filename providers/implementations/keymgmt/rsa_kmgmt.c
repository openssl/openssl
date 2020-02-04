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
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include "internal/param_build.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "crypto/rsa.h"

static OSSL_OP_keymgmt_new_fn rsa_newdata;
static OSSL_OP_keymgmt_free_fn rsa_freedata;
static OSSL_OP_keymgmt_get_params_fn rsa_get_params;
static OSSL_OP_keymgmt_gettable_params_fn rsa_gettable_params;
static OSSL_OP_keymgmt_has_fn rsa_has;
static OSSL_OP_keymgmt_validate_fn rsa_validate;
static OSSL_OP_keymgmt_import_fn rsa_import;
static OSSL_OP_keymgmt_import_types_fn rsa_import_types;
static OSSL_OP_keymgmt_export_fn rsa_export;
static OSSL_OP_keymgmt_export_types_fn rsa_export_types;

#define RSA_DEFAULT_MD "SHA256"
#define RSA_POSSIBLE_SELECTIONS                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

DEFINE_STACK_OF(BIGNUM)
DEFINE_SPECIAL_STACK_OF_CONST(BIGNUM_const, BIGNUM)

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
                             OSSL_PKEY_PARAM_RSA_FACTOR)
            || !collect_numbers(exps = sk_BIGNUM_new_null(), params,
                                OSSL_PKEY_PARAM_RSA_EXPONENT)
            || !collect_numbers(coeffs = sk_BIGNUM_new_null(), params,
                                OSSL_PKEY_PARAM_RSA_COEFFICIENT))
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

static int export_numbers(OSSL_PARAM_BLD *tmpl, const char *key,
                          STACK_OF(BIGNUM_const) *numbers)
{
    int i, nnum;

    if (numbers == NULL)
        return 0;

    nnum = sk_BIGNUM_const_num(numbers);

    for (i = 0; i < nnum; i++) {
        if (!ossl_param_bld_push_BN(tmpl, key,
                                    sk_BIGNUM_const_value(numbers, i)))
            return 0;
    }

    return 1;
}

static int key_to_params(RSA *rsa, OSSL_PARAM_BLD *tmpl)
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

    if (rsa_n != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, rsa_n))
        goto err;
    if (rsa_e != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, rsa_e))
        goto err;
    if (rsa_d != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_D, rsa_d))
        goto err;

    if (!export_numbers(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR, factors)
        || !export_numbers(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT, exps)
        || !export_numbers(tmpl, OSSL_PKEY_PARAM_RSA_COEFFICIENT, coeffs))
        goto err;

    ret = 1;
 err:
    sk_BIGNUM_const_free(factors);
    sk_BIGNUM_const_free(exps);
    sk_BIGNUM_const_free(coeffs);
    return ret;
}

static void *rsa_newdata(void *provctx)
{
    return RSA_new();
}

static void rsa_freedata(void *keydata)
{
    RSA_free(keydata);
}

static int rsa_has(void *keydata, int selection)
{
    RSA *rsa = keydata;
    int ok = 0;

    if ((selection & RSA_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    ok = ok && (RSA_get0_e(rsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (RSA_get0_n(rsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (RSA_get0_d(rsa) != NULL);
    return ok;
}

static int rsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    RSA *rsa = keydata;
    int ok = 1;

    if (rsa == NULL)
        return 0;

    /* TODO(3.0) PSS and OAEP should bring on parameters */

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && params_to_key(rsa, params);

    return ok;
}

static int rsa_export(void *keydata, int selection,
                      OSSL_CALLBACK *param_callback, void *cbarg)
{
    RSA *rsa = keydata;
    OSSL_PARAM_BLD tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (rsa == NULL)
        return 0;

    /* TODO(3.0) PSS and OAEP should bring on parameters */

    ossl_param_bld_init(&tmpl);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && key_to_params(rsa, &tmpl);

    if (!ok
        || (params = ossl_param_bld_to_param(&tmpl)) == NULL)
        return 0;

    ok = param_callback(params, cbarg);
    ossl_param_bld_free(params);
    return ok;
}

/*
 * This provider can export everything in an RSA key, so we use the exact
 * same type description for export as for import.  Other providers might
 * choose to import full keys, but only export the public parts, and will
 * therefore have the importkey_types and importkey_types functions return
 * different arrays.
 */
static const OSSL_PARAM rsa_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
    /* We tolerate up to 10 factors... */
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, NULL, 0),
    /* ..., up to 10 CRT exponents... */
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, NULL, 0),
    /* ..., and up to 9 CRT coefficients */
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, NULL, 0),
};
/*
 * We lied about the amount of factors, exponents and coefficients, the
 * export and import functions can really deal with an infinite amount
 * of these numbers.  However, RSA keys with too many primes are futile,
 * so we at least pretend to have some limits.
 */

static const OSSL_PARAM *rsa_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return rsa_key_types;
    return NULL;
}

static const OSSL_PARAM *rsa_import_types(int selection)
{
    return rsa_imexport_types(selection);
}


static const OSSL_PARAM *rsa_export_types(int selection)
{
    return rsa_imexport_types(selection);
}

static int rsa_get_params(void *key, OSSL_PARAM params[])
{
    RSA *rsa = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, RSA_bits(rsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, RSA_security_bits(rsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, RSA_size(rsa)))
        return 0;

# if 0                           /* PSS support pending */
    if ((p = OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL
        && RSA_get0_pss_params(rsa) != NULL) {
        const EVP_MD *md, *mgf1md;
        int min_saltlen;

        if (!rsa_pss_get_param(RSA_get0_pss_params(rsa),
                               &md, &mgf1md, &min_saltlen)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (!OSSL_PARAM_set_utf8_string(p, EVP_MD_name(md)))
            return 0;
    }
#endif
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
        && RSA_get0_pss_params(rsa) == NULL)
        if (!OSSL_PARAM_set_utf8_string(p, RSA_DEFAULT_MD))
            return 0;

    return 1;
}

static const OSSL_PARAM rsa_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *rsa_gettable_params(void)
{
    return rsa_params;
}

static int rsa_validate(void *keydata, int selection)
{
    RSA *rsa = keydata;
    int ok = 0;

    if ((selection & RSA_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    /* If the whole key is selected, we do a pairwise validation */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        == OSSL_KEYMGMT_SELECT_KEYPAIR) {
        ok = ok && rsa_validate_pairwise(rsa);
    } else {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && rsa_validate_private(rsa);
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && rsa_validate_public(rsa);
    }
    return ok;
}

const OSSL_DISPATCH rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))rsa_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))rsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))rsa_has },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))rsa_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))rsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))rsa_export_types },
    { 0, NULL }
};
