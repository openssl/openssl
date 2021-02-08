/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include "internal/sizes.h"
#include "internal/param_build_set.h"
#include "crypto/rsa.h"

#include "e_os.h"                /* strcasecmp for Windows() */

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

int ossl_rsa_fromdata(RSA *rsa, const OSSL_PARAM params[])
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
                             ossl_rsa_mp_factor_names)
            || !collect_numbers(exps = sk_BIGNUM_new_null(), params,
                                ossl_rsa_mp_exp_names)
            || !collect_numbers(coeffs = sk_BIGNUM_new_null(), params,
                                ossl_rsa_mp_coeff_names))
            goto err;

        /* It's ok if this private key just has n, e and d */
        if (sk_BIGNUM_num(factors) != 0
            && !ossl_rsa_set0_all_params(rsa, factors, exps, coeffs))
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

int ossl_rsa_todata(RSA *rsa, OSSL_PARAM_BLD *bld, OSSL_PARAM params[])
{
    int ret = 0;
    const BIGNUM *rsa_d = NULL, *rsa_n = NULL, *rsa_e = NULL;
    STACK_OF(BIGNUM_const) *factors = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *exps = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *coeffs = sk_BIGNUM_const_new_null();

    if (rsa == NULL || factors == NULL || exps == NULL || coeffs == NULL)
        goto err;

    RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
    ossl_rsa_get0_all_params(rsa, factors, exps, coeffs);

    if (!ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_N, rsa_n)
        || !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_E, rsa_e))
        goto err;

    /* Check private key data integrity */
    if (rsa_d != NULL) {
        int numprimes = sk_BIGNUM_const_num(factors);
        int numexps = sk_BIGNUM_const_num(exps);
        int numcoeffs = sk_BIGNUM_const_num(coeffs);

        /*
         * It's permissible to have zero primes, i.e. no CRT params.
         * Otherwise, there must be at least two, as many exponents,
         * and one coefficient less.
         */
        if (numprimes != 0
            && (numprimes < 2 || numexps < 2 || numcoeffs < 1))
            goto err;

        if (!ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_D,
                                     rsa_d)
            || !ossl_param_build_set_multi_key_bn(bld, params,
                                                  ossl_rsa_mp_factor_names,
                                                  factors)
            || !ossl_param_build_set_multi_key_bn(bld, params,
                                                  ossl_rsa_mp_exp_names, exps)
            || !ossl_param_build_set_multi_key_bn(bld, params,
                                                  ossl_rsa_mp_coeff_names,
                                                  coeffs))
        goto err;
    }

#if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)
    /* The acvp test results are not meant for export so check for bld == NULL */
    if (bld == NULL)
        rsa_acvp_test_get_params(rsa, params);
#endif
    ret = 1;
 err:
    sk_BIGNUM_const_free(factors);
    sk_BIGNUM_const_free(exps);
    sk_BIGNUM_const_free(coeffs);
    return ret;
}

int ossl_rsa_pss_params_30_todata(const RSA_PSS_PARAMS_30 *pss,
                                  OSSL_PARAM_BLD *bld, OSSL_PARAM params[])
{
    if (!ossl_rsa_pss_params_30_is_unrestricted(pss)) {
        int hashalg_nid = ossl_rsa_pss_params_30_hashalg(pss);
        int maskgenalg_nid = ossl_rsa_pss_params_30_maskgenalg(pss);
        int maskgenhashalg_nid = ossl_rsa_pss_params_30_maskgenhashalg(pss);
        int saltlen = ossl_rsa_pss_params_30_saltlen(pss);
        int default_hashalg_nid = ossl_rsa_pss_params_30_hashalg(NULL);
        int default_maskgenalg_nid = ossl_rsa_pss_params_30_maskgenalg(NULL);
        int default_maskgenhashalg_nid =
                ossl_rsa_pss_params_30_maskgenhashalg(NULL);
        const char *mdname =
            (hashalg_nid == default_hashalg_nid
             ? NULL : ossl_rsa_oaeppss_nid2name(hashalg_nid));
        const char *mgfname =
            (maskgenalg_nid == default_maskgenalg_nid
             ? NULL : ossl_rsa_oaeppss_nid2name(maskgenalg_nid));
        const char *mgf1mdname =
            (maskgenhashalg_nid == default_maskgenhashalg_nid
             ? NULL : ossl_rsa_oaeppss_nid2name(maskgenhashalg_nid));
        const char *key_md = OSSL_PKEY_PARAM_RSA_DIGEST;
        const char *key_mgf = OSSL_PKEY_PARAM_RSA_MASKGENFUNC;
        const char *key_mgf1_md = OSSL_PKEY_PARAM_RSA_MGF1_DIGEST;
        const char *key_saltlen = OSSL_PKEY_PARAM_RSA_PSS_SALTLEN;

        /*
         * To ensure that the key isn't seen as unrestricted by the recipient,
         * we make sure that at least one PSS-related parameter is passed, even
         * if it has a default value; saltlen.
         */
        if ((mdname != NULL
             && !ossl_param_build_set_utf8_string(bld, params, key_md, mdname))
            || (mgfname != NULL
                && !ossl_param_build_set_utf8_string(bld, params,
                                                     key_mgf, mgfname))
            || (mgf1mdname != NULL
                && !ossl_param_build_set_utf8_string(bld, params,
                                                     key_mgf1_md, mgf1mdname))
            || (!ossl_param_build_set_int(bld, params, key_saltlen, saltlen)))
            return 0;
    }
    return 1;
}

int ossl_rsa_pss_params_30_fromdata(RSA_PSS_PARAMS_30 *pss_params,
                                    int *defaults_set,
                                    const OSSL_PARAM params[],
                                    OSSL_LIB_CTX *libctx)
{
    const OSSL_PARAM *param_md, *param_mgf, *param_mgf1md,  *param_saltlen;
    const OSSL_PARAM *param_propq;
    const char *propq = NULL;
    EVP_MD *md = NULL, *mgf1md = NULL;
    int saltlen;
    int ret = 0;

    if (pss_params == NULL)
        return 0;
    param_propq =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST_PROPS);
    param_md =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST);
    param_mgf =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MASKGENFUNC);
    param_mgf1md =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST);
    param_saltlen =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);

    if (param_propq != NULL) {
        if (param_propq->data_type == OSSL_PARAM_UTF8_STRING)
            propq = param_propq->data;
    }
    /*
     * If we get any of the parameters, we know we have at least some
     * restrictions, so we start by setting default values, and let each
     * parameter override their specific restriction data.
     */
    if (!*defaults_set
        && (param_md != NULL || param_mgf != NULL || param_mgf1md != NULL
            || param_saltlen != NULL)) {
        if (!ossl_rsa_pss_params_30_set_defaults(pss_params))
            return 0;
        *defaults_set = 1;
    }

    if (param_mgf != NULL) {
        int default_maskgenalg_nid = ossl_rsa_pss_params_30_maskgenalg(NULL);
        const char *mgfname = NULL;

        if (param_mgf->data_type == OSSL_PARAM_UTF8_STRING)
            mgfname = param_mgf->data;
        else if (!OSSL_PARAM_get_utf8_ptr(param_mgf, &mgfname))
            return 0;

        /* TODO Revisit this if / when a new MGF algorithm appears */
        if (strcasecmp(param_mgf->data,
                       ossl_rsa_mgf_nid2name(default_maskgenalg_nid)) != 0)
            return 0;
    }

    /*
     * We're only interested in the NIDs that correspond to the MDs, so the
     * exact propquery is unimportant in the EVP_MD_fetch() calls below.
     */

    if (param_md != NULL) {
        const char *mdname = NULL;

        if (param_md->data_type == OSSL_PARAM_UTF8_STRING)
            mdname = param_md->data;
        else if (!OSSL_PARAM_get_utf8_ptr(param_mgf, &mdname))
            goto err;

        if ((md = EVP_MD_fetch(libctx, mdname, propq)) == NULL
            || !ossl_rsa_pss_params_30_set_hashalg(pss_params,
                                                   ossl_rsa_oaeppss_md2nid(md)))
            goto err;
    }

    if (param_mgf1md != NULL) {
        const char *mgf1mdname = NULL;

        if (param_mgf1md->data_type == OSSL_PARAM_UTF8_STRING)
            mgf1mdname = param_mgf1md->data;
        else if (!OSSL_PARAM_get_utf8_ptr(param_mgf, &mgf1mdname))
            goto err;

        if ((mgf1md = EVP_MD_fetch(libctx, mgf1mdname, propq)) == NULL
            || !ossl_rsa_pss_params_30_set_maskgenhashalg(
                    pss_params, ossl_rsa_oaeppss_md2nid(mgf1md)))
            goto err;
    }

    if (param_saltlen != NULL) {
        if (!OSSL_PARAM_get_int(param_saltlen, &saltlen)
            || !ossl_rsa_pss_params_30_set_saltlen(pss_params, saltlen))
            goto err;
    }

    ret = 1;

 err:
    EVP_MD_free(md);
    EVP_MD_free(mgf1md);
    return ret;
}
