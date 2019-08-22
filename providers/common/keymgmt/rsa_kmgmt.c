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
#include "internal/provider_algs.h"

static OSSL_OP_keymgmt_importkey_fn rsa_importkey;

static int params_to_key(RSA *rsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_n, *param_e, *param_d;
    const OSSL_PARAM *param_p, *param_q, *param_dmp1, *param_dmq1, *param_iqmp;
    BIGNUM *n = NULL, *e = NULL, *d =  NULL;
    BIGNUM *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

    if (rsa == NULL)
        return 0;
    param_n = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    param_e = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    param_d = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_P);
    param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_Q);
    param_dmp1 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DMP1);
    param_dmq1 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DMQ1);
    param_iqmp = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_IQMP);

    /*
     * RSA documentation says that public key components must be present if a
     * private key is present.
     * We want to have at least a public key either way, so we end up
     * requiring it unconditionally.
     */
    if (param_n == NULL || param_e == NULL)
        return 0;

    if ((param_d != NULL && !OSSL_PARAM_get_BN(param_d, &d))
        || (param_p != NULL && !OSSL_PARAM_get_BN(param_p, &p))
        || (param_q != NULL && !OSSL_PARAM_get_BN(param_q, &q))
        || (param_dmp1 != NULL && !OSSL_PARAM_get_BN(param_dmp1, &dmp1))
        || (param_dmq1 != NULL && !OSSL_PARAM_get_BN(param_dmq1, &dmq1))
        || (param_iqmp != NULL && !OSSL_PARAM_get_BN(param_iqmp, &iqmp))
        || !OSSL_PARAM_get_BN(param_n, &n)
        || !OSSL_PARAM_get_BN(param_e, &e))
        goto err;

    if (!RSA_set0_factors(rsa, p, q)
        || !RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp))
        goto err;
    p = q = dmp1 = dmq1 = iqmp = NULL;

    if (!RSA_set0_key(rsa, n, e, d))
        goto err;
    n = e = d = NULL;

    return 1;

 err:
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    return 0;
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

const OSSL_DISPATCH rsa_keymgmt_functions[] = {
    /*
     * TODO(3.0) When implementing OSSL_FUNC_KEYMGMT_GENKEY, remember to also
     * implement OSSL_FUNC_KEYMGMT_EXPORTKEY.
     */
    { OSSL_FUNC_KEYMGMT_IMPORTKEY, (void (*)(void))rsa_importkey },
    { OSSL_FUNC_KEYMGMT_FREEKEY, (void (*)(void))RSA_free },
    { 0, NULL }
};
