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
#include <openssl/dh.h>
#include <openssl/params.h>
#include "internal/param_build.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

static OSSL_OP_keymgmt_importdomparams_fn dh_importdomparams;
static OSSL_OP_keymgmt_exportdomparams_fn dh_exportdomparams;
static OSSL_OP_keymgmt_get_key_params_fn dh_get_domparam_params;
static OSSL_OP_keymgmt_isdomparams_fn dh_isdomparams;
static OSSL_OP_keymgmt_cmpdomparams_fn dh_cmpdomparams;
static OSSL_OP_keymgmt_dupdomparams_fn dh_dupdomparams;
static OSSL_OP_keymgmt_importkey_fn dh_importkey;
static OSSL_OP_keymgmt_exportkey_fn dh_exportkey;
static OSSL_OP_keymgmt_get_key_params_fn dh_get_key_params;
static OSSL_OP_keymgmt_iskey_fn dh_iskey;
static OSSL_OP_keymgmt_cmpkey_fn dh_cmpkey;
static OSSL_OP_keymgmt_dupkey_fn dh_dupkey;

static int params_to_domparams(DH *dh, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_p, *param_g;
    BIGNUM *p = NULL, *g = NULL;

    if (dh == NULL)
        return 0;

    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
    param_g = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);

    if ((param_p != NULL && !OSSL_PARAM_get_BN(param_p, &p))
        || (param_g != NULL && !OSSL_PARAM_get_BN(param_g, &g)))
        goto err;

    if (!DH_set0_pqg(dh, p, NULL, g))
        goto err;

    return 1;

 err:
    BN_free(p);
    BN_free(g);
    return 0;
}

static int domparams_to_params(DH *dh, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *dh_p = NULL, *dh_g = NULL;

    if (dh == NULL)
        return 0;

    DH_get0_pqg(dh, &dh_p, NULL, &dh_g);
    if (dh_p != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, dh_p))
        return 0;
    if (dh_g != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, dh_g))
        return 0;

    return 1;
}

static int params_to_key(DH *dh, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dh == NULL)
        return 0;

    if (!params_to_domparams(dh, params))
        return 0;

    param_priv_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PUB_KEY);

    /*
     * DH documentation says that a public key must be present if a
     * private key is present.
     * We want to have at least a public key either way, so we end up
     * requiring it unconditionally.
     */
    if (param_pub_key == NULL)
        return 0;

    if ((param_priv_key != NULL
         && !OSSL_PARAM_get_BN(param_priv_key, &priv_key))
        || !OSSL_PARAM_get_BN(param_pub_key, &pub_key))
        goto err;

    if (!DH_set0_key(dh, pub_key, priv_key))
        goto err;

    return 1;

 err:
    BN_free(priv_key);
    BN_free(pub_key);
    return 0;
}

static int key_to_params(DH *dh, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dh == NULL)
        return 0;
    if (!domparams_to_params(dh, tmpl))
        return 0;

    DH_get0_key(dh, &pub_key, &priv_key);
    if (priv_key != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_DH_PRIV_KEY, priv_key))
        return 0;
    if (pub_key != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_DH_PUB_KEY, pub_key))
        return 0;

    return 1;
}

static void *dh_importdomparams(void *provctx, const OSSL_PARAM params[])
{
    DH *dh;

    if ((dh = DH_new()) == NULL
        || !params_to_domparams(dh, params)) {
        DH_free(dh);
        dh = NULL;
    }
    return dh;
}

static int dh_exportdomparams(void *domparams, OSSL_CALLBACK *param_cb,
                              void *cbarg)
{
    DH *dh = domparams;
    OSSL_PARAM_BLD tmpl;
    OSSL_PARAM *params = NULL;
    int ret;

    ossl_param_bld_init(&tmpl);
    if (dh == NULL
        || !domparams_to_params(dh, &tmpl)
        || (params = ossl_param_bld_to_param(&tmpl)) == NULL)
        return 0;
    ret = param_cb(params, cbarg);
    ossl_param_bld_free(params);
    return ret;
}

static int dh_isdomparams(const void *domparams)
{
    /*
     * dh should always contain the domain parameters, so we could as well
     * return 1 here and be done with it.  However, future development might
     * change this, so we make this future proof and test for real.
     */
    return DH_get0_p(domparams) != NULL && DH_get0_g(domparams) != NULL;
}

static int dh_cmpdomparams(const void *domparams1, const void *domparams2)
{
    const BIGNUM *q1, *q2;

    if (BN_cmp(DH_get0_p(domparams1), DH_get0_p(domparams2)) != 0
        && BN_cmp(DH_get0_g(domparams1), DH_get0_g(domparams2)) != 0)
        return 0;
    /* Support DHX, compare Q if available */
    q1 = DH_get0_q(domparams1);
    q2 = DH_get0_q(domparams2);
    if (q1 == NULL && q2 == NULL)
        return 1;
    if (q1 == NULL || q2 == NULL)
        return 0;
    return (BN_cmp(q1, q1) == 0);
}

static void *dh_dupdomparams(void *domparams, int do_copy)
{
    DH *new = domparams;

    if (do_copy)
        new = DHparams_dup(domparams);
    else
        DH_up_ref(new);
    return new;
}

static void *dh_importkey(void *provctx, const OSSL_PARAM params[])
{
    DH *dh;

    if ((dh = DH_new()) == NULL
        || !params_to_key(dh, params)) {
        DH_free(dh);
        dh = NULL;
    }
    return dh;
}

static int dh_exportkey(void *key, OSSL_CALLBACK *param_cb, void *cbarg)
{
    DH *dh = key;
    OSSL_PARAM_BLD tmpl;
    OSSL_PARAM *params = NULL;
    int ret;

    ossl_param_bld_init(&tmpl);
    if (dh == NULL
        || !key_to_params(dh, &tmpl)
        || (params = ossl_param_bld_to_param(&tmpl)) == NULL)
        return 0;
    ret = param_cb(params, cbarg);
    ossl_param_bld_free(params);
    return ret;
}

/*
 * Same function for domain parameters and for keys.
 * "dpk" = "domain parameters & keys"
 */
static ossl_inline int dh_get_dpk_params(void *key, OSSL_PARAM params[])
{
    DH *dh = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DH_bits(dh)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DH_security_bits(dh)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, DH_size(dh)))
        return 0;
    return 1;
}

/*
 * We have wrapper functions to make sure we get signatures right, see
 * the forward declarations at the beginning of this file.
 */
static int dh_get_domparam_params(void *domparams, OSSL_PARAM params[])
{
    return dh_get_dpk_params(domparams, params);
}

static int dh_get_key_params(void *key, OSSL_PARAM params[])
{
    return dh_get_dpk_params(key, params);
}

static int dh_iskey(const void *key)
{
    return DH_get0_pub_key(key) != NULL;
}

static int dh_cmpkey(const void *key1, const void *key2)
{
    if (BN_cmp(DH_get0_pub_key(key1), DH_get0_pub_key(key2)) != 0)
        return 0;
    return 1;
}

static void *dh_dupkey(void *key, int do_copy)
{
    if (do_copy)
        /*
         * the EVP library currently only supports copying domain params,
         * so we don't need to care...  besides, if we want to support
         * copying DH keys, there should be a function in the low level
         * DH library.
         */
        return NULL;
    else
        DH_up_ref(key);
    return key;
}

const OSSL_DISPATCH dh_keymgmt_functions[] = {
    /*
     * TODO(3.0) When implementing OSSL_FUNC_KEYMGMT_GENKEY, remember to also
     * implement OSSL_FUNC_KEYMGMT_EXPORTKEY.
     */
    { OSSL_FUNC_KEYMGMT_IMPORTDOMPARAMS, (void (*)(void))dh_importdomparams },
    { OSSL_FUNC_KEYMGMT_EXPORTDOMPARAMS, (void (*)(void))dh_exportdomparams },
    { OSSL_FUNC_KEYMGMT_GET_DOMPARAM_PARAMS,
      (void (*) (void))dh_get_domparam_params },
    { OSSL_FUNC_KEYMGMT_FREEDOMPARAMS, (void (*)(void))DH_free },
    { OSSL_FUNC_KEYMGMT_ISDOMPARAMS, (void (*)(void))dh_isdomparams },
    { OSSL_FUNC_KEYMGMT_CMPDOMPARAMS, (void (*)(void))dh_cmpdomparams },
    { OSSL_FUNC_KEYMGMT_DUPDOMPARAMS, (void (*)(void))dh_dupdomparams },
    { OSSL_FUNC_KEYMGMT_IMPORTKEY, (void (*)(void))dh_importkey },
    { OSSL_FUNC_KEYMGMT_EXPORTKEY, (void (*)(void))dh_exportkey },
    { OSSL_FUNC_KEYMGMT_FREEKEY, (void (*)(void))DH_free },
    { OSSL_FUNC_KEYMGMT_GET_KEY_PARAMS,  (void (*) (void))dh_get_key_params },
    { OSSL_FUNC_KEYMGMT_ISKEY, (void (*)(void))dh_iskey },
    { OSSL_FUNC_KEYMGMT_CMPKEY, (void (*)(void))dh_cmpkey },
    { OSSL_FUNC_KEYMGMT_DUPKEY, (void (*)(void))dh_dupkey },
    { 0, NULL }
};
