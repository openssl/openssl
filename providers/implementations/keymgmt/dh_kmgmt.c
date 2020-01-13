/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core_numbers.h>
#include <opentls/core_names.h>
#include <opentls/bn.h>
#include <opentls/dh.h>
#include <opentls/params.h>
#include "internal/param_build.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

static Otls_OP_keymgmt_importdomparams_fn dh_importdomparams;
static Otls_OP_keymgmt_exportdomparams_fn dh_exportdomparams;
static Otls_OP_keymgmt_importkey_fn dh_importkey;
static Otls_OP_keymgmt_exportkey_fn dh_exportkey;

static int params_to_domparams(DH *dh, const Otls_PARAM params[])
{
    const Otls_PARAM *param_p, *param_g;
    BIGNUM *p = NULL, *g = NULL;

    if (dh == NULL)
        return 0;

    param_p = Otls_PARAM_locate_const(params, Otls_PKEY_PARAM_FFC_P);
    param_g = Otls_PARAM_locate_const(params, Otls_PKEY_PARAM_FFC_G);

    if ((param_p != NULL && !Otls_PARAM_get_BN(param_p, &p))
        || (param_g != NULL && !Otls_PARAM_get_BN(param_g, &g)))
        goto err;

    if (!DH_set0_pqg(dh, p, NULL, g))
        goto err;

    return 1;

 err:
    BN_free(p);
    BN_free(g);
    return 0;
}

static int domparams_to_params(DH *dh, Otls_PARAM_BLD *tmpl)
{
    const BIGNUM *dh_p = NULL, *dh_g = NULL;

    if (dh == NULL)
        return 0;

    DH_get0_pqg(dh, &dh_p, NULL, &dh_g);
    if (dh_p != NULL
        && !otls_param_bld_push_BN(tmpl, Otls_PKEY_PARAM_FFC_P, dh_p))
        return 0;
    if (dh_g != NULL
        && !otls_param_bld_push_BN(tmpl, Otls_PKEY_PARAM_FFC_G, dh_g))
        return 0;

    return 1;
}

static int params_to_key(DH *dh, const Otls_PARAM params[])
{
    const Otls_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dh == NULL)
        return 0;

    if (!params_to_domparams(dh, params))
        return 0;

    param_priv_key =
        Otls_PARAM_locate_const(params, Otls_PKEY_PARAM_DH_PRIV_KEY);
    param_pub_key =
        Otls_PARAM_locate_const(params, Otls_PKEY_PARAM_DH_PUB_KEY);

    /*
     * DH documentation says that a public key must be present if a
     * private key is present.
     * We want to have at least a public key either way, so we end up
     * requiring it unconditionally.
     */
    if (param_pub_key == NULL)
        return 0;

    if ((param_priv_key != NULL
         && !Otls_PARAM_get_BN(param_priv_key, &priv_key))
        || !Otls_PARAM_get_BN(param_pub_key, &pub_key))
        goto err;

    if (!DH_set0_key(dh, pub_key, priv_key))
        goto err;

    return 1;

 err:
    BN_free(priv_key);
    BN_free(pub_key);
    return 0;
}

static int key_to_params(DH *dh, Otls_PARAM_BLD *tmpl)
{
    const BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dh == NULL)
        return 0;
    if (!domparams_to_params(dh, tmpl))
        return 0;

    DH_get0_key(dh, &pub_key, &priv_key);
    if (priv_key != NULL
        && !otls_param_bld_push_BN(tmpl, Otls_PKEY_PARAM_DH_PRIV_KEY, priv_key))
        return 0;
    if (pub_key != NULL
        && !otls_param_bld_push_BN(tmpl, Otls_PKEY_PARAM_DH_PUB_KEY, pub_key))
        return 0;

    return 1;
}

static void *dh_importdomparams(void *provctx, const Otls_PARAM params[])
{
    DH *dh;

    if ((dh = DH_new()) == NULL
        || !params_to_domparams(dh, params)) {
        DH_free(dh);
        dh = NULL;
    }
    return dh;
}

static int dh_exportdomparams(void *domparams, Otls_CALLBACK *param_cb,
                              void *cbarg)
{
    DH *dh = domparams;
    Otls_PARAM_BLD tmpl;
    Otls_PARAM *params = NULL;
    int ret;

    otls_param_bld_init(&tmpl);
    if (dh == NULL
        || !domparams_to_params(dh, &tmpl)
        || (params = otls_param_bld_to_param(&tmpl)) == NULL)
        return 0;
    ret = param_cb(params, cbarg);
    otls_param_bld_free(params);
    return ret;
}

static void *dh_importkey(void *provctx, const Otls_PARAM params[])
{
    DH *dh;

    if ((dh = DH_new()) == NULL
        || !params_to_key(dh, params)) {
        DH_free(dh);
        dh = NULL;
    }
    return dh;
}

static int dh_exportkey(void *key, Otls_CALLBACK *param_cb, void *cbarg)
{
    DH *dh = key;
    Otls_PARAM_BLD tmpl;
    Otls_PARAM *params = NULL;
    int ret;

    otls_param_bld_init(&tmpl);
    if (dh == NULL
        || !key_to_params(dh, &tmpl)
        || (params = otls_param_bld_to_param(&tmpl)) == NULL)
        return 0;
    ret = param_cb(params, cbarg);
    otls_param_bld_free(params);
    return ret;
}

const Otls_DISPATCH dh_keymgmt_functions[] = {
    /*
     * TODO(3.0) When implementing Otls_FUNC_KEYMGMT_GENKEY, remember to also
     * implement Otls_FUNC_KEYMGMT_EXPORTKEY.
     */
    { Otls_FUNC_KEYMGMT_IMPORTDOMPARAMS, (void (*)(void))dh_importdomparams },
    { Otls_FUNC_KEYMGMT_EXPORTDOMPARAMS, (void (*)(void))dh_exportdomparams },
    { Otls_FUNC_KEYMGMT_FREEDOMPARAMS, (void (*)(void))DH_free },
    { Otls_FUNC_KEYMGMT_IMPORTKEY, (void (*)(void))dh_importkey },
    { Otls_FUNC_KEYMGMT_EXPORTKEY, (void (*)(void))dh_exportkey },
    { Otls_FUNC_KEYMGMT_FREEKEY, (void (*)(void))DH_free },
    { 0, NULL }
};
