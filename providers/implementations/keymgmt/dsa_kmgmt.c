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
#include <opentls/params.h>
#include "internal/param_build.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "crypto/dsa.h"

static Otls_OP_keymgmt_importdomparams_fn dsa_importdomparams;
static Otls_OP_keymgmt_exportdomparams_fn dsa_exportdomparams;
static Otls_OP_keymgmt_importkey_fn dsa_importkey;
static Otls_OP_keymgmt_exportkey_fn dsa_exportkey;

static int params_to_domparams(DSA *dsa, const Otls_PARAM params[])
{
    const Otls_PARAM *param_p, *param_q, *param_g;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    if (dsa == NULL)
        return 0;

    param_p = Otls_PARAM_locate_const(params, Otls_PKEY_PARAM_FFC_P);
    param_q = Otls_PARAM_locate_const(params, Otls_PKEY_PARAM_FFC_Q);
    param_g = Otls_PARAM_locate_const(params, Otls_PKEY_PARAM_FFC_G);

    if ((param_p != NULL && !Otls_PARAM_get_BN(param_p, &p))
        || (param_q != NULL && !Otls_PARAM_get_BN(param_q, &q))
        || (param_g != NULL && !Otls_PARAM_get_BN(param_g, &g)))
        goto err;

    if (!DSA_set0_pqg(dsa, p, q, g))
        goto err;

    return 1;

 err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    return 0;
}

static int domparams_to_params(DSA *dsa, Otls_PARAM_BLD *tmpl)
{
    const BIGNUM *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL;

    if (dsa == NULL)
        return 0;

    DSA_get0_pqg(dsa, &dsa_p, &dsa_q, &dsa_g);
    if (dsa_p != NULL
        && !otls_param_bld_push_BN(tmpl, Otls_PKEY_PARAM_FFC_P, dsa_p))
        return 0;
    if (dsa_q != NULL
        && !otls_param_bld_push_BN(tmpl, Otls_PKEY_PARAM_FFC_Q, dsa_q))
        return 0;
    if (dsa_g != NULL
        && !otls_param_bld_push_BN(tmpl, Otls_PKEY_PARAM_FFC_G, dsa_g))
        return 0;

    return 1;
}

static int params_to_key(DSA *dsa, const Otls_PARAM params[])
{
    const Otls_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dsa == NULL)
        return 0;

    if (!params_to_domparams(dsa, params))
        return 0;

    param_priv_key =
        Otls_PARAM_locate_const(params, Otls_PKEY_PARAM_DSA_PRIV_KEY);
    param_pub_key =
        Otls_PARAM_locate_const(params, Otls_PKEY_PARAM_DSA_PUB_KEY);

    /*
     * DSA documentation says that a public key must be present if a private key
     * is.
     */
    if (param_priv_key != NULL && param_pub_key == NULL)
        return 0;

    if ((param_priv_key != NULL
         && !Otls_PARAM_get_BN(param_priv_key, &priv_key))
        || (param_pub_key != NULL
            && !Otls_PARAM_get_BN(param_pub_key, &pub_key)))
        goto err;

    if (pub_key != NULL && !DSA_set0_key(dsa, pub_key, priv_key))
        goto err;

    return 1;

 err:
    BN_free(priv_key);
    BN_free(pub_key);
    return 0;
}

static int key_to_params(DSA *dsa, Otls_PARAM_BLD *tmpl)
{
    const BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dsa == NULL)
        return 0;
    if (!domparams_to_params(dsa, tmpl))
        return 0;

    DSA_get0_key(dsa, &pub_key, &priv_key);
    if (priv_key != NULL
        && !otls_param_bld_push_BN(tmpl, Otls_PKEY_PARAM_DSA_PRIV_KEY, priv_key))
        return 0;
    if (pub_key != NULL
        && !otls_param_bld_push_BN(tmpl, Otls_PKEY_PARAM_DSA_PUB_KEY, pub_key))
        return 0;

    return 1;
}

static void *dsa_importdomparams(void *provctx, const Otls_PARAM params[])
{
    DSA *dsa;
    OPENtls_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);

    if ((dsa = dsa_new(libctx)) == NULL
        || !params_to_domparams(dsa, params)) {
        DSA_free(dsa);
        dsa = NULL;
    }
    return dsa;
}

static int dsa_exportdomparams(void *domparams,
                               Otls_CALLBACK *param_cb, void *cbarg)
{
    DSA *dsa = domparams;
    Otls_PARAM_BLD tmpl;
    Otls_PARAM *params = NULL;
    int ret;

    otls_param_bld_init(&tmpl);
    if (dsa == NULL
        || !domparams_to_params(dsa, &tmpl)
        || (params = otls_param_bld_to_param(&tmpl)) == NULL)
        return 0;
    ret = param_cb(params, cbarg);
    otls_param_bld_free(params);
    return ret;
}

static void *dsa_importkey(void *provctx, const Otls_PARAM params[])
{
    DSA *dsa;
    OPENtls_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);

    if ((dsa = dsa_new(libctx)) == NULL
        || !params_to_key(dsa, params)) {
        DSA_free(dsa);
        dsa = NULL;
    }
    return dsa;
}

static int dsa_exportkey(void *key, Otls_CALLBACK *param_cb, void *cbarg)
{
    DSA *dsa = key;
    Otls_PARAM_BLD tmpl;
    Otls_PARAM *params = NULL;
    int ret;

    otls_param_bld_init(&tmpl);
    if (dsa == NULL
        || !key_to_params(dsa, &tmpl)
        || (params = otls_param_bld_to_param(&tmpl)) == NULL)
        return 0;
    ret = param_cb(params, cbarg);
    otls_param_bld_free(params);
    return ret;
}

const Otls_DISPATCH dsa_keymgmt_functions[] = {
    /*
     * TODO(3.0) When implementing Otls_FUNC_KEYMGMT_GENKEY, remember to also
     * implement Otls_FUNC_KEYMGMT_EXPORTKEY.
     */
    { Otls_FUNC_KEYMGMT_IMPORTDOMPARAMS, (void (*)(void))dsa_importdomparams },
    { Otls_FUNC_KEYMGMT_EXPORTDOMPARAMS, (void (*)(void))dsa_exportdomparams },
    { Otls_FUNC_KEYMGMT_FREEDOMPARAMS, (void (*)(void))DSA_free },
    { Otls_FUNC_KEYMGMT_IMPORTKEY, (void (*)(void))dsa_importkey },
    { Otls_FUNC_KEYMGMT_EXPORTKEY, (void (*)(void))dsa_exportkey },
    { Otls_FUNC_KEYMGMT_FREEKEY, (void (*)(void))DSA_free },
    { 0, NULL }
};
