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
#include <openssl/dsa.h>
#include <openssl/params.h>
#include "prov/implementations.h"

static OSSL_OP_keymgmt_importdomparams_fn dsa_importdomparams;
static OSSL_OP_keymgmt_importkey_fn dsa_importkey;

static int params_to_domparams(DSA *dsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_p, *param_q, *param_g;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    if (dsa == NULL)
        return 0;

    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
    param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);
    param_g = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);

    if ((param_p != NULL && !OSSL_PARAM_get_BN(param_p, &p))
        || (param_q != NULL && !OSSL_PARAM_get_BN(param_q, &q))
        || (param_g != NULL && !OSSL_PARAM_get_BN(param_g, &g)))
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

static int params_to_key(DSA *dsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dsa == NULL)
        return 0;

    if (!params_to_domparams(dsa, params))
        return 0;

    param_priv_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DSA_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DSA_PUB_KEY);

    /*
     * DSA documentation says that a public key must be present if a private key
     * is.
     */
    if (param_priv_key != NULL && param_pub_key == NULL)
        return 0;

    if ((param_priv_key != NULL
         && !OSSL_PARAM_get_BN(param_priv_key, &priv_key))
        || (param_pub_key != NULL
            && !OSSL_PARAM_get_BN(param_pub_key, &pub_key)))
        goto err;

    if (pub_key != NULL && !DSA_set0_key(dsa, pub_key, priv_key))
        goto err;

    return 1;

 err:
    BN_free(priv_key);
    BN_free(pub_key);
    return 0;
}

static void *dsa_importdomparams(void *provctx, const OSSL_PARAM params[])
{
    DSA *dsa;

    if ((dsa = DSA_new()) == NULL
        || !params_to_domparams(dsa, params)) {
        DSA_free(dsa);
        dsa = NULL;
    }
    return dsa;
}

static void *dsa_importkey(void *provctx, const OSSL_PARAM params[])
{
    DSA *dsa;

    if ((dsa = DSA_new()) == NULL
        || !params_to_key(dsa, params)) {
        DSA_free(dsa);
        dsa = NULL;
    }
    return dsa;
}

const OSSL_DISPATCH dsa_keymgmt_functions[] = {
    /*
     * TODO(3.0) When implementing OSSL_FUNC_KEYMGMT_GENKEY, remember to also
     * implement OSSL_FUNC_KEYMGMT_EXPORTKEY.
     */
    { OSSL_FUNC_KEYMGMT_IMPORTDOMPARAMS, (void (*)(void))dsa_importdomparams },
    { OSSL_FUNC_KEYMGMT_FREEDOMPARAMS, (void (*)(void))DSA_free },
    { OSSL_FUNC_KEYMGMT_IMPORTKEY, (void (*)(void))dsa_importkey },
    { OSSL_FUNC_KEYMGMT_FREEKEY, (void (*)(void))DSA_free },
    { 0, NULL }
};
