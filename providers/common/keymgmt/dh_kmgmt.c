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
#include "internal/provider_algs.h"

static OSSL_OP_keymgmt_importkey_fn dh_importkey;

static int params_to_key(DH *dh, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_p, *param_q, *param_g;
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv_key = NULL, *pub_key = NULL;

    if (dh == NULL)
        return 0;

    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
    param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);
    param_g = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);
    param_priv_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PUB_KEY);

    /* Domain parameters p and g must be present, the rest might not */
    if (param_p == NULL || param_g == NULL)
        return 0;

    if (!OSSL_PARAM_get_BN(param_p, &p)
        || !OSSL_PARAM_get_BN(param_g, &g)
        || (param_q != NULL && !OSSL_PARAM_get_BN(param_q, &q))
        || (param_priv_key != NULL
            && !OSSL_PARAM_get_BN(param_priv_key, &priv_key))
        || (param_pub_key != NULL
            && !OSSL_PARAM_get_BN(param_pub_key, &pub_key)))
        goto err;

    if (!DH_set0_pqg(dh, p, q, g))
        goto err;
    p = q = g = NULL;

    if (!DH_set0_key(dh, pub_key, priv_key))
        goto err;
    priv_key = pub_key = NULL;

    return 1;

 err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(priv_key);
    BN_free(pub_key);
    return 0;
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

const OSSL_DISPATCH dh_keymgmt_functions[] = {
    /*
     * TODO(3.0) When implementing OSSL_FUNC_KEYMGMT_GENKEY, remember to also
     * implement OSSL_FUNC_KEYMGMT_EXPORTKEY.
     */
    { OSSL_FUNC_KEYMGMT_IMPORTKEY, (void (*)(void))dh_importkey },
    { OSSL_FUNC_KEYMGMT_FREEKEY, (void (*)(void))DH_free },
    { 0, NULL }
};
