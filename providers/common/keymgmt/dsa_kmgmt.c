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
#include "internal/provider_algs.h"

static OSSL_OP_keymgmt_importkey_fn dsa_importkey;

static int params_to_key(DSA *dsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_p, *param_q, *param_g;
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv_key = NULL, *pub_key = NULL;

    if (dsa == NULL)
        return 0;

    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
    param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);
    param_g = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);
    param_priv_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DSA_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DSA_PUB_KEY);

    /* Domain parameters must be present, the rest might not */
    if (param_p == NULL || param_q == NULL || param_g == NULL)
        return 0;

    if (!OSSL_PARAM_get_BN(param_p, &p)
        || !OSSL_PARAM_get_BN(param_q, &q)
        || !OSSL_PARAM_get_BN(param_g, &g)
        || (param_priv_key != NULL
            && !OSSL_PARAM_get_BN(param_priv_key, &priv_key))
        || (param_pub_key != NULL
            && !OSSL_PARAM_get_BN(param_pub_key, &pub_key)))
        goto err;

    if (!DSA_set0_pqg(dsa, p, q, g))
        goto err;
    p = q = g = NULL;

    if (!DSA_set0_key(dsa, pub_key, priv_key))
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
    { OSSL_FUNC_KEYMGMT_IMPORTKEY, (void (*)(void))dsa_importkey },
    { OSSL_FUNC_KEYMGMT_FREEKEY, (void (*)(void))DSA_free },
    { 0, NULL }
};
