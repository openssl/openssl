/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DH low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_names.h>
#include "internal/param_build_set.h"
#include "crypto/dh.h"

/*
 * The intention with the "backend" source file is to offer backend functions
 * for legacy backends (EVP_PKEY_ASN1_METHOD and EVP_PKEY_METHOD) and provider
 * implementations alike.
 */

static int dh_ffc_params_fromdata(DH *dh, const OSSL_PARAM params[])
{
    int ret;
    FFC_PARAMS *ffc;

    if (dh == NULL)
        return 0;
    ffc = dh_get0_params(dh);
    if (ffc == NULL)
        return 0;

    ret = ossl_ffc_params_fromdata(ffc, params);
    if (ret)
        dh_cache_named_group(dh); /* This increments dh->dirty_cnt */
    return ret;
}

int dh_params_fromdata(DH *dh, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_priv_len;
    long priv_len;

    if (!dh_ffc_params_fromdata(dh, params))
        return 0;

    param_priv_len =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN);
    if (param_priv_len != NULL
        && (!OSSL_PARAM_get_long(param_priv_len, &priv_len)
            || !DH_set_length(dh, priv_len)))
        return 0;

    return 1;
}

int dh_key_fromdata(DH *dh, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dh == NULL)
        return 0;

    param_priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);

    if ((param_priv_key != NULL
         && !OSSL_PARAM_get_BN(param_priv_key, &priv_key))
        || (param_pub_key != NULL
            && !OSSL_PARAM_get_BN(param_pub_key, &pub_key)))
        goto err;

    if (!DH_set0_key(dh, pub_key, priv_key))
        goto err;

    return 1;

 err:
    BN_clear_free(priv_key);
    BN_free(pub_key);
    return 0;
}

int dh_params_todata(DH *dh, OSSL_PARAM_BLD *bld, OSSL_PARAM params[])
{
    long l = DH_get_length(dh);

    if (!ossl_ffc_params_todata(dh_get0_params(dh), bld, params))
        return 0;
    if (l > 0
        && !ossl_param_build_set_long(bld, params, OSSL_PKEY_PARAM_DH_PRIV_LEN, l))
        return 0;
    return 1;
}

int dh_key_todata(DH *dh, OSSL_PARAM_BLD *bld, OSSL_PARAM params[])
{
    const BIGNUM *priv = NULL, *pub = NULL;

    if (dh == NULL)
        return 0;

    DH_get0_key(dh, &pub, &priv);
    if (priv != NULL
        && !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PRIV_KEY, priv))
        return 0;
    if (pub != NULL
        && !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PUB_KEY, pub))
        return 0;

    return 1;
}
