/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_names.h>
#include "crypto/dsa.h"

/*
 * The intention with the "backend" source file is to offer backend support
 * for legacy backends (EVP_PKEY_ASN1_METHOD and EVP_PKEY_METHOD) and provider
 * implementations alike.
 */

int dsa_key_fromdata(DSA *dsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dsa == NULL)
        return 0;

    param_priv_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);

    /* It's ok if neither half is present */
    if (param_priv_key == NULL && param_pub_key == NULL)
        return 1;

    if (param_pub_key != NULL && !OSSL_PARAM_get_BN(param_pub_key, &pub_key))
        goto err;
    if (param_priv_key != NULL && !OSSL_PARAM_get_BN(param_priv_key, &priv_key))
        goto err;

    if (!DSA_set0_key(dsa, pub_key, priv_key))
        goto err;

    return 1;

 err:
    BN_clear_free(priv_key);
    BN_free(pub_key);
    return 0;
}
