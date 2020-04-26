/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include "crypto/dh.h"

/*
 * The intention with the "backend" source file is to offer backend functions
 * for legacy backends (EVP_PKEY_ASN1_METHOD and EVP_PKEY_METHOD) and provider
 * implementations alike.
 */

int dh_key_fromdata(DH *dh, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dh == NULL)
        return 0;

    param_priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);

    /*
     * DH documentation says that a public key must be present if a
     * private key is present.
     * We want to have at least a public key either way, so we end up
     * requiring it unconditionally.
     */
    if (param_priv_key != NULL && param_pub_key == NULL)
        return 0;

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
