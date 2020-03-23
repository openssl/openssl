/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/params.h>
#include "crypto/ecx.h"
#include "ecx_backend.h"

/*
 * The intention with the "backend" source file is to offer backend support
 * for legacy backends (EVP_PKEY_ASN1_METHOD and EVP_PKEY_METHOD) and provider
 * implementations alike.
 */

int ecx_key_fromdata(ECX_KEY *ecx, const OSSL_PARAM params[],
                     int include_private)
{
    size_t privkeylen = 0, pubkeylen;
    const OSSL_PARAM *param_priv_key = NULL, *param_pub_key;
    unsigned char *pubkey;

    if (ecx == NULL)
        return 0;

    param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (include_private)
        param_priv_key =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    /*
     * If a private key is present then a public key must also be present.
     * Alternatively we've just got a public key.
     */
    if (param_pub_key == NULL)
        return 0;

    if (param_priv_key != NULL
        && !OSSL_PARAM_get_octet_string(param_priv_key,
                                        (void **)&ecx->privkey, ecx->keylen,
                                        &privkeylen))
        return 0;

    pubkey = ecx->pubkey;
    if (!OSSL_PARAM_get_octet_string(param_pub_key,
                                     (void **)&pubkey,
                                     sizeof(ecx->pubkey), &pubkeylen))
        return 0;

    if (pubkeylen != ecx->keylen
        || (param_priv_key != NULL && privkeylen != ecx->keylen))
        return 0;

    ecx->haspubkey = 1;

    return 1;
}

