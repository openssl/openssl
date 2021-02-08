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
#include <openssl/ec.h>
#include <openssl/err.h>
#include "crypto/ecx.h"
#include "ecx_backend.h"

/*
 * The intention with the "backend" source file is to offer backend support
 * for legacy backends (EVP_PKEY_ASN1_METHOD and EVP_PKEY_METHOD) and provider
 * implementations alike.
 */

int ecx_public_from_private(ECX_KEY *key)
{
    switch (key->type) {
    case ECX_KEY_TYPE_X25519:
        X25519_public_from_private(key->pubkey, key->privkey);
        break;
    case ECX_KEY_TYPE_ED25519:
        if (!ED25519_public_from_private(key->libctx, key->pubkey, key->privkey,
                                         key->propq)) {
            ERR_raise(ERR_LIB_EC, EC_R_FAILED_MAKING_PUBLIC_KEY);
            return 0;
        }
        break;
    case ECX_KEY_TYPE_X448:
        X448_public_from_private(key->pubkey, key->privkey);
        break;
    case ECX_KEY_TYPE_ED448:
        if (!ED448_public_from_private(key->libctx, key->pubkey, key->privkey,
                                       key->propq)) {
            ERR_raise(ERR_LIB_EC, EC_R_FAILED_MAKING_PUBLIC_KEY);
            return 0;
        }
        break;
    }
    return 1;
}

int ecx_key_fromdata(ECX_KEY *ecx, const OSSL_PARAM params[],
                     int include_private)
{
    size_t privkeylen = 0, pubkeylen = 0;
    const OSSL_PARAM *param_priv_key = NULL, *param_pub_key;
    unsigned char *pubkey;

    if (ecx == NULL)
        return 0;

    param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (include_private)
        param_priv_key =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);

    if (param_pub_key == NULL && param_priv_key == NULL)
        return 0;

    if (param_priv_key != NULL
        && !OSSL_PARAM_get_octet_string(param_priv_key,
                                        (void **)&ecx->privkey, ecx->keylen,
                                        &privkeylen))
        return 0;

    pubkey = ecx->pubkey;
    if (param_pub_key != NULL
        && !OSSL_PARAM_get_octet_string(param_pub_key,
                                        (void **)&pubkey,
                                         sizeof(ecx->pubkey), &pubkeylen))
        return 0;

    if ((param_pub_key != NULL && pubkeylen != ecx->keylen)
        || (param_priv_key != NULL && privkeylen != ecx->keylen))
        return 0;

    if (param_pub_key == NULL && !ecx_public_from_private(ecx))
        return 0;

    ecx->haspubkey = 1;

    return 1;
}

