/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/param_build.h"
#include "crypto/ecx.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

static OSSL_OP_keymgmt_new_fn x25519_new_key;
static OSSL_OP_keymgmt_new_fn x448_new_key;
static OSSL_OP_keymgmt_get_params_fn x25519_get_params;
static OSSL_OP_keymgmt_get_params_fn x448_get_params;
static OSSL_OP_keymgmt_gettable_params_fn ecx_gettable_params;
static OSSL_OP_keymgmt_has_fn ecx_has;
static OSSL_OP_keymgmt_import_fn ecx_import;
static OSSL_OP_keymgmt_import_types_fn ecx_imexport_types;
static OSSL_OP_keymgmt_export_fn ecx_export;
static OSSL_OP_keymgmt_export_types_fn ecx_imexport_types;

static void *x25519_new_key(void *provctx)
{
    return ecx_key_new(X25519_KEYLEN, 0);
}

static void *x448_new_key(void *provctx)
{
    return ecx_key_new(X448_KEYLEN, 0);
}

static int ecx_has(void *keydata, int selection)
{
    ECX_KEY *key = keydata;
    const int ecx_selections = OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                               | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    int ok = 1;

    if ((selection & ~ecx_selections) != 0
            || (selection & ecx_selections) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && key->haspubkey;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && key->privkey != NULL;

    return ok;
}

static int ecx_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    ECX_KEY *key = keydata;
    size_t privkeylen = 0, pubkeylen;
    const OSSL_PARAM *param_priv_key = NULL, *param_pub_key;
    unsigned char *pubkey;
    const int ecx_selections = OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                               | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

    if (key == NULL)
        return 0;

    if ((selection & ~ecx_selections) != 0
            || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        param_priv_key =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);

    /*
     * If a private key is present then a public key must also be present.
     * Alternatively we've just got a public key.
     */
    if (param_pub_key == NULL
            || (param_priv_key == NULL
                && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0))
        return 0;

    if (param_priv_key != NULL
             && !OSSL_PARAM_get_octet_string(param_priv_key,
                                            (void **)&key->privkey, key->keylen,
                                             &privkeylen))
        return 0;

    pubkey = key->pubkey;
    if (!OSSL_PARAM_get_octet_string(param_pub_key,
                                     (void **)&pubkey,
                                     sizeof(key->pubkey), &pubkeylen))
        return 0;

    if (pubkeylen != key->keylen
            || (param_priv_key != NULL && privkeylen != key->keylen))
        return 0;

    key->haspubkey = 1;

    return 1;
}

static int key_to_params(ECX_KEY *key, OSSL_PARAM_BLD *tmpl)
{
    if (key == NULL)
        return 0;

    if (!ossl_param_bld_push_octet_string(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                          key->pubkey, key->keylen))
        return 0;

    if (key->privkey != NULL
        && !ossl_param_bld_push_octet_string(tmpl, OSSL_PKEY_PARAM_PRIV_KEY,
                                             key->privkey, key->keylen))
        return 0;

    return 1;
}

static int ecx_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    ECX_KEY *key = keydata;
    OSSL_PARAM_BLD tmpl;
    OSSL_PARAM *params = NULL;
    int ret;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0
            && !key_to_params(key, &tmpl))
        return 0;

    ossl_param_bld_init(&tmpl);
    params = ossl_param_bld_to_param(&tmpl);
    if (params == NULL) {
        ossl_param_bld_free(params);
        return 0;
    }

    ret = param_cb(params, cbarg);
    ossl_param_bld_free(params);
    return ret;
}

static const OSSL_PARAM ecx_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *ecx_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ecx_key_types;
    return NULL;
}

static int ecx_get_params(OSSL_PARAM params[], int bits, int secbits,
                          int size)
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, bits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, secbits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, size))
        return 0;
    return 1;
}

static int x25519_get_params(void *key, OSSL_PARAM params[])
{
    return ecx_get_params(params, X25519_BITS, X25519_SECURITY_BITS, X25519_KEYLEN);
}

static int x448_get_params(void *key, OSSL_PARAM params[])
{
    return ecx_get_params(params, X448_BITS, X448_SECURITY_BITS, X448_KEYLEN);
}

static const OSSL_PARAM ecx_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ecx_gettable_params(void)
{
    return ecx_params;
}

const OSSL_DISPATCH x25519_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))x25519_new_key },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ecx_key_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))x25519_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))ecx_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ecx_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ecx_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ecx_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ecx_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ecx_imexport_types },
    { 0, NULL }
};

const OSSL_DISPATCH x448_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))x448_new_key },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ecx_key_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))x448_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))ecx_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ecx_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ecx_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ecx_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ecx_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ecx_imexport_types },
    { 0, NULL }
};
