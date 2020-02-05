/*
 * Copyright 2006-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#include "crypto/bn.h"
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "evp_local.h"

int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY *pkey = ctx->pkey;
    void *key;
    EVP_KEYMGMT *keymgmt;

    if (pkey == NULL) {
        EVPerr(EVP_F_EVP_PKEY_PUBLIC_CHECK, EVP_R_NO_KEY_SET);
        return 0;
    }

    keymgmt = pkey->pkeys[0].keymgmt;
    key = pkey->pkeys[0].keydata;

    if (key != NULL && keymgmt != NULL)
        return evp_keymgmt_validate(keymgmt, key,
                                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY);

    /* legacy */
    /* call customized public key check function first */
    if (ctx->pmeth->public_check != NULL)
        return ctx->pmeth->public_check(pkey);

    /* use default public key check function in ameth */
    if (pkey->ameth == NULL || pkey->ameth->pkey_public_check == NULL) {
        EVPerr(EVP_F_EVP_PKEY_PUBLIC_CHECK,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    return pkey->ameth->pkey_public_check(pkey);
}

int EVP_PKEY_param_check(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY *pkey = ctx->pkey;
    void *key;
    EVP_KEYMGMT *keymgmt;

    if (pkey == NULL) {
        EVPerr(EVP_F_EVP_PKEY_PARAM_CHECK, EVP_R_NO_KEY_SET);
        return 0;
    }

    keymgmt = pkey->pkeys[0].keymgmt;
    key = pkey->pkeys[0].keydata;

    if (key != NULL && keymgmt != NULL)
        return evp_keymgmt_validate(keymgmt, key,
                                    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);

    /* call customized param check function first */
    if (ctx->pmeth->param_check != NULL)
        return ctx->pmeth->param_check(pkey);

    /* legacy */
    /* use default param check function in ameth */
    if (pkey->ameth == NULL || pkey->ameth->pkey_param_check == NULL) {
        EVPerr(EVP_F_EVP_PKEY_PARAM_CHECK,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    return pkey->ameth->pkey_param_check(pkey);
}

int EVP_PKEY_private_check(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY *pkey = ctx->pkey;
    void *key;
    EVP_KEYMGMT *keymgmt;

    if (pkey == NULL) {
        EVPerr(0, EVP_R_NO_KEY_SET);
        return 0;
    }

    keymgmt = pkey->pkeys[0].keymgmt;
    key = pkey->pkeys[0].keydata;

    if (key != NULL && keymgmt != NULL)
        return evp_keymgmt_validate(keymgmt, key,
                                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
    /* not supported for legacy keys */
    return -2;
}

int EVP_PKEY_pairwise_check(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY *pkey = ctx->pkey;
    void *key;
    EVP_KEYMGMT *keymgmt;

    if (pkey == NULL) {
        EVPerr(0, EVP_R_NO_KEY_SET);
        return 0;
    }

    keymgmt = pkey->pkeys[0].keymgmt;
    key = pkey->pkeys[0].keydata;

    if (key != NULL && keymgmt != NULL)
        return evp_keymgmt_validate(keymgmt, key, OSSL_KEYMGMT_SELECT_KEYPAIR);
    /* not supported for legacy keys */
    return -2;
}

int EVP_PKEY_check(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY *pkey = ctx->pkey;
    void *key;
    EVP_KEYMGMT *keymgmt;

    if (pkey == NULL) {
        EVPerr(EVP_F_EVP_PKEY_CHECK, EVP_R_NO_KEY_SET);
        return 0;
    }

    keymgmt = pkey->pkeys[0].keymgmt;
    key = pkey->pkeys[0].keydata;

    if (key != NULL && keymgmt != NULL)
        return evp_keymgmt_validate(keymgmt, key, OSSL_KEYMGMT_SELECT_ALL);

    /* legacy */
    /* call customized check function first */
    if (ctx->pmeth->check != NULL)
        return ctx->pmeth->check(pkey);

    /* use default check function in ameth */
    if (pkey->ameth == NULL || pkey->ameth->pkey_check == NULL) {
        EVPerr(EVP_F_EVP_PKEY_CHECK,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    return pkey->ameth->pkey_check(pkey);
}

