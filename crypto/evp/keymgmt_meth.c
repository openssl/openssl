/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "internal/provider.h"
#include "internal/refcount.h"
#include "internal/evp_int.h"
#include "evp_locl.h"


static void *keymgmt_new(void)
{
    EVP_KEYMGMT *keymgmt = NULL;

    if ((keymgmt = OPENSSL_zalloc(sizeof(*keymgmt))) == NULL
        || (keymgmt->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        EVP_KEYMGMT_free(keymgmt);
        return NULL;
    }

    keymgmt->refcnt = 1;

    return keymgmt;
}

static void *keymgmt_from_dispatch(const OSSL_DISPATCH *fns,
                                   OSSL_PROVIDER *prov)
{
    EVP_KEYMGMT *keymgmt = NULL;

    if ((keymgmt = keymgmt_new()) == NULL)
        return NULL;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_KEYMGMT_IMPORTDOMAIN:
            if (keymgmt->importdomain != NULL)
                break;
            keymgmt->importdomain = OSSL_get_OP_keymgmt_importdomain(fns);
            break;
        case OSSL_FUNC_KEYMGMT_GENDOMAIN:
            if (keymgmt->gendomain != NULL)
                break;
            keymgmt->gendomain = OSSL_get_OP_keymgmt_gendomain(fns);
            break;
        case OSSL_FUNC_KEYMGMT_FREEDOMAIN:
            if (keymgmt->freedomain != NULL)
                break;
            keymgmt->freedomain = OSSL_get_OP_keymgmt_freedomain(fns);
            break;
        case OSSL_FUNC_KEYMGMT_EXPORTDOMAIN:
            if (keymgmt->exportdomain != NULL)
                break;
            keymgmt->exportdomain = OSSL_get_OP_keymgmt_exportdomain(fns);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORTDOMAIN_TYPES:
            if (keymgmt->importdomain_types != NULL)
                break;
            keymgmt->importdomain_types =
                OSSL_get_OP_keymgmt_importdomain_types(fns);
            break;
        case OSSL_FUNC_KEYMGMT_EXPORTDOMAIN_TYPES:
            if (keymgmt->exportdomain_types != NULL)
                break;
            keymgmt->exportdomain_types =
                OSSL_get_OP_keymgmt_exportdomain_types(fns);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORTKEY_PRIV:
            if (keymgmt->importkey_priv != NULL)
                break;
            keymgmt->importkey_priv =
                OSSL_get_OP_keymgmt_importkey_priv(fns);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORTKEY_PUB:
            if (keymgmt->importkey_pub != NULL)
                break;
            keymgmt->importkey_pub = OSSL_get_OP_keymgmt_importkey_pub(fns);
            break;
        case OSSL_FUNC_KEYMGMT_GENKEY:
            if (keymgmt->genkey != NULL)
                break;
            keymgmt->genkey = OSSL_get_OP_keymgmt_genkey(fns);
            break;
        case OSSL_FUNC_KEYMGMT_LOADKEY:
            if (keymgmt->loadkey != NULL)
                break;
            keymgmt->loadkey = OSSL_get_OP_keymgmt_loadkey(fns);
            break;
        case OSSL_FUNC_KEYMGMT_FREEKEY:
            if (keymgmt->freekey != NULL)
                break;
            keymgmt->freekey = OSSL_get_OP_keymgmt_freekey(fns);
            break;
        case OSSL_FUNC_KEYMGMT_EXPORTKEY_PRIV:
            if (keymgmt->exportkey_priv != NULL)
                break;
            keymgmt->exportkey_priv =
                OSSL_get_OP_keymgmt_exportkey_priv(fns);
            break;
        case OSSL_FUNC_KEYMGMT_EXPORTKEY_PUB:
            if (keymgmt->exportkey_pub != NULL)
                break;
            keymgmt->exportkey_pub = OSSL_get_OP_keymgmt_exportkey_pub(fns);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORTKEY_PRIV_TYPES:
            if (keymgmt->importkey_priv_types != NULL)
                break;
            keymgmt->importkey_priv_types =
                OSSL_get_OP_keymgmt_importkey_priv_types(fns);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORTKEY_PUB_TYPES:
            if (keymgmt->importkey_pub_types != NULL)
                break;
            keymgmt->importkey_pub_types =
                OSSL_get_OP_keymgmt_importkey_pub_types(fns);
            break;
        case OSSL_FUNC_KEYMGMT_EXPORTKEY_PRIV_TYPES:
            if (keymgmt->exportkey_priv_types != NULL)
                break;
            keymgmt->exportkey_priv_types =
                OSSL_get_OP_keymgmt_exportkey_priv_types(fns);
            break;
        case OSSL_FUNC_KEYMGMT_EXPORTKEY_PUB_TYPES:
            if (keymgmt->exportkey_pub_types != NULL)
                break;
            keymgmt->exportkey_pub_types =
                OSSL_get_OP_keymgmt_exportkey_pub_types(fns);
            break;
        }
    }
    /*
     * Try to check that the method is sensible.
     * It makes no sense being able to free stuff if you can't create it.
     * It makes no sense providing OSSL_PARAM descriptors for import and
     * export if you can't import or export.
     */
    if ((keymgmt->freedomain != NULL
         && (keymgmt->importdomain == NULL
             && keymgmt->gendomain == NULL))
        || (keymgmt->freekey != NULL
            && (keymgmt->importkey_priv == NULL
                && keymgmt->importkey_pub == NULL
                && keymgmt->genkey == NULL
                && keymgmt->loadkey == NULL))
        || (keymgmt->importdomain_types != NULL
            && keymgmt->importdomain == NULL)
        || (keymgmt->exportdomain_types != NULL
            && keymgmt->exportdomain == NULL)
        || (keymgmt->importkey_priv_types != NULL
            && keymgmt->importkey_priv == NULL)
        || (keymgmt->importkey_pub_types != NULL
            && keymgmt->importkey_pub == NULL)
        || (keymgmt->exportkey_priv_types != NULL
            && keymgmt->exportkey_priv == NULL)
        || (keymgmt->exportkey_pub_types != NULL
            && keymgmt->exportkey_pub == NULL)) {
        EVP_KEYMGMT_free(keymgmt);
        EVPerr(0, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    keymgmt->prov = prov;
    if (prov != NULL)
        ossl_provider_up_ref(prov);

    return keymgmt;
}

EVP_KEYMGMT *EVP_KEYMGMT_fetch(OPENSSL_CTX *ctx, const char *algorithm,
                               const char *properties)
{
    EVP_KEYMGMT *keymgmt =
        evp_generic_fetch(ctx, OSSL_OP_KEYMGMT, algorithm, properties,
                          keymgmt_from_dispatch,
                          (int (*)(void *))EVP_KEYMGMT_up_ref,
                          (void (*)(void *))EVP_KEYMGMT_free);

    return keymgmt;
}

int EVP_KEYMGMT_up_ref(EVP_KEYMGMT *keymgmt)
{
    int ref = 0;

    CRYPTO_UP_REF(&keymgmt->refcnt, &ref, keymgmt->lock);
    return 1;
}

void EVP_KEYMGMT_free(EVP_KEYMGMT *keymgmt)
{
    int ref = 0;

    if (keymgmt == NULL)
        return;

    CRYPTO_DOWN_REF(&keymgmt->refcnt, &ref, keymgmt->lock);
    if (ref > 0)
        return;
    ossl_provider_free(keymgmt->prov);
    CRYPTO_THREAD_lock_free(keymgmt->lock);
    OPENSSL_free(keymgmt);
}

const OSSL_PROVIDER *EVP_KEYMGMT_provider(const EVP_KEYMGMT *keymgmt)
{
    return keymgmt->prov;
}

