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
#include "crypto/evp.h"
#include "evp_local.h"


static void *keymgmt_new(void)
{
    EVP_KEYMGMT *keymgmt = NULL;

    if ((keymgmt = OPENSSL_zalloc(sizeof(*keymgmt))) == NULL
        || (keymgmt->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        EVP_KEYMGMT_free(keymgmt);
        EVPerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    keymgmt->refcnt = 1;

    return keymgmt;
}

static void *keymgmt_from_dispatch(int name_id,
                                   const OSSL_DISPATCH *fns,
                                   OSSL_PROVIDER *prov)
{
    EVP_KEYMGMT *keymgmt = NULL;

    if ((keymgmt = keymgmt_new()) == NULL) {
        EVP_KEYMGMT_free(keymgmt);
        return NULL;
    }
    keymgmt->name_id = name_id;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_KEYMGMT_IMPORTDOMPARAMS:
            if (keymgmt->importdomparams != NULL)
                break;
            keymgmt->importdomparams =
                OSSL_get_OP_keymgmt_importdomparams(fns);
            break;
        case OSSL_FUNC_KEYMGMT_GENDOMPARAMS:
            if (keymgmt->gendomparams != NULL)
                break;
            keymgmt->gendomparams = OSSL_get_OP_keymgmt_gendomparams(fns);
            break;
        case OSSL_FUNC_KEYMGMT_FREEDOMPARAMS:
            if (keymgmt->freedomparams != NULL)
                break;
            keymgmt->freedomparams = OSSL_get_OP_keymgmt_freedomparams(fns);
            break;
        case OSSL_FUNC_KEYMGMT_EXPORTDOMPARAMS:
            if (keymgmt->exportdomparams != NULL)
                break;
            keymgmt->exportdomparams =
                OSSL_get_OP_keymgmt_exportdomparams(fns);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORTDOMPARAM_TYPES:
            if (keymgmt->importdomparam_types != NULL)
                break;
            keymgmt->importdomparam_types =
                OSSL_get_OP_keymgmt_importdomparam_types(fns);
            break;
        case OSSL_FUNC_KEYMGMT_EXPORTDOMPARAM_TYPES:
            if (keymgmt->exportdomparam_types != NULL)
                break;
            keymgmt->exportdomparam_types =
                OSSL_get_OP_keymgmt_exportdomparam_types(fns);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORTKEY:
            if (keymgmt->importkey != NULL)
                break;
            keymgmt->importkey = OSSL_get_OP_keymgmt_importkey(fns);
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
        case OSSL_FUNC_KEYMGMT_EXPORTKEY:
            if (keymgmt->exportkey != NULL)
                break;
            keymgmt->exportkey = OSSL_get_OP_keymgmt_exportkey(fns);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORTKEY_TYPES:
            if (keymgmt->importkey_types != NULL)
                break;
            keymgmt->importkey_types =
                OSSL_get_OP_keymgmt_importkey_types(fns);
            break;
        case OSSL_FUNC_KEYMGMT_EXPORTKEY_TYPES:
            if (keymgmt->exportkey_types != NULL)
                break;
            keymgmt->exportkey_types =
                OSSL_get_OP_keymgmt_exportkey_types(fns);
            break;
        }
    }
    /*
     * Try to check that the method is sensible.
     * It makes no sense being able to free stuff if you can't create it.
     * It makes no sense providing OSSL_PARAM descriptors for import and
     * export if you can't import or export.
     */
    if ((keymgmt->freedomparams != NULL
         && (keymgmt->importdomparams == NULL
             && keymgmt->gendomparams == NULL))
        || (keymgmt->freekey != NULL
            && (keymgmt->importkey == NULL
                && keymgmt->genkey == NULL
                && keymgmt->loadkey == NULL))
        || (keymgmt->importdomparam_types != NULL
            && keymgmt->importdomparams == NULL)
        || (keymgmt->exportdomparam_types != NULL
            && keymgmt->exportdomparams == NULL)
        || (keymgmt->importkey_types != NULL
            && keymgmt->importkey == NULL)
        || (keymgmt->exportkey_types != NULL
            && keymgmt->exportkey == NULL)) {
        EVP_KEYMGMT_free(keymgmt);
        EVPerr(0, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    keymgmt->prov = prov;
    if (prov != NULL)
        ossl_provider_up_ref(prov);

    return keymgmt;
}

EVP_KEYMGMT *evp_keymgmt_fetch_by_number(OPENSSL_CTX *ctx, int name_id,
                                         const char *properties)
{
    return evp_generic_fetch_by_number(ctx,
                                       OSSL_OP_KEYMGMT, name_id, properties,
                                       keymgmt_from_dispatch,
                                       (int (*)(void *))EVP_KEYMGMT_up_ref,
                                       (void (*)(void *))EVP_KEYMGMT_free);
}

EVP_KEYMGMT *EVP_KEYMGMT_fetch(OPENSSL_CTX *ctx, const char *algorithm,
                               const char *properties)
{
    return evp_generic_fetch(ctx, OSSL_OP_KEYMGMT, algorithm, properties,
                             keymgmt_from_dispatch,
                             (int (*)(void *))EVP_KEYMGMT_up_ref,
                             (void (*)(void *))EVP_KEYMGMT_free);
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

int EVP_KEYMGMT_number(const EVP_KEYMGMT *keymgmt)
{
    return keymgmt->name_id;
}

int EVP_KEYMGMT_is_a(const EVP_KEYMGMT *keymgmt, const char *name)
{
    return evp_is_a(keymgmt->prov, keymgmt->name_id, name);
}

void EVP_KEYMGMT_do_all_provided(OPENSSL_CTX *libctx,
                                 void (*fn)(EVP_KEYMGMT *keymgmt, void *arg),
                                 void *arg)
{
    evp_generic_do_all(libctx, OSSL_OP_KEYMGMT,
                       (void (*)(void *, void *))fn, arg,
                       keymgmt_from_dispatch,
                       (void (*)(void *))EVP_KEYMGMT_free);
}

void EVP_KEYMGMT_names_do_all(const EVP_KEYMGMT *keymgmt,
                              void (*fn)(const char *name, void *data),
                              void *data)
{
    if (keymgmt->prov != NULL)
        evp_names_do_all(keymgmt->prov, keymgmt->name_id, fn, data);
}
