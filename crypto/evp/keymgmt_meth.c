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
    int paramfncnt = 0, importfncnt = 0, exportfncnt = 0;

    if ((keymgmt = keymgmt_new()) == NULL) {
        EVP_KEYMGMT_free(keymgmt);
        return NULL;
    }
    keymgmt->name_id = name_id;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_KEYMGMT_NEW:
            if (keymgmt->new == NULL)
                keymgmt->new = OSSL_get_OP_keymgmt_new(fns);
            break;
        case OSSL_FUNC_KEYMGMT_FREE:
            if (keymgmt->free == NULL)
                keymgmt->free = OSSL_get_OP_keymgmt_free(fns);
            break;
        case OSSL_FUNC_KEYMGMT_GET_PARAMS:
            if (keymgmt->get_params == NULL) {
                paramfncnt++;
                keymgmt->get_params = OSSL_get_OP_keymgmt_get_params(fns);
            }
            break;
        case OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS:
            if (keymgmt->gettable_params == NULL) {
                paramfncnt++;
                keymgmt->gettable_params =
                    OSSL_get_OP_keymgmt_gettable_params(fns);
            }
            break;
        case OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME:
            if (keymgmt->query_operation_name == NULL)
                keymgmt->query_operation_name =
                    OSSL_get_OP_keymgmt_query_operation_name(fns);
            break;
        case OSSL_FUNC_KEYMGMT_HAS:
            if (keymgmt->has == NULL)
                keymgmt->has = OSSL_get_OP_keymgmt_has(fns);
            break;
        case OSSL_FUNC_KEYMGMT_VALIDATE:
            if (keymgmt->validate == NULL)
                keymgmt->validate = OSSL_get_OP_keymgmt_validate(fns);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORT:
            if (keymgmt->import == NULL) {
                importfncnt++;
                keymgmt->import = OSSL_get_OP_keymgmt_import(fns);
            }
            break;
        case OSSL_FUNC_KEYMGMT_IMPORT_TYPES:
            if (keymgmt->import_types == NULL) {
                importfncnt++;
                keymgmt->import_types = OSSL_get_OP_keymgmt_import_types(fns);
            }
            break;
        case OSSL_FUNC_KEYMGMT_EXPORT:
            if (keymgmt->export == NULL) {
                exportfncnt++;
                keymgmt->export = OSSL_get_OP_keymgmt_export(fns);
            }
            break;
        case OSSL_FUNC_KEYMGMT_EXPORT_TYPES:
            if (keymgmt->export_types == NULL) {
                exportfncnt++;
                keymgmt->export_types = OSSL_get_OP_keymgmt_export_types(fns);
            }
            break;
        }
    }
    /*
     * Try to check that the method is sensible.
     * At least one constructor and the destructor are MANDATORY
     * The functions 'has' is MANDATORY
     * It makes no sense being able to free stuff if you can't create it.
     * It makes no sense providing OSSL_PARAM descriptors for import and
     * export if you can't import or export.
     */
    if (keymgmt->free == NULL
        || keymgmt->new == NULL
        || keymgmt->has == NULL
        || (paramfncnt != 0 && paramfncnt != 2)
        || (importfncnt != 0 && importfncnt != 2)
        || (exportfncnt != 0 && exportfncnt != 2)) {
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
    return evp_is_a(keymgmt->prov, keymgmt->name_id, NULL, name);
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

/*
 * Internal API that interfaces with the method function pointers
 */
void *evp_keymgmt_newdata(const EVP_KEYMGMT *keymgmt)
{
    void *provctx = ossl_provider_ctx(EVP_KEYMGMT_provider(keymgmt));

    /*
     * TODO(3.0) 'new' is currently mandatory on its own, but when new
     * constructors appear, it won't be quite as mandatory, so we have
     * a check for future cases.
     */
    if (keymgmt->new == NULL)
        return NULL;
    return keymgmt->new(provctx);
}

void evp_keymgmt_freedata(const EVP_KEYMGMT *keymgmt, void *keydata)
{
    /* This is mandatory, no need to check for its presence */
    keymgmt->free(keydata);
}

int evp_keymgmt_get_params(const EVP_KEYMGMT *keymgmt, void *keydata,
                           OSSL_PARAM params[])
{
    if (keymgmt->get_params == NULL)
        return 1;
    return keymgmt->get_params(keydata, params);
}

const OSSL_PARAM *evp_keymgmt_gettable_params(const EVP_KEYMGMT *keymgmt)
{
    if (keymgmt->gettable_params == NULL)
        return NULL;
    return keymgmt->gettable_params();
}

int evp_keymgmt_has(const EVP_KEYMGMT *keymgmt, void *keydata, int selection)
{
    /* This is mandatory, no need to check for its presence */
    return keymgmt->has(keydata, selection);
}

int evp_keymgmt_validate(const EVP_KEYMGMT *keymgmt, void *keydata,
                         int selection)
{
    /* We assume valid if the implementation doesn't have a function */
    if (keymgmt->validate == NULL)
        return 1;
    return keymgmt->validate(keydata, selection);
}

int evp_keymgmt_import(const EVP_KEYMGMT *keymgmt, void *keydata,
                       int selection, const OSSL_PARAM params[])
{
    if (keymgmt->import == NULL)
        return 0;
    return keymgmt->import(keydata, selection, params);
}

const OSSL_PARAM *evp_keymgmt_import_types(const EVP_KEYMGMT *keymgmt,
                                           int selection)
{
    if (keymgmt->import_types == NULL)
        return NULL;
    return keymgmt->import_types(selection);
}

int evp_keymgmt_export(const EVP_KEYMGMT *keymgmt, void *keydata,
                       int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    if (keymgmt->export == NULL)
        return 0;
    return keymgmt->export(keydata, selection, param_cb, cbarg);
}

const OSSL_PARAM *evp_keymgmt_export_types(const EVP_KEYMGMT *keymgmt,
                                           int selection)
{
    if (keymgmt->export_types == NULL)
        return NULL;
    return keymgmt->export_types(selection);
}
