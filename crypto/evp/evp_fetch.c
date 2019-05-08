/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include "internal/cryptlib.h"
#include "internal/thread_once.h"
#include "internal/property.h"
#include "internal/core.h"
#include "internal/namemap.h"
#include "internal/evp_int.h"    /* evp_locl.h needs it */
#include "evp_locl.h"

static void default_method_store_free(void *vstore)
{
    ossl_method_store_free(vstore);
}

static void *default_method_store_new(OPENSSL_CTX *ctx)
{
    return ossl_method_store_new(ctx);
}


static const OPENSSL_CTX_METHOD default_method_store_method = {
    default_method_store_new,
    default_method_store_free,
};

/* Data to be passed through ossl_method_construct() */
struct method_data_st {
    OPENSSL_CTX *libctx;
    const char *name;
    int id;
    OSSL_METHOD_CONSTRUCT_METHOD *mcm;
    void *(*method_from_dispatch)(const OSSL_DISPATCH *, OSSL_PROVIDER *);
    int (*refcnt_up_method)(void *method);
    void (*destruct_method)(void *method);
};

/*
 * Generic routines to fetch / create EVP methods with ossl_method_construct()
 */
static void *alloc_tmp_method_store(OPENSSL_CTX *ctx)
{
    return ossl_method_store_new(ctx);
}

 static void dealloc_tmp_method_store(void *store)
{
    if (store != NULL)
        ossl_method_store_free(store);
}

static OSSL_METHOD_STORE *get_default_method_store(OPENSSL_CTX *libctx)
{
    return openssl_ctx_get_data(libctx, OPENSSL_CTX_DEFAULT_METHOD_STORE_INDEX,
                                &default_method_store_method);
}

static void *get_method_from_store(OPENSSL_CTX *libctx, void *store,
                                   const char *name, const char *propquery,
                                   void *data)
{
    struct method_data_st *methdata = data;
    void *method = NULL;
    OSSL_NAMEMAP *namemap;
    int id;

    if (store == NULL
        && (store = get_default_method_store(libctx)) == NULL)
        return NULL;

    if ((namemap = ossl_namemap_stored(libctx)) == NULL
        || (id = ossl_namemap_add(namemap, name)) == 0)
        return NULL;

    (void)ossl_method_store_fetch(store, id, propquery, &method);

    if (method != NULL
        && !methdata->refcnt_up_method(method)) {
        method = NULL;
    }
    return method;
}

static int put_method_in_store(OPENSSL_CTX *libctx, void *store,
                               void *method, const char *name,
                               const char *propdef, void *data)
{
    struct method_data_st *methdata = data;
    OSSL_NAMEMAP *namemap;
    int id;

    if ((namemap = ossl_namemap_stored(methdata->libctx)) == NULL
        || (id = ossl_namemap_add(namemap, name)) == 0)
        return 0;

    if (store == NULL
        && (store = get_default_method_store(libctx)) == NULL)
        return 0;

    if (methdata->refcnt_up_method(method)
        && ossl_method_store_add(store, id, propdef, method,
                                 methdata->destruct_method))
        return 1;
    return 0;
}

static void *construct_method(const char *name, const OSSL_DISPATCH *fns,
                              OSSL_PROVIDER *prov, void *data)
{
    struct method_data_st *methdata = data;

    return methdata->method_from_dispatch(fns, prov);
}

static void destruct_method(void *method, void *data)
{
    struct method_data_st *methdata = data;

    methdata->destruct_method(method);
}

void *evp_generic_fetch(OPENSSL_CTX *libctx, int operation_id,
                        const char *name, const char *properties,
                        void *(*new_method)(const OSSL_DISPATCH *fns,
                                            OSSL_PROVIDER *prov),
                        int (*upref_method)(void *),
                        void (*free_method)(void *))
{
    OSSL_METHOD_STORE *store = get_default_method_store(libctx);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);
    int id;
    void *method = NULL;

    if (store == NULL || namemap == NULL)
        return NULL;

    if ((id = ossl_namemap_number(namemap, name)) == 0
        || !ossl_method_store_cache_get(store, id, properties, &method)) {
        OSSL_METHOD_CONSTRUCT_METHOD mcm = {
            alloc_tmp_method_store,
            dealloc_tmp_method_store,
            get_method_from_store,
            put_method_in_store,
            construct_method,
            destruct_method
        };
        struct method_data_st mcmdata;

        mcmdata.mcm = &mcm;
        mcmdata.libctx = libctx;
        mcmdata.method_from_dispatch = new_method;
        mcmdata.destruct_method = free_method;
        mcmdata.refcnt_up_method = upref_method;
        mcmdata.destruct_method = free_method;
        method = ossl_method_construct(libctx, operation_id, name,
                                       properties, 0 /* !force_cache */,
                                       &mcm, &mcmdata);
        ossl_method_store_cache_set(store, id, properties, method);
    } else {
        upref_method(method);
    }

    return method;
}

int EVP_set_default_properties(OPENSSL_CTX *libctx, const char *propq)
{
    OSSL_METHOD_STORE *store = get_default_method_store(libctx);

    if (store != NULL)
        return ossl_method_store_set_global_properties(store, propq);
    EVPerr(EVP_F_EVP_SET_DEFAULT_PROPERTIES, ERR_R_INTERNAL_ERROR);
    return 0;
}
