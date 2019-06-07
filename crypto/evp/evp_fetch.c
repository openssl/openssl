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

/*
 * To identity the method in the method store, we mix the name identity
 * with the operation identity, with the assumption that we don't have
 * more than 2^24 names or more than 2^8 operation types.
 *
 * The resulting identity is a 32-bit integer, composed like this:
 *
 * +---------24 bits--------+-8 bits-+
 * |      name identity     | op id  |
 * +------------------------+--------+
 */
static uint32_t method_id(unsigned int operation_id, unsigned int name_id)
{
    if (!ossl_assert(name_id < (1 << 24) || operation_id < (1 << 8))
        || !ossl_assert(name_id > 0 && operation_id > 0))
        return 0;
    return ((name_id << 8) & 0xFFFFFF00) | (operation_id & 0x000000FF);
}

static void *get_method_from_store(OPENSSL_CTX *libctx, void *store,
                                   int operation_id, const char *name,
                                   const char *propquery, void *data)
{
    struct method_data_st *methdata = data;
    void *method = NULL;
    OSSL_NAMEMAP *namemap;
    int nameid;
    uint32_t methid;

    if (store == NULL
        && (store = get_default_method_store(libctx)) == NULL)
        return NULL;

    if ((namemap = ossl_namemap_stored(libctx)) == NULL
        || (nameid = ossl_namemap_add(namemap, name)) == 0
        || (methid = method_id(operation_id, nameid)) == 0)
        return NULL;

    (void)ossl_method_store_fetch(store, methid, propquery, &method);

    if (method != NULL
        && !methdata->refcnt_up_method(method)) {
        method = NULL;
    }
    return method;
}

static int put_method_in_store(OPENSSL_CTX *libctx, void *store,
                               void *method, int operation_id,
                               const char *name, const char *propdef,
                               void *data)
{
    struct method_data_st *methdata = data;
    OSSL_NAMEMAP *namemap;
    int nameid;
    uint32_t methid;

    if ((namemap = ossl_namemap_stored(methdata->libctx)) == NULL
        || (nameid = ossl_namemap_add(namemap, name)) == 0
        || (methid = method_id(operation_id, nameid)) == 0)
        return 0;

    if (store == NULL
        && (store = get_default_method_store(libctx)) == NULL)
        return 0;

    if (methdata->refcnt_up_method(method)
        && ossl_method_store_add(store, methid, propdef, method,
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
    int nameid;
    uint32_t methid;
    void *method = NULL;

    if (store == NULL || namemap == NULL)
        return NULL;

    if ((nameid = ossl_namemap_number(namemap, name)) == 0
        || !ossl_method_store_cache_get(store,
                                        method_id(operation_id, nameid),
                                        properties, &method)) {
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
        mcmdata.name = name;
        mcmdata.method_from_dispatch = new_method;
        mcmdata.destruct_method = free_method;
        mcmdata.refcnt_up_method = upref_method;
        mcmdata.destruct_method = free_method;
        method = ossl_method_construct(libctx, operation_id, name,
                                       properties, 0 /* !force_cache */,
                                       &mcm, &mcmdata);
        nameid = ossl_namemap_number(namemap, name);
        methid = method_id(operation_id, nameid);
        ossl_method_store_cache_set(store, methid, properties, method);
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
