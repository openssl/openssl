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
#include "internal/asn1_int.h"
#include "internal/property.h"
#include "internal/core.h"
#include "internal/evp_int.h"    /* evp_locl.h needs it */
#include "evp_locl.h"

/* The OpenSSL library context index for the default method store */
static int default_method_store_index = -1;

static void default_method_store_free(void *vstore)
{
    ossl_method_store_free(vstore);
}

static void *default_method_store_new(void)
{
    return ossl_method_store_new();
}


static const OPENSSL_CTX_METHOD default_method_store_method = {
    default_method_store_new,
    default_method_store_free,
};

static int default_method_store_init(void)
{
    default_method_store_index =
        openssl_ctx_new_index(&default_method_store_method);

    return default_method_store_index != -1;
}

static CRYPTO_ONCE default_method_store_init_flag = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_default_method_store_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && default_method_store_init();
}

/* Data to be passed through ossl_method_construct() */
struct method_data_st {
    const char *name;
    int nid;
    OSSL_METHOD_CONSTRUCT_METHOD *mcm;
    void *(*method_from_dispatch)(int nid, const OSSL_DISPATCH *,
                                  OSSL_PROVIDER *);
    int (*refcnt_up_method)(void *method);
    void (*destruct_method)(void *method);
};

/*
 * Generic routines to fetch / create EVP methods with ossl_method_construct()
 */
static void *alloc_tmp_method_store(void)
{
    return ossl_method_store_new();
}

 static void dealloc_tmp_method_store(void *store)
{
    if (store != NULL)
        ossl_method_store_free(store);
}

static
struct OSSL_METHOD_STORE *get_default_method_store(OPENSSL_CTX *libctx)
{
    if (!RUN_ONCE(&default_method_store_init_flag,
                  do_default_method_store_init))
        return NULL;
    return openssl_ctx_get_data(libctx, default_method_store_index);
}

static void *get_method_from_store(OPENSSL_CTX *libctx, void *store,
                                   const char *propquery, void *data)
{
    struct method_data_st *methdata = data;
    void *method = NULL;

    if (store == NULL
        && (store = get_default_method_store(libctx)) == NULL)
        return NULL;

    (void)ossl_method_store_fetch(store, methdata->nid, propquery, &method);

    if (method != NULL
        && !methdata->refcnt_up_method(method)) {
        method = NULL;
    }
    return method;
}

static int put_method_in_store(OPENSSL_CTX *libctx, void *store,
                               const char *propdef, void *method,
                               void *data)
{
    struct method_data_st *methdata = data;

    if (store == NULL
        && (store = get_default_method_store(libctx)) == NULL)
        return 0;

    if (methdata->refcnt_up_method(method)
        && ossl_method_store_add(store, methdata->nid, propdef, method,
                                 methdata->destruct_method))
        return 1;
    return 0;
}

static void *construct_method(const OSSL_DISPATCH *fns, OSSL_PROVIDER *prov,
                              void *data)
{
    struct method_data_st *methdata = data;
    void *method = NULL;

    if (methdata->nid == NID_undef) {
        /* Create a new NID for that name on the fly */
        ASN1_OBJECT tmpobj;

        /* This is the same as OBJ_create() but without requiring a OID */
        tmpobj.nid = OBJ_new_nid(1);
        tmpobj.sn = tmpobj.ln = methdata->name;
        tmpobj.flags = ASN1_OBJECT_FLAG_DYNAMIC;
        tmpobj.length = 0;
        tmpobj.data = NULL;

        methdata->nid = OBJ_add_object(&tmpobj);
    }

    if (methdata->nid == NID_undef)
        return NULL;

    method = methdata->method_from_dispatch(methdata->nid, fns, prov);
    if (method == NULL)
        return NULL;
    return method;
}

static void destruct_method(void *method, void *data)
{
    struct method_data_st *methdata = data;

    methdata->destruct_method(method);
}

void *evp_generic_fetch(OPENSSL_CTX *libctx, int operation_id,
                        const char *algorithm, const char *properties,
                        void *(*new_method)(int nid, const OSSL_DISPATCH *fns,
                                            OSSL_PROVIDER *prov),
                        int (*upref_method)(void *),
                        void (*free_method)(void *))
{
    int nid = OBJ_sn2nid(algorithm);
    void *method = NULL;

    if (nid == NID_undef
        || !ossl_method_store_cache_get(NULL, nid, properties, &method)) {
        OSSL_METHOD_CONSTRUCT_METHOD mcm = {
            alloc_tmp_method_store,
            dealloc_tmp_method_store,
            get_method_from_store,
            put_method_in_store,
            construct_method,
            destruct_method
        };
        struct method_data_st mcmdata;

        mcmdata.nid = nid;
        mcmdata.mcm = &mcm;
        mcmdata.method_from_dispatch = new_method;
        mcmdata.destruct_method = free_method;
        mcmdata.refcnt_up_method = upref_method;
        mcmdata.destruct_method = free_method;
        method = ossl_method_construct(libctx, operation_id, algorithm,
                                       properties, 0 /* !force_cache */,
                                       &mcm, &mcmdata);
        ossl_method_store_cache_set(NULL, nid, properties, method);
    }

    return method;
}
