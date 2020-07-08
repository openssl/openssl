/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/deserializer.h>
#include <openssl/ui.h>
#include "internal/core.h"
#include "internal/namemap.h"
#include "internal/property.h"
#include "internal/provider.h"
#include "crypto/serializer.h"
#include "serializer_local.h"

static void OSSL_DESERIALIZER_INSTANCE_free(OSSL_DESERIALIZER_INSTANCE *instance);

/*
 * Deserializer can have multiple names, separated with colons in a name string
 */
#define NAME_SEPARATOR ':'

/* Simple method structure constructor and destructor */
static OSSL_DESERIALIZER *ossl_deserializer_new(void)
{
    OSSL_DESERIALIZER *deser = NULL;

    if ((deser = OPENSSL_zalloc(sizeof(*deser))) == NULL
        || (deser->base.lock = CRYPTO_THREAD_lock_new()) == NULL) {
        OSSL_DESERIALIZER_free(deser);
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    deser->base.refcnt = 1;

    return deser;
}

int OSSL_DESERIALIZER_up_ref(OSSL_DESERIALIZER *deser)
{
    int ref = 0;

    CRYPTO_UP_REF(&deser->base.refcnt, &ref, deser->base.lock);
    return 1;
}

void OSSL_DESERIALIZER_free(OSSL_DESERIALIZER *deser)
{
    int ref = 0;

    if (deser == NULL)
        return;

    CRYPTO_DOWN_REF(&deser->base.refcnt, &ref, deser->base.lock);
    if (ref > 0)
        return;
    ossl_provider_free(deser->base.prov);
    CRYPTO_THREAD_lock_free(deser->base.lock);
    OPENSSL_free(deser);
}

/* Permanent deserializer method store, constructor and destructor */
static void deserializer_store_free(void *vstore)
{
    ossl_method_store_free(vstore);
}

static void *deserializer_store_new(OPENSSL_CTX *ctx)
{
    return ossl_method_store_new(ctx);
}


static const OPENSSL_CTX_METHOD deserializer_store_method = {
    deserializer_store_new,
    deserializer_store_free,
};

/* Data to be passed through ossl_method_construct() */
struct deserializer_data_st {
    OPENSSL_CTX *libctx;
    OSSL_METHOD_CONSTRUCT_METHOD *mcm;
    int id;                      /* For get_deserializer_from_store() */
    const char *names;           /* For get_deserializer_from_store() */
    const char *propquery;       /* For get_deserializer_from_store() */
};

/*
 * Generic routines to fetch / create DESERIALIZER methods with
 * ossl_method_construct()
 */

/* Temporary deserializer method store, constructor and destructor */
static void *alloc_tmp_deserializer_store(OPENSSL_CTX *ctx)
{
    return ossl_method_store_new(ctx);
}

 static void dealloc_tmp_deserializer_store(void *store)
{
    if (store != NULL)
        ossl_method_store_free(store);
}

/* Get the permanent deserializer store */
static OSSL_METHOD_STORE *get_deserializer_store(OPENSSL_CTX *libctx)
{
    return openssl_ctx_get_data(libctx, OPENSSL_CTX_DESERIALIZER_STORE_INDEX,
                                &deserializer_store_method);
}

/* Get deserializer methods from a store, or put one in */
static void *get_deserializer_from_store(OPENSSL_CTX *libctx, void *store,
                                         void *data)
{
    struct deserializer_data_st *methdata = data;
    void *method = NULL;
    int id;

    if ((id = methdata->id) == 0) {
        OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);

        id = ossl_namemap_name2num(namemap, methdata->names);
    }

    if (store == NULL
        && (store = get_deserializer_store(libctx)) == NULL)
        return NULL;

    if (!ossl_method_store_fetch(store, id, methdata->propquery, &method))
        return NULL;
    return method;
}

static int put_deserializer_in_store(OPENSSL_CTX *libctx, void *store,
                                     void *method, const OSSL_PROVIDER *prov,
                                     int operation_id, const char *names,
                                     const char *propdef, void *unused)
{
    OSSL_NAMEMAP *namemap;
    int id;

    if ((namemap = ossl_namemap_stored(libctx)) == NULL
        || (id = ossl_namemap_name2num(namemap, names)) == 0)
        return 0;

    if (store == NULL && (store = get_deserializer_store(libctx)) == NULL)
        return 0;

    return ossl_method_store_add(store, prov, id, propdef, method,
                                 (int (*)(void *))OSSL_DESERIALIZER_up_ref,
                                 (void (*)(void *))OSSL_DESERIALIZER_free);
}

/* Create and populate a deserializer method */
static void *deserializer_from_dispatch(int id, const OSSL_ALGORITHM *algodef,
                                        OSSL_PROVIDER *prov)
{
    OSSL_DESERIALIZER *deser = NULL;
    const OSSL_DISPATCH *fns = algodef->implementation;

    if ((deser = ossl_deserializer_new()) == NULL)
        return NULL;
    deser->base.id = id;
    deser->base.propdef = algodef->property_definition;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_DESERIALIZER_NEWCTX:
            if (deser->newctx == NULL)
                deser->newctx = OSSL_FUNC_deserializer_newctx(fns);
            break;
        case OSSL_FUNC_DESERIALIZER_FREECTX:
            if (deser->freectx == NULL)
                deser->freectx = OSSL_FUNC_deserializer_freectx(fns);
            break;
        case OSSL_FUNC_DESERIALIZER_GET_PARAMS:
            if (deser->get_params == NULL)
                deser->get_params =
                    OSSL_FUNC_deserializer_get_params(fns);
            break;
        case OSSL_FUNC_DESERIALIZER_GETTABLE_PARAMS:
            if (deser->gettable_params == NULL)
                deser->gettable_params =
                    OSSL_FUNC_deserializer_gettable_params(fns);
            break;
        case OSSL_FUNC_DESERIALIZER_SET_CTX_PARAMS:
            if (deser->set_ctx_params == NULL)
                deser->set_ctx_params =
                    OSSL_FUNC_deserializer_set_ctx_params(fns);
            break;
        case OSSL_FUNC_DESERIALIZER_SETTABLE_CTX_PARAMS:
            if (deser->settable_ctx_params == NULL)
                deser->settable_ctx_params =
                    OSSL_FUNC_deserializer_settable_ctx_params(fns);
            break;
        case OSSL_FUNC_DESERIALIZER_DESERIALIZE:
            if (deser->deserialize == NULL)
                deser->deserialize = OSSL_FUNC_deserializer_deserialize(fns);
            break;
        case OSSL_FUNC_DESERIALIZER_EXPORT_OBJECT:
            if (deser->export_object == NULL)
                deser->export_object = OSSL_FUNC_deserializer_export_object(fns);
            break;
        }
    }
    /*
     * Try to check that the method is sensible.
     * If you have a constructor, you must have a destructor and vice versa.
     * You must have at least one of the serializing driver functions.
     */
    if (!((deser->newctx == NULL && deser->freectx == NULL)
          || (deser->newctx != NULL && deser->freectx != NULL))
        || (deser->deserialize == NULL && deser->export_object == NULL)) {
        OSSL_DESERIALIZER_free(deser);
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }

    if (prov != NULL && !ossl_provider_up_ref(prov)) {
        OSSL_DESERIALIZER_free(deser);
        return NULL;
    }

    deser->base.prov = prov;
    return deser;
}


/*
 * The core fetching functionality passes the names of the implementation.
 * This function is responsible to getting an identity number for them,
 * then call deserializer_from_dispatch() with that identity number.
 */
static void *construct_deserializer(const OSSL_ALGORITHM *algodef,
                                    OSSL_PROVIDER *prov, void *unused)
{
    /*
     * This function is only called if get_deserializer_from_store() returned
     * NULL, so it's safe to say that of all the spots to create a new
     * namemap entry, this is it.  Should the name already exist there, we
     * know that ossl_namemap_add() will return its corresponding number.
     */
    OPENSSL_CTX *libctx = ossl_provider_library_context(prov);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);
    const char *names = algodef->algorithm_names;
    int id = ossl_namemap_add_names(namemap, 0, names, NAME_SEPARATOR);
    void *method = NULL;

    if (id != 0)
        method = deserializer_from_dispatch(id, algodef, prov);

    return method;
}

/* Intermediary function to avoid ugly casts, used below */
static void destruct_deserializer(void *method, void *data)
{
    OSSL_DESERIALIZER_free(method);
}

static int up_ref_deserializer(void *method)
{
    return OSSL_DESERIALIZER_up_ref(method);
}

static void free_deserializer(void *method)
{
    OSSL_DESERIALIZER_free(method);
}

/* Fetching support.  Can fetch by numeric identity or by name */
static OSSL_DESERIALIZER *inner_ossl_deserializer_fetch(OPENSSL_CTX *libctx,
                                                        int id,
                                                        const char *name,
                                                        const char *properties)
{
    OSSL_METHOD_STORE *store = get_deserializer_store(libctx);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);
    void *method = NULL;

    if (store == NULL || namemap == NULL)
        return NULL;

    /*
     * If we have been passed neither a name_id or a name, we have an
     * internal programming error.
     */
    if (!ossl_assert(id != 0 || name != NULL))
        return NULL;

    if (id == 0)
        id = ossl_namemap_name2num(namemap, name);

    if (id == 0
        || !ossl_method_store_cache_get(store, id, properties, &method)) {
        OSSL_METHOD_CONSTRUCT_METHOD mcm = {
            alloc_tmp_deserializer_store,
            dealloc_tmp_deserializer_store,
            get_deserializer_from_store,
            put_deserializer_in_store,
            construct_deserializer,
            destruct_deserializer
        };
        struct deserializer_data_st mcmdata;

        mcmdata.libctx = libctx;
        mcmdata.mcm = &mcm;
        mcmdata.id = id;
        mcmdata.names = name;
        mcmdata.propquery = properties;
        if ((method = ossl_method_construct(libctx, OSSL_OP_DESERIALIZER,
                                            0 /* !force_cache */,
                                            &mcm, &mcmdata)) != NULL) {
            /*
             * If construction did create a method for us, we know that
             * there is a correct name_id and meth_id, since those have
             * already been calculated in get_deserializer_from_store() and
             * put_deserializer_in_store() above.
             */
            if (id == 0)
                id = ossl_namemap_name2num(namemap, name);
            ossl_method_store_cache_set(store, id, properties, method,
                                        up_ref_deserializer, free_deserializer);
        }
    }

    return method;
}

OSSL_DESERIALIZER *OSSL_DESERIALIZER_fetch(OPENSSL_CTX *libctx,
                                           const char *name,
                                           const char *properties)
{
    return inner_ossl_deserializer_fetch(libctx, 0, name, properties);
}

OSSL_DESERIALIZER *ossl_deserializer_fetch_by_number(OPENSSL_CTX *libctx,
                                                     int id,
                                                     const char *properties)
{
    return inner_ossl_deserializer_fetch(libctx, id, NULL, properties);
}

/*
 * Library of basic method functions
 */

const OSSL_PROVIDER *OSSL_DESERIALIZER_provider(const OSSL_DESERIALIZER *deser)
{
    if (!ossl_assert(deser != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return deser->base.prov;
}

const char *OSSL_DESERIALIZER_properties(const OSSL_DESERIALIZER *deser)
{
    if (!ossl_assert(deser != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return deser->base.propdef;
}

int OSSL_DESERIALIZER_number(const OSSL_DESERIALIZER *deser)
{
    if (!ossl_assert(deser != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return deser->base.id;
}

int OSSL_DESERIALIZER_is_a(const OSSL_DESERIALIZER *deser, const char *name)
{
    if (deser->base.prov != NULL) {
        OPENSSL_CTX *libctx = ossl_provider_library_context(deser->base.prov);
        OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);

        return ossl_namemap_name2num(namemap, name) == deser->base.id;
    }
    return 0;
}

struct deserializer_do_all_data_st {
    void (*user_fn)(void *method, void *arg);
    void *user_arg;
};

static void deserializer_do_one(OSSL_PROVIDER *provider,
                                const OSSL_ALGORITHM *algodef,
                                int no_store, void *vdata)
{
    struct deserializer_do_all_data_st *data = vdata;
    OPENSSL_CTX *libctx = ossl_provider_library_context(provider);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);
    const char *names = algodef->algorithm_names;
    int id = ossl_namemap_add_names(namemap, 0, names, NAME_SEPARATOR);
    void *method = NULL;

    if (id != 0)
        method =
            deserializer_from_dispatch(id, algodef, provider);

    if (method != NULL) {
        data->user_fn(method, data->user_arg);
        OSSL_DESERIALIZER_free(method);
    }
}

void OSSL_DESERIALIZER_do_all_provided(OPENSSL_CTX *libctx,
                                       void (*fn)(OSSL_DESERIALIZER *deser,
                                                  void *arg),
                                       void *arg)
{
    struct deserializer_do_all_data_st data;

    data.user_fn = (void (*)(void *, void *))fn;
    data.user_arg = arg;
    ossl_algorithm_do_all(libctx, OSSL_OP_DESERIALIZER, NULL,
                          NULL, deserializer_do_one, NULL,
                          &data);
}

void OSSL_DESERIALIZER_names_do_all(const OSSL_DESERIALIZER *deser,
                                    void (*fn)(const char *name, void *data),
                                    void *data)
{
    if (deser == NULL)
        return;

    if (deser->base.prov != NULL) {
        OPENSSL_CTX *libctx = ossl_provider_library_context(deser->base.prov);
        OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);

        ossl_namemap_doall_names(namemap, deser->base.id, fn, data);
    }
}

const OSSL_PARAM *
OSSL_DESERIALIZER_gettable_params(OSSL_DESERIALIZER *deser)
{
    if (deser != NULL && deser->gettable_params != NULL)
        return deser->gettable_params();
    return NULL;
}

int OSSL_DESERIALIZER_get_params(OSSL_DESERIALIZER *deser, OSSL_PARAM params[])
{
    if (deser != NULL && deser->get_params != NULL)
        return deser->get_params(params);
    return 0;
}

const OSSL_PARAM *
OSSL_DESERIALIZER_settable_ctx_params(OSSL_DESERIALIZER *deser)
{
    if (deser != NULL && deser->settable_ctx_params != NULL)
        return deser->settable_ctx_params();
    return NULL;
}

/*
 * Deserializer context support
 */

/*
 * |ser| value NULL is valid, and signifies that there is no deserializer.
 * This is useful to provide fallback mechanisms.
 *  Functions that want to verify if there is a deserializer can do so with
 * OSSL_DESERIALIZER_CTX_get_deserializer()
 */
OSSL_DESERIALIZER_CTX *OSSL_DESERIALIZER_CTX_new(void)
{
    OSSL_DESERIALIZER_CTX *ctx;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ctx;
}

int OSSL_DESERIALIZER_CTX_set_params(OSSL_DESERIALIZER_CTX *ctx,
                                     const OSSL_PARAM params[])
{
    size_t i;
    size_t l;

    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ctx->deser_insts == NULL)
        return 1;

    l = (size_t)sk_OSSL_DESERIALIZER_INSTANCE_num(ctx->deser_insts);
    for (i = 0; i < l; i++) {
        OSSL_DESERIALIZER_INSTANCE *deser_inst =
            sk_OSSL_DESERIALIZER_INSTANCE_value(ctx->deser_insts, i);

        if (deser_inst->deserctx == NULL
            || deser_inst->deser->set_ctx_params == NULL)
            continue;
        if (!deser_inst->deser->set_ctx_params(deser_inst->deserctx, params))
            return 0;
    }
    return 1;
}

static void
OSSL_DESERIALIZER_INSTANCE_free(OSSL_DESERIALIZER_INSTANCE *deser_inst)
{
    if (deser_inst != NULL) {
        if (deser_inst->deser->freectx != NULL)
            deser_inst->deser->freectx(deser_inst->deserctx);
        deser_inst->deserctx = NULL;
        OSSL_DESERIALIZER_free(deser_inst->deser);
        deser_inst->deser = NULL;
        OPENSSL_free(deser_inst);
        deser_inst = NULL;
    }
}

void OSSL_DESERIALIZER_CTX_free(OSSL_DESERIALIZER_CTX *ctx)
{
    if (ctx != NULL) {
        if (ctx->cleaner != NULL)
            ctx->cleaner(ctx->finalize_arg);
        sk_OSSL_DESERIALIZER_INSTANCE_pop_free(ctx->deser_insts,
                                               OSSL_DESERIALIZER_INSTANCE_free);
        UI_destroy_method(ctx->allocated_ui_method);
        OPENSSL_free(ctx);
    }
}
