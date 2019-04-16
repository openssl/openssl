/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/params.h>
#include <openssl/opensslv.h>
#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "internal/thread_once.h"
#include "internal/provider.h"
#include "internal/refcount.h"
#include "provider_local.h"

static OSSL_PROVIDER *provider_new(const char *name,
                                   OSSL_provider_init_fn *init_function);

/*-
 * Provider Object structure
 * =========================
 */

typedef struct {
    char *name;
    char *value;
} INFOPAIR;
DEFINE_STACK_OF(INFOPAIR)

struct provider_store_st;        /* Forward declaration */

struct ossl_provider_st {
    /* Flag bits */
    unsigned int flag_initialized:1;
    unsigned int flag_fallback:1;

    /* OpenSSL library side data */
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *refcnt_lock;  /* For the ref counter */
    char *name;
    char *path;
    DSO *module;
    OSSL_provider_init_fn *init_function;
    STACK_OF(INFOPAIR) *parameters;
    struct provider_store_st *store; /* The store this instance belongs to */

    /* Provider side functions */
    OSSL_provider_teardown_fn *teardown;
    OSSL_provider_get_param_types_fn *get_param_types;
    OSSL_provider_get_params_fn *get_params;
    OSSL_provider_query_operation_fn *query_operation;
};
DEFINE_STACK_OF(OSSL_PROVIDER)

static int ossl_provider_cmp(const OSSL_PROVIDER * const *a,
                             const OSSL_PROVIDER * const *b)
{
    return strcmp((*a)->name, (*b)->name);
}

/*-
 * Provider Object store
 * =====================
 *
 * The Provider Object store is a library context object, and therefore needs
 * an index.
 */

struct provider_store_st {
    STACK_OF(OSSL_PROVIDER) *providers;
    CRYPTO_RWLOCK *lock;
    unsigned int use_fallbacks:1;
};
static int provider_store_index = -1;

static void provider_store_free(void *vstore)
{
    struct provider_store_st *store = vstore;

    if (store == NULL)
        return;
    sk_OSSL_PROVIDER_pop_free(store->providers, ossl_provider_free);
    CRYPTO_THREAD_lock_free(store->lock);
    OPENSSL_free(store);
}

static void *provider_store_new(void)
{
    struct provider_store_st *store = OPENSSL_zalloc(sizeof(*store));
    const struct predefined_providers_st *p = NULL;

    if (store == NULL
        || (store->providers = sk_OSSL_PROVIDER_new(ossl_provider_cmp)) == NULL
        || (store->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        provider_store_free(store);
        return NULL;
    }
    store->use_fallbacks = 1;

    for (p = predefined_providers; p->name != NULL; p++) {
        OSSL_PROVIDER *prov = NULL;

        /*
         * We use the internal constructor directly here,
         * otherwise we get a call loop
         */
        prov = provider_new(p->name, p->init);

        if (prov == NULL
            || sk_OSSL_PROVIDER_push(store->providers, prov) == 0) {
            ossl_provider_free(prov);
            provider_store_free(store);
            CRYPTOerr(CRYPTO_F_PROVIDER_STORE_NEW, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        prov->store = store;
        if(p->is_fallback)
            ossl_provider_set_fallback(prov);
    }

    return store;
}

static const OPENSSL_CTX_METHOD provider_store_method = {
    provider_store_new,
    provider_store_free,
};

static CRYPTO_ONCE provider_store_init_flag = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_provider_store_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && (provider_store_index =
            openssl_ctx_new_index(&provider_store_method)) != -1;
}


static struct provider_store_st *get_provider_store(OPENSSL_CTX *libctx)
{
    struct provider_store_st *store = NULL;

    if (!RUN_ONCE(&provider_store_init_flag, do_provider_store_init))
        return NULL;

    store = openssl_ctx_get_data(libctx, provider_store_index);
    if (store == NULL)
        CRYPTOerr(CRYPTO_F_GET_PROVIDER_STORE, ERR_R_INTERNAL_ERROR);
    return store;
}

OSSL_PROVIDER *ossl_provider_find(OPENSSL_CTX *libctx, const char *name)
{
    struct provider_store_st *store = NULL;
    OSSL_PROVIDER *prov = NULL;

    if ((store = get_provider_store(libctx)) != NULL) {
        OSSL_PROVIDER tmpl = { 0, };
        int i;

        tmpl.name = (char *)name;
        CRYPTO_THREAD_write_lock(store->lock);
        if ((i = sk_OSSL_PROVIDER_find(store->providers, &tmpl)) == -1
            || (prov = sk_OSSL_PROVIDER_value(store->providers, i)) == NULL
            || !ossl_provider_upref(prov))
            prov = NULL;
        CRYPTO_THREAD_unlock(store->lock);
    }

    return prov;
}

/*-
 * Provider Object methods
 * =======================
 */

static OSSL_PROVIDER *provider_new(const char *name,
                                   OSSL_provider_init_fn *init_function)
{
    OSSL_PROVIDER *prov = NULL;

    if ((prov = OPENSSL_zalloc(sizeof(*prov))) == NULL
#ifndef HAVE_ATOMICS
        || (prov->refcnt_lock = CRYPTO_THREAD_lock_new()) == NULL
#endif
        || !ossl_provider_upref(prov) /* +1 One reference to be returned */
        || (prov->name = OPENSSL_strdup(name)) == NULL) {
        ossl_provider_free(prov);
        CRYPTOerr(CRYPTO_F_PROVIDER_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    prov->init_function = init_function;
    return prov;
}

int ossl_provider_upref(OSSL_PROVIDER *prov)
{
    int ref = 0;

    CRYPTO_UP_REF(&prov->refcnt, &ref, prov->refcnt_lock);
    return ref;
}

OSSL_PROVIDER *ossl_provider_new(OPENSSL_CTX *libctx, const char *name,
                                 OSSL_provider_init_fn *init_function)
{
    struct provider_store_st *store = NULL;
    OSSL_PROVIDER *prov = NULL;

    if ((store = get_provider_store(libctx)) == NULL)
        return NULL;

    if ((prov = ossl_provider_find(libctx, name)) != NULL) { /* refcount +1 */
        ossl_provider_free(prov); /* refcount -1 */
        CRYPTOerr(CRYPTO_F_OSSL_PROVIDER_NEW,
                  CRYPTO_R_PROVIDER_ALREADY_EXISTS);
        ERR_add_error_data(2, "name=", name);
        return NULL;
    }

    /* provider_new() generates an error, so no need here */
    if ((prov = provider_new(name, init_function)) == NULL)
        return NULL;

    CRYPTO_THREAD_write_lock(store->lock);
    if (!ossl_provider_upref(prov)) { /* +1 One reference for the store */
        ossl_provider_free(prov); /* -1 Reference that was to be returned */
        prov = NULL;
    } else if (sk_OSSL_PROVIDER_push(store->providers, prov) == 0) {
        ossl_provider_free(prov); /* -1 Store reference */
        ossl_provider_free(prov); /* -1 Reference that was to be returned */
        prov = NULL;
    } else {
        prov->store = store;
    }
    CRYPTO_THREAD_unlock(store->lock);

    if (prov == NULL)
        CRYPTOerr(CRYPTO_F_OSSL_PROVIDER_NEW, ERR_R_MALLOC_FAILURE);

    /*
     * At this point, the provider is only partially "loaded".  To be
     * fully "loaded", ossl_provider_activate() must also be called.
     */

    return prov;
}

static void free_infopair(INFOPAIR *pair)
{
    OPENSSL_free(pair->name);
    OPENSSL_free(pair->value);
    OPENSSL_free(pair);
}

void ossl_provider_free(OSSL_PROVIDER *prov)
{
    if (prov != NULL) {
        int ref = 0;

        CRYPTO_DOWN_REF(&prov->refcnt, &ref, prov->refcnt_lock);

        /*
         * When the refcount drops below two, the store is the only
         * possible reference, or it has already been taken away from
         * the store (this may happen if a provider was activated
         * because it's a fallback, but isn't currently used)
         * When that happens, the provider is inactivated.
         */
        if (ref < 2 && prov->flag_initialized) {
            if (prov->teardown != NULL)
                prov->teardown();
            prov->flag_initialized = 0;
        }

        /*
         * When the refcount drops to zero, it has been taken out of
         * the store.  All we have to do here is clean it out.
         */
        if (ref == 0) {
            DSO_free(prov->module);
            OPENSSL_free(prov->name);
            OPENSSL_free(prov->path);
            sk_INFOPAIR_pop_free(prov->parameters, free_infopair);
#ifndef HAVE_ATOMICS
            CRYPTO_THREAD_lock_free(prov->refcnt_lock);
#endif
            OPENSSL_free(prov);
        }
    }
}

/* Setters */
int ossl_provider_set_module_path(OSSL_PROVIDER *prov, const char *module_path)
{
    OPENSSL_free(prov->path);
    if (module_path == NULL)
        return 1;
    if ((prov->path = OPENSSL_strdup(module_path)) != NULL)
        return 1;
    CRYPTOerr(CRYPTO_F_OSSL_PROVIDER_SET_MODULE_PATH, ERR_R_MALLOC_FAILURE);
    return 0;
}

int ossl_provider_add_parameter(OSSL_PROVIDER *prov,
                                const char *name, const char *value)
{
    INFOPAIR *pair = NULL;

    if ((pair = OPENSSL_zalloc(sizeof(*pair))) != NULL
        && (prov->parameters != NULL
            || (prov->parameters = sk_INFOPAIR_new_null()) != NULL)
        && (pair->name = OPENSSL_strdup(name)) != NULL
        && (pair->value = OPENSSL_strdup(value)) != NULL
        && sk_INFOPAIR_push(prov->parameters, pair) > 0)
        return 1;

    if (pair != NULL) {
        OPENSSL_free(pair->name);
        OPENSSL_free(pair->value);
        OPENSSL_free(pair);
    }
    CRYPTOerr(CRYPTO_F_OSSL_PROVIDER_ADD_PARAMETER, ERR_R_MALLOC_FAILURE);
    return 0;
}

/*
 * Provider activation.
 *
 * What "activation" means depends on the provider form; for built in
 * providers (in the library or the application alike), the provider
 * can already be considered to be loaded, all that's needed is to
 * initialize it.  However, for dynamically loadable provider modules,
 * we must first load that module.
 *
 * Built in modules are distinguished from dynamically loaded modules
 * with an already assigned init function.
 */
static const OSSL_DISPATCH *core_dispatch; /* Define further down */

/*
 * Internal version that doesn't affect the store flags, and thereby avoid
 * locking.  Direct callers must remember to set the store flags when
 * appropriate
 */
static int provider_activate(OSSL_PROVIDER *prov)
{
    const OSSL_DISPATCH *provider_dispatch = NULL;

    if (prov->flag_initialized)
        return 1;

    /*
     * If the init function isn't set, it indicates that this provider is
     * a loadable module.
     */
    if (prov->init_function == NULL) {
        if (prov->module == NULL) {
            char *allocated_path = NULL;
            const char *module_path = NULL;
            char *merged_path = NULL;
            const char *load_dir = ossl_safe_getenv("OPENSSL_MODULES");

            if ((prov->module = DSO_new()) == NULL) {
                /* DSO_new() generates an error already */
                return 0;
            }

            if (load_dir == NULL)
                load_dir = MODULESDIR;

            DSO_ctrl(prov->module, DSO_CTRL_SET_FLAGS,
                     DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, NULL);

            module_path = prov->path;
            if (module_path == NULL)
                module_path = allocated_path =
                    DSO_convert_filename(prov->module, prov->name);
            if (module_path != NULL)
                merged_path = DSO_merge(prov->module, module_path, load_dir);

            if (merged_path == NULL
                || (DSO_load(prov->module, merged_path, NULL, 0)) == NULL) {
                DSO_free(prov->module);
                prov->module = NULL;
            }

            OPENSSL_free(merged_path);
            OPENSSL_free(allocated_path);
        }

        if (prov->module != NULL)
            prov->init_function = (OSSL_provider_init_fn *)
                DSO_bind_func(prov->module, "OSSL_provider_init");
    }

    if (prov->init_function == NULL
        || !prov->init_function(prov, core_dispatch, &provider_dispatch)) {
        CRYPTOerr(CRYPTO_F_PROVIDER_ACTIVATE, ERR_R_INIT_FAIL);
        ERR_add_error_data(2, "name=", prov->name);
        DSO_free(prov->module);
        prov->module = NULL;
        return 0;
    }

    for (; provider_dispatch->function_id != 0; provider_dispatch++) {
        switch (provider_dispatch->function_id) {
        case OSSL_FUNC_PROVIDER_TEARDOWN:
            prov->teardown =
                OSSL_get_provider_teardown(provider_dispatch);
            break;
        case OSSL_FUNC_PROVIDER_GET_PARAM_TYPES:
            prov->get_param_types =
                OSSL_get_provider_get_param_types(provider_dispatch);
            break;
        case OSSL_FUNC_PROVIDER_GET_PARAMS:
            prov->get_params =
                OSSL_get_provider_get_params(provider_dispatch);
            break;
        case OSSL_FUNC_PROVIDER_QUERY_OPERATION:
            prov->query_operation =
                OSSL_get_provider_query_operation(provider_dispatch);
            break;
        }
    }

    /* With this flag set, this provider has become fully "loaded". */
    prov->flag_initialized = 1;

    return 1;
}

int ossl_provider_activate(OSSL_PROVIDER *prov)
{
    if (provider_activate(prov)) {
        CRYPTO_THREAD_write_lock(prov->store->lock);
        prov->store->use_fallbacks = 0;
        CRYPTO_THREAD_unlock(prov->store->lock);
        return 1;
    }

    return 0;
}


static int provider_forall_loaded(struct provider_store_st *store,
                                  int *found_activated,
                                  int (*cb)(OSSL_PROVIDER *provider,
                                            void *cbdata),
                                  void *cbdata)
{
    int i;
    int ret = 1;
    int num_provs = sk_OSSL_PROVIDER_num(store->providers);

    if (found_activated != NULL)
        *found_activated = 0;
    for (i = 0; i < num_provs; i++) {
        OSSL_PROVIDER *prov =
            sk_OSSL_PROVIDER_value(store->providers, i);

        if (prov->flag_initialized) {
            if (found_activated != NULL)
                *found_activated = 1;
            if (!(ret = cb(prov, cbdata)))
                break;
        }
    }

    return ret;
}

int ossl_provider_forall_loaded(OPENSSL_CTX *ctx,
                                int (*cb)(OSSL_PROVIDER *provider,
                                          void *cbdata),
                                void *cbdata)
{
    int ret = 1;
    int i;
    struct provider_store_st *store = get_provider_store(ctx);

    if (store != NULL) {
        int found_activated = 0;

        CRYPTO_THREAD_read_lock(store->lock);
        ret = provider_forall_loaded(store, &found_activated, cb, cbdata);

        /*
         * If there's nothing activated ever in this store, try to activate
         * all fallbacks.
         */
        if (!found_activated && store->use_fallbacks) {
            int num_provs = sk_OSSL_PROVIDER_num(store->providers);
            int activated_fallback_count = 0;

            for (i = 0; i < num_provs; i++) {
                OSSL_PROVIDER *prov =
                    sk_OSSL_PROVIDER_value(store->providers, i);

                /*
                 * Note that we don't care if the activation succeeds or
                 * not.  If it doesn't succeed, then the next loop will
                 * fail anyway.
                 */
                if (prov->flag_fallback) {
                    activated_fallback_count++;
                    provider_activate(prov);
                }
            }

            if (activated_fallback_count > 0) {
                /*
                 * We assume that all fallbacks have been added to the store
                 * before any fallback is activated.
                 * TODO: We may have to reconsider this, IF we find ourselves
                 * adding fallbacks after any previous fallback has been
                 * activated.
                 */
                store->use_fallbacks = 0;

                /*
                 * Now that we've activated available fallbacks, try a
                 * second sweep
                 */
                ret = provider_forall_loaded(store, NULL, cb, cbdata);
            }
        }
        CRYPTO_THREAD_unlock(store->lock);
    }

    return ret;
}

/* Setters of Provider Object data */
int ossl_provider_set_fallback(OSSL_PROVIDER *prov)
{
    if (prov == NULL)
        return 0;

    prov->flag_fallback = 1;
    return 1;
}

/* Getters of Provider Object data */
const char *ossl_provider_name(OSSL_PROVIDER *prov)
{
    return prov->name;
}

const DSO *ossl_provider_dso(OSSL_PROVIDER *prov)
{
    return prov->module;
}

const char *ossl_provider_module_name(OSSL_PROVIDER *prov)
{
    return DSO_get_filename(prov->module);
}

const char *ossl_provider_module_path(OSSL_PROVIDER *prov)
{
    /* FIXME: Ensure it's a full path */
    return DSO_get_filename(prov->module);
}

/* Wrappers around calls to the provider */
void ossl_provider_teardown(const OSSL_PROVIDER *prov)
{
    if (prov->teardown != NULL)
        prov->teardown();
}

const OSSL_ITEM *ossl_provider_get_param_types(const OSSL_PROVIDER *prov)
{
    return prov->get_param_types == NULL ? NULL : prov->get_param_types(prov);
}

int ossl_provider_get_params(const OSSL_PROVIDER *prov,
                             const OSSL_PARAM params[])
{
    return prov->get_params == NULL ? 0 : prov->get_params(prov, params);
}


const OSSL_ALGORITHM *ossl_provider_query_operation(const OSSL_PROVIDER *prov,
                                                    int operation_id,
                                                    int *no_cache)
{
    return prov->query_operation(prov, operation_id, no_cache);
}

/*-
 * Core functions for the provider
 * ===============================
 *
 * This is the set of functions that the core makes available to the provider
 */

/*
 * This returns a list of Provider Object parameters with their types, for
 * discovery.  We do not expect that many providers will use this, but one
 * never knows.
 */
static const OSSL_ITEM param_types[] = {
    { OSSL_PARAM_UTF8_PTR, "openssl-version" },
    { OSSL_PARAM_UTF8_PTR, "provider-name" },
    { 0, NULL }
};

static const OSSL_ITEM *core_get_param_types(const OSSL_PROVIDER *prov)
{
    return param_types;
}

static int core_get_params(const OSSL_PROVIDER *prov, const OSSL_PARAM params[])
{
    int i;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, "openssl-version")) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR);
    if ((p = OSSL_PARAM_locate(params, "provider-name")) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, prov->name);

    if (prov->parameters == NULL)
        return 1;

    for (i = 0; i < sk_INFOPAIR_num(prov->parameters); i++) {
        INFOPAIR *pair = sk_INFOPAIR_value(prov->parameters, i);

        if ((p = OSSL_PARAM_locate(params, pair->name)) != NULL)
            OSSL_PARAM_set_utf8_ptr(p, pair->value);
    }

    return 1;
}

static const OSSL_DISPATCH core_dispatch_[] = {
    { OSSL_FUNC_CORE_GET_PARAM_TYPES, (void (*)(void))core_get_param_types },
    { OSSL_FUNC_CORE_GET_PARAMS, (void (*)(void))core_get_params },
    { 0, NULL }
};
static const OSSL_DISPATCH *core_dispatch = core_dispatch_;
