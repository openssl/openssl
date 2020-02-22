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
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/opensslv.h>
#include "crypto/cryptlib.h"
#include "internal/nelem.h"
#include "internal/thread_once.h"
#include "internal/provider.h"
#include "internal/refcount.h"
#include "provider_local.h"
#ifndef FIPS_MODE
# include <openssl/self_test.h>
#endif

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
    OPENSSL_CTX *libctx; /* The library context this instance is in */
    struct provider_store_st *store; /* The store this instance belongs to */
#ifndef FIPS_MODE
    /*
     * In the FIPS module inner provider, this isn't needed, since the
     * error upcalls are always direct calls to the outer provider.
     */
    int error_lib;     /* ERR library number, one for each provider */
# ifndef OPENSSL_NO_ERR
    ERR_STRING_DATA *error_strings; /* Copy of what the provider gives us */
# endif
#endif

    /* Provider side functions */
    OSSL_provider_teardown_fn *teardown;
    OSSL_provider_gettable_params_fn *gettable_params;
    OSSL_provider_get_params_fn *get_params;
    OSSL_provider_query_operation_fn *query_operation;

    /* Provider side data */
    void *provctx;
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

static void provider_store_free(void *vstore)
{
    struct provider_store_st *store = vstore;

    if (store == NULL)
        return;
    sk_OSSL_PROVIDER_pop_free(store->providers, ossl_provider_free);
    CRYPTO_THREAD_lock_free(store->lock);
    OPENSSL_free(store);
}

static void *provider_store_new(OPENSSL_CTX *ctx)
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
        prov->libctx = ctx;
        prov->store = store;
#ifndef FIPS_MODE
        prov->error_lib = ERR_get_next_error_library();
#endif
        if(p->is_fallback)
            ossl_provider_set_fallback(prov);
    }

    return store;
}

static const OPENSSL_CTX_METHOD provider_store_method = {
    provider_store_new,
    provider_store_free,
};

static struct provider_store_st *get_provider_store(OPENSSL_CTX *libctx)
{
    struct provider_store_st *store = NULL;

    store = openssl_ctx_get_data(libctx, OPENSSL_CTX_PROVIDER_STORE_INDEX,
                                 &provider_store_method);
    if (store == NULL)
        CRYPTOerr(CRYPTO_F_GET_PROVIDER_STORE, ERR_R_INTERNAL_ERROR);
    return store;
}

OSSL_PROVIDER *ossl_provider_find(OPENSSL_CTX *libctx, const char *name,
                                  int noconfig)
{
    struct provider_store_st *store = NULL;
    OSSL_PROVIDER *prov = NULL;

    if ((store = get_provider_store(libctx)) != NULL) {
        OSSL_PROVIDER tmpl = { 0, };
        int i;

#ifndef FIPS_MODE
        /*
         * Make sure any providers are loaded from config before we try to find
         * them.
         */
        if (!noconfig)
            OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif

        tmpl.name = (char *)name;
        CRYPTO_THREAD_write_lock(store->lock);
        if ((i = sk_OSSL_PROVIDER_find(store->providers, &tmpl)) == -1
            || (prov = sk_OSSL_PROVIDER_value(store->providers, i)) == NULL
            || !ossl_provider_up_ref(prov))
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
        || !ossl_provider_up_ref(prov) /* +1 One reference to be returned */
        || (prov->name = OPENSSL_strdup(name)) == NULL) {
        ossl_provider_free(prov);
        CRYPTOerr(CRYPTO_F_PROVIDER_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    prov->init_function = init_function;
    return prov;
}

int ossl_provider_up_ref(OSSL_PROVIDER *prov)
{
    int ref = 0;

    if (CRYPTO_UP_REF(&prov->refcnt, &ref, prov->refcnt_lock) <= 0)
        return 0;
    return ref;
}

OSSL_PROVIDER *ossl_provider_new(OPENSSL_CTX *libctx, const char *name,
                                 OSSL_provider_init_fn *init_function,
                                 int noconfig)
{
    struct provider_store_st *store = NULL;
    OSSL_PROVIDER *prov = NULL;

    if ((store = get_provider_store(libctx)) == NULL)
        return NULL;

    if ((prov = ossl_provider_find(libctx, name,
                                   noconfig)) != NULL) { /* refcount +1 */
        ossl_provider_free(prov); /* refcount -1 */
        ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_PROVIDER_ALREADY_EXISTS, NULL,
                       "name=%s", name);
        return NULL;
    }

    /* provider_new() generates an error, so no need here */
    if ((prov = provider_new(name, init_function)) == NULL)
        return NULL;

    CRYPTO_THREAD_write_lock(store->lock);
    if (!ossl_provider_up_ref(prov)) { /* +1 One reference for the store */
        ossl_provider_free(prov); /* -1 Reference that was to be returned */
        prov = NULL;
    } else if (sk_OSSL_PROVIDER_push(store->providers, prov) == 0) {
        ossl_provider_free(prov); /* -1 Store reference */
        ossl_provider_free(prov); /* -1 Reference that was to be returned */
        prov = NULL;
    } else {
        prov->libctx = libctx;
        prov->store = store;
#ifndef FIPS_MODE
        prov->error_lib = ERR_get_next_error_library();
#endif
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
#ifndef FIPS_MODE
            ossl_init_thread_deregister(prov);
#endif
            if (prov->teardown != NULL)
                prov->teardown(prov->provctx);
#ifndef OPENSSL_NO_ERR
# ifndef FIPS_MODE
            if (prov->error_strings != NULL) {
                ERR_unload_strings(prov->error_lib, prov->error_strings);
                OPENSSL_free(prov->error_strings);
                prov->error_strings = NULL;
            }
# endif
#endif
            prov->flag_initialized = 0;
        }

        /*
         * When the refcount drops to zero, it has been taken out of
         * the store.  All we have to do here is clean it out.
         */
        if (ref == 0) {
#ifndef FIPS_MODE
            DSO_free(prov->module);
#endif
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
 * appropriate.
 */
static int provider_activate(OSSL_PROVIDER *prov)
{
    const OSSL_DISPATCH *provider_dispatch = NULL;
#ifndef OPENSSL_NO_ERR
# ifndef FIPS_MODE
    OSSL_provider_get_reason_strings_fn *p_get_reason_strings = NULL;
# endif
#endif

    if (prov->flag_initialized)
        return 1;

    /*
     * If the init function isn't set, it indicates that this provider is
     * a loadable module.
     */
    if (prov->init_function == NULL) {
#ifdef FIPS_MODE
        return 0;
#else
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
#endif
    }

    /* Call the initialise function for the provider. */
    if (prov->init_function == NULL
        || !prov->init_function(prov, core_dispatch, &provider_dispatch,
                                &prov->provctx)) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INIT_FAIL, NULL,
                       "name=%s", prov->name);
#ifndef FIPS_MODE
        DSO_free(prov->module);
        prov->module = NULL;
#endif
        return 0;
    }

    for (; provider_dispatch->function_id != 0; provider_dispatch++) {
        switch (provider_dispatch->function_id) {
        case OSSL_FUNC_PROVIDER_TEARDOWN:
            prov->teardown =
                OSSL_get_provider_teardown(provider_dispatch);
            break;
        case OSSL_FUNC_PROVIDER_GETTABLE_PARAMS:
            prov->gettable_params =
                OSSL_get_provider_gettable_params(provider_dispatch);
            break;
        case OSSL_FUNC_PROVIDER_GET_PARAMS:
            prov->get_params =
                OSSL_get_provider_get_params(provider_dispatch);
            break;
        case OSSL_FUNC_PROVIDER_QUERY_OPERATION:
            prov->query_operation =
                OSSL_get_provider_query_operation(provider_dispatch);
            break;
#ifndef OPENSSL_NO_ERR
# ifndef FIPS_MODE
        case OSSL_FUNC_PROVIDER_GET_REASON_STRINGS:
            p_get_reason_strings =
                OSSL_get_provider_get_reason_strings(provider_dispatch);
            break;
# endif
#endif
        }
    }

#ifndef OPENSSL_NO_ERR
# ifndef FIPS_MODE
    if (p_get_reason_strings != NULL) {
        const OSSL_ITEM *reasonstrings = p_get_reason_strings(prov->provctx);
        size_t cnt, cnt2;

        /*
         * ERR_load_strings() handles ERR_STRING_DATA rather than OSSL_ITEM,
         * although they are essentially the same type.
         * Furthermore, ERR_load_strings() patches the array's error number
         * with the error library number, so we need to make a copy of that
         * array either way.
         */
        cnt = 1;                 /* One for the terminating item */
        while (reasonstrings[cnt].id != 0) {
            if (ERR_GET_LIB(reasonstrings[cnt].id) != 0)
                return 0;
            cnt++;
        }

        /* Allocate one extra item for the "library" name */
        prov->error_strings =
            OPENSSL_zalloc(sizeof(ERR_STRING_DATA) * (cnt + 1));
        if (prov->error_strings == NULL)
            return 0;

        /*
         * Set the "library" name.
         */
        prov->error_strings[0].error = ERR_PACK(prov->error_lib, 0, 0);
        prov->error_strings[0].string = prov->name;
        /*
         * Copy reasonstrings item 0..cnt-1 to prov->error_trings positions
         * 1..cnt.
         */
        for (cnt2 = 1; cnt2 <= cnt; cnt2++) {
            prov->error_strings[cnt2].error = (int)reasonstrings[cnt2-1].id;
            prov->error_strings[cnt2].string = reasonstrings[cnt2-1].ptr;
        }

        ERR_load_strings(prov->error_lib, prov->error_strings);
    }
# endif
#endif

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

void *ossl_provider_ctx(const OSSL_PROVIDER *prov)
{
    return prov->provctx;
}


static int provider_forall_loaded(struct provider_store_st *store,
                                  int *found_activated,
                                  int (*cb)(OSSL_PROVIDER *provider,
                                            void *cbdata),
                                  void *cbdata)
{
    int i;
    int ret = 1;
    int num_provs;

    num_provs = sk_OSSL_PROVIDER_num(store->providers);

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

/*
 * This function only does something once when store->use_fallbacks == 1,
 * and then sets store->use_fallbacks = 0, so the second call and so on is
 * effectively a no-op.
 */
static void provider_activate_fallbacks(struct provider_store_st *store)
{
    if (store->use_fallbacks) {
        int num_provs = sk_OSSL_PROVIDER_num(store->providers);
        int activated_fallback_count = 0;
        int i;

        for (i = 0; i < num_provs; i++) {
            OSSL_PROVIDER *prov = sk_OSSL_PROVIDER_value(store->providers, i);

            /*
             * Note that we don't care if the activation succeeds or not.
             * If it doesn't succeed, then any attempt to use any of the
             * fallback providers will fail anyway.
             */
            if (prov->flag_fallback) {
                activated_fallback_count++;
                provider_activate(prov);
            }
        }

        /*
         * We assume that all fallbacks have been added to the store before
         * any fallback is activated.
         * TODO: We may have to reconsider this, IF we find ourselves adding
         * fallbacks after any previous fallback has been activated.
         */
        if (activated_fallback_count > 0)
            store->use_fallbacks = 0;
    }
}

int ossl_provider_forall_loaded(OPENSSL_CTX *ctx,
                                int (*cb)(OSSL_PROVIDER *provider,
                                          void *cbdata),
                                void *cbdata)
{
    int ret = 1;
    struct provider_store_st *store = get_provider_store(ctx);

#ifndef FIPS_MODE
    /*
     * Make sure any providers are loaded from config before we try to use
     * them.
     */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif

    if (store != NULL) {
        CRYPTO_THREAD_read_lock(store->lock);

        provider_activate_fallbacks(store);

        /*
         * Now, we sweep through all providers
         */
        ret = provider_forall_loaded(store, NULL, cb, cbdata);

        CRYPTO_THREAD_unlock(store->lock);
    }

    return ret;
}

int ossl_provider_available(OSSL_PROVIDER *prov)
{
    if (prov != NULL) {
        CRYPTO_THREAD_read_lock(prov->store->lock);
        provider_activate_fallbacks(prov->store);
        CRYPTO_THREAD_unlock(prov->store->lock);

        return prov->flag_initialized;
    }
    return 0;
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
const char *ossl_provider_name(const OSSL_PROVIDER *prov)
{
    return prov->name;
}

const DSO *ossl_provider_dso(const OSSL_PROVIDER *prov)
{
    return prov->module;
}

const char *ossl_provider_module_name(const OSSL_PROVIDER *prov)
{
#ifdef FIPS_MODE
    return NULL;
#else
    return DSO_get_filename(prov->module);
#endif
}

const char *ossl_provider_module_path(const OSSL_PROVIDER *prov)
{
#ifdef FIPS_MODE
    return NULL;
#else
    /* FIXME: Ensure it's a full path */
    return DSO_get_filename(prov->module);
#endif
}

OPENSSL_CTX *ossl_provider_library_context(const OSSL_PROVIDER *prov)
{
    /* TODO(3.0) just: return prov->libctx; */
    return prov != NULL ? prov->libctx : NULL;
}

/* Wrappers around calls to the provider */
void ossl_provider_teardown(const OSSL_PROVIDER *prov)
{
    if (prov->teardown != NULL)
        prov->teardown(prov->provctx);
}

const OSSL_PARAM *ossl_provider_gettable_params(const OSSL_PROVIDER *prov)
{
    return prov->gettable_params == NULL
        ? NULL : prov->gettable_params(prov->provctx);
}

int ossl_provider_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    return prov->get_params == NULL
        ? 0 : prov->get_params(prov->provctx, params);
}


const OSSL_ALGORITHM *ossl_provider_query_operation(const OSSL_PROVIDER *prov,
                                                    int operation_id,
                                                    int *no_cache)
{
    return prov->query_operation(prov->provctx, operation_id, no_cache);
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
static const OSSL_PARAM param_types[] = {
    OSSL_PARAM_DEFN("openssl-version", OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN("provider-name", OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

/*
 * Forward declare all the functions that are provided aa dispatch.
 * This ensures that the compiler will complain if they aren't defined
 * with the correct signature.
 */
static OSSL_core_gettable_params_fn core_gettable_params;
static OSSL_core_get_params_fn core_get_params;
static OSSL_core_thread_start_fn core_thread_start;
static OSSL_core_get_library_context_fn core_get_libctx;
#ifndef FIPS_MODE
static OSSL_core_new_error_fn core_new_error;
static OSSL_core_set_error_debug_fn core_set_error_debug;
static OSSL_core_vset_error_fn core_vset_error;
static OSSL_core_set_error_mark_fn core_set_error_mark;
static OSSL_core_clear_last_error_mark_fn core_clear_last_error_mark;
static OSSL_core_pop_error_to_mark_fn core_pop_error_to_mark;
#endif

static const OSSL_PARAM *core_gettable_params(const OSSL_PROVIDER *prov)
{
    return param_types;
}

static int core_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    int i;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, "openssl-version")) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR);
    if ((p = OSSL_PARAM_locate(params, "provider-name")) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, prov->name);

#ifndef FIPS_MODE
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_MODULE_FILENAME)) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, ossl_provider_module_path(prov));
#endif

    if (prov->parameters == NULL)
        return 1;

    for (i = 0; i < sk_INFOPAIR_num(prov->parameters); i++) {
        INFOPAIR *pair = sk_INFOPAIR_value(prov->parameters, i);

        if ((p = OSSL_PARAM_locate(params, pair->name)) != NULL)
            OSSL_PARAM_set_utf8_ptr(p, pair->value);
    }
    return 1;
}

static OPENSSL_CTX *core_get_libctx(const OSSL_PROVIDER *prov)
{
    return ossl_provider_library_context(prov);
}

static int core_thread_start(const OSSL_PROVIDER *prov,
                             OSSL_thread_stop_handler_fn handfn)
{
    return ossl_init_thread_start(prov, prov->provctx, handfn);
}

/*
 * The FIPS module inner provider doesn't implement these.  They aren't
 * needed there, since the FIPS module upcalls are always the outer provider
 * ones.
 */
#ifndef FIPS_MODE
/*
 * TODO(3.0) These error functions should use |prov| to select the proper
 * library context to report in the correct error stack, at least if error
 * stacks become tied to the library context.
 * We cannot currently do that since there's no support for it in the
 * ERR subsystem.
 */
static void core_new_error(const OSSL_PROVIDER *prov)
{
    ERR_new();
}

static void core_set_error_debug(const OSSL_PROVIDER *prov,
                                 const char *file, int line, const char *func)
{
    ERR_set_debug(file, line, func);
}

static void core_vset_error(const OSSL_PROVIDER *prov,
                            uint32_t reason, const char *fmt, va_list args)
{
    /*
     * If the uppermost 8 bits are non-zero, it's an OpenSSL library
     * error and will be treated as such.  Otherwise, it's a new style
     * provider error and will be treated as such.
     */
    if (ERR_GET_LIB(reason) != 0) {
        ERR_vset_error(ERR_GET_LIB(reason), ERR_GET_REASON(reason), fmt, args);
    } else {
        ERR_vset_error(prov->error_lib, (int)reason, fmt, args);
    }
}

static int core_set_error_mark(const OSSL_PROVIDER *prov)
{
    return ERR_set_mark();
}

static int core_clear_last_error_mark(const OSSL_PROVIDER *prov)
{
    return ERR_clear_last_mark();
}

static int core_pop_error_to_mark(const OSSL_PROVIDER *prov)
{
    return ERR_pop_to_mark();
}
#endif

/*
 * Functions provided by the core.  Blank line separates "families" of related
 * functions.
 */
static const OSSL_DISPATCH core_dispatch_[] = {
    { OSSL_FUNC_CORE_GETTABLE_PARAMS, (void (*)(void))core_gettable_params },
    { OSSL_FUNC_CORE_GET_PARAMS, (void (*)(void))core_get_params },
    { OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT, (void (*)(void))core_get_libctx },
    { OSSL_FUNC_CORE_THREAD_START, (void (*)(void))core_thread_start },
#ifndef FIPS_MODE
    { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))core_new_error },
    { OSSL_FUNC_CORE_SET_ERROR_DEBUG, (void (*)(void))core_set_error_debug },
    { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))core_vset_error },
    { OSSL_FUNC_CORE_SET_ERROR_MARK, (void (*)(void))core_set_error_mark },
    { OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK,
      (void (*)(void))core_clear_last_error_mark },
    { OSSL_FUNC_CORE_POP_ERROR_TO_MARK,
      (void (*)(void))core_pop_error_to_mark },
    { OSSL_FUNC_BIO_NEW_FILE, (void (*)(void))BIO_new_file },
    { OSSL_FUNC_BIO_NEW_MEMBUF, (void (*)(void))BIO_new_mem_buf },
    { OSSL_FUNC_BIO_READ_EX, (void (*)(void))BIO_read_ex },
    { OSSL_FUNC_BIO_FREE, (void (*)(void))BIO_free },
    { OSSL_FUNC_BIO_VPRINTF, (void (*)(void))BIO_vprintf },
    { OSSL_FUNC_SELF_TEST_CB, (void (*)(void))OSSL_SELF_TEST_get_callback },
#endif
    { OSSL_FUNC_CRYPTO_MALLOC, (void (*)(void))CRYPTO_malloc },
    { OSSL_FUNC_CRYPTO_ZALLOC, (void (*)(void))CRYPTO_zalloc },
    { OSSL_FUNC_CRYPTO_FREE, (void (*)(void))CRYPTO_free },
    { OSSL_FUNC_CRYPTO_CLEAR_FREE, (void (*)(void))CRYPTO_clear_free },
    { OSSL_FUNC_CRYPTO_REALLOC, (void (*)(void))CRYPTO_realloc },
    { OSSL_FUNC_CRYPTO_CLEAR_REALLOC, (void (*)(void))CRYPTO_clear_realloc },
    { OSSL_FUNC_CRYPTO_SECURE_MALLOC, (void (*)(void))CRYPTO_secure_malloc },
    { OSSL_FUNC_CRYPTO_SECURE_ZALLOC, (void (*)(void))CRYPTO_secure_zalloc },
    { OSSL_FUNC_CRYPTO_SECURE_FREE, (void (*)(void))CRYPTO_secure_free },
    { OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE,
        (void (*)(void))CRYPTO_secure_clear_free },
    { OSSL_FUNC_CRYPTO_SECURE_ALLOCATED,
        (void (*)(void))CRYPTO_secure_allocated },
    { OSSL_FUNC_OPENSSL_CLEANSE, (void (*)(void))OPENSSL_cleanse },

    { 0, NULL }
};
static const OSSL_DISPATCH *core_dispatch = core_dispatch_;
