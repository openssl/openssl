/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/cryptlib.h"
#include <openssl/conf.h>
#include "internal/thread_once.h"
#include "internal/property.h"
#include "internal/core.h"
#include "internal/bio.h"
#include "internal/provider.h"

struct ossl_lib_ctx_onfree_list_st {
    ossl_lib_ctx_onfree_fn *fn;
    struct ossl_lib_ctx_onfree_list_st *next;
};

struct ossl_lib_ctx_st {
    CRYPTO_RWLOCK *lock;

    /*
     * For most data in the OSSL_LIB_CTX we just use ex_data to store it. But
     * that doesn't work for ex_data itself - so we store that directly.
     */
    OSSL_EX_DATA_GLOBAL global;

    void *property_string_data;
    void *evp_method_store;
    void *provider_store;
    void *namemap;
    void *property_defns;
    void *global_properties;
    void *drbg;
    void *drbg_nonce;
#ifndef FIPS_MODULE
    void *provider_conf;
    void *bio_core;
    void *child_provider;
    void *decoder_store;
    void *encoder_store;
    void *store_loader_store;
    void *self_test_cb;
#endif
    void *rand_crngt;
#ifdef FIPS_MODULE
    void *thread_event_handler;
#endif
    void *fips_prov;
    void (*fips_prov_free)(void *);


    CRYPTO_RWLOCK *oncelock;
    int run_once_done[OSSL_LIB_CTX_MAX_RUN_ONCE];
    int run_once_ret[OSSL_LIB_CTX_MAX_RUN_ONCE];
    struct ossl_lib_ctx_onfree_list_st *onfreelist;
    unsigned int ischild:1;
};

int ossl_lib_ctx_write_lock(OSSL_LIB_CTX *ctx)
{
    return CRYPTO_THREAD_write_lock(ossl_lib_ctx_get_concrete(ctx)->lock);
}

int ossl_lib_ctx_read_lock(OSSL_LIB_CTX *ctx)
{
    return CRYPTO_THREAD_read_lock(ossl_lib_ctx_get_concrete(ctx)->lock);
}

int ossl_lib_ctx_unlock(OSSL_LIB_CTX *ctx)
{
    return CRYPTO_THREAD_unlock(ossl_lib_ctx_get_concrete(ctx)->lock);
}

int ossl_lib_ctx_is_child(OSSL_LIB_CTX *ctx)
{
    ctx = ossl_lib_ctx_get_concrete(ctx);

    if (ctx == NULL)
        return 0;
    return ctx->ischild;
}

static void context_deinit_objs(OSSL_LIB_CTX *ctx);

void *provider_store_new(OSSL_LIB_CTX *);
void *property_string_data_new(OSSL_LIB_CTX *);
void *stored_namemap_new(OSSL_LIB_CTX *);
void *property_defns_new(OSSL_LIB_CTX *);
void *ossl_ctx_global_properties_new(OSSL_LIB_CTX *);
void *rand_ossl_ctx_new(OSSL_LIB_CTX *);
void *prov_conf_ossl_ctx_new(OSSL_LIB_CTX *);
void *bio_core_globals_new(OSSL_LIB_CTX *);
void *child_prov_ossl_ctx_new(OSSL_LIB_CTX *);
void *decoder_store_new(OSSL_LIB_CTX *);
void *loader_store_new(OSSL_LIB_CTX *);
void *encoder_store_new(OSSL_LIB_CTX *);
void *prov_drbg_nonce_ossl_ctx_new(OSSL_LIB_CTX *);
void *self_test_set_callback_new(OSSL_LIB_CTX *);
void *rand_crng_ossl_ctx_new(OSSL_LIB_CTX *);
void *thread_event_ossl_ctx_new(OSSL_LIB_CTX *);

void provider_store_free(void *);
void property_string_data_free(void *);
void stored_namemap_free(void *);
void property_defns_free(void *);
void ossl_ctx_global_properties_free(void *);
void rand_ossl_ctx_free(void *);
void prov_conf_ossl_ctx_free(void *);
void bio_core_globals_free(void *);
void child_prov_ossl_ctx_free(void *);
void decoder_store_free(void *);
void loader_store_free(void *);
void encoder_store_free(void *);
void prov_drbg_nonce_ossl_ctx_free(void *);
void self_test_set_callback_free(void *);
void rand_crng_ossl_ctx_free(void *);
void thread_event_ossl_ctx_free(void *);

static int context_init(OSSL_LIB_CTX *ctx)
{
    size_t i;
    int exdata_done = 0;

    ctx->lock = CRYPTO_THREAD_lock_new();
    if (ctx->lock == NULL)
        return 0;

    ctx->oncelock = CRYPTO_THREAD_lock_new();
    if (ctx->oncelock == NULL)
        goto err;

    /* OSSL_LIB_CTX is built on top of ex_data so we initialise that directly */
    if (!ossl_do_ex_data_init(ctx))
        goto err;
    exdata_done = 1;

    /* P2. We want evp_method_store to be cleaned up before the provider store */
    ctx->evp_method_store = ossl_method_store_new(ctx);
    if (ctx->evp_method_store == NULL)
        goto err;

#ifndef FIPS_MODULE
    /* P2. Must be freed before the provider store is freed */
    ctx->provider_conf = prov_conf_ossl_ctx_new(ctx);
    if (ctx->provider_conf == NULL)
        goto err;
#endif

    /* P2. */
    ctx->drbg = rand_ossl_ctx_new(ctx);
    if (ctx->drbg == NULL)
        goto err;

#ifndef FIPS_MODULE
    /* P2. We want decoder_store to be cleaned up before the provider store */
    ctx->decoder_store = decoder_store_new(ctx);
    if (ctx->decoder_store == NULL)
        goto err;

    /* P2. We want encoder_store to be cleaned up before the provider store */
    ctx->encoder_store = encoder_store_new(ctx);
    if (ctx->encoder_store == NULL)
        goto err;

    /* P2. We want loader_store to be cleaned up before the provider store */
    ctx->store_loader_store = loader_store_new(ctx);
    if (ctx->store_loader_store == NULL)
        goto err;
#endif

    /* P1. Needs to be freed before the child provider data is freed */
    ctx->provider_store = provider_store_new(ctx);
    if (ctx->provider_store == NULL)
        goto err;

    /* Default priority. */
    ctx->property_string_data = property_string_data_new(ctx);
    if (ctx->property_string_data == NULL)
        goto err;

    ctx->namemap = stored_namemap_new(ctx);
    if (ctx->namemap == NULL)
        goto err;

    ctx->property_defns = property_defns_new(ctx);
    if (ctx->property_defns == NULL)
        goto err;

    ctx->global_properties = ossl_ctx_global_properties_new(ctx);
    if (ctx->global_properties == NULL)
        goto err;

#ifndef FIPS_MODULE
    ctx->bio_core = bio_core_globals_new(ctx);
    if (ctx->bio_core == NULL)
        goto err;
#endif

    ctx->drbg_nonce = prov_drbg_nonce_ossl_ctx_new(ctx);
    if (ctx->drbg_nonce == NULL)
        goto err;

#ifndef FIPS_MODULE
    ctx->self_test_cb = self_test_set_callback_new(ctx);
    if (ctx->self_test_cb == NULL)
        goto err;
#endif

#ifdef FIPS_MODULE
    ctx->thread_event_handler = thread_event_ossl_ctx_new(ctx);
    if (ctx->thread_event_handler == NULL)
        goto err;
#endif

    /* Low priority. */
#ifndef FIPS_MODULE
    ctx->child_provider = child_prov_ossl_ctx_new(ctx);
    if (ctx->child_provider == NULL)
        goto err;
#endif

    /* Everything depends on properties, so we also pre-initialise that */
    if (!ossl_property_parse_init(ctx))
        goto err;

    return 1;

 err:
    context_deinit_objs(ctx);

    if (exdata_done)
        ossl_crypto_cleanup_all_ex_data_int(ctx);

    CRYPTO_THREAD_lock_free(ctx->oncelock);
    CRYPTO_THREAD_lock_free(ctx->lock);
    memset(ctx, '\0', sizeof(*ctx));
    return 0;
}

static void context_deinit_objs(OSSL_LIB_CTX *ctx)
{
    /* P2. We want evp_method_store to be cleaned up before the provider store */
    if (ctx->evp_method_store != NULL) {
        ossl_method_store_free(ctx->evp_method_store);
        ctx->evp_method_store = NULL;
    }

    /* P2. */
    if (ctx->drbg != NULL) {
        rand_ossl_ctx_free(ctx->drbg);
        ctx->drbg = NULL;
    }

#ifndef FIPS_MODULE
    /* P2. */
    if (ctx->provider_conf != NULL) {
        prov_conf_ossl_ctx_free(ctx->provider_conf);
        ctx->provider_conf = NULL;
    }

    /* P2. We want decoder_store to be cleaned up before the provider store */
    if (ctx->decoder_store != NULL) {
        decoder_store_free(ctx->decoder_store);
        ctx->decoder_store = NULL;
    }

    /* P2. We want encoder_store to be cleaned up before the provider store */
    if (ctx->encoder_store != NULL) {
        encoder_store_free(ctx->encoder_store);
        ctx->encoder_store = NULL;
    }

    /* P2. We want loader_store to be cleaned up before the provider store */
    if (ctx->store_loader_store != NULL) {
        loader_store_free(ctx->store_loader_store);
        ctx->store_loader_store = NULL;
    }
#endif

    /* P1. Needs to be freed before the child provider data is freed */
    if (ctx->provider_store != NULL) {
        provider_store_free(ctx->provider_store);
        ctx->provider_store = NULL;
    }

    /* Default priority. */
    if (ctx->property_string_data != NULL) {
        property_string_data_free(ctx->property_string_data);
        ctx->property_string_data = NULL;
    }

    if (ctx->namemap != NULL) {
        stored_namemap_free(ctx->namemap);
        ctx->namemap = NULL;
    }

    if (ctx->property_defns != NULL) {
        property_defns_free(ctx->property_defns);
        ctx->property_defns = NULL;
    }

    if (ctx->global_properties != NULL) {
        ossl_ctx_global_properties_free(ctx->global_properties);
        ctx->global_properties = NULL;
    }

#ifndef FIPS_MODULE
    if (ctx->bio_core != NULL) {
        bio_core_globals_free(ctx->bio_core);
        ctx->bio_core = NULL;
    }
#endif

    if (ctx->drbg_nonce != NULL) {
        prov_drbg_nonce_ossl_ctx_free(ctx->drbg_nonce);
        ctx->drbg_nonce = NULL;
    }

#ifndef FIPS_MODULE
    if (ctx->self_test_cb != NULL) {
        self_test_set_callback_free(ctx->self_test_cb);
        ctx->self_test_cb = NULL;
    }
#endif

    if (ctx->rand_crngt != NULL) {
        rand_crng_ossl_ctx_free(ctx->rand_crngt);
        ctx->rand_crngt = NULL;
    }

#ifdef FIPS_MODULE
    if (ctx->thread_event_handler != NULL) {
        thread_event_ossl_ctx_free(ctx->thread_event_handler);
        ctx->thread_event_handler = NULL;
    }
#endif

    if (ctx->fips_prov != NULL) {
        ctx->fips_prov_free(ctx->fips_prov);
        ctx->fips_prov = NULL;
        ctx->fips_prov_free = NULL;
    }

    /* Low priority. */
#ifndef FIPS_MODULE
    if (ctx->child_provider != NULL) {
        child_prov_ossl_ctx_free(ctx->child_provider);
        ctx->child_provider = NULL;
    }
#endif
}

static int context_deinit(OSSL_LIB_CTX *ctx)
{
    struct ossl_lib_ctx_onfree_list_st *tmp, *onfree;
    int i;

    if (ctx == NULL)
        return 1;

    ossl_ctx_thread_stop(ctx);

    context_deinit_objs(ctx);

    onfree = ctx->onfreelist;
    while (onfree != NULL) {
        onfree->fn(ctx);
        tmp = onfree;
        onfree = onfree->next;
        OPENSSL_free(tmp);
    }

    ossl_crypto_cleanup_all_ex_data_int(ctx);

    CRYPTO_THREAD_lock_free(ctx->oncelock);
    CRYPTO_THREAD_lock_free(ctx->lock);
    ctx->oncelock = NULL;
    ctx->lock = NULL;
    return 1;
}

#ifndef FIPS_MODULE
/* The default default context */
static OSSL_LIB_CTX default_context_int;

static CRYPTO_ONCE default_context_init = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_THREAD_LOCAL default_context_thread_local;

DEFINE_RUN_ONCE_STATIC(default_context_do_init)
{
    return CRYPTO_THREAD_init_local(&default_context_thread_local, NULL)
        && context_init(&default_context_int);
}

void ossl_lib_ctx_default_deinit(void)
{
    context_deinit(&default_context_int);
    CRYPTO_THREAD_cleanup_local(&default_context_thread_local);
}

static OSSL_LIB_CTX *get_thread_default_context(void)
{
    if (!RUN_ONCE(&default_context_init, default_context_do_init))
        return NULL;

    return CRYPTO_THREAD_get_local(&default_context_thread_local);
}

static OSSL_LIB_CTX *get_default_context(void)
{
    OSSL_LIB_CTX *current_defctx = get_thread_default_context();

    if (current_defctx == NULL)
        current_defctx = &default_context_int;
    return current_defctx;
}

static int set_default_context(OSSL_LIB_CTX *defctx)
{
    if (defctx == &default_context_int)
        defctx = NULL;

    return CRYPTO_THREAD_set_local(&default_context_thread_local, defctx);
}
#endif

OSSL_LIB_CTX *OSSL_LIB_CTX_new(void)
{
    OSSL_LIB_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL && !context_init(ctx)) {
        OPENSSL_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

#ifndef FIPS_MODULE
OSSL_LIB_CTX *OSSL_LIB_CTX_new_from_dispatch(const OSSL_CORE_HANDLE *handle,
                                             const OSSL_DISPATCH *in)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();

    if (ctx == NULL)
        return NULL;

    if (!ossl_bio_init_core(ctx, in)) {
        OSSL_LIB_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

OSSL_LIB_CTX *OSSL_LIB_CTX_new_child(const OSSL_CORE_HANDLE *handle,
                                     const OSSL_DISPATCH *in)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);

    if (ctx == NULL)
        return NULL;

    if (!ossl_provider_init_as_child(ctx, handle, in)) {
        OSSL_LIB_CTX_free(ctx);
        return NULL;
    }
    ctx->ischild = 1;

    return ctx;
}

int OSSL_LIB_CTX_load_config(OSSL_LIB_CTX *ctx, const char *config_file)
{
    return CONF_modules_load_file_ex(ctx, config_file, NULL, 0) > 0;
}
#endif

void OSSL_LIB_CTX_free(OSSL_LIB_CTX *ctx)
{
    if (ossl_lib_ctx_is_default(ctx))
        return;

#ifndef FIPS_MODULE
    if (ctx->ischild)
        ossl_provider_deinit_child(ctx);
#endif
    context_deinit(ctx);
    OPENSSL_free(ctx);
}

#ifndef FIPS_MODULE
OSSL_LIB_CTX *OSSL_LIB_CTX_get0_global_default(void)
{
    if (!RUN_ONCE(&default_context_init, default_context_do_init))
        return NULL;

    return &default_context_int;
}

OSSL_LIB_CTX *OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX *libctx)
{
    OSSL_LIB_CTX *current_defctx;

    if ((current_defctx = get_default_context()) != NULL) {
        if (libctx != NULL)
            set_default_context(libctx);
        return current_defctx;
    }

    return NULL;
}
#endif

OSSL_LIB_CTX *ossl_lib_ctx_get_concrete(OSSL_LIB_CTX *ctx)
{
#ifndef FIPS_MODULE
    if (ctx == NULL)
        return get_default_context();
#endif
    return ctx;
}

int ossl_lib_ctx_is_default(OSSL_LIB_CTX *ctx)
{
#ifndef FIPS_MODULE
    if (ctx == NULL || ctx == get_default_context())
        return 1;
#endif
    return 0;
}

int ossl_lib_ctx_is_global_default(OSSL_LIB_CTX *ctx)
{
#ifndef FIPS_MODULE
    if (ossl_lib_ctx_get_concrete(ctx) == &default_context_int)
        return 1;
#endif
    return 0;
}

void *ossl_lib_ctx_get_data(OSSL_LIB_CTX *ctx, int index,
                            const OSSL_LIB_CTX_METHOD *meth)
{
    void *p;

    ctx = ossl_lib_ctx_get_concrete(ctx);
    if (ctx == NULL)
        return NULL;

    switch (index) {
        case OSSL_LIB_CTX_PROPERTY_STRING_INDEX:
            return ctx->property_string_data;
        case OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX:
            return ctx->evp_method_store;
        case OSSL_LIB_CTX_PROVIDER_STORE_INDEX:
            return ctx->provider_store;
        case OSSL_LIB_CTX_NAMEMAP_INDEX:
            return ctx->namemap;
        case OSSL_LIB_CTX_PROPERTY_DEFN_INDEX:
            return ctx->property_defns;
        case OSSL_LIB_CTX_GLOBAL_PROPERTIES:
            return ctx->global_properties;
        case OSSL_LIB_CTX_DRBG_INDEX:
            return ctx->drbg;
        case OSSL_LIB_CTX_DRBG_NONCE_INDEX:
            return ctx->drbg_nonce;
#ifndef FIPS_MODULE
        case OSSL_LIB_CTX_PROVIDER_CONF_INDEX:
            return ctx->provider_conf;
        case OSSL_LIB_CTX_BIO_CORE_INDEX:
            return ctx->bio_core;
        case OSSL_LIB_CTX_CHILD_PROVIDER_INDEX:
            return ctx->child_provider;
        case OSSL_LIB_CTX_DECODER_STORE_INDEX:
            return ctx->decoder_store;
        case OSSL_LIB_CTX_ENCODER_STORE_INDEX:
            return ctx->encoder_store;
        case OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX:
            return ctx->store_loader_store;
        case OSSL_LIB_CTX_SELF_TEST_CB_INDEX:
            return ctx->self_test_cb;
#endif

        case OSSL_LIB_CTX_RAND_CRNGT_INDEX: {

            /*
             * rand_crngt must be lazily initialized because it calls into
             * libctx, so must not be called from context_init, else a deadlock
             * will occur.
             */
            if (CRYPTO_THREAD_read_lock(ctx->lock) != 1)
                return NULL;

            if (ctx->rand_crngt == NULL) {
                CRYPTO_THREAD_unlock(ctx->lock);

                if (CRYPTO_THREAD_write_lock(ctx->lock) != 1)
                    return NULL;

                ctx->rand_crngt = rand_crng_ossl_ctx_new(ctx);
            }

            p = ctx->rand_crngt;

            CRYPTO_THREAD_unlock(ctx->lock);
            return p;
        }

#ifdef FIPS_MODULE
        case OSSL_LIB_CTX_THREAD_EVENT_HANDLER_INDEX:
            return ctx->thread_event_handler;
#endif

        case OSSL_LIB_CTX_FIPS_PROV_INDEX: {
            /*
             * fips is a separate module which may or may not be loaded,
             * so we have to do this lazily.
             */
            if (CRYPTO_THREAD_read_lock(ctx->lock) != 1)
                return NULL;

            if (ctx->fips_prov == NULL) {
                CRYPTO_THREAD_unlock(ctx->lock);

                if (CRYPTO_THREAD_write_lock(ctx->lock) != 1)
                    return NULL;

                ctx->fips_prov = meth->new_func(ctx);
                if (ctx->fips_prov != NULL)
                    ctx->fips_prov_free = meth->free_func;
            }

            p = ctx->fips_prov;

            CRYPTO_THREAD_unlock(ctx->lock);
            return p;
        }

        default:
            return NULL;
    }
}

OSSL_EX_DATA_GLOBAL *ossl_lib_ctx_get_ex_data_global(OSSL_LIB_CTX *ctx)
{
    ctx = ossl_lib_ctx_get_concrete(ctx);
    if (ctx == NULL)
        return NULL;
    return &ctx->global;
}

int ossl_lib_ctx_run_once(OSSL_LIB_CTX *ctx, unsigned int idx,
                          ossl_lib_ctx_run_once_fn run_once_fn)
{
    int done = 0, ret = 0;

    ctx = ossl_lib_ctx_get_concrete(ctx);
    if (ctx == NULL)
        return 0;

    if (!CRYPTO_THREAD_read_lock(ctx->oncelock))
        return 0;
    done = ctx->run_once_done[idx];
    if (done)
        ret = ctx->run_once_ret[idx];
    CRYPTO_THREAD_unlock(ctx->oncelock);

    if (done)
        return ret;

    if (!CRYPTO_THREAD_write_lock(ctx->oncelock))
        return 0;
    if (ctx->run_once_done[idx]) {
        ret = ctx->run_once_ret[idx];
        CRYPTO_THREAD_unlock(ctx->oncelock);
        return ret;
    }

    ret = run_once_fn(ctx);
    ctx->run_once_done[idx] = 1;
    ctx->run_once_ret[idx] = ret;
    CRYPTO_THREAD_unlock(ctx->oncelock);

    return ret;
}

int ossl_lib_ctx_onfree(OSSL_LIB_CTX *ctx, ossl_lib_ctx_onfree_fn onfreefn)
{
    struct ossl_lib_ctx_onfree_list_st *newonfree
        = OPENSSL_malloc(sizeof(*newonfree));

    if (newonfree == NULL)
        return 0;

    newonfree->fn = onfreefn;
    newonfree->next = ctx->onfreelist;
    ctx->onfreelist = newonfree;

    return 1;
}

const char *ossl_lib_ctx_get_descriptor(OSSL_LIB_CTX *libctx)
{
#ifdef FIPS_MODULE
    return "FIPS internal library context";
#else
    if (ossl_lib_ctx_is_global_default(libctx))
        return "Global default library context";
    if (ossl_lib_ctx_is_default(libctx))
        return "Thread-local default library context";
    return "Non-default library context";
#endif
}
