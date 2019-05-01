/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "internal/thread_once.h"

struct openssl_ctx_onfree_list_st {
    openssl_ctx_onfree_fn *fn;
    struct openssl_ctx_onfree_list_st *next;
};

struct openssl_ctx_st {
    CRYPTO_RWLOCK *lock;
    CRYPTO_EX_DATA data;

    /*
     * For most data in the OPENSSL_CTX we just use ex_data to store it. But
     * that doesn't work for ex_data itself - so we store that directly.
     */
    OSSL_EX_DATA_GLOBAL global;

    /* Map internal static indexes to dynamically created indexes */
    int dyn_indexes[OPENSSL_CTX_MAX_INDEXES];

    CRYPTO_RWLOCK *oncelock;
    int run_once_done[OPENSSL_CTX_MAX_RUN_ONCE];
    int run_once_ret[OPENSSL_CTX_MAX_RUN_ONCE];
    struct openssl_ctx_onfree_list_st *onfreelist;
};

#ifndef FIPS_MODE
static OPENSSL_CTX default_context_int;
#endif

/* Always points at default_context_int if it has been initialised */
static OPENSSL_CTX *default_context = NULL;

static int context_init(OPENSSL_CTX *ctx)
{
    size_t i;

    ctx->lock = CRYPTO_THREAD_lock_new();
    if (ctx->lock == NULL)
        return 0;

    ctx->oncelock = CRYPTO_THREAD_lock_new();
    if (ctx->oncelock == NULL)
        goto err;

    for (i = 0; i < OPENSSL_CTX_MAX_INDEXES; i++)
        ctx->dyn_indexes[i] = -1;

    if (!do_ex_data_init(ctx))
        goto err;

    if (!crypto_new_ex_data_ex(ctx, CRYPTO_EX_INDEX_OPENSSL_CTX, NULL,
                               &ctx->data)) {
        crypto_cleanup_all_ex_data_int(ctx);
        goto err;
    }

    return 1;
 err:
    CRYPTO_THREAD_lock_free(ctx->oncelock);
    CRYPTO_THREAD_lock_free(ctx->lock);
    ctx->lock = NULL;
    return 0;
}

static int context_deinit(OPENSSL_CTX *ctx)
{
    struct openssl_ctx_onfree_list_st *tmp, *onfree;

    if (ctx == NULL)
        return 1;

    onfree = ctx->onfreelist;
    while (onfree != NULL) {
        onfree->fn(ctx);
        tmp = onfree;
        onfree = onfree->next;
        OPENSSL_free(tmp);
    }
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_OPENSSL_CTX, NULL, &ctx->data);
    crypto_cleanup_all_ex_data_int(ctx);
    CRYPTO_THREAD_lock_free(ctx->oncelock);
    CRYPTO_THREAD_lock_free(ctx->lock);
    ctx->lock = NULL;
    return 1;
}

#ifndef FIPS_MODE
void openssl_ctx_default_deinit(void)
{
    context_deinit(default_context);
}

static CRYPTO_ONCE default_context_init = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_default_context_init)
{
    if (context_init(&default_context_int))
        default_context = &default_context_int;

    return 1;
}
#endif

OPENSSL_CTX *OPENSSL_CTX_new(void)
{
    OPENSSL_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL && !context_init(ctx)) {
        OPENSSL_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

void OPENSSL_CTX_free(OPENSSL_CTX *ctx)
{
    if (ctx != NULL)
        context_deinit(ctx);
    OPENSSL_free(ctx);
}

static void openssl_ctx_generic_new(void *parent_ign, void *ptr_ign,
                                    CRYPTO_EX_DATA *ad, int index,
                                    long argl_ign, void *argp)
{
    const OPENSSL_CTX_METHOD *meth = argp;
    void *ptr = meth->new_func(crypto_ex_data_get_openssl_ctx(ad));

    if (ptr != NULL)
        CRYPTO_set_ex_data(ad, index, ptr);
}
static void openssl_ctx_generic_free(void *parent_ign, void *ptr,
                                     CRYPTO_EX_DATA *ad, int index,
                                     long argl_ign, void *argp)
{
    const OPENSSL_CTX_METHOD *meth = argp;

    meth->free_func(ptr);
}

/* Non-static so we can use it in context_internal_test */
static int openssl_ctx_init_index(OPENSSL_CTX *ctx, int static_index,
                                  const OPENSSL_CTX_METHOD *meth)
{
    int idx;

#ifndef FIPS_MODE
    if (ctx == NULL) {
        if (!RUN_ONCE(&default_context_init, do_default_context_init))
            return 0;
        ctx = default_context;
    }
#endif
    if (ctx == NULL)
        return 0;

    idx = crypto_get_ex_new_index_ex(ctx, CRYPTO_EX_INDEX_OPENSSL_CTX, 0,
                                     (void *)meth,
                                     openssl_ctx_generic_new,
                                     NULL, openssl_ctx_generic_free);
    if (idx < 0)
        return 0;

    ctx->dyn_indexes[static_index] = idx;
    return 1;
}

void *openssl_ctx_get_data(OPENSSL_CTX *ctx, int index,
                           const OPENSSL_CTX_METHOD *meth)
{
    void *data = NULL;

#ifndef FIPS_MODE
    if (ctx == NULL) {
        if (!RUN_ONCE(&default_context_init, do_default_context_init))
            return NULL;
        ctx = default_context;
    }
#endif
    if (ctx == NULL)
        return NULL;

    CRYPTO_THREAD_read_lock(ctx->lock);

    if (ctx->dyn_indexes[index] == -1
            && !openssl_ctx_init_index(ctx, index, meth)) {
        CRYPTO_THREAD_unlock(ctx->lock);
        return NULL;
    }

    /* The alloc call ensures there's a value there */
    if (CRYPTO_alloc_ex_data(CRYPTO_EX_INDEX_OPENSSL_CTX, NULL,
                             &ctx->data, ctx->dyn_indexes[index]))
        data = CRYPTO_get_ex_data(&ctx->data, ctx->dyn_indexes[index]);

    CRYPTO_THREAD_unlock(ctx->lock);

    return data;
}

OSSL_EX_DATA_GLOBAL *openssl_ctx_get_ex_data_global(OPENSSL_CTX *ctx)
{
    /*
     * The default context code is not needed in FIPS_MODE and ctx should never
     * be NULL in the FIPS provider. However we compile this code out to ensure
     * we fail immediately if ctx == NULL in FIPS_MODE
     */
#ifndef FIPS_MODE
    if (ctx == NULL) {
        if (!RUN_ONCE(&default_context_init, do_default_context_init))
            return NULL;
        ctx = default_context;
    }
#endif
    if (ctx == NULL)
        return NULL;
    return &ctx->global;
}

int openssl_ctx_run_once(OPENSSL_CTX *ctx, unsigned int idx,
                         openssl_ctx_run_once_fn run_once_fn)
{
    int done = 0, ret = 0;

#ifndef FIPS_MODE
    if (ctx == NULL) {
        if (!RUN_ONCE(&default_context_init, do_default_context_init))
            return 0;
        ctx = default_context;
    }
#endif
    if (ctx == NULL)
        return 0;

    CRYPTO_THREAD_read_lock(ctx->oncelock);
    done = ctx->run_once_done[idx];
    if (done)
        ret = ctx->run_once_ret[idx];
    CRYPTO_THREAD_unlock(ctx->oncelock);

    if (done)
        return ret;

    CRYPTO_THREAD_write_lock(ctx->oncelock);
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

int openssl_ctx_onfree(OPENSSL_CTX *ctx, openssl_ctx_onfree_fn onfreefn)
{
    struct openssl_ctx_onfree_list_st *newonfree
        = OPENSSL_malloc(sizeof(*newonfree));

    if (newonfree == NULL)
        return 0;

    newonfree->fn = onfreefn;
    newonfree->next = ctx->onfreelist;
    ctx->onfreelist = newonfree;

    return 1;
}
