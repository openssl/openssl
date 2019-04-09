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

struct openssl_ctx_st {
    CRYPTO_RWLOCK *lock;
    CRYPTO_EX_DATA data;
};

static OPENSSL_CTX default_context;

static int context_init(OPENSSL_CTX *ctx)
{
    return (ctx->lock = CRYPTO_THREAD_lock_new()) != NULL
        && CRYPTO_new_ex_data(CRYPTO_EX_INDEX_OPENSSL_CTX, NULL,
                              &ctx->data);
}

static int context_deinit(OPENSSL_CTX *ctx)
{
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_OPENSSL_CTX, NULL, &ctx->data);
    CRYPTO_THREAD_lock_free(ctx->lock);
    return 1;
}

static CRYPTO_ONCE default_context_init = CRYPTO_ONCE_STATIC_INIT;
static void do_default_context_deinit(void)
{
    context_deinit(&default_context);
}
DEFINE_RUN_ONCE_STATIC(do_default_context_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && context_init(&default_context)
        && OPENSSL_atexit(do_default_context_deinit);
}

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
    void *ptr = meth->new_func();

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
int openssl_ctx_new_index(const OPENSSL_CTX_METHOD *meth)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_OPENSSL_CTX, 0, (void *)meth,
                                   openssl_ctx_generic_new, NULL,
                                   openssl_ctx_generic_free);
}

void *openssl_ctx_get_data(OPENSSL_CTX *ctx, int index)
{
    void *data = NULL;

    if (ctx == NULL) {
        if (!RUN_ONCE(&default_context_init, do_default_context_init))
            return 0;
        ctx = &default_context;
    }

    CRYPTO_THREAD_read_lock(ctx->lock);

    /* The alloc call ensures there's a value there */
    if (CRYPTO_alloc_ex_data(CRYPTO_EX_INDEX_OPENSSL_CTX, NULL,
                             &ctx->data, index))
        data = CRYPTO_get_ex_data(&ctx->data, index);

    CRYPTO_THREAD_unlock(ctx->lock);

    return data;
}

