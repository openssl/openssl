/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CRYPTO_OPENSSL_CTX_THREADS_H
# define OPENSSL_CRYPTO_OPENSSL_CTX_THREADS_H
# include <openssl/configuration.h>
# if defined(OPENSSL_THREADS)
#  include <openssl/e_os2.h>
#  include <openssl/crypto.h>
#  include <openssl/types.h>
#  include <internal/list.h>
#  include <internal/cryptlib.h>
#  include "task.h"

typedef struct openssl_threads_st {
    int enabled;
    CRYPTO_MUTEX lock;
    struct {
        int cap;
        struct list started;
        struct list active;
    } threads;
    struct {
        struct list available;
        struct list busy;
        struct list terminated;
    } workers;
    struct {
        uint32_t created_tasks;
        struct list queue;
        struct list active;
        struct list done;
        CRYPTO_CONDVAR cond_create;
        CRYPTO_CONDVAR cond_assigned;
    } tasks;
} OPENSSL_CTX_THREADS;

# define OPENSSL_CTX_GET_THREADS(CTX)                                       \
    openssl_ctx_get_data(CTX, OPENSSL_CTX_THREAD_INDEX,                     \
                         &openssl_threads_method);

static ossl_inline int openssl_ctx_threads_all_busy(OPENSSL_CTX_THREADS*);
static ossl_inline
int openssl_ctx_threads_can_spawn_thread(OPENSSL_CTX_THREADS*, int);
static void *openssl_threads_new(OPENSSL_CTX*);
static void openssl_threads_free(void*);

static ossl_inline int openssl_ctx_threads_all_busy(OPENSSL_CTX_THREADS *t)
{
    if (list_size(&t->workers.available) != 0)
        return 0;
    if (t->threads.cap >= 0)
        return t->threads.cap-list_size(&t->threads.active) == 0;
    return 0;
}

static ossl_inline
int openssl_ctx_threads_can_spawn_thread(OPENSSL_CTX_THREADS *t, int lock)
{
    int retval;

    retval = 1;
    if (lock)
        CRYPTO_MUTEX_lock(t->lock);

    if (list_size(&t->workers.available) > 0)
    {
        retval = 0;
        goto end;
    }

    if (t->threads.cap >= 0)
    {
        retval = t->threads.cap-list_size(&t->threads.active) > 0;
        goto end;
    }

    retval = 1;

end:

    if (lock)
        CRYPTO_MUTEX_unlock(t->lock);

    return retval;
}

static const OPENSSL_CTX_METHOD openssl_threads_method = {
    openssl_threads_new,
    openssl_threads_free
};

static void openssl_threads_free(void *vdata)
{
    OPENSSL_CTX_THREADS *t;

    t = vdata;
    if (t == NULL)
        return;

    CRYPTO_MUTEX_destroy(&t->lock);
    CRYPTO_CONDVAR_destroy(&t->tasks.cond_create);
    CRYPTO_CONDVAR_destroy(&t->tasks.cond_assigned);
    OPENSSL_free(t);
}

static void *openssl_threads_new(OPENSSL_CTX *ctx)
{
    struct openssl_threads_st *t;

    t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL)
        return NULL;

    t->tasks.created_tasks = 0;

    list_init(&t->tasks.queue);
    list_init(&t->tasks.active);
    list_init(&t->tasks.done);

    list_init(&t->threads.started);
    list_init(&t->threads.active);
    list_init(&t->workers.available);
    list_init(&t->workers.terminated);
    list_init(&t->workers.busy);

    t->lock = CRYPTO_MUTEX_create();
    t->tasks.cond_create = CRYPTO_CONDVAR_create();
    t->tasks.cond_assigned = CRYPTO_CONDVAR_create();

    if (t->lock == NULL)
        goto fail;

    if (t->tasks.cond_create == NULL || t->tasks.cond_assigned == NULL)
        goto fail;

    if (CRYPTO_MUTEX_init(t->lock) == 0)
        goto fail;

    if (CRYPTO_CONDVAR_init(t->tasks.cond_create) == 0)
        goto fail;

    if (CRYPTO_CONDVAR_init(t->tasks.cond_assigned) == 0)
        goto fail;

    return t;

fail:
    CRYPTO_MUTEX_destroy(&t->lock);
    CRYPTO_CONDVAR_destroy(&t->tasks.cond_create);
    CRYPTO_CONDVAR_destroy(&t->tasks.cond_assigned);
    OPENSSL_free(t);
    return NULL;
}

# endif /* defined(OPENSSL_THREADS) */
#endif /* OPENSSL_CRYPTO_OPENSSL_CTX_THREADS_H */
