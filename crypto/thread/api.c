/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/configuration.h>
#if defined(OPENSSL_THREADS)
# include <openssl/e_os2.h>
# include <openssl/crypto.h>
# include <internal/worker.h>
# include <internal/thread.h>
# include "openssl_threads.h"
# include "worker.h"

static int crypto_thread_spawn_worker_task(OPENSSL_CTX*,
                                           CRYPTO_WORKER_CALLBACK, void*);
static ossl_inline void crypto_thread_schedule(OPENSSL_CTX_THREADS*,
                                               struct crypto_task_st*);
static int crypto_thread_start_now(OPENSSL_CTX*, struct crypto_task_st *);

int CRYPTO_THREAD_enabled(OPENSSL_CTX *ctx)
{
    int enabled;
    OPENSSL_CTX_THREADS *tdata;

    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    CRYPTO_MUTEX_lock(tdata->lock);
    enabled = tdata->enabled;
    CRYPTO_MUTEX_unlock(tdata->lock);

    return enabled;
}

int CRYPTO_THREAD_enable(OPENSSL_CTX *ctx, int max_threads)
{
    OPENSSL_CTX_THREADS *tdata;

    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    CRYPTO_MUTEX_lock(tdata->lock);
    tdata->threads.cap = max_threads;
    tdata->enabled = 1;
    CRYPTO_MUTEX_unlock(tdata->lock);

    return 1;
}

int CRYPTO_THREAD_disable(OPENSSL_CTX *ctx)
{
    OPENSSL_CTX_THREADS *tdata;
    struct list *iter, *tmp;
    void *task;
    CRYPTO_WORKER *worker;

    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    CRYPTO_MUTEX_lock(tdata->lock);

    if (list_size(&tdata->workers.busy) > 0) {
        CRYPTO_MUTEX_unlock(tdata->lock);
        return 0;
    }

    if (list_size(&tdata->threads.active) > 0) {
        CRYPTO_MUTEX_unlock(tdata->lock);
        return 0;
    }

    tdata->threads.cap = 0;
    tdata->enabled = 0;

    list_for_each_safe(iter, tmp, &tdata->workers.available) {
        worker = container_of(iter, struct crypto_worker_st, list);
        worker->cb = worker_internal_cb;
    }

    while (list_size(&tdata->workers.available) > 0) {
        task = crypto_thread_start(ctx, NULL, NULL, CRYPTO_THREAD_START_AWAIT);
        crypto_thread_join(ctx, task, NULL);
    }

    CRYPTO_MUTEX_unlock(tdata->lock);
    crypto_thread_clean(ctx, NULL);
    return 1;
}

int CRYPTO_THREAD_cap(OPENSSL_CTX *ctx, int max_threads)
{
    OPENSSL_CTX_THREADS *tdata;

    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    if (tdata->enabled == 0)
        return 0;

    CRYPTO_MUTEX_lock(tdata->lock);
    tdata->threads.cap = max_threads;
    CRYPTO_MUTEX_unlock(tdata->lock);
    return 1;
}

size_t crypto_thread_get_available_threads(OPENSSL_CTX *ctx)
{
    size_t retval;
    OPENSSL_CTX_THREADS *t;

    t = OPENSSL_CTX_GET_THREADS(ctx);
    if (t == NULL)
        return 0;

    if (t->enabled == 0)
        return 0;

    if (t->threads.cap < 0)
        return -1;

    CRYPTO_MUTEX_lock(t->lock);
    retval = t->threads.cap - list_size(&t->threads.active) +
        list_size(&t->workers.available);
    CRYPTO_MUTEX_unlock(t->lock);
    return retval;
}

static int crypto_thread_spawn_worker_task(OPENSSL_CTX *ctx,
                                           CRYPTO_WORKER_CALLBACK cb,
                                           void *vtask)
{
    CRYPTO_WORKER *worker;
    OPENSSL_CTX_THREADS *tdata;

    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (tdata == NULL || tdata->enabled == 0)
        return 0;

    worker = CRYPTO_WORKER_new(ctx, cb, vtask);
    if (worker == NULL)
        return 0;

    CRYPTO_MUTEX_lock(worker->lock);
    worker->handle = crypto_thread_native_start(worker_main, (void*)worker, 0);
    if (worker->handle == NULL)
        goto fail;

    while (worker->initialized == 0) {
        CRYPTO_CONDVAR_wait(worker->cond, worker->lock);
    }

    CRYPTO_MUTEX_unlock(worker->lock);

    return 1;

fail:
    CRYPTO_WORKER_free(worker);
    return 0;
}

int CRYPTO_THREAD_spawn_worker(OPENSSL_CTX *ctx, CRYPTO_WORKER_CALLBACK cb)
{
    return crypto_thread_spawn_worker_task(ctx, cb, NULL);
}

static ossl_inline void crypto_thread_schedule(OPENSSL_CTX_THREADS *tdata,
                                               struct crypto_task_st *t)
{
    CRYPTO_MUTEX_lock(tdata->lock);
    list_add_tail(&t->list, &tdata->tasks.queue);
    CRYPTO_CONDVAR_broadcast(tdata->tasks.cond_create);
    CRYPTO_MUTEX_unlock(tdata->lock);
}

static int crypto_thread_start_now(OPENSSL_CTX *ctx, struct crypto_task_st *t)
{
    OPENSSL_CTX_THREADS *tdata;

    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (tdata == NULL || tdata->enabled == 0)
        return 0;

    if (crypto_thread_spawn_worker_task(ctx, worker_internal_cb, t) == 0)
        return 0;

    CRYPTO_MUTEX_lock(tdata->lock);
    list_add_tail(&t->list, &tdata->tasks.active);
    CRYPTO_MUTEX_unlock(tdata->lock);

    return 1;
}

void *crypto_thread_start(OPENSSL_CTX *ctx,  CRYPTO_THREAD_ROUTINE start,
                          void *data, int options)
{
    struct crypto_task_st *t;
    OPENSSL_CTX_THREADS *tdata;

    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (tdata == NULL || tdata->enabled == 0)
        return NULL;

    t = crypto_task_new(start, data);
    if (t == NULL)
        return NULL;

    CRYPTO_MUTEX_lock(tdata->lock);
    t->id = tdata->tasks.created_tasks++;
    CRYPTO_MUTEX_unlock(tdata->lock);

    CRYPTO_MUTEX_lock(t->lock);

    if (openssl_ctx_threads_can_spawn_thread(tdata, 0) == 0)
        crypto_thread_schedule(tdata, t);
    else if (crypto_thread_start_now(ctx, t) == 0)
        crypto_thread_schedule(tdata, t);

    while ((options & CRYPTO_THREAD_START_AWAIT) != 0) {
        CRYPTO_mem_barrier();
        if (t->state >= CRYPTO_TASK_STARTED)
            break;
        CRYPTO_CONDVAR_wait(t->cond, t->lock);
    }
    CRYPTO_MUTEX_unlock(t->lock);

    return (void*) t;
}

int crypto_thread_join(OPENSSL_CTX *ctx, void *vtask,
                       CRYPTO_THREAD_RETVAL *retval)
{
    CRYPTO_TASK *task;
    OPENSSL_CTX_THREADS *tdata;

    task = (CRYPTO_TASK*) vtask;
    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (task == NULL || tdata == NULL)
        return 0;

    CRYPTO_MUTEX_lock(task->lock);
    while (1) {
        CRYPTO_mem_barrier();
        if (task->state == CRYPTO_TASK_FINISHED)
            break;
        CRYPTO_CONDVAR_wait(task->cond, task->lock);
    }

    if (retval != NULL) {
        *retval = task->retval;
    }
    CRYPTO_MUTEX_unlock(task->lock);

    return 1;
}

int crypto_thread_clean(OPENSSL_CTX *ctx, void *vtask)
{
    CRYPTO_TASK *task;
    OPENSSL_CTX_THREADS *tdata;
    CRYPTO_WORKER *worker;
    struct list *iter, *tmp;

    task = (CRYPTO_TASK*) vtask;
    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    CRYPTO_MUTEX_lock(tdata->lock);

    list_for_each_safe(iter, tmp, &tdata->workers.terminated) {
        worker = container_of(iter, struct crypto_worker_st, list);
        if (crypto_thread_native_clean(worker->handle) == 0)
            continue;
        list_del(iter);
        CRYPTO_WORKER_free(worker);
    }

    if (task == NULL) {
        list_for_each_safe(iter, tmp, &tdata->tasks.done) {
            task = container_of(iter, struct crypto_task_st, list);
            list_del(iter);
            crypto_task_free(task);
        }
    } else {
        list_del(&task->list);
        crypto_task_free(task);
    }

    CRYPTO_MUTEX_unlock(tdata->lock);

    return 1;
}

#endif /* defined(OPENSSL_THREADS) */
