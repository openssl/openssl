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

# include "openssl_threads.h"
# include "task.h"
# include "worker.h"

static CRYPTO_TASK * worker_pick_task(OPENSSL_CTX_THREADS*, CRYPTO_WORKER*);
static void worker_initialize(OPENSSL_CTX_THREADS*, CRYPTO_WORKER*);
static CRYPTO_TASK * worker_extract_task(OPENSSL_CTX_THREADS*, CRYPTO_WORKER*);
static CRYPTO_TASK * worker_poll_task(OPENSSL_CTX_THREADS*, CRYPTO_WORKER*);
static int worker_keep_alive(OPENSSL_CTX_THREADS*, CRYPTO_WORKER *,
                             CRYPTO_TASK*);
static void signal_task(OPENSSL_CTX_THREADS*, CRYPTO_WORKER*, CRYPTO_TASK*,
                        enum crypto_task_state state);

CRYPTO_WORKER * CRYPTO_WORKER_new(OPENSSL_CTX *ctx, CRYPTO_WORKER_CALLBACK cb,
                                void *vtask)
{
    struct crypto_worker_st *worker;

    worker = OPENSSL_zalloc(sizeof(*worker));
    if (worker == NULL)
        return NULL;

    worker->cb = cb;
    worker->ctx = ctx;
    worker->initialized = 0;

    if (vtask != NULL) {
        worker->task = (CRYPTO_TASK*) vtask;
        worker->type = CRYPTO_WORKER_INTERNAL;
    } else {
        worker->type = CRYPTO_WORKER_EXTERNAL;
    }

    worker->lock = CRYPTO_MUTEX_create();
    worker->cond = CRYPTO_CONDVAR_create();

    if (worker->lock == NULL || worker->cond == NULL)
        goto fail;

    if (CRYPTO_MUTEX_init(worker->lock) == 0)
        goto fail;

    if (CRYPTO_CONDVAR_init(worker->cond) == 0)
        goto fail;

    return worker;

fail:
    CRYPTO_WORKER_free(worker);
    return NULL;
}

void CRYPTO_WORKER_free(CRYPTO_WORKER *worker)
{
    CRYPTO_MUTEX_destroy(&worker->lock);
    CRYPTO_CONDVAR_destroy(&worker->cond);
    OPENSSL_free(worker);
}

static CRYPTO_TASK * worker_pick_task(OPENSSL_CTX_THREADS *tdata,
                                    CRYPTO_WORKER *worker)
{
    struct list *task_list;
    CRYPTO_TASK *task;

    if (list_empty(&tdata->tasks.queue) == 1) {
        task = NULL;
        goto end;
    }

    list_del(&worker->list);
    if (worker->type == CRYPTO_WORKER_INTERNAL) {
        list_add_tail(&worker->list, &tdata->threads.active);
    }
    else {
        list_add_tail(&worker->list, &tdata->workers.busy);
    }

    task_list = tdata->tasks.queue.next;
    task = container_of(task_list, struct crypto_task_st, list);

    list_del(&task->list);
    list_add_tail(&task->list, &tdata->tasks.active);

end:
    return task;
}

static void worker_initialize(OPENSSL_CTX_THREADS *tdata,
                              CRYPTO_WORKER *worker)
{
    CRYPTO_MUTEX_lock(worker->lock);
    worker->initialized = 1;

    CRYPTO_CONDVAR_broadcast(worker->cond);

    CRYPTO_MUTEX_unlock(worker->lock);
}

static CRYPTO_TASK * worker_extract_task(OPENSSL_CTX_THREADS *tdata,
                                         CRYPTO_WORKER *worker)
{
    CRYPTO_TASK *task;

    task = NULL;
    CRYPTO_MUTEX_lock(tdata->lock);
        CRYPTO_MUTEX_lock(worker->lock);

    if (worker->task == NULL)
        goto end;

    task = worker->task;
    worker->task = NULL;

    list_del(&worker->list);
    if (worker->type == CRYPTO_WORKER_INTERNAL)
        list_add_tail(&worker->list, &tdata->threads.active);
    else
        list_add_tail(&worker->list, &tdata->workers.busy);

end:
    CRYPTO_MUTEX_unlock(worker->lock);
    CRYPTO_MUTEX_unlock(tdata->lock);

    return task;
}

static CRYPTO_TASK * worker_poll_task(OPENSSL_CTX_THREADS *tdata,
                                      CRYPTO_WORKER *worker)
{
    CRYPTO_TASK *task;

    CRYPTO_MUTEX_lock(tdata->lock);

    CRYPTO_MUTEX_lock(worker->lock);
    list_del(&worker->list);
    list_add_tail(&worker->list, &tdata->workers.available);
    CRYPTO_MUTEX_unlock(worker->lock);

    while (list_empty(&tdata->tasks.queue) == 1)
        CRYPTO_CONDVAR_wait(tdata->tasks.cond_create, tdata->lock);

    task = worker_pick_task(tdata, worker);
    CRYPTO_CONDVAR_broadcast(task->cond);

    CRYPTO_MUTEX_unlock(tdata->lock);

    return task;
}

static int worker_keep_alive(OPENSSL_CTX_THREADS *tdata,
                             CRYPTO_WORKER *worker, CRYPTO_TASK *task)
{
    size_t task_cnt;
    CRYPTO_WORKER_CMD cmd;

    cmd = CRYPTO_WORKER_TERMINATE;

    CRYPTO_MUTEX_lock(tdata->lock);
    CRYPTO_MUTEX_lock(task->lock);

    if (task->list.prev != NULL && task->list.next != NULL)
    {
        list_del(&task->list);
        list_add_tail(&task->list, &tdata->tasks.done);
    }

    if (worker->cb != NULL) {
        task_cnt = list_size(&tdata->tasks.queue);
        cmd = worker->cb(worker->ctx, task_cnt);
    }

    CRYPTO_MUTEX_unlock(task->lock);
    CRYPTO_MUTEX_lock(worker->lock);

    list_del(&worker->list);

    if (cmd == CRYPTO_WORKER_POLL)
        worker->task = worker_pick_task(tdata, worker);

    CRYPTO_MUTEX_unlock(worker->lock);
    CRYPTO_MUTEX_unlock(tdata->lock);

    return (cmd == CRYPTO_WORKER_POLL);
}

CRYPTO_WORKER_CMD worker_internal_cb(OPENSSL_CTX *ctx, size_t queued_tasks)
{
    OPENSSL_CTX_THREADS *tdata;

    tdata = OPENSSL_CTX_GET_THREADS(ctx);
    if (tdata == NULL)
        return CRYPTO_WORKER_TERMINATE;

    if (openssl_ctx_threads_all_busy(tdata))
        if (list_size(&tdata->tasks.queue) > 0)
            return CRYPTO_WORKER_POLL;

    return CRYPTO_WORKER_TERMINATE;
}

static void signal_task(OPENSSL_CTX_THREADS *tdata, CRYPTO_WORKER *worker,
                        CRYPTO_TASK *task, enum crypto_task_state state)
{
    CRYPTO_MUTEX_lock(task->lock);
    task->state = state;
    CRYPTO_CONDVAR_broadcast(task->cond);
    CRYPTO_MUTEX_unlock(task->lock);
}

CRYPTO_THREAD_RETVAL worker_main(void *data)
{
    int keep_alive;
    CRYPTO_TASK *task;
    CRYPTO_WORKER *worker;
    OPENSSL_CTX_THREADS *tdata;

    if (data == NULL)
        return 0UL;

    worker = (CRYPTO_WORKER*) data;
    tdata = OPENSSL_CTX_GET_THREADS(worker->ctx);

    if (tdata == NULL)
        return 0UL;

    CRYPTO_MUTEX_lock(tdata->lock);
    CRYPTO_MUTEX_lock(worker->lock);
    if (worker->type == CRYPTO_WORKER_INTERNAL)
        list_add_tail(&worker->list, &tdata->threads.started);
    else
        list_add_tail(&worker->list, &tdata->workers.available);
    CRYPTO_MUTEX_unlock(worker->lock);
    CRYPTO_MUTEX_unlock(tdata->lock);

    do {
        task = worker_extract_task(tdata, worker);

        if (worker->initialized == 0)
            worker_initialize(tdata, worker);

        if (task == NULL)
            task = worker_poll_task(tdata, worker);

        signal_task(tdata, worker, task, CRYPTO_TASK_STARTED);
        task->retval = task->routine(task->data);
        keep_alive = worker_keep_alive(tdata, worker, task);
        signal_task(tdata, worker, task, CRYPTO_TASK_FINISHED);
    } while(keep_alive);

    CRYPTO_MUTEX_lock(tdata->lock);
    CRYPTO_MUTEX_lock(worker->lock);
    list_add_tail(&worker->list, &tdata->workers.terminated);
    CRYPTO_MUTEX_unlock(worker->lock);
    CRYPTO_MUTEX_unlock(tdata->lock);

    return 0UL;
}

#endif /* defined(OPENSSL_THREADS) */
