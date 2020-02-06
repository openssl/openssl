/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>

#if defined(OPENSSL_THREADS)
# include <openssl/crypto.h>

# include "e_os.h"

#  if defined(_WIN32)
#   include <windows.h>
#  endif

# include <openssl/async.h>

# include "thread.h"
# include "thread_external.h"
# include "internal/list.h"

/* The following is required to keep ABI compat with CRYPTO_THREAD_ROUTINE
 * as defined in openssl/crypto.h */
# if !defined(CALLBACK)
#  if defined(_WIN32) || defined(_STDCALL_SUPPORTED)
#   define CALLBACK __stdcall
#  else
#   define CALLBACK
#  endif
# elif !defined(_WIN32) && !defined(_STDCALL_SUPPORTED)
#  undef CALLBACK
# endif

volatile int CRYPTO_THREAD_EXTERN_enabled = 0;

# ifdef OPENSSL_NO_EXTERN_THREAD

int CRYPTO_THREAD_EXTERN_enable(CRYPTO_SIGNAL** props)
{
    return 0;
}

int CRYPTO_THREAD_EXTERN_disable()
{
    return 1;
}

# else /* ! OPENSSL_NO_EXTERN_THREAD */

static struct list    CRYPTO_THREAD_EXTERN_task_queue;
static struct list    CRYPTO_THREAD_EXTERN_task_done;
static CRYPTO_MUTEX   CRYPTO_THREAD_EXTERN_task_lock;
static CRYPTO_CONDVAR CRYPTO_THREAD_EXTERN_task_cond_create;
static CRYPTO_CONDVAR CRYPTO_THREAD_EXTERN_task_cond_finish;

int CRYPTO_THREAD_EXTERN_enable(CRYPTO_SIGNAL** props)
{
    if (CRYPTO_THREAD_EXTERN_enabled == 1)
        return 1;

    if (props != NULL && CRYPTO_SIGNAL_block_set(props) != 1)
        goto fail;

    list_init(&CRYPTO_THREAD_EXTERN_task_queue);
    list_init(&CRYPTO_THREAD_EXTERN_task_done);

    CRYPTO_THREAD_EXTERN_task_lock = CRYPTO_MUTEX_create();
    CRYPTO_THREAD_EXTERN_task_cond_create = CRYPTO_CONDVAR_create();
    CRYPTO_THREAD_EXTERN_task_cond_finish = CRYPTO_CONDVAR_create();

    if (CRYPTO_MUTEX_init(CRYPTO_THREAD_EXTERN_task_lock) == 0)
        goto fail;

    if (CRYPTO_CONDVAR_init(CRYPTO_THREAD_EXTERN_task_cond_create) == 0)
        goto fail;

    if (CRYPTO_CONDVAR_init(CRYPTO_THREAD_EXTERN_task_cond_finish) == 0)
        goto fail;

    CRYPTO_mem_barrier();

    CRYPTO_THREAD_EXTERN_enabled = 1;
    return 1;

fail:
    OPENSSL_free(CRYPTO_THREAD_EXTERN_task_lock);
    OPENSSL_free(CRYPTO_THREAD_EXTERN_task_cond_create);
    OPENSSL_free(CRYPTO_THREAD_EXTERN_task_cond_finish);

    CRYPTO_THREAD_EXTERN_disable();
    return 0;
}

int CRYPTO_THREAD_EXTERN_disable(void)
{
    if (CRYPTO_THREAD_EXTERN_enabled) {
        CRYPTO_MUTEX_destroy(&CRYPTO_THREAD_EXTERN_task_lock);
        CRYPTO_CONDVAR_destroy(&CRYPTO_THREAD_EXTERN_task_cond_create);
        CRYPTO_CONDVAR_destroy(&CRYPTO_THREAD_EXTERN_task_cond_finish);
    }

    CRYPTO_THREAD_EXTERN_enabled = 0;
    return 1;
}

# endif

static int CRYPTO_THREAD_EXTERN_job(void* arg)
{
    ASYNC_JOB * currjob;
    CRYPTO_THREAD_TASK* task;

    if (arg == NULL)
        return 0;

    task = (CRYPTO_THREAD_TASK*)arg;

    if ((currjob = ASYNC_get_current_job()) == NULL)
        return 0;

    ASYNC_block_pause();
    task->retval = task->task(task->data);
    ASYNC_unblock_pause();

    return 1;
}

static void CRYPTO_THREAD_EXTERN_worker_async(CRYPTO_THREAD_TASK* task,
                                              char* async_state)
{
    int r1, r2 = 1;
    ASYNC_JOB* async_job;
    ASYNC_WAIT_CTX* async_ctx;

    if ((async_ctx = ASYNC_WAIT_CTX_new()) == NULL) {
        *async_state |= (char)THREAD_ASYNC_ERR;
        return;
    }

    r1 = ASYNC_start_job(&async_job, async_ctx, &r2, CRYPTO_THREAD_EXTERN_job,
                         task, sizeof(task));

    /* Async job creation either failed, or no jobs were detected, or an error
     * occured in job initialization. Use sync approach instead. */
    if (r1 == ASYNC_ERR || r1 == ASYNC_NO_JOBS || r2 == 0)
        *async_state |= (char)THREAD_ASYNC_ERR;

    ASYNC_WAIT_CTX_free(async_ctx);

    /**
     * If a job didn't gracefully finish (i.e., had the chance to cleanup all
     * private data; e.g., when CRYPTO_THREAD_exit is called from an arbitrary
     * location), we forcefully destroy all data associated with the job.
     */
    if (r1 == ASYNC_PAUSE) {
        ASYNC_cleanup_thread();
        *async_state &= (char)~THREAD_ASYNC_RDY;
    }
}

static CRYPTO_THREAD_RETVAL CALLBACK CRYPTO_THREAD_EXTERN_worker(CRYPTO_THREAD_DATA data)
{
    size_t task_cnt;
    char async_state;

    CRYPTO_THREAD_TASK* task;
    CRYPTO_THREAD_CALLBACK worker_exit_cb;

    worker_exit_cb = ((struct crypto_thread_extern_cb*)data)->cb;
    async_state = THREAD_ASYNC_CAPABLE * (ASYNC_is_capable() == 0);

    OPENSSL_free(data);

    while (1) {
        struct list* job_l;

        if (async_state == THREAD_ASYNC_CAPABLE)
            async_state |= (ASYNC_init_thread(1, 1) > 0)* THREAD_ASYNC_RDY;

        CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);

        /* Avoid spurious wakeups and allow immediate job processing: */
        while (list_empty(&CRYPTO_THREAD_EXTERN_task_queue) == 1)
            CRYPTO_CONDVAR_wait(CRYPTO_THREAD_EXTERN_task_cond_create,
                                CRYPTO_THREAD_EXTERN_task_lock);

        job_l = CRYPTO_THREAD_EXTERN_task_queue.next;
        task = container_of(job_l, CRYPTO_THREAD_TASK, list);
        list_del(job_l);
        CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

        task->state = CRYPTO_THREAD_RUNNING;

        if (async_state & THREAD_ASYNC_RDY)
            CRYPTO_THREAD_EXTERN_worker_async(task, &async_state);

        if (async_state != (THREAD_ASYNC_RDY | THREAD_ASYNC_CAPABLE))
            task->retval = task->task(task->data);

        task->state = CRYPTO_THREAD_STOPPED;

        CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
        list_add_tail(&task->list, &CRYPTO_THREAD_EXTERN_task_done);
        CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

        if (worker_exit_cb != NULL) {
            CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
            task_cnt = list_size(&CRYPTO_THREAD_EXTERN_task_queue);
            CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

            if (worker_exit_cb(task_cnt) == 0)
                break;
        }
    }

    if (async_state & THREAD_ASYNC_RDY)
        ASYNC_cleanup_thread();

    return 0UL;
}

CRYPTO_THREAD CRYPTO_THREAD_EXTERN_provide(CRYPTO_THREAD_CALLBACK cb)
{
    CRYPTO_THREAD ret;
    struct crypto_thread_extern_cb *cb_wrap;

    cb_wrap = OPENSSL_zalloc(sizeof(*cb_wrap));
    if (cb_wrap == NULL)
        return NULL;
    cb_wrap->cb = cb;

    ret = CRYPTO_THREAD_arch_create(CRYPTO_THREAD_EXTERN_worker,
                                    (CRYPTO_THREAD_DATA) cb_wrap);

    if (ret == NULL)
        OPENSSL_free(cb_wrap);

    return ret;
}

CRYPTO_THREAD CRYPTO_THREAD_EXTERN_add_job(CRYPTO_THREAD_ROUTINE task, void* data)
{
    CRYPTO_THREAD_TASK* t;

    t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL)
        return NULL;

    t->task = task;
    t->data = data;
    t->state = CRYPTO_THREAD_AWAITING;

    /* Never write .handle here! */

    CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
    list_add_tail(&t->list, &CRYPTO_THREAD_EXTERN_task_queue);
    CRYPTO_CONDVAR_broadcast(CRYPTO_THREAD_EXTERN_task_cond_create);
    CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

    return (CRYPTO_THREAD) t;
}

int CRYPTO_THREAD_EXTERN_join(CRYPTO_THREAD task_id,
                              CRYPTO_THREAD_RETVAL* retval)
{
    struct list* i;
    CRYPTO_THREAD_TASK* task = NULL;

loop:
    CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
    list_for_each(i, &CRYPTO_THREAD_EXTERN_task_done) {
        task = container_of(i, CRYPTO_THREAD_TASK, list);
        if (task == (CRYPTO_THREAD_TASK*) task_id)
            break;
    }
    CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

    if (task != (CRYPTO_THREAD_TASK*) task_id) {
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
        goto loop;
    }

    if (retval != NULL)
        *retval = task->retval;

    return 1;
}

void CRYPTO_THREAD_EXTERN_exit(CRYPTO_THREAD_RETVAL retval)
{
    (void)retval;
    if (ASYNC_is_capable()) {
        ASYNC_unblock_pause();
        ASYNC_pause_job();
    }
}

int CRYPTO_THREAD_EXTERN_clean(CRYPTO_THREAD* thread)
{
    CRYPTO_THREAD_TASK* task = (CRYPTO_THREAD_TASK*) *thread;

    switch(CRYPTO_THREAD_state(*thread)) {
    case CRYPTO_THREAD_STOPPED:
    case CRYPTO_THREAD_FAILED:
    case CRYPTO_THREAD_AWAITING:
        CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
        list_del(&task->list);
        CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);
        break;
    default:
        return 0;
    }

    *thread = NULL;
    CRYPTO_mem_barrier();
    OPENSSL_free(task);
    return 1;
}

#endif
