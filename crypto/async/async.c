/* crypto/async/async.c */
/*
 * Written by Matt Caswell (matt@openssl.org) for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/*
 * Without this we start getting longjmp crashes because it thinks we're jumping
 * up the stack when in fact we are jumping to an entirely different stack. The
 * cost of this is not having certain buffer overrun/underrun checks etc for
 * this source file :-(
 */
#undef _FORTIFY_SOURCE

#include <openssl/err.h>
#include <openssl/async.h>
#include <string.h>
#include "async_locl.h"

#define ASYNC_JOB_RUNNING   0
#define ASYNC_JOB_PAUSING   1
#define ASYNC_JOB_PAUSED    2
#define ASYNC_JOB_STOPPING  3

static async_ctx *async_ctx_new(void)
{
    async_ctx *nctx = NULL;

    nctx = OPENSSL_malloc(sizeof (async_ctx));
    if (nctx == NULL) {
        ASYNCerr(ASYNC_F_ASYNC_CTX_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    async_fibre_init_dispatcher(&nctx->dispatcher);
    nctx->currjob = NULL;
    nctx->blocked = 0;
    if (!async_set_ctx(nctx))
        goto err;

    return nctx;
err:
    OPENSSL_free(nctx);

    return NULL;
}

static int async_ctx_free(void)
{
    async_ctx *ctx;

    ctx = async_get_ctx();

    if (!async_set_ctx(NULL))
        return 0;

    OPENSSL_free(ctx);

    return 1;
}

static ASYNC_JOB *async_job_new(void)
{
    ASYNC_JOB *job = NULL;
    OSSL_ASYNC_FD pipefds[2];

    job = OPENSSL_malloc(sizeof (ASYNC_JOB));
    if (job == NULL) {
        ASYNCerr(ASYNC_F_ASYNC_JOB_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!async_pipe(pipefds)) {
        OPENSSL_free(job);
        ASYNCerr(ASYNC_F_ASYNC_JOB_NEW, ASYNC_R_CANNOT_CREATE_WAIT_PIPE);
        return NULL;
    }

    job->wake_set = 0;
    job->wait_fd = pipefds[0];
    job->wake_fd = pipefds[1];

    job->status = ASYNC_JOB_RUNNING;
    job->funcargs = NULL;

    return job;
}

static void async_job_free(ASYNC_JOB *job)
{
    if (job != NULL) {
        OPENSSL_free(job->funcargs);
        async_fibre_free(&job->fibrectx);
        OPENSSL_free(job);
    }
}

static ASYNC_JOB *async_get_pool_job(void) {
    ASYNC_JOB *job;
    STACK_OF(ASYNC_JOB) *pool;

    pool = async_get_pool();
    if (pool == NULL) {
        /*
         * Pool has not been initialised, so init with the defaults, i.e.
         * no max size and no pre-created jobs
         */
        if (ASYNC_init_pool(0, 0) == 0)
            return NULL;
        pool = async_get_pool();
    }

    job = sk_ASYNC_JOB_pop(pool);
    if (job == NULL) {
        /* Pool is empty */
        if (!async_pool_can_grow())
            return NULL;

        job = async_job_new();
        if (job) {
            async_fibre_makecontext(&job->fibrectx);
            async_increment_pool_size();
        }
    }
    return job;
}

static void async_release_job(ASYNC_JOB *job) {
    OPENSSL_free(job->funcargs);
    job->funcargs = NULL;
    /* Ignore error return */
    async_release_job_to_pool(job);
}

void async_start_func(void)
{
    ASYNC_JOB *job;

    while (1) {
        /* Run the job */
        job = async_get_ctx()->currjob;
        job->ret = job->func(job->funcargs);

        /* Stop the job */
        job->status = ASYNC_JOB_STOPPING;
        if (!async_fibre_swapcontext(&job->fibrectx,
                                     &async_get_ctx()->dispatcher, 1)) {
            /*
             * Should not happen. Getting here will close the thread...can't do
             * much about it
             */
            ASYNCerr(ASYNC_F_ASYNC_START_FUNC, ASYNC_R_FAILED_TO_SWAP_CONTEXT);
        }
    }
}

int ASYNC_start_job(ASYNC_JOB **job, int *ret, int (*func)(void *),
                         void *args, size_t size)
{
    if (async_get_ctx() == NULL && async_ctx_new() == NULL) {
        return ASYNC_ERR;
    }

    if (*job) {
        async_get_ctx()->currjob = *job;
    }

    for (;;) {
        if (async_get_ctx()->currjob != NULL) {
            if (async_get_ctx()->currjob->status == ASYNC_JOB_STOPPING) {
                *ret = async_get_ctx()->currjob->ret;
                async_release_job(async_get_ctx()->currjob);
                async_get_ctx()->currjob = NULL;
                *job = NULL;
                return ASYNC_FINISH;
            }

            if (async_get_ctx()->currjob->status == ASYNC_JOB_PAUSING) {
                *job = async_get_ctx()->currjob;
                async_get_ctx()->currjob->status = ASYNC_JOB_PAUSED;
                async_get_ctx()->currjob = NULL;
                return ASYNC_PAUSE;
            }

            if (async_get_ctx()->currjob->status == ASYNC_JOB_PAUSED) {
                async_get_ctx()->currjob = *job;
                /* Resume previous job */
                if (!async_fibre_swapcontext(&async_get_ctx()->dispatcher,
                        &async_get_ctx()->currjob->fibrectx, 1)) {
                    ASYNCerr(ASYNC_F_ASYNC_START_JOB,
                             ASYNC_R_FAILED_TO_SWAP_CONTEXT);
                    goto err;
                }
                continue;
            }

            /* Should not happen */
            ASYNCerr(ASYNC_F_ASYNC_START_JOB, ERR_R_INTERNAL_ERROR);
            async_release_job(async_get_ctx()->currjob);
            async_get_ctx()->currjob = NULL;
            *job = NULL;
            return ASYNC_ERR;
        }

        /* Start a new job */
        if ((async_get_ctx()->currjob = async_get_pool_job()) == NULL) {
            return ASYNC_NO_JOBS;
        }

        if (args != NULL) {
            async_get_ctx()->currjob->funcargs = OPENSSL_malloc(size);
            if (async_get_ctx()->currjob->funcargs == NULL) {
                ASYNCerr(ASYNC_F_ASYNC_START_JOB, ERR_R_MALLOC_FAILURE);
                async_release_job(async_get_ctx()->currjob);
                async_get_ctx()->currjob = NULL;
                return ASYNC_ERR;
            }
            memcpy(async_get_ctx()->currjob->funcargs, args, size);
        } else {
            async_get_ctx()->currjob->funcargs = NULL;
        }

        async_get_ctx()->currjob->func = func;
        if (!async_fibre_swapcontext(&async_get_ctx()->dispatcher,
                &async_get_ctx()->currjob->fibrectx, 1)) {
            ASYNCerr(ASYNC_F_ASYNC_START_JOB, ASYNC_R_FAILED_TO_SWAP_CONTEXT);
            goto err;
        }
    }

err:
    async_release_job(async_get_ctx()->currjob);
    async_get_ctx()->currjob = NULL;
    *job = NULL;
    return ASYNC_ERR;
}


int ASYNC_pause_job(void)
{
    ASYNC_JOB *job;

    if (async_get_ctx() == NULL
            || async_get_ctx()->currjob == NULL
            || async_get_ctx()->blocked) {
        /*
         * Could be we've deliberately not been started within a job so this is
         * counted as success.
         */
        return 1;
    }

    job = async_get_ctx()->currjob;
    job->status = ASYNC_JOB_PAUSING;

    if (!async_fibre_swapcontext(&job->fibrectx,
                                 &async_get_ctx()->dispatcher, 1)) {
        ASYNCerr(ASYNC_F_ASYNC_PAUSE_JOB, ASYNC_R_FAILED_TO_SWAP_CONTEXT);
        return 0;
    }

    return 1;
}

static void async_empty_pool(STACK_OF(ASYNC_JOB) *pool)
{
    ASYNC_JOB *job;

    do {
        job = sk_ASYNC_JOB_pop(pool);
        async_job_free(job);
    } while (job);
}

int ASYNC_init_pool(size_t max_size, size_t init_size)
{
    STACK_OF(ASYNC_JOB) *pool;
    size_t curr_size = 0;

    if (init_size > max_size) {
        ASYNCerr(ASYNC_F_ASYNC_INIT_POOL, ASYNC_R_INVALID_POOL_SIZE);
        return 0;
    }

    pool = sk_ASYNC_JOB_new_null();
    if (pool == NULL) {
        ASYNCerr(ASYNC_F_ASYNC_INIT_POOL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    /* Pre-create jobs as required */
    while (init_size) {
        ASYNC_JOB *job;
        job = async_job_new();
        if (job) {
            async_fibre_makecontext(&job->fibrectx);
            job->funcargs = NULL;
            sk_ASYNC_JOB_push(pool, job);
            curr_size++;
            init_size--;
        } else {
            /*
             * Not actually fatal because we already created the pool, just skip
             * creation of any more jobs
             */
            init_size = 0;
        }
    }

    if (!async_set_pool(pool, curr_size, max_size)) {
        ASYNCerr(ASYNC_F_ASYNC_INIT_POOL, ASYNC_R_FAILED_TO_SET_POOL);
        async_empty_pool(pool);
        sk_ASYNC_JOB_free(pool);
        return 0;
    }

    return 1;
}

void ASYNC_free_pool(void)
{
    STACK_OF(ASYNC_JOB) *pool;

    pool = async_get_pool();
    if (pool == NULL)
        return;

    async_empty_pool(pool);
    async_release_pool();
    async_ctx_free();
}

ASYNC_JOB *ASYNC_get_current_job(void)
{
    async_ctx *ctx;

    ctx = async_get_ctx();
    if(ctx == NULL)
        return NULL;

    return ctx->currjob;
}

OSSL_ASYNC_FD ASYNC_get_wait_fd(ASYNC_JOB *job)
{
    return job->wait_fd;
}

void ASYNC_wake(ASYNC_JOB *job)
{
    char dummy = 0;

    if (job->wake_set)
        return;
    async_write1(job->wake_fd, &dummy);
    job->wake_set = 1;
}

void ASYNC_clear_wake(ASYNC_JOB *job)
{
    char dummy = 0;
    if (!job->wake_set)
        return;
    async_read1(job->wait_fd, &dummy);
    job->wake_set = 0;
}

void ASYNC_block_pause(void)
{
    if (async_get_ctx() == NULL
            || async_get_ctx()->currjob == NULL) {
        /*
         * We're not in a job anyway so ignore this
         */
        return;
    }
    async_get_ctx()->blocked++;
}

void ASYNC_unblock_pause(void)
{
    if (async_get_ctx() == NULL
            || async_get_ctx()->currjob == NULL) {
        /*
         * We're not in a job anyway so ignore this
         */
        return;
    }
    if(async_get_ctx()->blocked > 0)
        async_get_ctx()->blocked--;
}
