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

/* This must be the first #include file */
#include "async_locl.h"

#include <openssl/err.h>
#include <internal/cryptlib_int.h>
#include <string.h>

#define ASYNC_JOB_RUNNING   0
#define ASYNC_JOB_PAUSING   1
#define ASYNC_JOB_PAUSED    2
#define ASYNC_JOB_STOPPING  3

static void async_free_pool_internal(async_pool *pool);

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

static async_ctx *async_get_ctx(void)
{
    if (!OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, NULL))
        return NULL;
    return async_arch_get_ctx();
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

    job = OPENSSL_zalloc(sizeof (ASYNC_JOB));
    if (job == NULL) {
        ASYNCerr(ASYNC_F_ASYNC_JOB_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    job->status = ASYNC_JOB_RUNNING;

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
    async_pool *pool;

    pool = async_get_pool();
    if (pool == NULL) {
        /*
         * Pool has not been initialised, so init with the defaults, i.e.
         * no max size and no pre-created jobs
         */
        if (ASYNC_init_thread(0, 0) == 0)
            return NULL;
        pool = async_get_pool();
    }

    job = sk_ASYNC_JOB_pop(pool->jobs);
    if (job == NULL) {
        /* Pool is empty */
        if ((pool->max_size != 0) && (pool->curr_size >= pool->max_size))
            return NULL;

        job = async_job_new();
        if (job != NULL) {
            if (! async_fibre_makecontext(&job->fibrectx)) {
                async_job_free(job);
                return NULL;
            }
            pool->curr_size++;
        }
    }
    return job;
}

static void async_release_job(ASYNC_JOB *job) {
    async_pool *pool;

    pool = async_get_pool();
    OPENSSL_free(job->funcargs);
    job->funcargs = NULL;
    sk_ASYNC_JOB_push(pool->jobs, job);
}

void async_start_func(void)
{
    ASYNC_JOB *job;
    async_ctx *ctx = async_get_ctx();

    while (1) {
        /* Run the job */
        job = ctx->currjob;
        job->ret = job->func(job->funcargs);

        /* Stop the job */
        job->status = ASYNC_JOB_STOPPING;
        if (!async_fibre_swapcontext(&job->fibrectx,
                                     &ctx->dispatcher, 1)) {
            /*
             * Should not happen. Getting here will close the thread...can't do
             * much about it
             */
            ASYNCerr(ASYNC_F_ASYNC_START_FUNC, ASYNC_R_FAILED_TO_SWAP_CONTEXT);
        }
    }
}

int ASYNC_start_job(ASYNC_JOB **job, ASYNC_WAIT_CTX *wctx, int *ret,
                    int (*func)(void *), void *args, size_t size)
{
    async_ctx *ctx = async_get_ctx();
    if (ctx == NULL)
        ctx = async_ctx_new();
    if (ctx == NULL) {
        return ASYNC_ERR;
    }

    if (*job) {
        ctx->currjob = *job;
    }

    for (;;) {
        if (ctx->currjob != NULL) {
            if (ctx->currjob->status == ASYNC_JOB_STOPPING) {
                *ret = ctx->currjob->ret;
                ctx->currjob->waitctx = NULL;
                async_release_job(ctx->currjob);
                ctx->currjob = NULL;
                *job = NULL;
                return ASYNC_FINISH;
            }

            if (ctx->currjob->status == ASYNC_JOB_PAUSING) {
                *job = ctx->currjob;
                ctx->currjob->status = ASYNC_JOB_PAUSED;
                ctx->currjob = NULL;
                return ASYNC_PAUSE;
            }

            if (ctx->currjob->status == ASYNC_JOB_PAUSED) {
                ctx->currjob = *job;
                /* Resume previous job */
                if (!async_fibre_swapcontext(&ctx->dispatcher,
                        &ctx->currjob->fibrectx, 1)) {
                    ASYNCerr(ASYNC_F_ASYNC_START_JOB,
                             ASYNC_R_FAILED_TO_SWAP_CONTEXT);
                    goto err;
                }
                continue;
            }

            /* Should not happen */
            ASYNCerr(ASYNC_F_ASYNC_START_JOB, ERR_R_INTERNAL_ERROR);
            async_release_job(ctx->currjob);
            ctx->currjob = NULL;
            *job = NULL;
            return ASYNC_ERR;
        }

        /* Start a new job */
        if ((ctx->currjob = async_get_pool_job()) == NULL) {
            return ASYNC_NO_JOBS;
        }

        if (args != NULL) {
            ctx->currjob->funcargs = OPENSSL_malloc(size);
            if (ctx->currjob->funcargs == NULL) {
                ASYNCerr(ASYNC_F_ASYNC_START_JOB, ERR_R_MALLOC_FAILURE);
                async_release_job(ctx->currjob);
                ctx->currjob = NULL;
                return ASYNC_ERR;
            }
            memcpy(ctx->currjob->funcargs, args, size);
        } else {
            ctx->currjob->funcargs = NULL;
        }

        ctx->currjob->func = func;
        ctx->currjob->waitctx = wctx;
        if (!async_fibre_swapcontext(&ctx->dispatcher,
                &ctx->currjob->fibrectx, 1)) {
            ASYNCerr(ASYNC_F_ASYNC_START_JOB, ASYNC_R_FAILED_TO_SWAP_CONTEXT);
            goto err;
        }
    }

err:
    async_release_job(ctx->currjob);
    ctx->currjob = NULL;
    *job = NULL;
    return ASYNC_ERR;
}

int ASYNC_pause_job(void)
{
    ASYNC_JOB *job;
    async_ctx *ctx = async_get_ctx();

    if (ctx == NULL
            || ctx->currjob == NULL
            || ctx->blocked) {
        /*
         * Could be we've deliberately not been started within a job so this is
         * counted as success.
         */
        return 1;
    }

    job = ctx->currjob;
    job->status = ASYNC_JOB_PAUSING;

    if (!async_fibre_swapcontext(&job->fibrectx,
                                 &ctx->dispatcher, 1)) {
        ASYNCerr(ASYNC_F_ASYNC_PAUSE_JOB, ASYNC_R_FAILED_TO_SWAP_CONTEXT);
        return 0;
    }
    /* Reset counts of added and deleted fds */
    async_wait_ctx_reset_counts(job->waitctx);

    return 1;
}

static void async_empty_pool(async_pool *pool)
{
    ASYNC_JOB *job;

    if (!pool || !pool->jobs)
        return;

    do {
        job = sk_ASYNC_JOB_pop(pool->jobs);
        async_job_free(job);
    } while (job);
}

int async_init(void)
{
    if (!async_global_init())
        return 0;

    return 1;
}

int ASYNC_init_thread(size_t max_size, size_t init_size)
{
    async_pool *pool;
    size_t curr_size = 0;

    if (init_size > max_size) {
        ASYNCerr(ASYNC_F_ASYNC_INIT_THREAD, ASYNC_R_INVALID_POOL_SIZE);
        return 0;
    }

    if (!OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, NULL)) {
        return 0;
    }
    if (!ossl_init_thread_start(OPENSSL_INIT_THREAD_ASYNC)) {
        return 0;
    }

    pool = OPENSSL_zalloc(sizeof *pool);
    if (pool == NULL) {
        ASYNCerr(ASYNC_F_ASYNC_INIT_THREAD, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    pool->jobs = sk_ASYNC_JOB_new_null();
    if (pool->jobs == NULL) {
        ASYNCerr(ASYNC_F_ASYNC_INIT_THREAD, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(pool);
        return 0;
    }

    pool->max_size = max_size;

    /* Pre-create jobs as required */
    while (init_size--) {
        ASYNC_JOB *job;
        job = async_job_new();
        if (job == NULL || !async_fibre_makecontext(&job->fibrectx)) {
            /*
             * Not actually fatal because we already created the pool, just
             * skip creation of any more jobs
             */
            async_job_free(job);
            break;
        }
        job->funcargs = NULL;
        sk_ASYNC_JOB_push(pool->jobs, job);
        curr_size++;
    }
    pool->curr_size = curr_size;
    if (!async_set_pool(pool)) {
        ASYNCerr(ASYNC_F_ASYNC_INIT_THREAD, ASYNC_R_FAILED_TO_SET_POOL);
        goto err;
    }

    return 1;
err:
    async_free_pool_internal(pool);
    return 0;
}

static void async_free_pool_internal(async_pool *pool)
{
    if (pool == NULL)
        return;

    async_empty_pool(pool);
    sk_ASYNC_JOB_free(pool->jobs);
    OPENSSL_free(pool);
    (void)async_set_pool(NULL);
    async_local_cleanup();
    async_ctx_free();
}

void ASYNC_cleanup_thread(void)
{
    async_free_pool_internal(async_get_pool());
}

ASYNC_JOB *ASYNC_get_current_job(void)
{
    async_ctx *ctx;

    ctx = async_get_ctx();
    if(ctx == NULL)
        return NULL;

    return ctx->currjob;
}

ASYNC_WAIT_CTX *ASYNC_get_wait_ctx(ASYNC_JOB *job)
{
    return job->waitctx;
}

void ASYNC_block_pause(void)
{
    async_ctx *ctx = async_get_ctx();
    if (ctx == NULL || ctx->currjob == NULL) {
        /*
         * We're not in a job anyway so ignore this
         */
        return;
    }
    ctx->blocked++;
}

void ASYNC_unblock_pause(void)
{
    async_ctx *ctx = async_get_ctx();
    if (ctx == NULL || ctx->currjob == NULL) {
        /*
         * We're not in a job anyway so ignore this
         */
        return;
    }
    if(ctx->blocked > 0)
        ctx->blocked--;
}
