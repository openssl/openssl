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

#include <openssl/crypto.h>
#include <openssl/async.h>
#include <ucontext.h>
#include <string.h>

#define ASYNC_JOB_RUNNING   0
#define ASYNC_JOB_PAUSING   1
#define ASYNC_JOB_PAUSED    2
#define ASYNC_JOB_STOPPING  3


typedef struct async_ctx_st {
    ucontext_t dispatcher;
    ASYNC_JOB *currjob;
} ASYNC_CTX;

__thread ASYNC_CTX *ctx;

struct async_job_st {
    ucontext_t fibrectx;
    int (*func)(void *);
    void *funcargs;
    int ret;
    int status;
};


static ASYNC_CTX *ASYNC_CTX_new(void)
{
    ASYNC_CTX *nctx = NULL;

    if(!(nctx = OPENSSL_malloc(sizeof (ASYNC_CTX)))) {
        /* Error here */
        goto err;
    }

    nctx->currjob = NULL;
    ctx = nctx;

    return nctx;
err:
    if(nctx) {
        OPENSSL_free(nctx);
    }

    return NULL;
}

static int ASYNC_CTX_free(void)
{
    if(ctx) {
        OPENSSL_free(ctx);
    }

    ctx = NULL;

    return 1;
}

static ASYNC_JOB *ASYNC_JOB_new(void)
{
    ASYNC_JOB *job = NULL;
    void *stack = NULL;

    if(!(job = OPENSSL_malloc(sizeof (ASYNC_JOB)))) {
        goto err;
    }

    if(!(stack = OPENSSL_malloc(SIGSTKSZ))) {
        goto err;
    }
    if(getcontext(&job->fibrectx))
        goto err;
    job->fibrectx.uc_stack.ss_sp = stack;
    job->fibrectx.uc_stack.ss_size = SIGSTKSZ;
    job->fibrectx.uc_link = NULL;
    job->status = ASYNC_JOB_RUNNING;
    job->funcargs = NULL;

    return job;
err:
    if(job) {
        if(stack)
            OPENSSL_free(stack);
        OPENSSL_free(job);
    }
    return NULL;
}

static void ASYNC_JOB_free(ASYNC_JOB *job)
{
    if(job) {
        if(job->funcargs)
            OPENSSL_free(job->funcargs);
        if(job->fibrectx.uc_stack.ss_sp)
            OPENSSL_free(job->fibrectx.uc_stack.ss_sp);
        OPENSSL_free(job);
    }
}

static void ASYNC_start_func(void)
{
    ASYNC_JOB *job;

    /* Run the job */
    job = ctx->currjob;
    job->ret = job->func(job->funcargs);

    /* Stop the job */
    job->status = ASYNC_JOB_STOPPING;
    setcontext(&ctx->dispatcher);

    /*
     * Should not happen. Getting here will close the thread...can't do much
     * about it
     */
}

int ASYNC_start_job(ASYNC_JOB **job, int *ret, int (*func)(void *),
                         void *args, size_t size)
{
    if(ctx || !ASYNC_CTX_new()) {
        return ASYNC_ERR;
    }

    if(*job) {
        ctx->currjob = *job;
    }

    getcontext(&ctx->dispatcher);

    if(ctx->currjob) {
        if(ctx->currjob->status == ASYNC_JOB_STOPPING) {
            *ret = ctx->currjob->ret;
            ASYNC_JOB_free(ctx->currjob);
            ctx->currjob = NULL;
            ASYNC_CTX_free();
            return ASYNC_FINISH;
        }

        if(ctx->currjob->status == ASYNC_JOB_PAUSING) {
            *job = ctx->currjob;
            ctx->currjob->status = ASYNC_JOB_PAUSED;
            ASYNC_CTX_free();
            return ASYNC_PAUSE;
        }

        if(ctx->currjob->status == ASYNC_JOB_PAUSED) {
            ctx->currjob = *job;
            /* Resume previous job */
            setcontext(&ctx->currjob->fibrectx);
            /* Does not return */
        }

        /* Should not happen */
        ASYNC_JOB_free(ctx->currjob);
        ctx->currjob = NULL;
        ASYNC_CTX_free();
        return ASYNC_ERR;
    }

    /* Start a new job */
    if(!(ctx->currjob = ASYNC_JOB_new())) {
        ASYNC_CTX_free();
        return ASYNC_ERR;
    }

    if(args != NULL) {
        ctx->currjob->funcargs = OPENSSL_malloc(size);
        if(!ctx->currjob->funcargs) {
            ASYNC_JOB_free(ctx->currjob);
            ctx->currjob = NULL;
            ASYNC_CTX_free();
            return ASYNC_ERR;
        }
        memcpy(ctx->currjob->funcargs, args, size);
    } else {
        ctx->currjob->funcargs = NULL;
    }

    ctx->currjob->func = func;
    makecontext(&ctx->currjob->fibrectx, ASYNC_start_func, 0);
    setcontext(&ctx->currjob->fibrectx);

    /* Does not return except in error */
    ASYNC_JOB_free(ctx->currjob);
    ctx->currjob = NULL;
    ASYNC_CTX_free();
    return ASYNC_ERR;
}


int ASYNC_pause_job(void)
{
    ASYNC_JOB *job;

    if(!ctx || !ctx->currjob)
        return 0;

    job = ctx->currjob;
    job->status = ASYNC_JOB_PAUSING;

    if(swapcontext(&job->fibrectx, &ctx->dispatcher)) {
        /* Error */
        return 0;
    }

    return 1;
}

int ASYNC_in_job(void)
{
    if(ctx)
        return 1;

    return 0;
}

int ASYNC_job_is_waiting(ASYNC_JOB *job)
{
    return job->status == ASYNC_JOB_PAUSED;
}
