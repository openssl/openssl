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
#include <string.h>
#include "async_locl.h"

#define ASYNC_JOB_RUNNING   0
#define ASYNC_JOB_PAUSING   1
#define ASYNC_JOB_PAUSED    2
#define ASYNC_JOB_STOPPING  3


static ASYNC_CTX *ASYNC_CTX_new(void)
{
    ASYNC_CTX *nctx = NULL;

    if(!(nctx = OPENSSL_malloc(sizeof (ASYNC_CTX)))) {
        /* Error here */
        goto err;
    }

    ASYNC_FIBRE_init_dispatcher(&nctx->dispatcher);
    nctx->currjob = NULL;
    if(!ASYNC_set_ctx(nctx))
        goto err;

    return nctx;
err:
    if(nctx) {
        OPENSSL_free(nctx);
    }

    return NULL;
}

static int ASYNC_CTX_free(void)
{
    if(ASYNC_get_ctx()) {
        OPENSSL_free(ASYNC_get_ctx());
    }

    if(!ASYNC_set_ctx(NULL))
        return 0;

    return 1;
}

static ASYNC_JOB *ASYNC_JOB_new(void)
{
    ASYNC_JOB *job = NULL;

    if(!(job = OPENSSL_malloc(sizeof (ASYNC_JOB)))) {
        return NULL;
    }

    job->status = ASYNC_JOB_RUNNING;
    job->funcargs = NULL;

    return job;
}

static void ASYNC_JOB_free(ASYNC_JOB *job)
{
    if(job) {
        if(job->funcargs)
            OPENSSL_free(job->funcargs);
        ASYNC_FIBRE_free(&job->fibrectx);
        OPENSSL_free(job);
    }
}

void ASYNC_start_func(void)
{
    ASYNC_JOB *job;

    /* Run the job */
    job = ASYNC_get_ctx()->currjob;
    job->ret = job->func(job->funcargs);

    /* Stop the job */
    job->status = ASYNC_JOB_STOPPING;
    if(!ASYNC_FIBRE_swapcontext(&job->fibrectx,
                                &ASYNC_get_ctx()->dispatcher, 0)) {
        /*
         * Should not happen. Getting here will close the thread...can't do much
         * about it
         */
    }
}

int ASYNC_start_job(ASYNC_JOB **job, int *ret, int (*func)(void *),
                         void *args, size_t size)
{
    if(ASYNC_get_ctx() || !ASYNC_CTX_new()) {
        return ASYNC_ERR;
    }

    if(*job) {
        ASYNC_get_ctx()->currjob = *job;
    }

    for (;;) {
        if(ASYNC_get_ctx()->currjob) {
            if(ASYNC_get_ctx()->currjob->status == ASYNC_JOB_STOPPING) {
                *ret = ASYNC_get_ctx()->currjob->ret;
                ASYNC_JOB_free(ASYNC_get_ctx()->currjob);
                ASYNC_get_ctx()->currjob = NULL;
                *job = NULL;
                ASYNC_CTX_free();
                return ASYNC_FINISH;
            }

            if(ASYNC_get_ctx()->currjob->status == ASYNC_JOB_PAUSING) {
                *job = ASYNC_get_ctx()->currjob;
                ASYNC_get_ctx()->currjob->status = ASYNC_JOB_PAUSED;
                ASYNC_CTX_free();
                return ASYNC_PAUSE;
            }

            if(ASYNC_get_ctx()->currjob->status == ASYNC_JOB_PAUSED) {
                ASYNC_get_ctx()->currjob = *job;
                /* Resume previous job */
                if(!ASYNC_FIBRE_swapcontext(&ASYNC_get_ctx()->dispatcher,
                    &ASYNC_get_ctx()->currjob->fibrectx, 1))
                    goto err;
                continue;
            }

            /* Should not happen */
            ASYNC_JOB_free(ASYNC_get_ctx()->currjob);
            ASYNC_get_ctx()->currjob = NULL;
            *job = NULL;
            ASYNC_CTX_free();
            return ASYNC_ERR;
        }

        /* Start a new job */
        if(!(ASYNC_get_ctx()->currjob = ASYNC_JOB_new())) {
            ASYNC_CTX_free();
            return ASYNC_ERR;
        }

        if(args != NULL) {
            ASYNC_get_ctx()->currjob->funcargs = OPENSSL_malloc(size);
            if(!ASYNC_get_ctx()->currjob->funcargs) {
                ASYNC_JOB_free(ASYNC_get_ctx()->currjob);
                ASYNC_get_ctx()->currjob = NULL;
                ASYNC_CTX_free();
                return ASYNC_ERR;
            }
            memcpy(ASYNC_get_ctx()->currjob->funcargs, args, size);
        } else {
            ASYNC_get_ctx()->currjob->funcargs = NULL;
        }

        ASYNC_get_ctx()->currjob->func = func;
        ASYNC_FIBRE_makecontext(&ASYNC_get_ctx()->currjob->fibrectx);
        if(!ASYNC_FIBRE_swapcontext(&ASYNC_get_ctx()->dispatcher,
            &ASYNC_get_ctx()->currjob->fibrectx, 1))
            goto err;
    }

err:
    ASYNC_JOB_free(ASYNC_get_ctx()->currjob);
    ASYNC_get_ctx()->currjob = NULL;
    *job = NULL;
    ASYNC_CTX_free();
    return ASYNC_ERR;
}


int ASYNC_pause_job(void)
{
    ASYNC_JOB *job;

    if(!ASYNC_get_ctx() || !ASYNC_get_ctx()->currjob)
        return 0;

    job = ASYNC_get_ctx()->currjob;
    job->status = ASYNC_JOB_PAUSING;

    if(!ASYNC_FIBRE_swapcontext(&job->fibrectx,
                               &ASYNC_get_ctx()->dispatcher, 1)) {
        /* Error */
        return 0;
    }

    return 1;
}

int ASYNC_in_job(void)
{
    if(ASYNC_get_ctx())
        return 1;

    return 0;
}
