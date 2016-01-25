/*
 * Written by Matt Caswell for the OpenSSL project.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <string.h>
#include <openssl/async.h>
#include <openssl/crypto.h>
#include <../apps/apps.h>

#if (defined(OPENSSL_SYS_UNIX) || defined(OPENSSL_SYS_CYGWIN)) && defined(OPENSSL_THREADS)
# include <unistd.h>
# if _POSIX_VERSION >= 200112L
#  define ASYNC_POSIX
# endif
#elif defined(_WIN32)
# define ASYNC_WIN
#endif

#if !defined(ASYNC_POSIX) && !defined(ASYNC_WIN)
# define ASYNC_NULL
#endif

#ifndef ASYNC_NULL

static int ctr = 0;
static ASYNC_JOB *currjob = NULL;

static int only_pause(void *args)
{
    ASYNC_pause_job();

    return 1;
}

static int add_two(void *args)
{
    ctr++;
    ASYNC_pause_job();
    ctr++;

    return 2;
}

static int save_current(void *args)
{
    currjob = ASYNC_get_current_job();
    ASYNC_pause_job();

    return 1;
}

#define MAGIC_WAIT_FD   ((OSSL_ASYNC_FD)99)
static int waitfd(void *args)
{
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    ASYNC_pause_job();
    job = ASYNC_get_current_job();
    if (job == NULL)
        return 0;
    waitctx = ASYNC_get_wait_ctx(job);
    if (waitctx == NULL)
        return 0;
    if(!ASYNC_WAIT_CTX_set_wait_fd(waitctx, waitctx, MAGIC_WAIT_FD, NULL, NULL))
        return 0;
    ASYNC_pause_job();

    if (!ASYNC_WAIT_CTX_clear_fd(waitctx, waitctx))
        return 0;

    return 1;
}

static int blockpause(void *args)
{
    ASYNC_block_pause();
    ASYNC_pause_job();
    ASYNC_unblock_pause();
    ASYNC_pause_job();

    return 1;
}

static int test_ASYNC_init_thread()
{
    ASYNC_JOB *job1 = NULL, *job2 = NULL, *job3 = NULL;
    int funcret1, funcret2, funcret3;
    ASYNC_WAIT_CTX *waitctx;

    if (       !ASYNC_init_thread(2, 0)
            || (waitctx = ASYNC_WAIT_CTX_new()) == NULL
            || ASYNC_start_job(&job1, waitctx, &funcret1, only_pause, NULL, 0)
                != ASYNC_PAUSE
            || ASYNC_start_job(&job2, waitctx, &funcret2, only_pause, NULL, 0)
                != ASYNC_PAUSE
            || ASYNC_start_job(&job3, waitctx, &funcret3, only_pause, NULL, 0)
                != ASYNC_NO_JOBS
            || ASYNC_start_job(&job1, waitctx, &funcret1, only_pause, NULL, 0)
                != ASYNC_FINISH
            || ASYNC_start_job(&job3, waitctx, &funcret3, only_pause, NULL, 0)
                != ASYNC_PAUSE
            || ASYNC_start_job(&job2, waitctx, &funcret2, only_pause, NULL, 0)
                != ASYNC_FINISH
            || ASYNC_start_job(&job3, waitctx, &funcret3, only_pause, NULL, 0)
                != ASYNC_FINISH
            || funcret1 != 1
            || funcret2 != 1
            || funcret3 != 1) {
        fprintf(stderr, "test_ASYNC_init_thread() failed\n");
        ASYNC_WAIT_CTX_free(waitctx);
        ASYNC_cleanup_thread();
        return 0;
    }

    ASYNC_WAIT_CTX_free(waitctx);
    ASYNC_cleanup_thread();
    return 1;
}

static int test_ASYNC_start_job()
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx;

    ctr = 0;

    if (       !ASYNC_init_thread(1, 0)
            || (waitctx = ASYNC_WAIT_CTX_new()) == NULL
            || ASYNC_start_job(&job, waitctx, &funcret, add_two, NULL, 0)
               != ASYNC_PAUSE
            || ctr != 1
            || ASYNC_start_job(&job, waitctx, &funcret, add_two, NULL, 0)
               != ASYNC_FINISH
            || ctr != 2
            || funcret != 2) {
        fprintf(stderr, "test_ASYNC_start_job() failed\n");
        ASYNC_WAIT_CTX_free(waitctx);
        ASYNC_cleanup_thread();
        return 0;
    }

    ASYNC_WAIT_CTX_free(waitctx);
    ASYNC_cleanup_thread();
    return 1;
}

static int test_ASYNC_get_current_job()
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx;

    currjob = NULL;

    if (       !ASYNC_init_thread(1, 0)
            || (waitctx = ASYNC_WAIT_CTX_new()) == NULL
            || ASYNC_start_job(&job, waitctx, &funcret, save_current, NULL, 0)
                != ASYNC_PAUSE
            || currjob != job
            || ASYNC_start_job(&job, waitctx, &funcret, save_current, NULL, 0)
                != ASYNC_FINISH
            || funcret != 1) {
        fprintf(stderr, "test_ASYNC_get_current_job() failed\n");
        ASYNC_WAIT_CTX_free(waitctx);
        ASYNC_cleanup_thread();
        return 0;
    }

    ASYNC_WAIT_CTX_free(waitctx);
    ASYNC_cleanup_thread();
    return 1;
}

static int test_ASYNC_WAIT_CTX_get_all_fds()
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD fd = OSSL_BAD_ASYNC_FD, delfd = OSSL_BAD_ASYNC_FD;
    size_t numfds, numdelfds;

    if (       !ASYNC_init_thread(1, 0)
            || (waitctx = ASYNC_WAIT_CTX_new()) == NULL
               /* On first run we're not expecting any wait fds */
            || ASYNC_start_job(&job, waitctx, &funcret, waitfd, NULL, 0)
                != ASYNC_PAUSE
            || !ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds)
            || numfds != 0
            || !ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, NULL,
                                               &numdelfds)
            || numfds != 0
            || numdelfds != 0
               /* On second run we're expecting one added fd */
            || ASYNC_start_job(&job, waitctx, &funcret, waitfd, NULL, 0)
                != ASYNC_PAUSE
            || !ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds)
            || numfds != 1
            || !ASYNC_WAIT_CTX_get_all_fds(waitctx, &fd, &numfds)
            || fd != MAGIC_WAIT_FD
            || (fd = OSSL_BAD_ASYNC_FD, 0) /* Assign to something else */
            || !ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, NULL,
                                              &numdelfds)
            || numfds != 1
            || numdelfds != 0
            || !ASYNC_WAIT_CTX_get_changed_fds(waitctx, &fd, &numfds, NULL,
                                               &numdelfds)
            || fd != MAGIC_WAIT_FD
               /* On final run we expect one deleted fd */
            || ASYNC_start_job(&job, waitctx, &funcret, waitfd, NULL, 0)
                != ASYNC_FINISH
            || !ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds)
            || numfds != 0
            || !ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, NULL,
                                               &numdelfds)
            || numfds != 0
            || numdelfds != 1
            || !ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, &delfd,
                                               &numdelfds)
            || delfd != MAGIC_WAIT_FD
            || funcret != 1) {
        fprintf(stderr, "test_ASYNC_get_wait_fd() failed\n");
        ASYNC_WAIT_CTX_free(waitctx);
        ASYNC_cleanup_thread();
        return 0;
    }

    ASYNC_WAIT_CTX_free(waitctx);
    ASYNC_cleanup_thread();
    return 1;
}

static int test_ASYNC_block_pause()
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx;

    if (       !ASYNC_init_thread(1, 0)
            || (waitctx = ASYNC_WAIT_CTX_new()) == NULL
            || ASYNC_start_job(&job, waitctx, &funcret, blockpause, NULL, 0)
                != ASYNC_PAUSE
            || ASYNC_start_job(&job, waitctx, &funcret, blockpause, NULL, 0)
                != ASYNC_FINISH
            || funcret != 1) {
        fprintf(stderr, "test_ASYNC_block_pause() failed\n");
        ASYNC_WAIT_CTX_free(waitctx);
        ASYNC_cleanup_thread();
        return 0;
    }

    ASYNC_WAIT_CTX_free(waitctx);
    ASYNC_cleanup_thread();
    return 1;
}

#endif

int main(int argc, char **argv)
{

#ifdef ASYNC_NULL
    fprintf(stderr, "NULL implementation - skipping async tests\n");
#else
    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    if (       !test_ASYNC_init_thread()
            || !test_ASYNC_start_job()
            || !test_ASYNC_get_current_job()
            || !test_ASYNC_WAIT_CTX_get_all_fds()
            || !test_ASYNC_block_pause()) {
        return 1;
    }
#endif
    printf("PASS\n");
    return 0;
}
