/* test/asynctest.c */
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

#ifdef OPENSSL_SYS_UNIX
# include <unistd.h>
# if _POSIX_VERSION >= 200112L
#  define ASYNC_POSIX
# endif
#elif (defined(_WIN32) || defined(__CYGWIN__)) && defined(_WINDLL)
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

static int wake(void *args)
{
    ASYNC_pause_job();
    ASYNC_wake(ASYNC_get_current_job());
    ASYNC_pause_job();
    ASYNC_clear_wake(ASYNC_get_current_job());

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

static int test_ASYNC_init_pool()
{
    ASYNC_JOB *job1 = NULL, *job2 = NULL, *job3 = NULL;
    int funcret1, funcret2, funcret3;

    if (       !ASYNC_init_pool(2, 0)
            || ASYNC_start_job(&job1, &funcret1, only_pause, NULL, 0)
                != ASYNC_PAUSE
            || ASYNC_start_job(&job2, &funcret2, only_pause, NULL, 0)
                != ASYNC_PAUSE
            || ASYNC_start_job(&job3, &funcret3, only_pause, NULL, 0)
                != ASYNC_NO_JOBS
            || ASYNC_start_job(&job1, &funcret1, only_pause, NULL, 0)
                != ASYNC_FINISH
            || ASYNC_start_job(&job3, &funcret3, only_pause, NULL, 0)
                != ASYNC_PAUSE
            || ASYNC_start_job(&job2, &funcret2, only_pause, NULL, 0)
                != ASYNC_FINISH
            || ASYNC_start_job(&job3, &funcret3, only_pause, NULL, 0)
                != ASYNC_FINISH
            || funcret1 != 1
            || funcret2 != 1
            || funcret3 != 1) {
        fprintf(stderr, "test_ASYNC_init_pool() failed\n");
        ASYNC_free_pool();
        return 0;
    }

    ASYNC_free_pool();
    return 1;
}

static int test_ASYNC_start_job()
{
    ASYNC_JOB *job = NULL;
    int funcret;

    ctr = 0;

    if (       !ASYNC_init_pool(1, 0)
            || ASYNC_start_job(&job, &funcret, add_two, NULL, 0) != ASYNC_PAUSE
            || ctr != 1
            || ASYNC_start_job(&job, &funcret, add_two, NULL, 0) != ASYNC_FINISH
            || ctr != 2
            || funcret != 2) {
        fprintf(stderr, "test_ASYNC_start_job() failed\n");
        ASYNC_free_pool();
        return 0;
    }

    ASYNC_free_pool();
    return 1;
}

static int test_ASYNC_get_current_job()
{
    ASYNC_JOB *job = NULL;
    int funcret;

    currjob = NULL;

    if (       !ASYNC_init_pool(1, 0)
            || ASYNC_start_job(&job, &funcret, save_current, NULL, 0)
                != ASYNC_PAUSE
            || currjob != job
            || ASYNC_start_job(&job, &funcret, save_current, NULL, 0)
                != ASYNC_FINISH
            || funcret != 1) {
        fprintf(stderr, "test_ASYNC_get_current_job() failed\n");
        ASYNC_free_pool();
        return 0;
    }

    ASYNC_free_pool();
    return 1;
}

static int hasdata(int fd)
{
    fd_set checkfds;
    struct timeval tv;
    FD_ZERO(&checkfds);
    openssl_fdset(fd, &checkfds);
    memset(&tv, 0, sizeof tv);
    if (select(fd + 1, (void *)&checkfds, NULL, NULL, &tv) < 0)
        return -1;
    if (FD_ISSET(fd, &checkfds))
        return 1;
    return 0;
}

static int test_ASYNC_get_wait_fd()
{
    ASYNC_JOB *job = NULL;
    int funcret, fd;

    if (       !ASYNC_init_pool(1, 0)
            || ASYNC_start_job(&job, &funcret, wake, NULL, 0)
                != ASYNC_PAUSE
            || (fd = ASYNC_get_wait_fd(job)) < 0
            || hasdata(fd) != 0
            || ASYNC_start_job(&job, &funcret, save_current, NULL, 0)
                != ASYNC_PAUSE
            || hasdata(fd) != 1
            || (ASYNC_clear_wake(job), 0)
            || hasdata(fd) != 0
            || (ASYNC_wake(job), 0)
            || hasdata(fd) != 1
            || ASYNC_start_job(&job, &funcret, save_current, NULL, 0)
                != ASYNC_FINISH
            || funcret != 1) {
        fprintf(stderr, "test_ASYNC_get_wait_fd() failed\n");
        ASYNC_free_pool();
        return 0;
    }

    ASYNC_free_pool();
    return 1;
}

static int test_ASYNC_block_pause()
{
    ASYNC_JOB *job = NULL;
    int funcret;

    if (       !ASYNC_init_pool(1, 0)
            || ASYNC_start_job(&job, &funcret, blockpause, NULL, 0)
                != ASYNC_PAUSE
            || ASYNC_start_job(&job, &funcret, blockpause, NULL, 0)
                != ASYNC_FINISH
            || funcret != 1) {
        fprintf(stderr, "test_ASYNC_block_pause() failed\n");
        ASYNC_free_pool();
        return 0;
    }

    ASYNC_free_pool();
    return 1;
}

#endif

int main(int argc, char **argv)
{

#ifdef ASYNC_NULL
    fprintf(stderr, "NULL implementation - skipping async tests\n");
#else
    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    if (       !test_ASYNC_init_pool()
            || !test_ASYNC_start_job()
            || !test_ASYNC_get_current_job()
            || !test_ASYNC_get_wait_fd()
            || !test_ASYNC_block_pause()) {
        return 1;
    }
#endif
    printf("PASS\n");
    return 0;
}
