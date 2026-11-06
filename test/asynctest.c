/*
 * Copyright 2015-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef _WIN32
#include <windows.h>
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/async.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <crypto/aarch64_dit.h>

static int ctr = 0;
static ASYNC_JOB *currjob = NULL;
static int custom_alloc_used = 0;
static int custom_free_used = 0;

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

static int change_deflt_libctx(void *args)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *oldctx, *tmpctx;
    int ret = 0;

    if (libctx == NULL)
        return 0;

    oldctx = OSSL_LIB_CTX_set0_default(libctx);
    ASYNC_pause_job();

    /* Check the libctx is set up as we expect */
    tmpctx = OSSL_LIB_CTX_set0_default(oldctx);
    if (tmpctx != libctx)
        goto err;

    /* Set it back again to continue to use our own libctx */
    oldctx = OSSL_LIB_CTX_set0_default(libctx);
    ASYNC_pause_job();

    /* Check the libctx is set up as we expect */
    tmpctx = OSSL_LIB_CTX_set0_default(oldctx);
    if (tmpctx != libctx)
        goto err;

    ret = 1;
err:
    OSSL_LIB_CTX_free(libctx);
    return ret;
}

#define MAGIC_WAIT_FD ((OSSL_ASYNC_FD)99)
static int waitfd(void *args)
{
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    job = ASYNC_get_current_job();
    if (job == NULL)
        return 0;
    waitctx = ASYNC_get_wait_ctx(job);
    if (waitctx == NULL)
        return 0;

    /* First case: no fd added or removed */
    ASYNC_pause_job();

    /* Second case: one fd added */
    if (!ASYNC_WAIT_CTX_set_wait_fd(waitctx, waitctx, MAGIC_WAIT_FD, NULL, NULL))
        return 0;
    ASYNC_pause_job();

    /* Third case: all fd removed */
    if (!ASYNC_WAIT_CTX_clear_fd(waitctx, waitctx))
        return 0;
    ASYNC_pause_job();

    /* Last case: fd added and immediately removed */
    if (!ASYNC_WAIT_CTX_set_wait_fd(waitctx, waitctx, MAGIC_WAIT_FD, NULL, NULL))
        return 0;
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

static int test_ASYNC_init_thread(void)
{
    ASYNC_JOB *job1 = NULL, *job2 = NULL, *job3 = NULL;
    int funcret1, funcret2, funcret3;
    ASYNC_WAIT_CTX *waitctx = NULL;

    if (!ASYNC_init_thread(2, 0)
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

static int test_callback(void *arg)
{
    printf("callback test pass\n");
    return 1;
}

static int test_ASYNC_callback_status(void)
{
    ASYNC_WAIT_CTX *waitctx = NULL;
    int set_arg = 100;
    ASYNC_callback_fn get_callback;
    void *get_arg;
    int set_status = 1;

    if (!ASYNC_init_thread(1, 0)
        || (waitctx = ASYNC_WAIT_CTX_new()) == NULL
        || ASYNC_WAIT_CTX_set_callback(waitctx, test_callback, (void *)&set_arg)
            != 1
        || ASYNC_WAIT_CTX_get_callback(waitctx, &get_callback, &get_arg)
            != 1
        || test_callback != get_callback
        || get_arg != (void *)&set_arg
        || (*get_callback)(get_arg) != 1
        || ASYNC_WAIT_CTX_set_status(waitctx, set_status) != 1
        || set_status != ASYNC_WAIT_CTX_get_status(waitctx)) {
        fprintf(stderr, "test_ASYNC_callback_status() failed\n");
        ASYNC_WAIT_CTX_free(waitctx);
        ASYNC_cleanup_thread();
        return 0;
    }

    ASYNC_WAIT_CTX_free(waitctx);
    ASYNC_cleanup_thread();
    return 1;
}

static int test_ASYNC_start_job(void)
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx = NULL;

    ctr = 0;

    if (!ASYNC_init_thread(1, 0)
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

static int test_ASYNC_get_current_job(void)
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx = NULL;

    currjob = NULL;

    if (!ASYNC_init_thread(1, 0)
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

static int test_ASYNC_WAIT_CTX_get_all_fds(void)
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx = NULL;
    OSSL_ASYNC_FD fd = OSSL_BAD_ASYNC_FD, delfd = OSSL_BAD_ASYNC_FD;
    size_t numfds, numdelfds;

    if (!ASYNC_init_thread(1, 0)
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
        /* On third run we expect one deleted fd */
        || ASYNC_start_job(&job, waitctx, &funcret, waitfd, NULL, 0)
            != ASYNC_PAUSE
        || !ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds)
        || numfds != 0
        || !ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, NULL,
            &numdelfds)
        || numfds != 0
        || numdelfds != 1
        || !ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, &delfd,
            &numdelfds)
        || delfd != MAGIC_WAIT_FD
        /* On last run we are not expecting any wait fd */
        || ASYNC_start_job(&job, waitctx, &funcret, waitfd, NULL, 0)
            != ASYNC_FINISH
        || !ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds)
        || numfds != 0
        || !ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, NULL,
            &numdelfds)
        || numfds != 0
        || numdelfds != 0
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

static int test_ASYNC_block_pause(void)
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx = NULL;

    if (!ASYNC_init_thread(1, 0)
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

static int test_ASYNC_start_job_ex(void)
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx = NULL;
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *oldctx, *tmpctx, *globalctx;
    int ret = 0;

    if (libctx == NULL) {
        fprintf(stderr,
            "test_ASYNC_start_job_ex() failed to create libctx\n");
        goto err;
    }

    globalctx = oldctx = OSSL_LIB_CTX_set0_default(libctx);

    if ((waitctx = ASYNC_WAIT_CTX_new()) == NULL
        || ASYNC_start_job(&job, waitctx, &funcret, change_deflt_libctx,
               NULL, 0)
            != ASYNC_PAUSE) {
        fprintf(stderr,
            "test_ASYNC_start_job_ex() failed to start job\n");
        goto err;
    }

    /* Reset the libctx temporarily to find out what it is*/
    tmpctx = OSSL_LIB_CTX_set0_default(oldctx);
    oldctx = OSSL_LIB_CTX_set0_default(tmpctx);
    if (tmpctx != libctx) {
        fprintf(stderr,
            "test_ASYNC_start_job_ex() failed - unexpected libctx\n");
        goto err;
    }

    if (ASYNC_start_job(&job, waitctx, &funcret, change_deflt_libctx, NULL, 0)
        != ASYNC_PAUSE) {
        fprintf(stderr,
            "test_ASYNC_start_job_ex() - restarting job failed\n");
        goto err;
    }

    /* Reset the libctx and continue with the global default libctx */
    tmpctx = OSSL_LIB_CTX_set0_default(oldctx);
    if (tmpctx != libctx) {
        fprintf(stderr,
            "test_ASYNC_start_job_ex() failed - unexpected libctx\n");
        goto err;
    }

    if (ASYNC_start_job(&job, waitctx, &funcret, change_deflt_libctx, NULL, 0)
            != ASYNC_FINISH
        || funcret != 1) {
        fprintf(stderr,
            "test_ASYNC_start_job_ex() - finishing job failed\n");
        goto err;
    }

    /* Reset the libctx temporarily to find out what it is*/
    tmpctx = OSSL_LIB_CTX_set0_default(libctx);
    OSSL_LIB_CTX_set0_default(tmpctx);
    if (tmpctx != globalctx) {
        fprintf(stderr,
            "test_ASYNC_start_job_ex() failed - global libctx check failed\n");
        goto err;
    }

    ret = 1;
err:
    ASYNC_WAIT_CTX_free(waitctx);
    ASYNC_cleanup_thread();
    OSSL_LIB_CTX_free(libctx);
    return ret;
}

static void *test_alloc_stack(size_t *num)
{
    custom_alloc_used = 1;
    return OPENSSL_malloc(*num);
}

static void test_free_stack(void *addr)
{
    custom_free_used = 1;
    OPENSSL_free(addr);
}

static int test_ASYNC_set_mem_functions(void)
{
    ASYNC_stack_alloc_fn alloc_fn;
    ASYNC_stack_free_fn free_fn;

    /* Not all platforms support this */
    if (ASYNC_set_mem_functions(test_alloc_stack, test_free_stack) == 0)
        return 1;

    ASYNC_get_mem_functions(&alloc_fn, &free_fn);

    if ((alloc_fn != test_alloc_stack) || (free_fn != test_free_stack)) {
        fprintf(stderr,
            "test_ASYNC_set_mem_functions() - setting and retrieving custom allocators failed\n");
        return 0;
    }

    if (!ASYNC_init_thread(1, 1)) {
        fprintf(stderr,
            "test_ASYNC_set_mem_functions() - failed initialising ctx pool\n");
        return 0;
    }
    ASYNC_cleanup_thread();

    if (!custom_alloc_used || !custom_free_used) {
        fprintf(stderr,
            "test_ASYNC_set_mem_functions() - custom allocation functions not used\n");

        return 0;
    }

    return 1;
}

#if defined(__aarch64__) && !defined(OSSL_NO_DIT)
typedef struct {
    EVP_PKEY_CTX *ctx;
    const char *name;
    int paused;
    int entry_dit;
    int resume_dit;
} DIT_JOB;

static int test_ASYNC_DIT_key_generate(void *arg)
{
    DIT_JOB *job = *(DIT_JOB **)arg;
    EVP_PKEY *pkey = NULL;

    int result = EVP_PKEY_generate(job->ctx, &pkey);
    EVP_PKEY_free(pkey);

    return result;
}

static int test_ASYNC_DIT_keygen_callback(EVP_PKEY_CTX *ctx)
{
    DIT_JOB *job = EVP_PKEY_CTX_get_app_data(ctx);

    if (!job->paused) {
        job->paused = 1;
        job->entry_dit = ossl_get_dit(1);

        ASYNC_pause_job();

        job->resume_dit = ossl_get_dit(1);
    }
    return 1;
}

static int test_ASYNC_DIT(int initial_dit, int lifo)
{
    int ret = 0;
    int job_ret;

    DIT_JOB job_A = { NULL, "A", 0, -1, -1 };
    DIT_JOB *ptr_job_A = &job_A;
    DIT_JOB job_B = { NULL, "B", 0, -1, -1 };
    DIT_JOB *ptr_job_B = &job_B;

    int dit_prev = ossl_get_dit(1);

    /* Test that DIT is supported on this system. If its already turned on, then it must be
     * supported, otherwise try to turn it on, and see if that works. */
    if (dit_prev == 0) {
        ossl_set_dit(1, 1);

        if (!ossl_get_dit(1)) {
            ossl_set_dit(dit_prev, 1);
            fprintf(stderr,
                "test_ASYNC_DIT() - skipped, DIT is not enabled on this CPU.\n");
            return 1;
        }
    }

    ASYNC_WAIT_CTX *wait_context_A = ASYNC_WAIT_CTX_new();
    ASYNC_WAIT_CTX *wait_context_B = ASYNC_WAIT_CTX_new();

    if (ASYNC_init_thread(2, 2)) {
        ASYNC_JOB *async_job_A = NULL;
        ASYNC_JOB *async_job_B = NULL;
        int dit_after_pause = 0;
        int dit_after_finish = 0;

        ossl_set_dit(initial_dit, 1);

        job_A.ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=default");
        job_B.ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=default");

        if (job_A.ctx == NULL || job_B.ctx == NULL || wait_context_A == NULL
            || wait_context_B == NULL) {
            fprintf(stderr,
                "test_ASYNC_DIT() - failed to allocate contexts.\n");
            goto err;
        }

        if (EVP_PKEY_keygen_init(job_A.ctx) == 0 || EVP_PKEY_keygen_init(job_B.ctx) == 0) {
            fprintf(stderr,
                "test_ASYNC_DIT() - failed to init keygen.\n");
            goto err;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(job_A.ctx, 1024) == 0
            || EVP_PKEY_CTX_set_rsa_keygen_bits(job_B.ctx, 1024) == 0) {
            fprintf(stderr,
                "test_ASYNC_DIT() - failed to set key sizes.\n");
            goto err;
        }

        EVP_PKEY_CTX_set_cb(job_A.ctx, test_ASYNC_DIT_keygen_callback);
        EVP_PKEY_CTX_set_cb(job_B.ctx, test_ASYNC_DIT_keygen_callback);
        EVP_PKEY_CTX_set_app_data(job_A.ctx, &job_A);
        EVP_PKEY_CTX_set_app_data(job_B.ctx, &job_B);

        if (ASYNC_start_job(
                &async_job_A, wait_context_A, &job_ret, test_ASYNC_DIT_key_generate, &ptr_job_A,
                sizeof(ptr_job_A))
            != ASYNC_PAUSE) {
            fprintf(stderr,
                "test_ASYNC_DIT() - failed to start / pause job_A.\n");
            goto err;
        }

        if (ASYNC_start_job(
                &async_job_B, wait_context_B, &job_ret, test_ASYNC_DIT_key_generate, &ptr_job_B,
                sizeof(ptr_job_B))
            != ASYNC_PAUSE) {
            fprintf(stderr,
                "test_ASYNC_DIT() - failed to start / pause job_B.\n");
            goto err;
        }

        dit_after_pause = ossl_get_dit(1);

        if (lifo) {
            if (ASYNC_start_job(
                    &async_job_B, wait_context_B, &job_ret, test_ASYNC_DIT_key_generate,
                    &ptr_job_B, sizeof(ptr_job_B))
                != ASYNC_FINISH) {
                fprintf(stderr,
                    "test_ASYNC_DIT() - failed to finish job_B.\n");
                goto err;
            }

            if (ASYNC_start_job(
                    &async_job_A, wait_context_A, &job_ret, test_ASYNC_DIT_key_generate,
                    &ptr_job_A, sizeof(ptr_job_A))
                != ASYNC_FINISH) {
                fprintf(stderr,
                    "test_ASYNC_DIT() - failed to finish job_A.\n");
                goto err;
            }
        } else {
            if (ASYNC_start_job(
                    &async_job_A, wait_context_A, &job_ret, test_ASYNC_DIT_key_generate,
                    &ptr_job_A, sizeof(ptr_job_A))
                != ASYNC_FINISH) {
                fprintf(stderr,
                    "test_ASYNC_DIT() - failed to finish job_A.\n");
                goto err;
            }

            if (ASYNC_start_job(
                    &async_job_B, wait_context_B, &job_ret, test_ASYNC_DIT_key_generate,
                    &ptr_job_B, sizeof(ptr_job_B))
                != ASYNC_FINISH) {
                fprintf(stderr,
                    "test_ASYNC_DIT() - failed to finish job_B.\n");
                goto err;
            }
        }

        dit_after_finish = ossl_get_dit(1);

        /* Check that main thread DIT has not changed. */
        if (initial_dit != dit_after_pause) {
            fprintf(stderr,
                "test_ASYNC_DIT() - Main thread DIT was changed by async start\n");
            goto err;
        }

        if (initial_dit != dit_after_finish) {
            fprintf(stderr,
                "test_ASYNC_DIT() - Main thread DIT was changed by async finish\n");
            goto err;
        }

        /* Check that DIT state remained constant for both jobs. */
        if (job_A.entry_dit != job_A.resume_dit) {
            fprintf(stderr,
                "test_ASYNC_DIT() - Job A changed DIT state after resume\n");
            goto err;
        }

        if (job_B.entry_dit != job_B.resume_dit) {
            fprintf(stderr,
                "test_ASYNC_DIT() - Job B changed DIT state after resume\n");
            goto err;
        }

    } else {
        fprintf(stderr,
            "test_ASYNC_DIT() - failed to initialise threads\n");
        goto err;
    }

    ret = 1;

err:
    EVP_PKEY_CTX_free(job_A.ctx);
    EVP_PKEY_CTX_free(job_B.ctx);
    ASYNC_WAIT_CTX_free(wait_context_A);
    ASYNC_WAIT_CTX_free(wait_context_B);
    ASYNC_cleanup_thread();

    ossl_set_dit(dit_prev, 1);

    return ret;
}
#endif // defined(__aarch64__) && !defined(OSSL_NO_DIT)

int main(int argc, char **argv)
{
    if (!ASYNC_is_capable()) {
        fprintf(stderr,
            "OpenSSL build is not ASYNC capable - skipping async tests\n");
    } else {
        if (!test_ASYNC_init_thread()
            || !test_ASYNC_callback_status()
            || !test_ASYNC_start_job()
            || !test_ASYNC_get_current_job()
            || !test_ASYNC_WAIT_CTX_get_all_fds()
            || !test_ASYNC_block_pause()
            || !test_ASYNC_start_job_ex()
            || !test_ASYNC_set_mem_functions()
#if defined(__aarch64__) && !defined(OSSL_NO_DIT)
            || !test_ASYNC_DIT(0, 0)
            || !test_ASYNC_DIT(1, 0)
            || !test_ASYNC_DIT(0, 1)
            || !test_ASYNC_DIT(1, 1)
#endif // defined(__aarch64__) && !defined(OSSL_NO_DIT)
        ) {
            return 1;
        }
    }
    printf("PASS\n");
    return 0;
}
