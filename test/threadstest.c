/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined(_WIN32)
# include <windows.h>
#endif

#include <internal/cryptlib.h>
#include <internal/thread.h>
#include <internal/worker.h>
#include <openssl/crypto.h>
#include "testutil.h"

#if !defined(OPENSSL_THREADS) || defined(CRYPTO_TDEBUG)

typedef unsigned int thread_t;

static int run_thread(thread_t *t, void (*f)(void))
{
    f();
    return 1;
}

static int wait_for_thread(thread_t thread)
{
    return 1;
}

#elif defined(OPENSSL_SYS_WINDOWS)

typedef HANDLE thread_t;

static DWORD WINAPI thread_run(LPVOID arg)
{
    void (*f)(void);

    *(void **) (&f) = arg;

    f();
    return 0;
}

static int run_thread(thread_t *t, void (*f)(void))
{
    *t = CreateThread(NULL, 0, thread_run, *(void **) &f, 0, NULL);
    return *t != NULL;
}

static int wait_for_thread(thread_t thread)
{
    return WaitForSingleObject(thread, INFINITE) == 0;
}

#else

typedef pthread_t thread_t;

static void *thread_run(void *arg)
{
    void (*f)(void);

    *(void **) (&f) = arg;

    f();
    return NULL;
}

static int run_thread(thread_t *t, void (*f)(void))
{
    return pthread_create(t, NULL, thread_run, *(void **) &f) == 0;
}

static int wait_for_thread(thread_t thread)
{
    return pthread_join(thread, NULL) == 0;
}

#endif

static int test_lock(void)
{
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();

    if (!TEST_true(CRYPTO_THREAD_read_lock(lock))
        || !TEST_true(CRYPTO_THREAD_unlock(lock)))
        return 0;

    CRYPTO_THREAD_lock_free(lock);

    return 1;
}

static CRYPTO_ONCE once_run = CRYPTO_ONCE_STATIC_INIT;
static unsigned once_run_count = 0;

static void once_do_run(void)
{
    once_run_count++;
}

static void once_run_thread_cb(void)
{
    CRYPTO_THREAD_run_once(&once_run, once_do_run);
}

static int test_once(void)
{
    thread_t thread;

    if (!TEST_true(run_thread(&thread, once_run_thread_cb))
        || !TEST_true(wait_for_thread(thread))
        || !CRYPTO_THREAD_run_once(&once_run, once_do_run)
        || !TEST_int_eq(once_run_count, 1))
        return 0;
    return 1;
}

static CRYPTO_THREAD_LOCAL thread_local_key;
static unsigned destructor_run_count = 0;
static int thread_local_thread_cb_ok = 0;

static void thread_local_destructor(void *arg)
{
    unsigned *count;

    if (arg == NULL)
        return;

    count = arg;

    (*count)++;
}

static void thread_local_thread_cb(void)
{
    void *ptr;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr)
        || !TEST_true(CRYPTO_THREAD_set_local(&thread_local_key,
                                              &destructor_run_count)))
        return;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_eq(ptr, &destructor_run_count))
        return;

    thread_local_thread_cb_ok = 1;
}

static int test_thread_local(void)
{
    thread_t thread;
    void *ptr = NULL;

    if (!TEST_true(CRYPTO_THREAD_init_local(&thread_local_key,
                                            thread_local_destructor)))
        return 0;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr)
        || !TEST_true(run_thread(&thread, thread_local_thread_cb))
        || !TEST_true(wait_for_thread(thread))
        || !TEST_int_eq(thread_local_thread_cb_ok, 1))
        return 0;

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr))
        return 0;

# if !defined(OPENSSL_SYS_WINDOWS)
    if (!TEST_int_eq(destructor_run_count, 1))
        return 0;
# endif
#endif

    if (!TEST_true(CRYPTO_THREAD_cleanup_local(&thread_local_key)))
        return 0;
    return 1;
}

#if defined(OPENSSL_THREADS)

static uint32_t fn1_glob = 0;
static uint32_t test_thread_native_fn(void *data)
{
    ossl_sleep(5000);
    fn1_glob = *(uint32_t*)data;
    return 2;
}

static uint32_t test_or1(void *data)
{
    ossl_sleep(5000);
    fn1_glob |= *(uint32_t*)data;;
    return 0;
}

static CRYPTO_WORKER_CMD cb_three_tasks(OPENSSL_CTX *ctx, size_t jobs)
{
    static uint8_t terminate_after_jobs = 3;

    if (--terminate_after_jobs > 0)
        return CRYPTO_WORKER_POLL;
    
    return CRYPTO_WORKER_TERMINATE;
}

static int test_thread_native(void)
{
    uint32_t retval;
    uint32_t local;
    CRYPTO_THREAD *t;

    local = 1;
    fn1_glob = 0;
    t = crypto_thread_native_start(test_thread_native_fn, &local, 1);

    if (!TEST_int_eq(fn1_glob, 0))
        return 0;

    crypto_thread_native_join(t, &retval);
    if (!TEST_int_eq(retval, 2) || !TEST_int_eq(fn1_glob, local))
        return 0;

    if (!TEST_int_eq(crypto_thread_native_clean(t), 1))
        return 0;

    return 1;
}

static uint32_t test_thread_native_multiple_joins_fn1(void *data)
{
    ossl_sleep(5000);
    return 0;
}

static uint32_t test_thread_native_multiple_joins_fn2(void *data)
{
    crypto_thread_native_join((CRYPTO_THREAD*)data, NULL);
    ossl_sleep(2000);
    return 0;
}

static uint32_t test_thread_native_multiple_joins_fn3(void *data)
{
    crypto_thread_native_join((CRYPTO_THREAD*)data, NULL);
    ossl_sleep(1000);
    return 0;
}

static int test_thread_native_multiple_joins(void)
{
    CRYPTO_THREAD *t, *t1, *t2;

    t = crypto_thread_native_start(test_thread_native_multiple_joins_fn1, NULL, 1);
    t1 = crypto_thread_native_start(test_thread_native_multiple_joins_fn2, t, 1);
    t2 = crypto_thread_native_start(test_thread_native_multiple_joins_fn3, t, 1);

    if (!TEST_ptr(t) || !TEST_ptr(t1) || !TEST_ptr(t2))
        return 0;

    if (!TEST_int_eq(crypto_thread_native_join(t2, NULL), 1))
        return 0;
    if (!TEST_int_eq(crypto_thread_native_join(t1, NULL), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_native_clean(t2),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_native_clean(t1),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_native_clean(t),1))
        return 0;

    return 1;
}

static int test_thread_enablement(void)
{
    void *task;
    OPENSSL_CTX *custom_ctx;

    custom_ctx = OPENSSL_CTX_new();
    if (!TEST_ptr(custom_ctx))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(custom_ctx), 0))
        return 0;

    task = crypto_thread_start(NULL, test_thread_native_fn, NULL, 0);
    if (!TEST_ptr_null(task))
        return 0;

    task = crypto_thread_start(custom_ctx, test_thread_native_fn, NULL, 0);
    if (!TEST_ptr_null(task))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_spawn_worker(NULL, NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_spawn_worker(custom_ctx, NULL), 0))
        return 0;

    /* enable threading for the default context only */

    if (!TEST_int_eq(CRYPTO_THREAD_enable(NULL, 0), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_disable(NULL), 1))
        return 0;

    /* enable threading for the custom context only */

    if (!TEST_int_eq(CRYPTO_THREAD_enable(custom_ctx, 0), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(custom_ctx), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_disable(custom_ctx), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(custom_ctx), 0))
        return 0;

    OPENSSL_CTX_free(custom_ctx);

    return 1;
}

static int test_thread_worker_cb(void)
{
    void *task0;
    void *task1;
    void *task2;
    uint32_t local0;
    uint32_t local1;
    uint32_t local2;
    uint32_t retval;
    OPENSSL_CTX *custom_ctx;

    custom_ctx = OPENSSL_CTX_new();
    if (!TEST_ptr(custom_ctx))
        return 0;


    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enable(NULL, 0), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_spawn_worker(NULL, cb_three_tasks), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(custom_ctx), 0))
        return 0;

    /* test a callback on a single tasks, worker should remain active */

    local0 = 0;
    task0 = crypto_thread_start(NULL, test_thread_native_fn, &local0, CRYPTO_THREAD_START_AWAIT);
    if (!TEST_ptr(task0))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 0))
        return 0;

    retval = 0;
    if (!TEST_int_eq(crypto_thread_join(NULL, task0, &retval), 1))
        return 0;

    if (!TEST_int_eq(retval, 2) || !TEST_int_eq(fn1_glob, local0))
        return 0;

    /* test a callback on multiple tasks, worker should terminate */

    local1 = 1;
    task1 = crypto_thread_start(NULL, test_thread_native_fn, &local1, CRYPTO_THREAD_START_AWAIT);
    if (!TEST_ptr(task1))
        return 0;

    local2 = 2;
    task2 = crypto_thread_start(NULL, test_thread_native_fn, &local2, CRYPTO_THREAD_START_AWAIT);
    if (!TEST_ptr(task2))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 0))
        return 0;

    retval = 0;
    if (!TEST_int_eq(crypto_thread_join(NULL, task1, &retval), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 0))
        return 0;

    if (!TEST_int_eq(retval, 2) || !TEST_int_eq(fn1_glob, local1))
        return 0;

    retval = 0;
    if (!TEST_int_eq(crypto_thread_join(NULL, task2, &retval), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 0))
        return 0;

    if (!TEST_int_eq(retval, 2) || !TEST_int_eq(fn1_glob, local2))
        return 0;

    if (!TEST_int_eq(crypto_thread_clean(NULL, task1),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_clean(NULL, task2),1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_disable(NULL), 1))
        return 0;

    OPENSSL_CTX_free(custom_ctx);

    return 1;
}

static int test_thread_spawn(void)
{
    void *task;
    uint32_t local;
    uint32_t retval;
    OPENSSL_CTX *custom_ctx;

    custom_ctx = OPENSSL_CTX_new();
    if (!TEST_ptr(custom_ctx))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enable(NULL, 1), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_cap(NULL, 2), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 2))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_cap(NULL, -1), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), -1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_cap(NULL, 1), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_spawn_worker(NULL, NULL), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 2))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_cap(NULL, -1), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), -1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_cap(NULL, 1), 1))
        return 0;

    /* this will test a worker */

    local = 2;
    retval = 0;
    task = crypto_thread_start(NULL, test_thread_native_fn, &local, CRYPTO_THREAD_START_AWAIT);
    if (!TEST_ptr(task))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(crypto_thread_join(NULL, task, &retval),1))
        return 0;

    if (!TEST_int_eq(retval, 2) || !TEST_int_eq(fn1_glob, local))
        return 0;

    if (!TEST_int_eq(crypto_thread_clean(NULL,task),1))
        return 0;

    /* this will test an internally spawned thread */

    local = 3;
    retval = 0;
    task = crypto_thread_start(NULL, test_thread_native_fn, &local, CRYPTO_THREAD_START_AWAIT);
    if (!TEST_ptr(task))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 0))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(custom_ctx), 0))
        return 0;

    if (!TEST_int_eq(crypto_thread_join(NULL, task, &retval),1))
        return 0;

    if (!TEST_int_eq(retval, 2) || !TEST_int_eq(fn1_glob, local))
        return 0;

    if (!TEST_int_eq(crypto_thread_clean(NULL,task),1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_disable(NULL), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    OPENSSL_CTX_free(custom_ctx);

    return 1;
}

static int test_thread_spawn_policy(void)
{
    uint32_t local;
    uint32_t retval;
    void *task1, *task2, *task3;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enable(NULL, 2), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 2))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_spawn_worker(NULL, NULL), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_spawn_worker(NULL, NULL), 1))
        return 0;


    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 4))
        return 0;

    local = 2;
    retval = 0;
    task1 = crypto_thread_start(NULL, test_thread_native_fn, &local, CRYPTO_THREAD_START_AWAIT);
    task2 = crypto_thread_start(NULL, test_thread_native_fn, &local, CRYPTO_THREAD_START_AWAIT);
    task3 = crypto_thread_start(NULL, test_thread_native_fn, &local, CRYPTO_THREAD_START_AWAIT);
    if (!TEST_ptr(task1) || !TEST_ptr(task2) || !TEST_ptr(task3))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_join(NULL, task1, &retval),1))
        return 0;
    if (!TEST_int_eq(crypto_thread_join(NULL, task2, &retval),1))
        return 0;
    if (!TEST_int_eq(crypto_thread_join(NULL, task3, &retval),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_clean(NULL,NULL),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 2))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_disable(NULL), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    return 1;
}


static int test_thread_disable_policy(void)
{
    uint32_t local;
    uint32_t retval;
    void *task1, *task2, *task3;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enable(NULL, 2), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 2))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_spawn_worker(NULL, NULL), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_spawn_worker(NULL, NULL), 1))
        return 0;


    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 4))
        return 0;

    local = 2;
    retval = 0;
    task1 = crypto_thread_start(NULL, test_thread_native_fn, &local, CRYPTO_THREAD_START_AWAIT);
    task2 = crypto_thread_start(NULL, test_thread_native_fn, &local, CRYPTO_THREAD_START_AWAIT);
    task3 = crypto_thread_start(NULL, test_thread_native_fn, &local, CRYPTO_THREAD_START_AWAIT);
    if (!TEST_ptr(task1) || !TEST_ptr(task2) || !TEST_ptr(task3))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_disable(NULL), 0))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_join(NULL, task1, &retval),1))
        return 0;
    if (!TEST_int_eq(crypto_thread_join(NULL, task2, &retval),1))
        return 0;
    if (!TEST_int_eq(crypto_thread_join(NULL, task3, &retval),1))
        return 0;
    if (!TEST_int_eq(crypto_thread_clean(NULL,NULL),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 2))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_disable(NULL), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    return 1;
}

static int test_thread_reuse(void)
{
    uint32_t retval;
    void *task1, *task2, *task3, *task4;
    uint32_t local1, local2, local3, local4;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enable(NULL, 1), 1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 1))
        return 0;

    retval = 0;
    local1 = 1 << 0;
    local2 = 1 << 1;
    local3 = 1 << 2;
    local4 = 1 << 3;
    task1 = crypto_thread_start(NULL, test_or1, &local1, CRYPTO_THREAD_START_AWAIT);
    task2 = crypto_thread_start(NULL, test_or1, &local2, CRYPTO_THREAD_START_AWAIT);
    task3 = crypto_thread_start(NULL, test_or1, &local3, CRYPTO_THREAD_START_AWAIT);
    task4 = crypto_thread_start(NULL, test_or1, &local4, CRYPTO_THREAD_START_AWAIT);
    if (!TEST_ptr(task1) || !TEST_ptr(task2) || !TEST_ptr(task3) || !TEST_ptr(task4))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 0))
        return 0;

    if (!TEST_int_eq(crypto_thread_join(NULL, task1, &retval),1))
        return 0;
    if (!TEST_int_eq(crypto_thread_join(NULL, task2, &retval),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 0))
        return 0;

    if (!TEST_int_eq(crypto_thread_join(NULL, task3, &retval),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_join(NULL, task4, &retval),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_clean(NULL,NULL),1))
        return 0;

    if (!TEST_int_eq(crypto_thread_get_available_threads(NULL), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_disable(NULL), 1))
        return 0;

    if (!TEST_int_eq(CRYPTO_THREAD_enabled(NULL), 0))
        return 0;

    return 1;
}

#endif

int setup_tests(void)
{
    ADD_TEST(test_lock);
    ADD_TEST(test_once);
    ADD_TEST(test_thread_local);
#if defined(OPENSSL_THREADS)
    ADD_TEST(test_thread_native);
    ADD_TEST(test_thread_native_multiple_joins);
    ADD_TEST(test_thread_enablement);
    ADD_TEST(test_thread_worker_cb);
    ADD_TEST(test_thread_spawn);
    ADD_TEST(test_thread_spawn_policy);
    ADD_TEST(test_thread_disable_policy);
    ADD_TEST(test_thread_reuse);
#endif
    return 1;
}
