/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include "crypto/sparse_array.h"
#include "internal/threads_common.h"

#if defined(OPENSSL_SYS_UNIX)
# include <unistd.h>
#endif

static int allocation_count;
static int fail_after;
static int fail_once;

static int should_fail(void)
{
    int current = allocation_count++;

    return fail_once ? current == fail_after : current >= fail_after;
}

static void *fail_malloc(size_t size, const char *file, int line)
{
    return should_fail() ? NULL : malloc(size);
}

static void *fail_realloc(void *ptr, size_t size, const char *file, int line)
{
    return should_fail() ? NULL : realloc(ptr, size);
}

static void fail_free(void *ptr, const char *file, int line)
{
    free(ptr);
}

static int test_lock(void)
{
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();

    if (lock != NULL) {
        CRYPTO_THREAD_lock_free(lock);
        return 0;
    }
    return 1;
}

static int test_tls(void)
{
    return !CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY,
        CRYPTO_THREAD_NO_CONTEXT, (void *)1);
}

static int test_sparse_array(void)
{
    OPENSSL_SA *sa = ossl_sa_new();

    if (fail_after == 0)
        return sa == NULL;
    if (sa == NULL)
        return 0;
    if (ossl_sa_set(sa, 0, (void *)1)) {
        ossl_sa_free(sa);
        return 0;
    }
    ossl_sa_free(sa);
    return 1;
}

static int test_control(void)
{
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();
    OPENSSL_SA *sa = NULL;
    int ok = 0;

    if (lock == NULL)
        return 0;
    CRYPTO_THREAD_lock_free(lock);
    if (!CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY,
            CRYPTO_THREAD_NO_CONTEXT, (void *)1)
        || (sa = ossl_sa_new()) == NULL
        || !ossl_sa_set(sa, 0, (void *)1))
        goto end;
    ok = 1;
end:
    ossl_sa_free(sa);
    return ok;
}

static int prepare_err_test(int init_strings)
{
    fail_after = INT_MAX;
    if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)
        || !CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY,
            CRYPTO_THREAD_NO_CONTEXT, (void *)1)
        || !CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY,
            CRYPTO_THREAD_NO_CONTEXT, NULL))
        return 0;
    if (init_strings)
        (void)ERR_reason_error_string(ERR_R_MALLOC_FAILURE);
    allocation_count = 0;
    return 1;
}

static int test_err_init(void)
{
    if (!prepare_err_test(0))
        return 0;
    fail_after = 1;
    return ERR_reason_error_string(ERR_R_MALLOC_FAILURE) == NULL
        && CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY,
               CRYPTO_THREAD_NO_CONTEXT)
            == NULL;
}

static int test_err_load(void)
{
    static const ERR_STRING_DATA strings[] = {
        { ERR_PACK(ERR_LIB_USER, 0, 1), "test reason" },
        { 0, NULL },
    };

    if (!prepare_err_test(1))
        return 0;
    fail_after = 0;
    return ERR_load_strings_const(strings)
        && CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY,
               CRYPTO_THREAD_NO_CONTEXT)
            == NULL;
}

int main(int argc, char **argv)
{
    int ok = 0;

    if (argc != 2)
        return EXIT_FAILURE;

    if (strcmp(argv[1], "control") == 0) {
        fail_after = INT_MAX;
    } else if (strcmp(argv[1], "err-init") == 0
        || strcmp(argv[1], "err-load") == 0) {
        fail_after = INT_MAX;
        fail_once = 1;
    } else if (strcmp(argv[1], "lock") == 0) {
        fail_after = 0;
    } else if (strcmp(argv[1], "tls-master") == 0) {
        fail_after = 0;
    } else if (strcmp(argv[1], "tls-sparse") == 0) {
        fail_after = 1;
    } else if (strcmp(argv[1], "sparse-array") == 0) {
        fail_after = 0;
    } else if (strcmp(argv[1], "sparse-node") == 0) {
        fail_after = 1;
    } else {
        return EXIT_FAILURE;
    }

#if defined(OPENSSL_SYS_UNIX)
    alarm(5);
#endif
    if (!CRYPTO_set_mem_functions(fail_malloc, fail_realloc, fail_free))
        return EXIT_FAILURE;

    if (strcmp(argv[1], "control") == 0)
        ok = test_control();
    else if (strcmp(argv[1], "err-init") == 0)
        ok = test_err_init();
    else if (strcmp(argv[1], "err-load") == 0)
        ok = test_err_load();
    else if (strcmp(argv[1], "lock") == 0)
        ok = test_lock();
    else if (strncmp(argv[1], "tls-", 4) == 0)
        ok = test_tls();
    else
        ok = test_sparse_array();

    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
