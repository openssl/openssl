/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "crypto/cryptlib.h"
#include "crypto/err.h"
#include "internal/e_os.h"
#include "internal/threads_common.h"

static int armed;
static int persistent;
static int allocation_count;
static int fail_at;
static int injected;
static int live_allocations;
static int callbacks;

/* Fail bootstrap allocations persistently, and other allocations once. */
static int should_fail(void)
{
    if (!armed)
        return 0;
    if (++allocation_count > 4096) {
        fprintf(stderr, "Allocation-error reporting recursed\n");
        _Exit(2);
    }
    if (fail_at != 0 && (persistent ? allocation_count >= fail_at : allocation_count == fail_at)) {
        injected = 1;
        return 1;
    }
    return 0;
}

static void *test_malloc(size_t size, const char *file, int line)
{
    void *ptr;

    if (should_fail())
        return NULL;
    ptr = malloc(size);
    if (ptr != NULL)
        ++live_allocations;
    return ptr;
}

static void *test_realloc(void *ptr, size_t size, const char *file, int line)
{
    void *result;

    if (should_fail())
        return NULL;
    result = realloc(ptr, size);
    if (result != NULL && ptr == NULL)
        ++live_allocations;
    return result;
}

static void test_free(void *ptr, const char *file, int line)
{
    if (ptr != NULL)
        --live_allocations;
    free(ptr);
}

static void on_thread_stop(void *arg)
{
    ++callbacks;
}

/* Run before test infrastructure can initialise OpenSSL or its error queue. */
int main(int argc, char **argv)
{
    void *state;
    int result = 0, ret = 1;

    alarm(15);
    if (argc != 3 || !CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free))
        return 2;
    fail_at = atoi(argv[2]);
    persistent = strcmp(argv[1], "lock") == 0 || strcmp(argv[1], "tls") == 0;
    if (fail_at < 0 || fail_at > 100)
        return 2;

    if (strcmp(argv[1], "lock") == 0) {
        CRYPTO_RWLOCK *lock;

        armed = 1;
        lock = CRYPTO_THREAD_lock_new();
        result = lock != NULL;
        CRYPTO_THREAD_lock_free(lock);
    } else {
        if (!OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, NULL))
            goto end;
        if (strcmp(argv[1], "tls") == 0) {
            armed = 1;
            result = CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY,
                CRYPTO_THREAD_NO_CONTEXT, (void *)-1);
            if (injected && CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY, CRYPTO_THREAD_NO_CONTEXT, (void *)-1))
                goto end;
        } else {
            /* Warm TLS metadata without creating an error state or handlers. */
            if (!err_shelve_state(&state))
                goto end;
            err_unshelve_state(state);
            if (strcmp(argv[1], "registry") == 0) {
                armed = 1;
                result = ossl_init_thread_start(NULL, NULL, on_thread_stop);
            } else if (strcmp(argv[1], "strings") == 0) {
                armed = 1;
                result = ERR_get_next_error_library() != 0;
            } else if (strcmp(argv[1], "strings-insert") == 0) {
                ERR_STRING_DATA strings[129];
                int i, library = ERR_get_next_error_library();

                if (library == 0)
                    goto end;
                for (i = 0; i < 128; ++i) {
                    strings[i].error = ERR_PACK(library, 0, i + 1);
                    strings[i].string = "allocation failure test";
                }
                strings[128].error = 0;
                strings[128].string = NULL;
                armed = 1;
                result = ERR_load_strings_const(strings);
                armed = 0;
                if (!result || ERR_get_error() != 0)
                    goto end;
                ERR_unload_strings(library, strings);
                ret = 0;
                goto end;
            } else {
                goto end;
            }
        }
    }
    if (result == !injected)
        ret = 0;
end:
    armed = 0;
    OPENSSL_thread_stop();
    if (strcmp(argv[1], "registry") == 0 && callbacks != result)
        ret = 1;
    OPENSSL_cleanup();
    ossl_cleanup_destructor();
    if (live_allocations != 0)
        ret = 1;
    fprintf(stderr, "%s fail_at=%d allocations=%d injected=%d live=%d result=%d\n",
        argv[1], fail_at, allocation_count, injected, live_allocations, result);
    return ret;
}
