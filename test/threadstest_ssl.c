/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined(_WIN32)
# include <windows.h>
#endif

#include <openssl/ssl.h>
#include "internal/nelem.h"
#include "testutil.h"
#include "threadstest.h"

#define MAXIMUM_THREADS 20

static int success;

static void thread_ssl_ctx(void)
{
    SSL_CTX *ctx;

    OSSL_sleep(0);
    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method())))
        success = 0;
    SSL_CTX_free(ctx);
}

static int test_ssl_ctx_multithread(void)
{
    thread_t thread[MAXIMUM_THREADS];
    size_t i;

    success = 1;

    for (i = 0; i < OSSL_NELEM(thread); ++i) {
        if (!TEST_true(run_thread(&thread[i], thread_ssl_ctx)))
            return 0;
    }
    for (i = 0; i < OSSL_NELEM(thread); ++i) {
        if (!TEST_true(wait_for_thread(thread[i])))
            return 0;
    }
    return TEST_true(success);
}

int setup_tests(void)
{
    ADD_TEST(test_ssl_ctx_multithread);
    return 1;
}
