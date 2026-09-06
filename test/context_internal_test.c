/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the OpenSSL library context */

#include "internal/cryptlib.h"
#include "internal/pool.h"
#include "testutil.h"

static int test_set0_default(void)
{
    OSSL_LIB_CTX *global = OSSL_LIB_CTX_get0_global_default();
    OSSL_LIB_CTX *local = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *prev;
    int testresult = 0;

    if (!TEST_ptr(global)
        || !TEST_ptr(local)
        || !TEST_ptr_eq(global, OSSL_LIB_CTX_set0_default(NULL)))
        goto err;

    /* Check we can change the local default context */
    if (!TEST_ptr(prev = OSSL_LIB_CTX_set0_default(local))
        || !TEST_ptr_eq(global, prev))
        goto err;

    /* Calling OSSL_LIB_CTX_set0_default() with a NULL should be a no-op */
    if (!TEST_ptr_eq(local, OSSL_LIB_CTX_set0_default(NULL)))
        goto err;

    /* Global default should be unchanged */
    if (!TEST_ptr_eq(global, OSSL_LIB_CTX_get0_global_default()))
        goto err;

    /* Check we can swap back to the global default */
    if (!TEST_ptr(prev = OSSL_LIB_CTX_set0_default(global))
        || !TEST_ptr_eq(local, prev))
        goto err;

    testresult = 1;
err:
    OSSL_LIB_CTX_free(local);
    return testresult;
}

static int test_set_get_conf_diagnostics(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    int res = 0;

    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_false(OSSL_LIB_CTX_get_conf_diagnostics(ctx)))
        goto err;

    OSSL_LIB_CTX_set_conf_diagnostics(ctx, 1);

    if (!TEST_true(OSSL_LIB_CTX_get_conf_diagnostics(ctx)))
        goto err;

    OSSL_LIB_CTX_set_conf_diagnostics(ctx, 0);

    if (!TEST_false(OSSL_LIB_CTX_get_conf_diagnostics(ctx)))
        goto err;

    res = 1;
err:
    OSSL_LIB_CTX_free(ctx);
    return res;
}

/*
 * There is one certificate pool, reached through every context that has not
 * disabled pooling; buffers made in it share their bytes.
 */
static int test_certificate_pool(void)
{
    static const unsigned char bytes[] = "certificate";
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    CRYPTO_BUFFER_POOL *pool;
    CRYPTO_BUFFER *a = NULL, *b = NULL;
    int res = 0;

    if (!TEST_ptr(ctx)
        || !TEST_ptr(pool = ossl_lib_ctx_get0_certificate_pool(ctx))
        || !TEST_ptr_eq(pool, ossl_lib_ctx_get0_certificate_pool(NULL))
        || !TEST_ptr(a = CRYPTO_BUFFER_new(bytes, sizeof(bytes), pool))
        || !TEST_ptr(b = CRYPTO_BUFFER_new(bytes, sizeof(bytes), pool))
        || !TEST_ptr_eq(a, b)
        || !TEST_true(OSSL_LIB_CTX_set_certificate_pool(ctx, 0))
        || !TEST_ptr_null(ossl_lib_ctx_get0_certificate_pool(ctx))
        || !TEST_true(OSSL_LIB_CTX_set_certificate_pool(ctx, 1))
        || !TEST_ptr_eq(pool, ossl_lib_ctx_get0_certificate_pool(ctx)))
        goto err;

    res = 1;
err:
    CRYPTO_BUFFER_free(a);
    CRYPTO_BUFFER_free(b);
    OSSL_LIB_CTX_free(ctx);
    return res;
}

int setup_tests(void)
{
    ADD_TEST(test_set0_default);
    ADD_TEST(test_set_get_conf_diagnostics);
    ADD_TEST(test_certificate_pool);
    return 1;
}
