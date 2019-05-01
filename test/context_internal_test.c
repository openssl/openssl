/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the OpenSSL library context */

#include "internal/cryptlib.h"
#include "testutil.h"

/*
 * Everything between BEGIN EXAMPLE and END EXAMPLE is copied from
 * doc/internal/man3/openssl_ctx_get_data.pod
 */

/*
 * ======================================================================
 * BEGIN EXAMPLE
 */

typedef struct foo_st {
    int i;
    void *data;
} FOO;

static void *foo_new(OPENSSL_CTX *ctx)
{
    FOO *ptr = OPENSSL_zalloc(sizeof(*ptr));
    if (ptr != NULL)
        ptr->i = 42;
    return ptr;
}
static void foo_free(void *ptr)
{
    OPENSSL_free(ptr);
}
static const OPENSSL_CTX_METHOD foo_method = {
    foo_new,
    foo_free
};

/*
 * END EXAMPLE
 * ======================================================================
 */

static int test_context(OPENSSL_CTX *ctx)
{
    FOO *data = NULL;

    return TEST_ptr(data = openssl_ctx_get_data(ctx, 0, &foo_method))
        /* OPENSSL_zalloc in foo_new() initialized it to zero */
        && TEST_int_eq(data->i, 42);
}

static int test_app_context(void)
{
    OPENSSL_CTX *ctx = NULL;
    int result =
        TEST_ptr(ctx = OPENSSL_CTX_new())
        && test_context(ctx);

    OPENSSL_CTX_free(ctx);
    return result;
}

static int test_def_context(void)
{
    return test_context(NULL);
}

int setup_tests(void)
{
    ADD_TEST(test_app_context);
    ADD_TEST(test_def_context);
    return 1;
}
