/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the OpenSSL library context */

#include "internal/cryptlib.h"
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

int setup_tests(void)
{
    ADD_TEST(test_set0_default);
    return 1;
}
