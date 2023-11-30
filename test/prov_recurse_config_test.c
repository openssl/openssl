/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "testutil.h"

static char *configfile = NULL;

/*
 * Load a provider config with a recursive section and check
 * for errors after the fact to ensure we caught and aborted the
 * load
 */

static int errfound = 0;

static int err_cb(const char *str, size_t len, void *u)
{
    errfound = 1;
    return 1;
}

static int test_recursive_config(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    int testresult = 0;

    if (!TEST_ptr(configfile))
        goto err;

    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(OSSL_LIB_CTX_load_config(ctx, configfile)))
        goto err;

    ERR_print_errors_cb(err_cb, NULL);

    /* test passes if we found a load error */
    if (errfound == 1)
        testresult = 1;
 err:
    OSSL_LIB_CTX_free(ctx);
    return testresult;
}

OPT_TEST_DECLARE_USAGE("configfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(configfile = test_get_argument(0)))
        return 0;

    ADD_TEST(test_recursive_config);
    return 1;
}
