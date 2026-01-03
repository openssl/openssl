/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Allow use of deprecated functions without warning
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <string.h>
#include "testutil.h"
extern int do_dso1_setup(int cleanup);
extern int do_dso1_fini(void);
extern int do_dso2_setup(int cleanup);
extern int do_dso2_fini(void);

static int test_library_refcount_init_and_clean(void)
{
    int ret = 0;
    if (!TEST_true(do_dso1_setup(3)))
        goto err;
    if (!TEST_true(do_dso2_setup(3)))
        goto err;
    if (!TEST_true(do_dso1_fini()))
        goto err;
    if (!TEST_true(do_dso2_fini()))
        goto err;
    ret = 1;
err:
    return ret;
}

#ifndef OPENSSL_NO_DEPRECATED_4_0
static int test_library_refcount_legacy_usage(void)
{
    int ret = 0;
    if (!TEST_true(do_dso1_setup(3)))
        goto err;
    if (!TEST_true(do_dso2_setup(3)))
        goto err;
    if (!TEST_true(do_dso1_fini()))
        goto err;
    /*
     * Expressly call OPENSSL_cleanup here to ensure it works as a noop
     * Given that we are using the refcounting api above
     */
    OPENSSL_cleanup();
    if (!TEST_true(do_dso2_fini()))
        goto err;
    ret = 1;
err:
    return ret;
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_library_refcount_init_and_clean);
#ifndef OPENSSL_NO_DEPRECATED_4_0
    ADD_TEST(test_library_refcount_legacy_usage);
#endif
    return 1;
}
