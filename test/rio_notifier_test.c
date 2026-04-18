/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/rio_notifier.h"
#include "testutil.h"

static int test_rio_notifier_smoke(void)
{
    RIO_NOTIFIER nfy = { -1, -1 };
    int ret = 0;

    if (!TEST_true(ossl_rio_notifier_init(&nfy)))
        goto err;

    if (!TEST_int_ne(ossl_rio_notifier_as_fd(&nfy), (int)INVALID_SOCKET)
        || !TEST_true(ossl_rio_notifier_signal(&nfy))
        || !TEST_true(ossl_rio_notifier_unsignal(&nfy)))
        goto err;

    ret = 1;

err:
    ossl_rio_notifier_cleanup(&nfy);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_rio_notifier_smoke);
    return 1;
}
