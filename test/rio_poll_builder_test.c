/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl/rio/poll_builder.h"
#include "testutil.h"

static int test_duplicate_fd(void)
{
#if RIO_POLL_METHOD == RIO_POLL_METHOD_POLL
    RIO_POLL_BUILDER rpb;
    struct pollfd *pfds;
    int ret = 0;

    if (!TEST_true(ossl_rio_poll_builder_init(&rpb)))
        return 0;

    if (!TEST_true(ossl_rio_poll_builder_add_fd(&rpb, 0, 1, 0))
        || !TEST_true(ossl_rio_poll_builder_add_fd(&rpb, 0, 0, 1)))
        goto out;

    pfds = rpb.pfd_heap != NULL ? rpb.pfd_heap : rpb.pfds;
    if (!TEST_size_t_eq(rpb.pfd_num, 1)
        || !TEST_int_eq(pfds[0].events, POLLIN | POLLOUT))
        goto out;

    ret = 1;
out:
    ossl_rio_poll_builder_cleanup(&rpb);
    return ret;
#else
    return TEST_skip("poll() backend is not in use");
#endif
}

int setup_tests(void)
{
    ADD_TEST(test_duplicate_fd);
    return 1;
}
