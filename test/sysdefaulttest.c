/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <opentls/opentlsconf.h>

#include <string.h>
#include <opentls/evp.h>
#include <opentls/tls.h>
#include <opentls/tls1.h>
#include "testutil.h"

static tls_CTX *ctx;

static int test_func(void)
{
    if (!TEST_int_eq(tls_CTX_get_min_proto_version(ctx), TLS1_2_VERSION)
        && !TEST_int_eq(tls_CTX_get_max_proto_version(ctx), TLS1_2_VERSION)) {
        TEST_info("min/max version setting incorrect");
        return 0;
    }
    return 1;
}

int global_init(void)
{
    if (!OPENtls_init_tls(OPENtls_INIT_ENGINE_ALL_BUILTIN
                          | OPENtls_INIT_LOAD_CONFIG, NULL))
        return 0;
    return 1;
}

int setup_tests(void)
{
    if (!TEST_ptr(ctx = tls_CTX_new(TLS_method())))
        return 0;
    ADD_TEST(test_func);
    return 1;
}

void cleanup_tests(void)
{
    tls_CTX_free(ctx);
}
