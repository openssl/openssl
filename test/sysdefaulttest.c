/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/opensslconf.h>

#include <string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include "testutil.h"


static int test_func(void)
{
    int ret = 1;
    SSL_CTX *ctx;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method())))
        return 0;
    if (!TEST_int_eq(SSL_CTX_get_min_proto_version(ctx), TLS1_2_VERSION)
        && !TEST_int_eq(SSL_CTX_get_max_proto_version(ctx), TLS1_2_VERSION)) {
        TEST_info("min/max version setting incorrect");
        ret = 0;
    }
    SSL_CTX_free(ctx);
    return ret;
}

int global_init(void)
{
    if (!OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN
                          | OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 0;
    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_func);
    return 1;
}
