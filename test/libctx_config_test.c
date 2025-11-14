/*
 * Copyright 2021-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include "testutil.h"

static char *cfg1 = NULL;
static char *cfg2 = NULL;

static int test_libctx_config(void)
{
    OSSL_LIB_CTX *lib1 = NULL, *lib2 = NULL;
    SSL_CTX *ctx1 = NULL, *ctx2 = NULL;
    int test;

    test = TEST_ptr(lib1 = OSSL_LIB_CTX_new())
        && TEST_ptr(lib2 = OSSL_LIB_CTX_new())
        && TEST_true(OSSL_LIB_CTX_load_config(lib1, cfg1))
        && TEST_true(OSSL_LIB_CTX_load_config(lib2, cfg2))
        && TEST_ptr(ctx1 = SSL_CTX_new_ex(lib1, NULL, TLS_server_method()))
        && TEST_ptr(ctx2 = SSL_CTX_new_ex(lib2, NULL, TLS_server_method()))
        && TEST_int_eq(SSL_CTX_get_max_proto_version(ctx1), TLS1_2_VERSION)
        && TEST_int_eq(SSL_CTX_get_max_proto_version(ctx2), TLS1_2_VERSION);

    SSL_CTX_free(ctx1);
    SSL_CTX_free(ctx2);
    OSSL_LIB_CTX_free(lib1);
    OSSL_LIB_CTX_free(lib2);
    return test;
}

OPT_TEST_DECLARE_USAGE("configfile\n")

int setup_tests(void)
{
    int test;
    test = TEST_true(test_skip_common_options())
        && TEST_ptr(cfg1 = test_get_argument(0))
        && TEST_ptr(cfg2 = test_get_argument(1));

    ADD_TEST(test_libctx_config);
    return test;
}
