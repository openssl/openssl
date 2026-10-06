/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <sys/stat.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include "testutil.h"

static char *cfg1 = NULL;
static char *cfg2 = NULL;

static const struct cfg_proto_version {
    char **file;
    long minver, maxver;
} cfg_proto_version[] = {
    { &cfg1, TLS1_1_VERSION, TLS1_1_VERSION },
    { &cfg2, TLS1_2_VERSION, TLS1_2_VERSION }
};

static int test_config_libctx_global(int idx)
{
    const struct cfg_proto_version *cpv = &cfg_proto_version[idx];
    SSL_CTX *ctx = NULL;
    int test;

    CONF_modules_load_file(*cpv->file, NULL, 0);

    test = TEST_ptr(ctx = SSL_CTX_new(TLS_method()))
        && TEST_int_eq(SSL_CTX_get_min_proto_version(ctx), cpv->minver)
        && TEST_int_eq(SSL_CTX_get_max_proto_version(ctx), cpv->maxver);

    CONF_modules_unload(0);
    SSL_CTX_free(ctx);
    return test;
}

static int test_config_libctx_local(void)
{
    OSSL_LIB_CTX *lib1 = NULL, *lib2 = NULL;
    SSL_CTX *ctx1 = NULL, *ctx2 = NULL;
    int test;

    test = TEST_ptr(lib1 = OSSL_LIB_CTX_new())
        && TEST_ptr(lib2 = OSSL_LIB_CTX_new())
        && TEST_int_eq(OSSL_LIB_CTX_load_config(lib1, cfg1), 1)
        && TEST_int_eq(OSSL_LIB_CTX_load_config(lib2, cfg2), 1)
        && TEST_ptr(ctx1 = SSL_CTX_new_ex(lib1, NULL, TLS_server_method()))
        && TEST_ptr(ctx2 = SSL_CTX_new_ex(lib2, NULL, TLS_server_method()))
        && TEST_int_eq(SSL_CTX_get_min_proto_version(ctx1), TLS1_1_VERSION)
        && TEST_int_eq(SSL_CTX_get_min_proto_version(ctx2), TLS1_2_VERSION)
        && TEST_int_eq(SSL_CTX_get_max_proto_version(ctx1), TLS1_1_VERSION)
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

    ADD_TEST(test_config_libctx_local);
    ADD_ALL_TESTS(test_config_libctx_global, OSSL_NELEM(cfg_proto_version));

    return test;
}
