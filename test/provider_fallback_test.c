/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include "testutil.h"

static int test_provider(OPENSSL_CTX *ctx)
{
    EVP_KEYMGMT *rsameth = NULL;
    const OSSL_PROVIDER *prov = NULL;
    int ok;

    ok = TEST_true(OSSL_PROVIDER_available(ctx, "default"))
        && TEST_ptr(rsameth = EVP_KEYMGMT_fetch(ctx, "RSA", NULL))
        && TEST_ptr(prov = EVP_KEYMGMT_provider(rsameth))
        && TEST_str_eq(OSSL_PROVIDER_name(prov), "default");

    EVP_KEYMGMT_free(rsameth);
    return ok;
}

static int test_fallback_provider(void)
{
    return test_provider(NULL);
}

static int test_explicit_provider(void)
{
    OPENSSL_CTX *ctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    int ok;

    ok = TEST_ptr(ctx = OPENSSL_CTX_new())
        && TEST_ptr(prov = OSSL_PROVIDER_load(ctx, "default"))
        && test_provider(ctx)
        && TEST_true(OSSL_PROVIDER_unload(prov));

    OPENSSL_CTX_free(ctx);
    return ok;
}


int setup_tests(void)
{
    /*
     * We must ensure that there is no OPENSSL_CONF defined.  Otherwise,
     * we risk that the configuration file contains statements that load
     * providers, which defeats the purpose of this test.
     */
#ifndef _WIN32
    unsetenv("OPENSSL_CONF");
#else
    /*
     * Windows doesn't have unsetenv().  However, using _putenv() and giving
     * the environment variable the empty value has the same effect, according
     * to documentation.
     */
    _putenv("OPENSSL_CONF=");
#endif

    ADD_TEST(test_fallback_provider);
    ADD_TEST(test_explicit_provider);
    return 1;
}

