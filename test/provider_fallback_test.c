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

static int test_fallback_provider(void)
{
    EVP_KEYMGMT *rsameth = NULL;
    const OSSL_PROVIDER *prov = NULL;
    int ok = 1;

    if (!TEST_true(OSSL_PROVIDER_available(NULL, "default"))
        || !TEST_ptr(rsameth = EVP_KEYMGMT_fetch(NULL, "RSA", NULL))
        || !TEST_ptr(prov = EVP_KEYMGMT_provider(rsameth))
        || !TEST_str_eq(OSSL_PROVIDER_name(prov), "default"))
        ok = 0;

    EVP_KEYMGMT_free(rsameth);
    return ok;
}

int setup_tests(void)
{
    /*
     * We must ensure that there is no OPENSSL_CONF defined.  Otherwise,
     * we risk that the configuration file contains statements that load
     * providers, which defeats the purpose of this test.
     */
    unsetenv("OPENSSL_CONF");

    ADD_TEST(test_fallback_provider);
    return 1;
}

