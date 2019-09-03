/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/provider.h>
#include "testutil.h"

extern OSSL_provider_init_fn PROVIDER_INIT_FUNCTION_NAME;

static char buf[256];
static OSSL_PARAM greeting_request[] = {
    { "greeting", OSSL_PARAM_UTF8_STRING, buf, sizeof(buf) },
    { NULL, 0, NULL, 0, 0 }
};

static int test_provider(const char *name)
{
    OSSL_PROVIDER *prov = NULL;
    const char *greeting = NULL;
    char expected_greeting[256];

    BIO_snprintf(expected_greeting, sizeof(expected_greeting),
                 "Hello OpenSSL %.20s, greetings from %s!",
                 OPENSSL_VERSION_STR, name);

    return
        TEST_ptr(prov = OSSL_PROVIDER_load(NULL, name))
        && TEST_true(OSSL_PROVIDER_get_params(prov, greeting_request))
        && TEST_ptr(greeting = greeting_request[0].data)
        && TEST_size_t_gt(greeting_request[0].data_size, 0)
        && TEST_str_eq(greeting, expected_greeting)
        && TEST_true(OSSL_PROVIDER_unload(prov));
}

static int test_builtin_provider(void)
{
    const char *name = "p_test_builtin";

    return
        TEST_true(OSSL_PROVIDER_add_builtin(NULL, name,
                                            PROVIDER_INIT_FUNCTION_NAME))
        && test_provider(name);
}

#ifndef NO_PROVIDER_MODULE
static int test_loaded_provider(void)
{
    const char *name = "p_test";

    return test_provider(name);
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_builtin_provider);
#ifndef NO_PROVIDER_MODULE
    ADD_TEST(test_loaded_provider);
#endif
    return 1;
}

