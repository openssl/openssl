/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stddef.h>
#include <opentls/crypto.h>
#include "internal/provider.h"
#include "testutil.h"

extern Otls_provider_init_fn PROVIDER_INIT_FUNCTION_NAME;

static char buf[256];
static Otls_PARAM greeting_request[] = {
    { "greeting", Otls_PARAM_UTF8_STRING, buf, sizeof(buf), 0 },
    { NULL, 0, NULL, 0, 0 }
};

static int test_provider(Otls_PROVIDER *prov, const char *expected_greeting)
{
    const char *greeting = NULL;
    int ret = 0;

    ret =
        TEST_true(otls_provider_activate(prov))
        && TEST_true(otls_provider_get_params(prov, greeting_request))
        && TEST_ptr(greeting = greeting_request[0].data)
        && TEST_size_t_gt(greeting_request[0].data_size, 0)
        && TEST_str_eq(greeting, expected_greeting);

    TEST_info("Got this greeting: %s\n", greeting);
    otls_provider_free(prov);
    return ret;
}

static const char *expected_greeting1(const char *name)
{
    static char expected_greeting[256] = "";

    BIO_snprintf(expected_greeting, sizeof(expected_greeting),
                 "Hello Opentls %.20s, greetings from %s!",
                 OPENtls_VERSION_STR, name);

    return expected_greeting;
}

static int test_builtin_provider(void)
{
    const char *name = "p_test_builtin";
    Otls_PROVIDER *prov = NULL;

    return
        TEST_ptr(prov =
                 otls_provider_new(NULL, name, PROVIDER_INIT_FUNCTION_NAME, 0))
        && test_provider(prov, expected_greeting1(name));
}

#ifndef NO_PROVIDER_MODULE
static int test_loaded_provider(void)
{
    const char *name = "p_test";
    Otls_PROVIDER *prov = NULL;

    return
        TEST_ptr(prov = otls_provider_new(NULL, name, NULL, 0))
        && test_provider(prov, expected_greeting1(name));
}

static int test_configured_provider(void)
{
    const char *name = "p_test_configured";
    Otls_PROVIDER *prov = NULL;
    /* This MUST match the config file */
    const char *expected_greeting =
        "Hello Opentls, greetings from Test Provider";

    return
        TEST_ptr(prov = otls_provider_find(NULL, name, 0))
        && test_provider(prov, expected_greeting);
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_builtin_provider);
#ifndef NO_PROVIDER_MODULE
    ADD_TEST(test_loaded_provider);
    ADD_TEST(test_configured_provider);
#endif
    return 1;
}

