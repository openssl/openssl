/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include "internal/provider.h"
#include "testutil.h"

#if !defined(DSO_VMS) && !defined(DSO_DLCFN) && !defined(DSO_DL) \
    && !defined(DSO_WIN32) && !defined(DSO_DLFCN)
# define OPENSSL_NO_DSO
#endif

extern OSSL_provider_init_fn PROVIDER_INIT_FUNCTION_NAME;

static char buf[256];
static size_t buf_l = 0;
static OSSL_PARAM greeting_request[] = {
    { "greeting", OSSL_PARAM_UTF8_STRING, buf, sizeof(buf), &buf_l },
    { NULL, 0, NULL, 0, NULL }
};

static int test_provider(OSSL_PROVIDER *prov)
{
    const char *name = NULL;
    const char *greeting = NULL;
    char expected_greeting[256];
    int ret = 0;

    if (!TEST_ptr(name = ossl_provider_name(prov)))
        return 0;

    BIO_snprintf(expected_greeting, sizeof(expected_greeting),
                 "Hello OpenSSL %.20s, greetings from %s!",
                 OPENSSL_VERSION_STR, name);

    ret =
        TEST_true(ossl_provider_activate(prov))
        && TEST_true(ossl_provider_get_params(prov, greeting_request))
        && TEST_ptr(greeting = greeting_request[0].data)
        && TEST_size_t_gt(greeting_request[0].data_size, 0)
        && TEST_str_eq(greeting, expected_greeting);

    ossl_provider_free(prov);
    return ret;
}

static int test_builtin_provider(void)
{
    const char *name = "p_test_builtin";
    OSSL_PROVIDER *prov = NULL;

    return
        TEST_ptr(prov =
                 ossl_provider_new(NULL, name, PROVIDER_INIT_FUNCTION_NAME))
        && test_provider(prov);
}

#ifndef OPENSSL_NO_DSO
static int test_loaded_provider(void)
{
    const char *name = "p_test";
    OSSL_PROVIDER *prov = NULL;

    return
        TEST_ptr(prov = ossl_provider_new(NULL, name, NULL))
        && test_provider(prov);
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_builtin_provider);
#ifndef OPENSSL_NO_DSO
    ADD_TEST(test_loaded_provider);
#endif
    return 1;
}

