/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
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

static int test_provider(OSSL_LIB_CTX **libctx, const char *name)
{
    OSSL_PROVIDER *prov = NULL;
    const char *greeting = NULL;
    char expected_greeting[256];
    int ok = 0;
    long err;

    BIO_snprintf(expected_greeting, sizeof(expected_greeting),
                 "Hello OpenSSL %.20s, greetings from %s!",
                 OPENSSL_VERSION_STR, name);

    if (!TEST_ptr(prov = OSSL_PROVIDER_load(*libctx, name))
            || !TEST_true(OSSL_PROVIDER_get_params(prov, greeting_request))
            || !TEST_ptr(greeting = greeting_request[0].data)
            || !TEST_size_t_gt(greeting_request[0].data_size, 0)
            || !TEST_str_eq(greeting, expected_greeting)
            || !TEST_true(OSSL_PROVIDER_unload(prov)))
        goto err;

    prov = NULL;

    /*
     * We must free the libctx to force the provider to really be unloaded from
     * memory
     */
    OSSL_LIB_CTX_free(*libctx);
    *libctx = NULL;

    /* Make sure we got the error we were expecting */
    err = ERR_peek_last_error();
    if (!TEST_int_gt(err, 0)
            || !TEST_int_eq(ERR_GET_REASON(err), 1))
        goto err;

    /* We print out all the data to make sure it can still be accessed */
    ERR_print_errors_fp(stderr);
    ok = 1;
 err:
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(*libctx);
    *libctx = NULL;
    return ok;
}

static int test_builtin_provider(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    const char *name = "p_test_builtin";
    int ok;

    ok =
        TEST_ptr(libctx)
        && TEST_true(OSSL_PROVIDER_add_builtin(libctx, name,
                                               PROVIDER_INIT_FUNCTION_NAME))
        && test_provider(&libctx, name);

    OSSL_LIB_CTX_free(libctx);

    return ok;
}

#ifndef NO_PROVIDER_MODULE
static int test_loaded_provider(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    const char *name = "p_test";

    if (!TEST_ptr(libctx))
        return 0;

    /* test_provider will free libctx as part of the test */
    return test_provider(&libctx, name);
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

