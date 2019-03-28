/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#include "testutil.h"

static int test_509_dup_cert(int n)
{
    int ret = 0;
    X509_STORE_CTX *sctx = NULL;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;
    const char *cert_f = test_get_argument(n);

    if (TEST_ptr(store = X509_STORE_new())
        && TEST_ptr(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))
        && TEST_true(X509_load_cert_file(lookup, cert_f, X509_FILETYPE_PEM))
        && TEST_true(X509_load_cert_file(lookup, cert_f, X509_FILETYPE_PEM)))
        ret = 1;

    X509_STORE_CTX_free(sctx);
    X509_STORE_free(store);
    return ret;
}

static int test_X509_chain_up_ref(void)
{
    STACK_OF(X509) *chain1 = sk_X509_new_null();
    STACK_OF(X509) *chain2 = NULL;
    X509 *x1 = X509_new();
    X509 *x2 = X509_new();
    int i, ret = 0;

    if (!TEST_ptr(chain1)
            || !TEST_ptr(x1)
            || !TEST_ptr(x2))
        goto err;

    if (!TEST_true(sk_X509_push(chain1, x1)))
        goto err;
    x1 = NULL;

    if (!TEST_true(sk_X509_push(chain1, x2)))
        goto err;
    x2 = NULL;

    chain2 = X509_chain_up_ref(chain1);
    if (!TEST_ptr(chain2)
            || !TEST_int_eq(sk_X509_num(chain1), sk_X509_num(chain2)))
        goto err;

    for (i = 0; i < sk_X509_num(chain1); i++) {
        if (!TEST_true(sk_X509_value(chain1, i) == sk_X509_value(chain2, i)))
            goto err;
    }

    ret = 1;
 err:
    sk_X509_pop_free(chain1, X509_free);
    sk_X509_pop_free(chain2, X509_free);
    X509_free(x1);
    X509_free(x2);

    return ret;
}

OPT_TEST_DECLARE_USAGE("cert.pem...\n")

int setup_tests(void)
{
    size_t n = test_get_argument_count();

    if (!TEST_int_gt(n, 0))
        return 0;

    ADD_ALL_TESTS(test_509_dup_cert, n);
    ADD_TEST(test_X509_chain_up_ref);

    return 1;
}
