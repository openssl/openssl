/*
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#include "testutil.h"

static int test_load_cert_file(int n)
{
    int ret = 0;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;
    STACK_OF(X509) *certs = NULL;
    const char *chain = test_get_argument(n);

    if (TEST_ptr(store = X509_STORE_new())
        && TEST_ptr(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))
        && TEST_true(X509_load_cert_file(lookup, chain, X509_FILETYPE_PEM))
        && TEST_ptr(certs = X509_STORE_get1_all_certs(store))
        && TEST_int_eq(sk_X509_num(certs), 4))
        ret = 1;

    OSSL_STACK_OF_X509_free(certs);
    X509_STORE_free(store);
    return ret;
}

OPT_TEST_DECLARE_USAGE("cert.pem...\n")

int setup_tests(void)
{
    size_t n;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    n = test_get_argument_count();
    if (!TEST_int_gt(n, 0))
        return 0;

    ADD_ALL_TESTS(test_load_cert_file, n);
    return 1;
}
