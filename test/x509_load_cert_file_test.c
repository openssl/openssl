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

static const char *chain;
static const char *crl;

static int test_load_cert_file(void)
{
    int ret = 0;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;
    STACK_OF(X509) *certs = NULL;

    if (TEST_ptr(store = X509_STORE_new())
        && TEST_ptr(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))
        && TEST_true(X509_load_cert_file(lookup, chain, X509_FILETYPE_PEM))
        && TEST_ptr(certs = X509_STORE_get1_all_certs(store))
        && TEST_int_eq(sk_X509_num(certs), 4))
        ret = 1;

    if (crl != NULL && !TEST_true(X509_load_crl_file(lookup, crl, X509_FILETYPE_PEM)))
        ret = 0;

    OSSL_STACK_OF_X509_free(certs);
    X509_STORE_free(store);
    return ret;
}

OPT_TEST_DECLARE_USAGE("cert.pem [crl.pem]\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    chain = test_get_argument(0);
    if (chain == NULL)
        return 0;

    crl = test_get_argument(1);

    ADD_TEST(test_load_cert_file);
    return 1;
}
