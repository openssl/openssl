/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include "testutil.h"

/*
 * t: API type, "cert" for X509_ and "crl" for X509_CRL_ APIs.
 * c1: path of a cert in PEM format
 * c2: path of a cert in PEM format
 * e: expected, "ok" for success, "failed" for what should fail.
 */
static const char *t;
static const char *c1;
static const char *c2;
static const char *e;

static int test_x509_is_equal(void)
{
    BIO *bio1 = NULL;
    BIO *bio2 = NULL;
    X509 *x509_1 = NULL;
    X509 *x509_2 = NULL;
    X509_CRL *x509_crl1 = NULL;
    X509_CRL *x509_crl2 = NULL;
    int ret = 0, type = 0, expected = 0, result = 0;

    /*
     * we check them first thus if fails we don't need to do
     * those PEM parsing operations.
     */
    if (strcmp(t, "cert") == 0) {
        type = 1;
    } else if (strcmp(t, "crl") == 0) {
        type = 2;
    } else {
        TEST_error("invalid 'type'");
        goto failed;
    }

    if (strcmp(e, "ok") == 0) {
        expected = 1;
    } else if (strcmp(e, "failed") == 0) {
        expected = 0;
    } else {
        TEST_error("invalid 'expected'");
        goto failed;
    }

    /* process first cert or crl */
    if (!TEST_ptr(bio1 = BIO_new_file(c1, "r")))
        goto failed;
    /* process the second cert or crl */
    if (!TEST_ptr(bio2 = BIO_new_file(c2, "r")))
        goto failed;

    switch (type) {
    case 1:
        x509_1 = PEM_read_bio_X509(bio1, NULL, NULL, NULL);
        if (x509_1 == NULL) {
            TEST_error("read first PEM x509 failed");
            goto failed;
        }
        x509_2 = PEM_read_bio_X509(bio2, NULL, NULL, NULL);
        if (x509_2 == NULL) {
            TEST_error("read second PEM x509 failed");
            goto failed;
        }
        result = X509_is_equal(x509_1, x509_2);
        break;
    case 2:
        x509_crl1 = PEM_read_bio_X509_CRL(bio1, NULL, NULL, NULL);
        if (x509_crl1 == NULL) {
            TEST_error("read first PEM x509 crl failed");
            goto failed;
        }
        x509_crl2 = PEM_read_bio_X509_CRL(bio2, NULL, NULL, NULL);
        if (x509_crl2 == NULL) {
            TEST_error("read first PEM x509 crl failed");
            goto failed;
        }
        result = X509_CRL_is_equal(x509_crl1, x509_crl2);
        break;
    default:
        /* should never be here */
        break;
    }

    if (!TEST_int_eq(result, expected)) {
        TEST_error("X509 comparison: expected: %d, got: %d", expected, result);
        goto failed;
    }

    ret = 1;
failed:
    BIO_free(bio1);
    BIO_free(bio2);
    X509_free(x509_1);
    X509_free(x509_2);
    X509_CRL_free(x509_crl1);
    X509_CRL_free(x509_crl2);
    return ret;
}

const OPTIONS *test_get_options(void)
{
    enum { OPT_TEST_ENUM };
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_WITH_EXTRA_USAGE("type cert1 cert2 expected\n"),
        { OPT_HELP_STR, 1, '-', "type\t\tvalue must be 'cert' or 'crl'\n" },
        { OPT_HELP_STR, 1, '-', "cert1 name\tCertificate filename\n" },
        { OPT_HELP_STR, 1, '-', "cert2 name\tCertificate filename\n" },
        { OPT_HELP_STR, 1, '-', "expected\tthe expected return value\n" },
        { NULL }
    };

    return test_options;
}

int setup_tests(void)
{
    if (!TEST_int_eq(test_get_argument_count(), 4))
        return 0;

    if (!TEST_ptr(t = test_get_argument(0))
            || !TEST_ptr(c1 = test_get_argument(1))
            || !TEST_ptr(c2 = test_get_argument(2))
            || !TEST_ptr(e = test_get_argument(3)))
        return 0;

    ADD_TEST(test_x509_is_equal);
    return 1;
}
