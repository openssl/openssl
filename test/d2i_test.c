/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/* Regression tests for ASN.1 parsing bugs. */

#include <stdio.h>

#include "testutil.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

static const char *test_file;

typedef struct d2i_test_fixture {
    const char *test_case_name;
} D2I_TEST_FIXTURE;


static D2I_TEST_FIXTURE set_up(const char *const test_case_name)
{
    D2I_TEST_FIXTURE fixture;
    fixture.test_case_name = test_case_name;
    return fixture;
}

static int execute_test(D2I_TEST_FIXTURE fixture)
{
    BIO *bio = NULL;
    X509 *x509 = NULL;
    int ret = 1;

    if ((bio = BIO_new_file(test_file, "r")) == NULL)
        return 1;

    x509 = d2i_X509_bio(bio, NULL);
    if (x509 != NULL)
        goto err;

    ret = 0;

 err:
    BIO_free(bio);
    X509_free(x509);
    return ret;
}

static void tear_down(D2I_TEST_FIXTURE fixture)
{
    ERR_print_errors_fp(stderr);
}

#define SETUP_D2I_TEST_FIXTURE() \
    SETUP_TEST_FIXTURE(D2I_TEST_FIXTURE, set_up)

#define EXECUTE_D2I_TEST() \
    EXECUTE_TEST(execute_test, tear_down)

static int test_bad_certificate()
{
    SETUP_D2I_TEST_FIXTURE();
    EXECUTE_D2I_TEST();
}

int main(int argc, char **argv)
{
    int result = 0;

    if (argc != 2)
        return 1;

    test_file = argv[1];

    ADD_TEST(test_bad_certificate);

    result = run_tests(argv[0]);

    return result;
}
