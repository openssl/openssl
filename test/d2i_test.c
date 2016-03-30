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
#include <string.h>

#include "testutil.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static const ASN1_ITEM *item_type;
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
    ASN1_VALUE *value = NULL;
    int ret = 1;
    unsigned char buf[2048];
    const unsigned char *buf_ptr = buf;
    int len;

    if ((bio = BIO_new_file(test_file, "r")) == NULL)
        return 1;

    /*
     * We don't use ASN1_item_d2i_bio because it, apparently,
     * errors too early for some inputs.
     */
    len = BIO_read(bio, buf, sizeof buf);
    if (len < 0)
        goto err;

    value = ASN1_item_d2i(NULL, &buf_ptr, len, item_type);
    if (value != NULL)
        goto err;

    ret = 0;

 err:
    BIO_free(bio);
    ASN1_item_free(value, item_type);
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

static int test_bad_asn1()
{
    SETUP_D2I_TEST_FIXTURE();
    EXECUTE_D2I_TEST();
}

/*
 * Usage: d2i_test <type> <file>, e.g.
 * d2i_test generalname bad_generalname.der
 */
int main(int argc, char **argv)
{
    int result = 0;
    const char *test_type_name;

    if (argc != 3)
        return 1;

    test_type_name = argv[1];
    test_file = argv[2];

    if (strcmp(test_type_name, "generalname") == 0) {
        item_type = ASN1_ITEM_rptr(GENERAL_NAME);
    } else if (strcmp(test_type_name, "x509") == 0) {
        item_type = ASN1_ITEM_rptr(X509);
    } else {
        fprintf(stderr, "Bad type %s\n", test_type_name);
        return 1;
    }

    ADD_TEST(test_bad_asn1);

    result = run_tests(argv[0]);

    return result;
}
