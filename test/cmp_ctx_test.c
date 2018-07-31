/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.
 */

#include "cmptestlib.h"

typedef struct test_fixture {
    const char *test_case_name;
    X509_EXTENSIONS *exts;
} OSSL_CMP_CTX_TEST_FIXTURE;

static OSSL_CMP_CTX_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    OSSL_CMP_CTX_TEST_FIXTURE *fixture;
    int setup_ok = 0;
    /* Allocate memory owned by the fixture, exit on error */
    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))) ||
        !TEST_ptr(fixture->exts = sk_X509_EXTENSION_new_null()))
        goto err;
    fixture->test_case_name = test_case_name;

    setup_ok = 1;
 err:
    if (!setup_ok) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static void tear_down(OSSL_CMP_CTX_TEST_FIXTURE *fixture)
{
    sk_X509_EXTENSION_pop(fixture->exts);
    OPENSSL_free(fixture);
}

static int execute_cmp_ctx_reqextensions_have_san_test(OSSL_CMP_CTX_TEST_FIXTURE *
                                                       fixture)
{
    int good = 0;
    OSSL_CMP_CTX *ctx = NULL;
    if (!TEST_ptr(ctx = OSSL_CMP_CTX_create()))
        return good;
    if (TEST_false(OSSL_CMP_CTX_reqExtensions_have_SAN(ctx)))
        if (TEST_true(OSSL_CMP_CTX_set0_reqExtensions(ctx, fixture->exts))) {
            fixture->exts = NULL;
            good = TEST_true(OSSL_CMP_CTX_reqExtensions_have_SAN(ctx));
        }
    OSSL_CMP_CTX_delete(ctx);
    return good;
}

static int test_cmp_ctx_reqextensions_have_san(void)
{
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up);
    const int len = 16;
    unsigned char str[16/* len */];
    ASN1_OCTET_STRING *data = NULL;
    X509_EXTENSION *ext = NULL;

    if (!TEST_int_eq(1, RAND_bytes(str, len)) ||
        !TEST_ptr(data = ASN1_OCTET_STRING_new()) ||
        !TEST_true(ASN1_OCTET_STRING_set(data, str, len)) ||
        !TEST_ptr(ext =
                  X509_EXTENSION_create_by_NID(NULL, NID_subject_alt_name, 0,
                                               data))
        || !TEST_true(sk_X509_EXTENSION_push(fixture->exts, ext))) {
        X509_EXTENSION_free(ext);
        tear_down(fixture);
        fixture = NULL;
    }
    ASN1_OCTET_STRING_free(data);
    EXECUTE_TEST(execute_cmp_ctx_reqextensions_have_san_test, tear_down);
    return result;
}

void cleanup_tests(void)
{
    return;
}

int setup_tests(void)
{
    ADD_TEST(test_cmp_ctx_reqextensions_have_san);

    return 1;
}
