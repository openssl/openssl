/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "internal/nelem.h"

#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "testutil.h"
#include "helpers/pkcs12.h"

static OSSL_LIB_CTX *testctx = NULL;
static OSSL_PROVIDER *nullprov = NULL;

static int test_null_args(void)
{
    return TEST_false(PKCS12_parse(NULL, NULL, NULL, NULL, NULL));
}

static PKCS12 *PKCS12_load(const char *fpath)
{
    BIO *bio = NULL;
    PKCS12 *p12 = NULL;

    bio = BIO_new_file(fpath, "rb");
    if (!TEST_ptr(bio))
        goto err;

    p12 = PKCS12_init_ex(NID_pkcs7_data, testctx, "provider=default");
    if (!TEST_ptr(p12))
        goto err;

    if (!TEST_true(p12 == d2i_PKCS12_bio(bio, &p12)))
        goto err;

    BIO_free(bio);

    return p12;

err:
    BIO_free(bio);
    PKCS12_free(p12);
    return NULL;
}

static const char *in_file = NULL;
static const char *in_pass = "";
static int has_key = 0;
static int has_cert = 0;
static int has_ca = 0;
static int expected_ca_count = -1;
static const char *expected_cert_file = NULL;
static const char *expected_ca_file = NULL;
static int mismatched_key_pass = 0;

static int changepass(PKCS12 *p12, EVP_PKEY *key, X509 *cert, STACK_OF(X509) *ca)
{
    int ret = 0;
    PKCS12 *p12new = NULL;
    EVP_PKEY *key2 = NULL;
    X509 *cert2 = NULL;
    STACK_OF(X509) *ca2 = NULL;
    BIO *bio = NULL;

    if (!TEST_true(PKCS12_newpass(p12, in_pass, "NEWPASS")))
        goto err;
    if (!TEST_ptr(bio = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_true(i2d_PKCS12_bio(bio, p12)))
        goto err;
    if (!TEST_ptr(p12new = PKCS12_init_ex(NID_pkcs7_data, testctx, "provider=default")))
        goto err;
    if (!TEST_ptr(d2i_PKCS12_bio(bio, &p12new)))
        goto err;
    if (!TEST_true(PKCS12_parse(p12new, "NEWPASS", &key2, &cert2, &ca2)))
        goto err;
    if (has_key) {
        if (!TEST_ptr(key2) || !TEST_int_eq(EVP_PKEY_eq(key, key2), 1))
            goto err;
    }
    if (has_cert) {
        if (!TEST_ptr(cert2) || !TEST_int_eq(X509_cmp(cert, cert2), 0))
            goto err;
    }
    ret = 1;
err:
    BIO_free(bio);
    PKCS12_free(p12new);
    EVP_PKEY_free(key2);
    X509_free(cert2);
    OSSL_STACK_OF_X509_free(ca2);
    return ret;
}

static int pkcs12_parse_test(void)
{
    int ret = 0;
    PKCS12 *p12 = NULL;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    if (mismatched_key_pass)
        return TEST_skip("not applicable with mismatched key password");

    if (in_file != NULL) {
        p12 = PKCS12_load(in_file);
        if (!TEST_ptr(p12))
            goto err;

        if (!TEST_true(PKCS12_parse(p12, in_pass, &key, &cert, &ca)))
            goto err;

        if ((has_key && !TEST_ptr(key)) || (!has_key && !TEST_ptr_null(key)))
            goto err;
        if ((has_cert && !TEST_ptr(cert)) || (!has_cert && !TEST_ptr_null(cert)))
            goto err;
        if ((has_ca && !TEST_ptr(ca)) || (!has_ca && !TEST_ptr_null(ca)))
            goto err;
        if (has_key && !changepass(p12, key, cert, ca))
            goto err;
    }
    ret = 1;
err:
    PKCS12_free(p12);
    EVP_PKEY_free(key);
    X509_free(cert);
    OSSL_STACK_OF_X509_free(ca);
    return TEST_true(ret);
}

static int test_parse_combinations(int idx)
{
    int ret = 0;
    PKCS12 *p12 = NULL;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int want_key = (idx >> 2) & 1;
    int want_cert = (idx >> 1) & 1;
    int want_ca = idx & 1;

    if (in_file == NULL || !has_key || !has_cert)
        return 1;

    if (!TEST_int_ge(expected_ca_count, 0))
        return TEST_skip("test_parse_combinations requires -ca-count parameter");

    TEST_info("combination %d: want_key=%d want_cert=%d want_ca=%d",
        idx, want_key, want_cert, want_ca);

    if (!TEST_ptr(p12 = PKCS12_load(in_file)))
        goto err;
    if (!TEST_true(PKCS12_parse(p12, in_pass,
            want_key ? &key : NULL,
            want_cert ? &cert : NULL,
            want_ca ? &ca : NULL)))
        goto err;

    if (want_key) {
        if (!TEST_ptr(key))
            goto err;
    }

    if (want_cert) {
        /*
         * PKCS12_parse only sets *cert when the key is also requested and
         * found, because it matches certs against *pkey.
         */
        if (want_key) {
            if (!TEST_ptr(cert))
                goto err;
        } else {
            if (!TEST_ptr_null(cert))
                goto err;
        }
    }

    if (want_ca) {
        int actual_ca_count = ca == NULL ? 0 : sk_X509_num(ca);
        int expected_count = expected_ca_count;

        /*
         * The matching cert is only excluded from the CA stack when both
         * key and cert pointers are provided.  Otherwise it ends up in CA.
         */
        if (!want_key || !want_cert)
            expected_count++;

        if (!TEST_int_eq(actual_ca_count, expected_count))
            goto err;
    }

    ret = 1;
err:
    if (!ret)
        TEST_info("failed combination %d: want_key=%d want_cert=%d want_ca=%d",
            idx, want_key, want_cert, want_ca);
    PKCS12_free(p12);
    EVP_PKEY_free(key);
    X509_free(cert);
    OSSL_STACK_OF_X509_free(ca);
    return ret;
}

/*
 * If appending an additional certificate to the CA stack fails,
 * PKCS12_parse() should free its own allocated CA stack.
 */
static int pkcs12_parse_mfail_test(void)
{
    int ret;
    PKCS12 *p12 = NULL;
    STACK_OF(X509) *ca = NULL;

    if (!TEST_ptr(p12 = PKCS12_load(in_file)))
        return -1;

    MFAIL_start();
    ret = PKCS12_parse(p12, in_pass, NULL, NULL, &ca);
    MFAIL_end();

    if (ret == 0 && !TEST_ptr_null(ca))
        ret = -1;

    /*
     * Only free the stack on success, since PKCS12_parse()
     * should free its own allocated stack on failure.
     */
    if (ret == 1)
        OSSL_STACK_OF_X509_free(ca);

    PKCS12_free(p12);
    return ret;
}

/*
 * If appending an additional certificate to the CA stack fails,
 * PKCS12_parse() should leave the original CA stack unmodified.
 */
static int pkcs12_parse_existing_ca_mfail_test(void)
{
    int i, ret = -1;
    PKCS12 *p12 = NULL;
    STACK_OF(X509) *ca = NULL, *initial_ca = NULL;
    X509 *initial_certs[3] = { NULL };

    if (!TEST_ptr(p12 = PKCS12_load(in_file))
        || !TEST_ptr(ca = sk_X509_new_null()))
        goto err;

    for (i = 0; i < 3; i++) {
        if (!TEST_ptr(initial_certs[i] = X509_new()))
            goto err;

        if (!TEST_true(sk_X509_push(ca, initial_certs[i]))) {
            X509_free(initial_certs[i]);
            goto err;
        }
    }
    initial_ca = ca;

    MFAIL_start();
    ret = PKCS12_parse(p12, in_pass, NULL, NULL, &ca);
    MFAIL_end();

    if (ret == 0
        && (!TEST_ptr_eq(ca, initial_ca)
            || !TEST_int_eq(sk_X509_num(ca), 3)
            || !TEST_ptr_eq(sk_X509_value(ca, 0), initial_certs[0])
            || !TEST_ptr_eq(sk_X509_value(ca, 1), initial_certs[1])
            || !TEST_ptr_eq(sk_X509_value(ca, 2), initial_certs[2])))
        ret = -1;

err:
    PKCS12_free(p12);
    OSSL_STACK_OF_X509_free(ca);
    return ret;
}

static int pkcs12_create_cb(PKCS12_SAFEBAG *bag, void *cbarg)
{
    int cb_ret = *((int *)cbarg);
    return cb_ret;
}

static PKCS12 *pkcs12_create_ex2_setup(EVP_PKEY **key, X509 **cert, STACK_OF(X509) **ca)
{
    PKCS12 *p12 = NULL;
    p12 = PKCS12_load("out6.p12");
    if (!TEST_ptr(p12))
        goto err;

    if (!TEST_true(PKCS12_parse(p12, "", key, cert, ca)))
        goto err;

    return p12;
err:
    PKCS12_free(p12);
    return NULL;
}

static int pkcs12_create_ex2_test(int test)
{
    int ret = 0, cb_ret = 0;
    PKCS12 *ptr = NULL, *p12 = NULL;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    p12 = pkcs12_create_ex2_setup(&key, &cert, &ca);
    if (!TEST_ptr(p12))
        goto err;

    if (test == 0) {
        /* Confirm PKCS12_create_ex2 returns NULL */
        ptr = PKCS12_create_ex2(NULL, NULL, NULL,
            NULL, NULL, NID_undef, NID_undef,
            0, 0, 0,
            testctx, NULL,
            NULL, NULL);
        if (!TEST_ptr_null(ptr))
            goto err;

        /* Can't proceed without a valid cert at least */
        if (!TEST_ptr(cert))
            goto err;

        /* Specified call back called - return success */
        cb_ret = 1;
        ptr = PKCS12_create_ex2(NULL, NULL, NULL,
            cert, NULL, NID_undef, NID_undef,
            0, 0, 0,
            testctx, NULL,
            pkcs12_create_cb, (void *)&cb_ret);
        /* PKCS12 successfully created */
        if (!TEST_ptr(ptr))
            goto err;
    } else if (test == 1) {
        /* Specified call back called - return error*/
        cb_ret = -1;
        ptr = PKCS12_create_ex2(NULL, NULL, NULL,
            cert, NULL, NID_undef, NID_undef,
            0, 0, 0,
            testctx, NULL,
            pkcs12_create_cb, (void *)&cb_ret);
        /* PKCS12 not created */
        if (!TEST_ptr_null(ptr))
            goto err;
    } else if (test == 2) {
        /* Specified call back called - return failure */
        cb_ret = 0;
        ptr = PKCS12_create_ex2(NULL, NULL, NULL,
            cert, NULL, NID_undef, NID_undef,
            0, 0, 0,
            testctx, NULL,
            pkcs12_create_cb, (void *)&cb_ret);
        /* PKCS12 successfully created */
        if (!TEST_ptr(ptr))
            goto err;
    }

    ret = 1;
err:
    PKCS12_free(p12);
    PKCS12_free(ptr);
    EVP_PKEY_free(key);
    X509_free(cert);
    OSSL_STACK_OF_X509_free(ca);
    return TEST_true(ret);
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_IN_FILE,
    OPT_IN_PASS,
    OPT_IN_HAS_KEY,
    OPT_IN_HAS_CERT,
    OPT_IN_HAS_CA,
    OPT_CA_COUNT,
    OPT_EXPECTED_CERT,
    OPT_EXPECTED_CA,
    OPT_MISMATCHED_P12,
    OPT_LEGACY,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "in", OPT_IN_FILE, '<', "PKCS12 input file" },
        { "pass", OPT_IN_PASS, 's', "PKCS12 input file password" },
        { "has-key", OPT_IN_HAS_KEY, 'n', "Whether the input file does contain an user key" },
        { "has-cert", OPT_IN_HAS_CERT, 'n', "Whether the input file does contain an user certificate" },
        { "has-ca", OPT_IN_HAS_CA, 'n', "Whether the input file does contain other certificate" },
        { "ca-count", OPT_CA_COUNT, 'n', "Expected number of CA certificates" },
        { "expected-cert", OPT_EXPECTED_CERT, '<', "PEM file of expected main certificate" },
        { "expected-ca", OPT_EXPECTED_CA, '<', "PEM file of expected CA certificates in order" },
        { "mismatched-key-pass", OPT_MISMATCHED_P12, '-', "Input has key encrypted with a different password" },
        { "legacy", OPT_LEGACY, '-', "Test the legacy APIs" },
        { NULL }
    };
    return options;
}

static int test_PKCS12_set_pbmac1_pbkdf2_saltlen_zero(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12 = NULL;

    if (mismatched_key_pass)
        return TEST_skip("not applicable with mismatched key password");
    if (!TEST_ptr(p12 = PKCS12_load(in_file)))
        return 0;
    if (!TEST_true(PKCS12_parse(p12, in_pass, &key, &cert, &ca)))
        goto err;
    PKCS12_free(p12);

    if (!TEST_ptr(p12 = PKCS12_create_ex2("pass", NULL, key, cert, ca,
                      NID_undef, NID_undef, 0, -1, 0,
                      testctx, NULL, NULL, NULL)))
        goto err;
    ret = TEST_true(PKCS12_set_pbmac1_pbkdf2(p12, "pass", -1, NULL, 0, 0, NULL, NULL));
err:
    PKCS12_free(p12);
    EVP_PKEY_free(key);
    X509_free(cert);
    OSSL_STACK_OF_X509_free(ca);
    return ret;
}

static int test_PKCS12_set_pbmac1_pbkdf2_invalid_saltlen(void)
{
    int ret = 0;
    unsigned char salt[8] = { 0 };
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12 = NULL;

    if (mismatched_key_pass)
        return TEST_skip("not applicable with mismatched key password");
    if (!TEST_ptr(p12 = PKCS12_load(in_file)))
        return 0;
    if (!TEST_true(PKCS12_parse(p12, in_pass, &key, &cert, &ca)))
        goto err;
    PKCS12_free(p12);

    if (!TEST_ptr(p12 = PKCS12_create_ex2("pass", NULL, key, cert, ca,
                      NID_undef, NID_undef, 0, -1, 0,
                      testctx, NULL, NULL, NULL)))
        goto err;
    ret = TEST_false(PKCS12_set_pbmac1_pbkdf2(p12, "pass", -1,
        salt, -1, 0, NULL, NULL));
err:
    PKCS12_free(p12);
    EVP_PKEY_free(key);
    X509_free(cert);
    OSSL_STACK_OF_X509_free(ca);
    return ret;
}

static int test_parse_cert_placement(void)
{
    int ret = 0, i;
    PKCS12 *p12 = NULL;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL, *exp_cert = NULL, *x = NULL;
    STACK_OF(X509) *ca = NULL, *exp_ca = NULL;
    BIO *bio = NULL;

    if (in_file == NULL
        || (expected_cert_file == NULL && expected_ca_file == NULL))
        return 1;

    p12 = PKCS12_load(in_file);
    if (!TEST_ptr(p12))
        goto err;

    if (!TEST_true(PKCS12_parse(p12, in_pass, &key, &cert, &ca)))
        goto err;

    if (has_key && !TEST_ptr(key))
        goto err;

    if (expected_cert_file != NULL) {
        bio = BIO_new_file(expected_cert_file, "rb");
        if (!TEST_ptr(bio))
            goto err;
        exp_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        bio = NULL;
        if (!TEST_ptr(exp_cert))
            goto err;
        if (!TEST_ptr(cert))
            goto err;
        if (!TEST_int_eq(X509_cmp(cert, exp_cert), 0)) {
            TEST_info("main cert does not match expected cert");
            goto err;
        }
    }

    if (expected_ca_file != NULL) {
        int actual_count, expected_count;

        exp_ca = sk_X509_new_null();
        if (!TEST_ptr(exp_ca))
            goto err;

        bio = BIO_new_file(expected_ca_file, "rb");
        if (!TEST_ptr(bio))
            goto err;
        while ((x = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
            if (!sk_X509_push(exp_ca, x)) {
                X509_free(x);
                x = NULL;
                goto err;
            }
            x = NULL;
        }
        ERR_clear_error();
        BIO_free(bio);
        bio = NULL;

        actual_count = ca == NULL ? 0 : sk_X509_num(ca);
        expected_count = sk_X509_num(exp_ca);

        if (!TEST_int_eq(actual_count, expected_count))
            goto err;

        for (i = 0; i < expected_count; i++) {
            if (!TEST_int_eq(X509_cmp(sk_X509_value(ca, i),
                                 sk_X509_value(exp_ca, i)),
                    0)) {
                TEST_info("CA cert mismatch at index %d", i);
                goto err;
            }
        }
    }

    ret = 1;
err:
    PKCS12_free(p12);
    EVP_PKEY_free(key);
    X509_free(cert);
    OSSL_STACK_OF_X509_free(ca);
    X509_free(exp_cert);
    OSSL_STACK_OF_X509_free(exp_ca);
    BIO_free(bio);
    return ret;
}

/*
 * Load a pre-built PKCS#12 whose MAC and cert use one password but whose
 * private key is encrypted with a different one.  Parsing without requesting
 * the key must succeed (cert lands in the CA stack); requesting it must fail.
 */
static int test_parse_mismatched_key_password(void)
{
    int ret = 0;
    PKCS12 *p12 = NULL;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    if (in_file == NULL || !mismatched_key_pass)
        return 1;

    p12 = PKCS12_load(in_file);
    if (!TEST_ptr(p12))
        goto err;

    /* Omitting the key pointer succeeds; cert lands in the CA stack */
    if (!TEST_true(PKCS12_parse(p12, in_pass, NULL, NULL, &ca)))
        goto err;
    if (!TEST_ptr(ca) || !TEST_int_eq(sk_X509_num(ca), 1))
        goto err;
    OSSL_STACK_OF_X509_free(ca);
    ca = NULL;

    /* Requesting the key fails: wrong password for the shrouded key bag */
    ERR_set_mark();
    if (!TEST_false(PKCS12_parse(p12, in_pass, &key, &cert, &ca)))
        goto err;
    ERR_pop_to_mark();

    ret = 1;
err:
    PKCS12_free(p12);
    EVP_PKEY_free(key);
    X509_free(cert);
    OSSL_STACK_OF_X509_free(ca);
    return ret;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_IN_FILE:
            in_file = opt_arg();
            break;
        case OPT_IN_PASS:
            in_pass = opt_arg();
            break;
        case OPT_LEGACY:
            break;
        case OPT_IN_HAS_KEY:
            has_key = opt_int_arg();
            break;
        case OPT_IN_HAS_CERT:
            has_cert = opt_int_arg();
            break;
        case OPT_IN_HAS_CA:
            has_ca = opt_int_arg();
            break;
        case OPT_CA_COUNT:
            expected_ca_count = opt_int_arg();
            break;
        case OPT_EXPECTED_CERT:
            expected_cert_file = opt_arg();
            break;
        case OPT_EXPECTED_CA:
            expected_ca_file = opt_arg();
            break;
        case OPT_MISMATCHED_P12:
            mismatched_key_pass = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    if (!test_get_libctx(&testctx, &nullprov, NULL, NULL, NULL)) {
        OSSL_LIB_CTX_free(testctx);
        testctx = NULL;
        return 0;
    }

    ADD_TEST(test_null_args);
    ADD_TEST(pkcs12_parse_test);
    ADD_ALL_TESTS(test_parse_combinations, 8);
    ADD_TEST(test_parse_cert_placement);
    ADD_TEST(test_parse_mismatched_key_password);
    ADD_MFAIL_NO_CHECK_TEST(pkcs12_parse_mfail_test);
    ADD_MFAIL_NO_CHECK_TEST(pkcs12_parse_existing_ca_mfail_test);
    ADD_ALL_TESTS(pkcs12_create_ex2_test, 3);
    ADD_TEST(test_PKCS12_set_pbmac1_pbkdf2_saltlen_zero);
    ADD_TEST(test_PKCS12_set_pbmac1_pbkdf2_invalid_saltlen);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_LIB_CTX_free(testctx);
    OSSL_PROVIDER_unload(nullprov);
}
