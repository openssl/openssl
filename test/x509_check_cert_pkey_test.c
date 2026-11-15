/*
 * Copyright 2017-2023 The OpenSSL Project Authors. All Rights Reserved.
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
 * c: path of a cert in PEM format
 * k: path of a key in PEM format
 * t: API type, "cert" for X509_ and "req" for X509_REQ_ APIs.
 * e: expected, "ok" for success, "failed" for what should fail.
 */
static const char *c;
static const char *k;
static const char *t;
static const char *e;

static int test_x509_check_cert_pkey(void)
{
    BIO *bio = NULL;
    X509 *x509 = NULL;
    X509_REQ *x509_req = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0, type = 0, expected = 0, result = 0;

    /*
     * we check them first thus if fails we don't need to do
     * those PEM parsing operations.
     */
    if (strcmp(t, "cert") == 0) {
        type = 1;
    } else if (strcmp(t, "req") == 0) {
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

    /* process private key */
    if (!TEST_ptr(bio = BIO_new_file(k, "r")))
        goto failed;

    if (!TEST_ptr(pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)))
        goto failed;

    BIO_free(bio);

    /* process cert or cert request, use the same local var */
    if (!TEST_ptr(bio = BIO_new_file(c, "r")))
        goto failed;

    switch (type) {
    case 1:
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            TEST_error("read PEM x509 failed");
            goto failed;
        }

        result = X509_check_private_key(x509, pkey);
        break;
    case 2:
        x509_req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
        if (x509_req == NULL) {
            TEST_error("read PEM x509 req failed");
            goto failed;
        }

        result = X509_REQ_check_private_key(x509_req, pkey);
        break;
    default:
        /* should never be here */
        break;
    }

    if (!TEST_int_eq(result, expected)) {
        TEST_error("check private key: expected: %d, got: %d", expected, result);
        goto failed;
    }

    ret = 1;
failed:
    BIO_free(bio);
    X509_free(x509);
    X509_REQ_free(x509_req);
    EVP_PKEY_free(pkey);
    return ret;
}

static const char *file; /* path of a cert/CRL/key file in PEM format */
static int expected; /* expected number of certs/CRLs/keys included */

static int test_PEM_X509_INFO_read_bio(void)
{
    BIO *in;
    STACK_OF(X509_INFO) *sk;
    X509_INFO *it;
    int i, count = 0;

    if (!TEST_ptr((in = BIO_new_file(file, "r"))))
        return 0;
    sk = PEM_X509_INFO_read_bio(in, NULL, NULL, "");
    BIO_free(in);
    for (i = 0; i < sk_X509_INFO_num(sk); i++) {
        it = sk_X509_INFO_value(sk, i);
        if (it->x509 != NULL)
            count++;
        if (it->crl != NULL)
            count++;
        if (it->x_pkey != NULL)
            count++;
    }
    sk_X509_INFO_pop_free(sk, X509_INFO_free);
    return TEST_int_eq(count, expected);
}

/*
 * Counts the X509 objects that were tagged via X509_set_ex_data() and have
 * since been freed, i.e. whose last reference was dropped.
 */
static int x509_ex_idx = -1;
static int tagged_freed;

static void tagged_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp)
{
    if (ptr != NULL)
        (*(int *)argp)++;
}

/*
 * Build the PEM input for one append test:
 *
 * 0: a single malformed certificate (valid PEM armour, invalid DER)
 * 1: the contents of |file|, then a malformed certificate
 * 2: the contents of |file| only
 */
static BIO *append_input(int idx)
{
    static const char malformed[] = "-----BEGIN CERTIFICATE-----\n"
                                    "MAA=\n"
                                    "-----END CERTIFICATE-----\n";
    BIO *mem = NULL, *in = NULL;
    char buf[4096];
    int n;

    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        return NULL;
    if (idx != 0) {
        if (!TEST_ptr(in = BIO_new_file(file, "r")))
            goto err;
        while ((n = BIO_read(in, buf, sizeof(buf))) > 0)
            if (!TEST_int_eq(BIO_write(mem, buf, n), n))
                goto err;
        BIO_free(in);
        in = NULL;
    }
    if (idx != 2 && !TEST_int_gt(BIO_puts(mem, malformed), 0))
        goto err;
    return mem;
err:
    BIO_free(in);
    BIO_free(mem);
    return NULL;
}

/*
 * Appending to a caller-owned stack must leave the entries that were already
 * in the stack alone when the append fails, and must roll back any entries
 * added by the failed call.
 *
 * To check that the pre-existing entries are not freed, the test holds an
 * extra reference on the first certificate in the stack.  After the call the
 * stack must still own its reference, so dropping ours must not free the
 * certificate, and freeing the stack afterwards must.
 */
static int test_PEM_X509_INFO_read_bio_append(int idx)
{
    BIO *in = NULL, *mem = NULL;
    STACK_OF(X509_INFO) *sk = NULL, *ret;
    X509 *held = NULL;
    int i, n0, tagged = 0, ok = 0;
    int expect_ok = (idx == 2);

    tagged_freed = 0;
    if (!TEST_ptr(in = BIO_new_file(file, "r"))
        || !TEST_ptr(sk = PEM_X509_INFO_read_bio(in, NULL, NULL, "")))
        goto err;
    n0 = sk_X509_INFO_num(sk);

    /* Hold a tagged reference on the first certificate, if there is one. */
    for (i = 0; i < n0; i++) {
        X509_INFO *it = sk_X509_INFO_value(sk, i);

        if (it->x509 != NULL) {
            held = it->x509;
            if (!TEST_true(X509_up_ref(held))
                || !TEST_true(X509_set_ex_data(held, x509_ex_idx, held)))
                goto err;
            tagged = 1;
            break;
        }
    }

    if (!TEST_ptr(mem = append_input(idx)))
        goto err;
    ret = PEM_X509_INFO_read_bio(mem, sk, NULL, "");

    if (expect_ok) {
        if (!TEST_ptr_eq(ret, sk)
            || !TEST_int_eq(sk_X509_INFO_num(sk), 2 * n0))
            goto err;
    } else {
        if (!TEST_ptr_null(ret)
            || !TEST_int_eq(sk_X509_INFO_num(sk), n0))
            goto err;
    }

    if (tagged) {
        /* Our reference must not have been the stack's last one. */
        X509_free(held);
        held = NULL;
        if (!TEST_int_eq(tagged_freed, 0))
            goto err;
    }
    sk_X509_INFO_pop_free(sk, X509_INFO_free);
    sk = NULL;
    if (tagged && !TEST_int_eq(tagged_freed, 1))
        goto err;
    ok = 1;
err:
    X509_free(held);
    sk_X509_INFO_pop_free(sk, X509_INFO_free);
    BIO_free(in);
    BIO_free(mem);
    return ok;
}

const OPTIONS *test_get_options(void)
{
    enum { OPT_TEST_ENUM };
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_WITH_EXTRA_USAGE("cert key type expected\n"
                                          "     or [options] file num\n"),
        { OPT_HELP_STR, 1, '-', "cert\tcertificate or CSR filename in PEM\n" },
        { OPT_HELP_STR, 1, '-', "key\tprivate key filename in PEM\n" },
        { OPT_HELP_STR, 1, '-', "type\t\tvalue must be 'cert' or 'req'\n" },
        { OPT_HELP_STR, 1, '-', "expected\tthe expected return value, either 'ok' or 'failed'\n" },
        { OPT_HELP_STR, 1, '-', "file\tPEM format file containing certs, keys, and/OR CRLs\n" },
        { OPT_HELP_STR, 1, '-', "num\texpected number of credentials to be loaded from file\n" },
        { NULL }
    };
    return test_options;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (test_get_argument_count() == 2) {
        const char *num; /* expected number of certs/CRLs/keys included */

        if (!TEST_ptr(file = test_get_argument(0))
            || !TEST_ptr(num = test_get_argument(1)))
            return 0;
        if (!TEST_int_eq(sscanf(num, "%d", &expected), 1))
            return 0;
        x509_ex_idx = X509_get_ex_new_index(0, &tagged_freed, NULL, NULL,
            tagged_free_cb);
        if (!TEST_int_ge(x509_ex_idx, 0))
            return 0;
        ADD_TEST(test_PEM_X509_INFO_read_bio);
        ADD_ALL_TESTS(test_PEM_X509_INFO_read_bio_append, 3);
        return 1;
    }

    if (!TEST_ptr(c = test_get_argument(0))
        || !TEST_ptr(k = test_get_argument(1))
        || !TEST_ptr(t = test_get_argument(2))
        || !TEST_ptr(e = test_get_argument(3))) {
        return 0;
    }

    ADD_TEST(test_x509_check_cert_pkey);
    return 1;
}
