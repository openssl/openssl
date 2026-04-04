/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"); you may not use
 * this file except in compliance with the License.  You may obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Regression test for issue #30364: memory leak in load_key_certs_crls()
 * when X509_add_cert() or sk_X509_CRL_push() fails. Exercises the add/push
 * path under OPENSSL_MALLOC_FAILURES so that with the fix the cert/CRL is
 * freed on failure (memory_sanitizer would report a leak without the fix).
 */

#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/crypto.h>
#include "apps.h"
#include "app_libctx.h"
#include "testutil.h"

char *default_config_file = NULL;

static char *certfile = NULL;
static int mcount, rcount, fcount, scount;

static int do_load_key_certs_crls(int allow_failure)
{
    STACK_OF(X509) *certs = NULL;
    int ret = (allow_failure == 1) ? 0 : 1;
    char uri[1024];

    if (certfile == NULL)
        return 0;

    (void)snprintf(uri, sizeof(uri), "file:%s", certfile);
    if (!TEST_true(load_key_certs_crls(uri, FORMAT_UNDEF, 0, NULL, "cert",
            1, NULL, NULL, NULL, NULL, &certs,
            NULL, NULL, NULL)))
        goto err;

    ret = 1;
err:
    sk_X509_pop_free(certs, X509_free);
    return ret;
}

static int test_record_alloc_counts(void)
{
    return do_load_key_certs_crls(1);
}

static int test_alloc_failures(void)
{
    return do_load_key_certs_crls(0);
}

static int test_report_alloc_counts(void)
{
    CRYPTO_get_alloc_counts(&mcount, &rcount, &fcount);
    TEST_info("skip: %d count %d\n", scount, mcount - scount);
    return 1;
}

int setup_tests(void)
{
    int ret = 0;
    char *opmode = NULL;

    if (app_create_libctx() == NULL)
        return 0;

    if (!TEST_ptr(opmode = test_get_argument(0)))
        goto err;

    if (!TEST_ptr(certfile = test_get_argument(1)))
        goto err;

    if (strcmp(opmode, "count") == 0) {
        CRYPTO_get_alloc_counts(&scount, &rcount, &fcount);
        ADD_TEST(test_record_alloc_counts);
        ADD_TEST(test_report_alloc_counts);
    } else {
        ADD_TEST(test_alloc_failures);
    }
    ret = 1;
err:
    return ret;
}

void cleanup_tests(void)
{
}
