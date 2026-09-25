/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include "testutil.h"

/*
 * Number of allocations that are still to be failed.  Set to a positive
 * value right before the call whose allocation should fail.
 */
static int fail_allocs = 0;

static void *test_malloc(size_t num, const char *file, int line)
{
    if (fail_allocs > 0) {
        fail_allocs--;
        return NULL;
    }
    return malloc(num);
}

static void *test_realloc(void *addr, size_t num, const char *file, int line)
{
    return realloc(addr, num);
}

static void test_free(void *addr, const char *file, int line)
{
    free(addr);
}

int global_init(void)
{
    return CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free);
}

/*
 * Replacing the SSL object of a BIO_f_ssl() with BIO_set_ssl() frees the
 * BIO's internal state and allocates it afresh.  If that allocation fails
 * the BIO must be left in a consistent state: BIO_free() must not touch the
 * freed state and a further BIO_set_ssl() must work again.
 */
static int test_bio_set_ssl_alloc_failure(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl1 = NULL, *ssl2 = NULL, *ssl3 = NULL, *got = NULL;
    BIO *bio = NULL;
    int testresult = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method()))
        || !TEST_ptr(ssl1 = SSL_new(ctx))
        || !TEST_ptr(ssl2 = SSL_new(ctx))
        || !TEST_ptr(ssl3 = SSL_new(ctx))
        || !TEST_ptr(bio = BIO_new(BIO_f_ssl()))
        || !TEST_true(BIO_set_ssl(bio, ssl1, BIO_CLOSE)))
        goto end;
    /* Owned by the BIO from now on */
    ssl1 = NULL;

    /* Replacing the SSL frees the old one and allocates new BIO state */
    fail_allocs = 1;
    if (!TEST_false(BIO_set_ssl(bio, ssl2, BIO_CLOSE)))
        goto end;
    fail_allocs = 0;
    /* ssl2 was not adopted; the BIO must know it has no SSL */
    if (!TEST_false(BIO_get_ssl(bio, &got))
        || !TEST_ptr_null(got))
        goto end;

    /* The BIO must be usable again */
    if (!TEST_true(BIO_set_ssl(bio, ssl3, BIO_CLOSE)))
        goto end;
    ssl3 = NULL;
    if (!TEST_true(BIO_get_ssl(bio, &got))
        || !TEST_ptr(got))
        goto end;

    testresult = 1;
end:
    fail_allocs = 0;
    /* Frees the SSL the BIO owns; must not double free the BIO state */
    BIO_free(bio);
    SSL_free(ssl1);
    SSL_free(ssl2);
    SSL_free(ssl3);
    SSL_CTX_free(ctx);
    return testresult;
}

/* Replacing the SSL object without any allocation failure */
static int test_bio_set_ssl_replace(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl1 = NULL, *ssl2 = NULL, *got = NULL;
    BIO *bio = NULL;
    int testresult = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method()))
        || !TEST_ptr(ssl1 = SSL_new(ctx))
        || !TEST_ptr(ssl2 = SSL_new(ctx))
        || !TEST_ptr(bio = BIO_new(BIO_f_ssl()))
        || !TEST_true(BIO_set_ssl(bio, ssl1, BIO_CLOSE)))
        goto end;
    ssl1 = NULL;
    if (!TEST_true(BIO_set_ssl(bio, ssl2, BIO_CLOSE)))
        goto end;
    ssl2 = NULL;
    if (!TEST_true(BIO_get_ssl(bio, &got))
        || !TEST_ptr(got))
        goto end;

    testresult = 1;
end:
    BIO_free(bio);
    SSL_free(ssl1);
    SSL_free(ssl2);
    SSL_CTX_free(ctx);
    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test_bio_set_ssl_replace);
    ADD_TEST(test_bio_set_ssl_alloc_failure);
    return 1;
}
