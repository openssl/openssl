/*
 * Copyright 2000-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "testutil.h"

static int test_invalid_rsa_version(void)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    bio = BIO_new_file("test/invalid_version_17_key.pem", "r");
    if (!TEST_ptr(bio))
        goto end;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!TEST_ptr_null(pkey))
        goto end;

    if (!TEST_true(ERR_peek_error() != 0))
        goto end;

    ret = 1;
end:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_valid_rsa_version(void)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    bio = BIO_new_file("test/valid_version_1_0.pem", "r");
    if (!TEST_ptr(bio))
        goto end;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!TEST_ptr(pkey))
        goto end;

    if (!TEST_true(EVP_PKEY_is_a(pkey, "RSA")))
        goto end;

    ret = 1;
end:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_invalid_rsa_version);
    ADD_TEST(test_valid_rsa_version);
    return 1;
}
