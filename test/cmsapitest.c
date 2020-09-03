/*
 * Copyright 2018-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "testutil.h"

static X509 *cert = NULL;
static EVP_PKEY *privkey = NULL;

static int test_encrypt_decrypt(const EVP_CIPHER *cipher)
{
    int testresult = 0;
    STACK_OF(X509) *certstack = sk_X509_new_null();
    const char *msg = "Hello world";
    BIO *msgbio = BIO_new_mem_buf(msg, strlen(msg));
    BIO *outmsgbio = BIO_new(BIO_s_mem());
    CMS_ContentInfo* content = NULL;
    char buf[80];

    if (!TEST_ptr(certstack) || !TEST_ptr(msgbio) || !TEST_ptr(outmsgbio))
        goto end;

    if (!TEST_int_gt(sk_X509_push(certstack, cert), 0))
        goto end;

    content = CMS_encrypt(certstack, msgbio, cipher, CMS_TEXT);
    if (!TEST_ptr(content))
        goto end;

    if (!TEST_true(CMS_decrypt(content, privkey, cert, NULL, outmsgbio,
                               CMS_TEXT)))
        goto end;

    /* Check we got the message we first started with */
    if (!TEST_int_eq(BIO_gets(outmsgbio, buf, sizeof(buf)), strlen(msg))
            || !TEST_int_eq(strcmp(buf, msg), 0))
        goto end;

    testresult = 1;
 end:
    sk_X509_free(certstack);
    BIO_free(msgbio);
    BIO_free(outmsgbio);
    CMS_ContentInfo_free(content);

    return testresult;
}

static int test_encrypt_decrypt_aes_cbc(void)
{
    return test_encrypt_decrypt(EVP_aes_128_cbc());
}

static int test_encrypt_decrypt_aes_128_gcm(void)
{
    return test_encrypt_decrypt(EVP_aes_128_gcm());
}

static int test_encrypt_decrypt_aes_192_gcm(void)
{
    return test_encrypt_decrypt(EVP_aes_192_gcm());
}

static int test_encrypt_decrypt_aes_256_gcm(void)
{
    return test_encrypt_decrypt(EVP_aes_256_gcm());
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    char *certin = NULL, *privkeyin = NULL;
    BIO *certbio = NULL, *privkeybio = NULL;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certin = test_get_argument(0))
            || !TEST_ptr(privkeyin = test_get_argument(1)))
        return 0;

    certbio = BIO_new_file(certin, "r");
    if (!TEST_ptr(certbio))
        return 0;
    if (!TEST_true(PEM_read_bio_X509(certbio, &cert, NULL, NULL))) {
        BIO_free(certbio);
        return 0;
    }
    BIO_free(certbio);

    privkeybio = BIO_new_file(privkeyin, "r");
    if (!TEST_ptr(privkeybio)) {
        X509_free(cert);
        cert = NULL;
        return 0;
    }
    if (!TEST_true(PEM_read_bio_PrivateKey(privkeybio, &privkey, NULL, NULL))) {
        BIO_free(privkeybio);
        X509_free(cert);
        cert = NULL;
        return 0;
    }
    BIO_free(privkeybio);

    ADD_TEST(test_encrypt_decrypt_aes_cbc);
    ADD_TEST(test_encrypt_decrypt_aes_128_gcm);
    ADD_TEST(test_encrypt_decrypt_aes_192_gcm);
    ADD_TEST(test_encrypt_decrypt_aes_256_gcm);

    return 1;
}

void cleanup_tests(void)
{
    X509_free(cert);
    EVP_PKEY_free(privkey);
}
