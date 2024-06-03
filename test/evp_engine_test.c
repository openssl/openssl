/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/engine.h>
#include <openssl/proverr.h>

#include "testutil.h"
#include "internal/nelem.h"
#include "internal/sizes.h"

/* Test we can create a signature keys with an associated ENGINE */
static int test_signatures_with_engine(int tst)
{
    ENGINE *e;
    const char *engine_id = "dasync";
    EVP_PKEY *pkey = NULL;
    const unsigned char badcmackey[] = { 0x00, 0x01 };
    const unsigned char cmackey[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char ed25519key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    int testresult = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *mac = NULL;
    size_t maclen = 0;
    int ret;

#  ifdef OPENSSL_NO_CMAC
    /* Skip CMAC tests in a no-cmac build */
    if (tst <= 1)
        return 1;
#  endif
#  ifdef OPENSSL_NO_ECX
    /* Skip ECX tests in a no-ecx build */
    if (tst == 2)
        return 1;
#  endif

    if (!TEST_ptr(e = ENGINE_by_id(engine_id)))
        return 0;

    if (!TEST_true(ENGINE_init(e))) {
        ENGINE_free(e);
        return 0;
    }

    switch (tst) {
    case 0:
        pkey = EVP_PKEY_new_CMAC_key(e, cmackey, sizeof(cmackey),
                                     EVP_aes_128_cbc());
        break;
    case 1:
        pkey = EVP_PKEY_new_CMAC_key(e, badcmackey, sizeof(badcmackey),
                                     EVP_aes_128_cbc());
        break;
    case 2:
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, e, ed25519key,
                                            sizeof(ed25519key));
        break;
    default:
        TEST_error("Invalid test case");
        goto err;
    }
    if (!TEST_ptr(pkey))
        goto err;

    if (!TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    ret = EVP_DigestSignInit(ctx, NULL, tst == 2 ? NULL : EVP_sha256(), NULL,
                             pkey);
    if (tst == 0) {
        if (!TEST_true(ret))
            goto err;

        if (!TEST_true(EVP_DigestSignUpdate(ctx, msg, sizeof(msg)))
                || !TEST_true(EVP_DigestSignFinal(ctx, NULL, &maclen)))
            goto err;

        if (!TEST_ptr(mac = OPENSSL_malloc(maclen)))
            goto err;

        if (!TEST_true(EVP_DigestSignFinal(ctx, mac, &maclen)))
            goto err;
    } else {
        /* We used a bad key. We expect a failure here */
        if (!TEST_false(ret))
            goto err;
    }

    testresult = 1;
 err:
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(mac);
    EVP_PKEY_free(pkey);
    ENGINE_finish(e);
    ENGINE_free(e);

    return testresult;
}

static int test_cipher_with_engine(void)
{
    ENGINE *e;
    const char *engine_id = "dasync";
    const unsigned char keyiv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    int testresult = 0;
    EVP_CIPHER_CTX *ctx = NULL, *ctx2 = NULL;
    unsigned char buf[AES_BLOCK_SIZE];
    int len = 0;

    if (!TEST_ptr(e = ENGINE_by_id(engine_id)))
        return 0;

    if (!TEST_true(ENGINE_init(e))) {
        ENGINE_free(e);
        return 0;
    }

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_ptr(ctx2 = EVP_CIPHER_CTX_new()))
        goto err;

    if (!TEST_true(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), e, keyiv, keyiv)))
        goto err;

    /* Copy the ctx, and complete the operation with the new ctx */
    if (!TEST_true(EVP_CIPHER_CTX_copy(ctx2, ctx)))
        goto err;

    if (!TEST_true(EVP_EncryptUpdate(ctx2, buf, &len, msg, sizeof(msg)))
            || !TEST_true(EVP_EncryptFinal_ex(ctx2, buf + len, &len)))
        goto err;

    testresult = 1;
 err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(ctx2);
    ENGINE_finish(e);
    ENGINE_free(e);

    return testresult;
}

int setup_tests(void)
{
    /* Tests only support the default libctx */
#ifndef OPENSSL_NO_EC
    ADD_ALL_TESTS(test_signatures_with_engine, 3);
#else
    ADD_ALL_TESTS(test_signatures_with_engine, 2);
#endif
    ADD_TEST(test_cipher_with_engine);

    return 1;
}
