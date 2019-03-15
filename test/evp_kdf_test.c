/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018-2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Tests of the EVP_KDF_CTX APIs */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "testutil.h"

static int test_kdf_tls1_prf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[16];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_TLS1_PRF)) == NULL) {
        TEST_error("EVP_KDF_TLS1_PRF");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MD");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_TLS_SECRET,
                     "secret", (size_t)6) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_TLS_SECRET");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_TLS_SEED, "seed", (size_t)4) <= 0) {
        TEST_error("EVP_KDF_CTRL_ADD_TLS_SEED");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        TEST_error("EVP_KDF_derive");
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x8e, 0x4d, 0x93, 0x25, 0x30, 0xd7, 0x65, 0xa0,
            0xaa, 0xe9, 0x74, 0xc3, 0x04, 0x73, 0x5e, 0xcc
        };
        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_hkdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[10];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_HKDF)) == NULL) {
        TEST_error("EVP_KDF_HKDF");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MD");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "salt", (size_t)4) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SALT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, "secret", (size_t)6) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KEY");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_HKDF_INFO,
                     "label", (size_t)5) <= 0) {
        TEST_error("EVP_KDF_CTRL_ADD_HKDF_INFO");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        TEST_error("EVP_KDF_derive");
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x2a, 0xc4, 0x36, 0x9f, 0x52, 0x59, 0x96, 0xf8, 0xde, 0x13
        };
        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_pbkdf2(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[32];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_PBKDF2)) == NULL) {
        TEST_error("EVP_KDF_PBKDF2");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, "password", (size_t)8) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_PASS");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "salt", (size_t)4) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SALT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_ITER, 2) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_ITER");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MD");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        TEST_error("EVP_KDF_derive");
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
            0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
            0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
            0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43
        };
        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

#ifndef OPENSSL_NO_SCRYPT
static int test_kdf_scrypt(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[64];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_SCRYPT)) == NULL) {
        TEST_error("EVP_KDF_SCRYPT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, "password", (size_t)8) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_PASS");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "NaCl", (size_t)4) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SALT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_N, (uint64_t)1024) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SCRYPT_N");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_R, (uint32_t)8) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SCRYPT_R");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_P, (uint32_t)16) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SCRYPT_P");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAXMEM_BYTES, (uint64_t)16) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MAXMEM_BYTES");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) > 0) {
        TEST_error("EVP_KDF_derive should have failed");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAXMEM_BYTES,
                     (uint64_t)(10 * 1024 * 1024)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MAXMEM_BYTES");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        TEST_error("EVP_KDF_derive");
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
            0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
            0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
            0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
            0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
            0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
            0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
            0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40
        };
        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_kdf_tls1_prf);
    ADD_TEST(test_kdf_hkdf);
    ADD_TEST(test_kdf_pbkdf2);
#ifndef OPENSSL_NO_SCRYPT
    ADD_TEST(test_kdf_scrypt);
#endif
    return 1;
}
