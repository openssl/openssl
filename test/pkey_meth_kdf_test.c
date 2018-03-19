/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Tests of the EVP_PKEY_CTX_set_* macro family */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "testutil.h"

static int test_kdf_tls1_prf(void)
{
    EVP_PKEY_CTX *pctx;
    unsigned char out[16];
    size_t outlen = sizeof(out);
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        TEST_error("EVP_PKEY_derive_init");
        return 0;
    }
    if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) {
        TEST_error("EVP_PKEY_CTX_set_tls1_prf_md");
        return 0;
    }
    if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, "secret", 6) <= 0) {
        TEST_error("EVP_PKEY_CTX_set1_tls1_prf_secret");
        return 0;
    }
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, "seed", 4) <= 0) {
        TEST_error("EVP_PKEY_CTX_add1_tls1_prf_seed");
        return 0;
    }
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
        TEST_error("EVP_PKEY_derive");
        return 0;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x8e, 0x4d, 0x93, 0x25, 0x30, 0xd7, 0x65, 0xa0,
            0xaa, 0xe9, 0x74, 0xc3, 0x04, 0x73, 0x5e, 0xcc
        };
        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            return 0;
        }
    }
    EVP_PKEY_CTX_free(pctx);
    return 1;
}

static int test_kdf_hkdf(void)
{
    unsigned char out[10];
    size_t outlen = sizeof(out);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        TEST_error("EVP_PKEY_derive_init");
        return 0;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        TEST_error("EVP_PKEY_CTX_set_hkdf_md");
        return 0;
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "salt", 4) <= 0) {
        TEST_error("EVP_PKEY_CTX_set1_hkdf_salt");
        return 0;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, "secret", 6) <= 0) {
        TEST_error("EVP_PKEY_CTX_set1_hkdf_key");
        return 0;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "label", 5) <= 0) {
        TEST_error("EVP_PKEY_CTX_set1_hkdf_info");
        return 0;
    }
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
        TEST_error("EVP_PKEY_derive");
        return 0;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x2a, 0xc4, 0x36, 0x9f, 0x52, 0x59, 0x96, 0xf8, 0xde, 0x13
        };

        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            return 0;
        }
    }
    EVP_PKEY_CTX_free(pctx);
    return 1;
}

#ifndef OPENSSL_NO_SCRYPT
static int test_kdf_scrypt(void)
{
    unsigned char out[64];
    size_t outlen = sizeof(out);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        TEST_error("EVP_PKEY_derive_init");
        return 0;
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, "password", 8) <= 0) {
        TEST_error("EVP_PKEY_CTX_set1_pbe_pass");
        return 0;
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, "NaCl", 4) <= 0) {
        TEST_error("EVP_PKEY_CTX_set1_scrypt_salt");
        return 0;
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, 1024) <= 0) {
        TEST_error("EVP_PKEY_CTX_set_scrypt_N");
        return 0;
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, 8) <= 0) {
        TEST_error("EVP_PKEY_CTX_set_scrypt_r");
        return 0;
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, 16) <= 0) {
        TEST_error("EVP_PKEY_CTX_set_scrypt_p");
        return 0;
    }
    if (EVP_PKEY_CTX_set_scrypt_maxmem_bytes(pctx, 16) <= 0) {
        TEST_error("EVP_PKEY_CTX_set_maxmem_bytes");
        return 0;
    }
    if (EVP_PKEY_derive(pctx, out, &outlen) > 0) {
        TEST_error("EVP_PKEY_derive should have failed");
        return 0;
    }
    if (EVP_PKEY_CTX_set_scrypt_maxmem_bytes(pctx, 10 * 1024 * 1024) <= 0) {
        TEST_error("EVP_PKEY_CTX_set_maxmem_bytes");
        return 0;
    }
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
        TEST_error("EVP_PKEY_derive");
        return 0;
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
            return 0;
        }
    }
    EVP_PKEY_CTX_free(pctx);
    return 1;
}
#endif

static int test_kdf_pbkdf2(void)
{
    unsigned char out[20];
    size_t outlen = sizeof(out);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_PBKDF2, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        TEST_error("EVP_PKEY_derive_init");
        return 0;
    }
    if (EVP_PKEY_CTX_set_pbkdf2_md(pctx, EVP_sha1()) <= 0) {
        TEST_error("EVP_PKEY_CTX_set_pbkdf2_md");
        return 0;
    }
    if (EVP_PKEY_CTX_set1_pbkdf2_salt(pctx, "salt", 4) <= 0) {
        TEST_error("EVP_PKEY_CTX_set1_pbkdf2_salt");
        return 0;
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, "password", 8) <= 0) {
        TEST_error("EVP_PKEY_CTX_set1_pbe_pass");
        return 0;
    }
    if (EVP_PKEY_CTX_set_pbe_iter(pctx, 4096) <= 0) {
        TEST_error("EVP_PKEY_CTX_set1_pbkdf2_iter");
        return 0;
    }
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
        TEST_error("EVP_PKEY_derive");
        return 0;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
            0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
            0x65, 0xa4, 0x29, 0xc1
        };

        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            return 0;
        }
    }
    EVP_PKEY_CTX_free(pctx);
    return 1;
}

int setup_tests()
{
    ADD_TEST(test_kdf_tls1_prf);
    ADD_TEST(test_kdf_hkdf);
#ifndef OPENSSL_NO_SCRYPT
    ADD_TEST(test_kdf_scrypt);
#endif
    ADD_TEST(test_kdf_pbkdf2);
    return 1;
}
