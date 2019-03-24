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
    int ret;
    EVP_KDF_CTX *kctx;
    unsigned char out[16];
    const unsigned char expected[sizeof(out)] = {
        0x8e, 0x4d, 0x93, 0x25, 0x30, 0xd7, 0x65, 0xa0,
        0xaa, 0xe9, 0x74, 0xc3, 0x04, 0x73, 0x5e, 0xcc
    };

    ret = TEST_ptr(kctx = EVP_KDF_CTX_new_id(EVP_KDF_TLS1_PRF))
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()),
                         0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_TLS_SECRET,
                                      "secret", (size_t)6), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_TLS_SEED, "seed",
                                      (size_t)4), 0)
          && TEST_int_gt(EVP_KDF_derive(kctx, out, sizeof(out)), 0)
          && TEST_mem_eq(out, sizeof(out), expected, sizeof(expected));

    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_hkdf(void)
{
    int ret;
    EVP_KDF_CTX *kctx;
    unsigned char out[10];
    const unsigned char expected[sizeof(out)] = {
        0x2a, 0xc4, 0x36, 0x9f, 0x52, 0x59, 0x96, 0xf8, 0xde, 0x13
    };

    ret = TEST_ptr(kctx = EVP_KDF_CTX_new_id(EVP_KDF_HKDF))
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()),
                         0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "salt",
                                      (size_t)4), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, "secret",
                                      (size_t)6), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_HKDF_INFO,
                                      "label", (size_t)5), 0)
          && TEST_int_gt(EVP_KDF_derive(kctx, out, sizeof(out)), 0)
          && TEST_mem_eq(out, sizeof(out), expected, sizeof(expected));

    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_pbkdf2(void)
{
    int ret;
    EVP_KDF_CTX *kctx;
    unsigned char out[32];
    const unsigned char expected[sizeof(out)] = {
        0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
        0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
        0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
        0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43
    };

    ret = TEST_ptr(kctx = EVP_KDF_CTX_new_id(EVP_KDF_PBKDF2))
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, "password",
                                      (size_t)8), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "salt",
                                      (size_t)4), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_ITER, 2), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()),
                         0)
          && TEST_int_gt(EVP_KDF_derive(kctx, out, sizeof(out)), 0)
          && TEST_mem_eq(out, sizeof(out), expected, sizeof(expected));

    EVP_KDF_CTX_free(kctx);
    return ret;
}

#ifndef OPENSSL_NO_SCRYPT
static int test_kdf_scrypt(void)
{
    int ret;
    EVP_KDF_CTX *kctx;
    unsigned char out[64];
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

    ret = TEST_ptr(kctx = EVP_KDF_CTX_new_id(EVP_KDF_SCRYPT))
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, "password",
                                      (size_t)8), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "NaCl",
                                      (size_t)4), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_N,
                                      (uint64_t)1024), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_R,
                                      (uint32_t)8), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_P,
                                      (uint32_t)16), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAXMEM_BYTES,
                                      (uint64_t)16), 0)
          /* failure test */
          && TEST_int_le(EVP_KDF_derive(kctx, out, sizeof(out)), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAXMEM_BYTES,
                                      (uint64_t)(10 * 1024 * 1024)), 0)
          && TEST_int_gt(EVP_KDF_derive(kctx, out, sizeof(out)), 0)
          && TEST_mem_eq(out, sizeof(out), expected, sizeof(expected));

    EVP_KDF_CTX_free(kctx);
    return ret;
}
#endif /* OPENSSL_NO_SCRYPT */

static int test_kdf_ss_hash(void)
{
    int ret;
    EVP_KDF_CTX *kctx = NULL;
    const unsigned char z[] = {
        0x6d,0xbd,0xc2,0x3f,0x04,0x54,0x88,0xe4,0x06,0x27,0x57,0xb0,0x6b,0x9e,
        0xba,0xe1,0x83,0xfc,0x5a,0x59,0x46,0xd8,0x0d,0xb9,0x3f,0xec,0x6f,0x62,
        0xec,0x07,0xe3,0x72,0x7f,0x01,0x26,0xae,0xd1,0x2c,0xe4,0xb2,0x62,0xf4,
        0x7d,0x48,0xd5,0x42,0x87,0xf8,0x1d,0x47,0x4c,0x7c,0x3b,0x18,0x50,0xe9
    };
    const unsigned char other[] = {
        0xa1,0xb2,0xc3,0xd4,0xe5,0x43,0x41,0x56,0x53,0x69,0x64,0x3c,0x83,0x2e,
        0x98,0x49,0xdc,0xdb,0xa7,0x1e,0x9a,0x31,0x39,0xe6,0x06,0xe0,0x95,0xde,
        0x3c,0x26,0x4a,0x66,0xe9,0x8a,0x16,0x58,0x54,0xcd,0x07,0x98,0x9b,0x1e,
        0xe0,0xec,0x3f,0x8d,0xbe
    };
    const unsigned char expected[] = {
        0xa4,0x62,0xde,0x16,0xa8,0x9d,0xe8,0x46,0x6e,0xf5,0x46,0x0b,0x47,0xb8
    };
    unsigned char out[14];

    ret = TEST_ptr(kctx = EVP_KDF_CTX_new_id(EVP_KDF_SS))
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha224()),
                         0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, z, sizeof(z)),
                         0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSKDF_INFO, other,
                                      sizeof(other)), 0)
          && TEST_int_gt(EVP_KDF_derive(kctx, out, sizeof(out)), 0)
          && TEST_mem_eq(out, sizeof(out), expected, sizeof(expected));

    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_ss_hmac(void)
{
    int ret;
    EVP_KDF_CTX *kctx;
    const EVP_MAC *mac;

    const unsigned char z[] = {
        0xb7,0x4a,0x14,0x9a,0x16,0x15,0x46,0xf8,0xc2,0x0b,0x06,0xac,0x4e,0xd4
    };
    const unsigned char other[] = {
        0x34,0x8a,0x37,0xa2,0x7e,0xf1,0x28,0x2f,0x5f,0x02,0x0d,0xcc
    };
    const unsigned char salt[] = {
        0x36,0x38,0x27,0x1c,0xcd,0x68,0xa2,0x5d,0xc2,0x4e,0xcd,0xdd,0x39,0xef,
        0x3f,0x89
    };
    const unsigned char expected[] = {
        0x44,0xf6,0x76,0xe8,0x5c,0x1b,0x1a,0x8b,0xbc,0x3d,0x31,0x92,0x18,0x63,
        0x1c,0xa3
    };
    unsigned char out[16];

    ret = TEST_ptr(kctx = EVP_KDF_CTX_new_id(EVP_KDF_SS))
          && TEST_ptr(mac = EVP_get_macbyname("HMAC"))
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAC, mac), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD,  EVP_sha256()),
                         0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, z, sizeof(z)),
                         0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSKDF_INFO, other,
                                      sizeof(other)), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, salt,
                                      sizeof(salt)), 0)
          && TEST_int_gt(EVP_KDF_derive(kctx, out, sizeof(out)), 0)
          && TEST_mem_eq(out, sizeof(out), expected, sizeof(expected));

    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_ss_kmac(void)
{
    int ret;
    EVP_KDF_CTX *kctx;
    unsigned char out[64];
    const EVP_MAC *mac;

    const unsigned char z[] = {
        0xb7,0x4a,0x14,0x9a,0x16,0x15,0x46,0xf8,0xc2,0x0b,0x06,0xac,0x4e,0xd4
    };
    const unsigned char other[] = {
        0x34,0x8a,0x37,0xa2,0x7e,0xf1,0x28,0x2f,0x5f,0x02,0x0d,0xcc
    };
    const unsigned char salt[] = {
        0x36,0x38,0x27,0x1c,0xcd,0x68,0xa2,0x5d,0xc2,0x4e,0xcd,0xdd,0x39,0xef,
        0x3f,0x89
    };
    const unsigned char expected[] = {
        0xe9,0xc1,0x84,0x53,0xa0,0x62,0xb5,0x3b,0xdb,0xfc,0xbb,0x5a,0x34,0xbd,
        0xb8,0xe5,0xe7,0x07,0xee,0xbb,0x5d,0xd1,0x34,0x42,0x43,0xd8,0xcf,0xc2,
        0xc2,0xe6,0x33,0x2f,0x91,0xbd,0xa5,0x86,0xf3,0x7d,0xe4,0x8a,0x65,0xd4,
        0xc5,0x14,0xfd,0xef,0xaa,0x1e,0x67,0x54,0xf3,0x73,0xd2,0x38,0xe1,0x95,
        0xae,0x15,0x7e,0x1d,0xe8,0x14,0x98,0x03
    };

    ret = TEST_ptr(kctx = EVP_KDF_CTX_new_id(EVP_KDF_SS))
          && TEST_ptr(mac = EVP_get_macbyname("KMAC128"))
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAC, mac), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, z,
                                      sizeof(z)), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSKDF_INFO, other,
                                      sizeof(other)), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, salt,
                                      sizeof(salt)), 0)
          && TEST_int_gt(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAC_SIZE,
                                      (size_t)20), 0)
          && TEST_int_gt(EVP_KDF_derive(kctx, out, sizeof(out)), 0)
          && TEST_mem_eq(out, sizeof(out), expected, sizeof(expected));

    EVP_KDF_CTX_free(kctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_kdf_tls1_prf);
    ADD_TEST(test_kdf_hkdf);
    ADD_TEST(test_kdf_pbkdf2);
#ifndef OPENSSL_NO_SCRYPT
    ADD_TEST(test_kdf_scrypt);
#endif
    ADD_TEST(test_kdf_ss_hash);
    ADD_TEST(test_kdf_ss_hmac);
    ADD_TEST(test_kdf_ss_kmac);
    return 1;
}
