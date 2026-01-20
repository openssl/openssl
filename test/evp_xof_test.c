/*
 * Copyright 2023-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "testutil.h"
#include "internal/nelem.h"

static const uint8_t shake256_input[] = {
    0x8d, 0x80, 0x01, 0xe2, 0xc0, 0x96, 0xf1, 0xb8,
    0x8e, 0x7c, 0x92, 0x24, 0xa0, 0x86, 0xef, 0xd4,
    0x79, 0x7f, 0xbf, 0x74, 0xa8, 0x03, 0x3a, 0x2d,
    0x42, 0x2a, 0x2b, 0x6b, 0x8f, 0x67, 0x47, 0xe4
};

/*
 * This KAT output is 250 bytes, which is more than
 * the SHAKE256 block size (136 bytes).
 */
static const uint8_t shake256_output[] = {
    0x2e, 0x97, 0x5f, 0x6a, 0x8a, 0x14, 0xf0, 0x70,
    0x4d, 0x51, 0xb1, 0x36, 0x67, 0xd8, 0x19, 0x5c,
    0x21, 0x9f, 0x71, 0xe6, 0x34, 0x56, 0x96, 0xc4,
    0x9f, 0xa4, 0xb9, 0xd0, 0x8e, 0x92, 0x25, 0xd3,
    0xd3, 0x93, 0x93, 0x42, 0x51, 0x52, 0xc9, 0x7e,
    0x71, 0xdd, 0x24, 0x60, 0x1c, 0x11, 0xab, 0xcf,
    0xa0, 0xf1, 0x2f, 0x53, 0xc6, 0x80, 0xbd, 0x3a,
    0xe7, 0x57, 0xb8, 0x13, 0x4a, 0x9c, 0x10, 0xd4,
    0x29, 0x61, 0x58, 0x69, 0x21, 0x7f, 0xdd, 0x58,
    0x85, 0xc4, 0xdb, 0x17, 0x49, 0x85, 0x70, 0x3a,
    0x6d, 0x6d, 0xe9, 0x4a, 0x66, 0x7e, 0xac, 0x30,
    0x23, 0x44, 0x3a, 0x83, 0x37, 0xae, 0x1b, 0xc6,
    0x01, 0xb7, 0x6d, 0x7d, 0x38, 0xec, 0x3c, 0x34,
    0x46, 0x31, 0x05, 0xf0, 0xd3, 0x94, 0x9d, 0x78,
    0xe5, 0x62, 0xa0, 0x39, 0xe4, 0x46, 0x95, 0x48,
    0xb6, 0x09, 0x39, 0x5d, 0xe5, 0xa4, 0xfd, 0x43,
    0xc4, 0x6c, 0xa9, 0xfd, 0x6e, 0xe2, 0x9a, 0xda,
    0x5e, 0xfc, 0x07, 0xd8, 0x4d, 0x55, 0x32, 0x49,
    0x45, 0x0d, 0xab, 0x4a, 0x49, 0xc4, 0x83, 0xde,
    0xd2, 0x50, 0xc9, 0x33, 0x8f, 0x85, 0xcd, 0x93,
    0x7a, 0xe6, 0x6b, 0xb4, 0x36, 0xf3, 0xb4, 0x02,
    0x6e, 0x85, 0x9f, 0xda, 0x1c, 0xa5, 0x71, 0x43,
    0x2f, 0x3b, 0xfc, 0x09, 0xe7, 0xc0, 0x3c, 0xa4,
    0xd1, 0x83, 0xb7, 0x41, 0x11, 0x1c, 0xa0, 0x48,
    0x3d, 0x0e, 0xda, 0xbc, 0x03, 0xfe, 0xb2, 0x3b,
    0x17, 0xee, 0x48, 0xe8, 0x44, 0xba, 0x24, 0x08,
    0xd9, 0xdc, 0xfd, 0x01, 0x39, 0xd2, 0xe8, 0xc7,
    0x31, 0x01, 0x25, 0xae, 0xe8, 0x01, 0xc6, 0x1a,
    0xb7, 0x90, 0x0d, 0x1e, 0xfc, 0x47, 0xc0, 0x78,
    0x28, 0x17, 0x66, 0xf3, 0x61, 0xc5, 0xe6, 0x11,
    0x13, 0x46, 0x23, 0x5e, 0x1d, 0xc3, 0x83, 0x25,
    0x66, 0x6c
};

static const uint8_t cshake256_output[] = {
    0x30, 0xa6, 0x5f, 0xd5, 0xff, 0x3e, 0x49, 0xe8,
    0xa9, 0xef, 0x06, 0xa3, 0x56, 0x4b, 0x4f, 0x55,
    0x93, 0x0f, 0x4a, 0x9e, 0xe9, 0x74, 0x13, 0xf8,
    0x4a, 0x80, 0x44, 0x65, 0xec, 0x62, 0x83, 0x7a,
    0x21, 0xce, 0x96, 0x0e, 0x27, 0x1f, 0x81, 0x26,
    0xcb, 0xd8, 0x42, 0x7b, 0x7d, 0x71, 0x6a, 0xdc,
    0xaf, 0x4d, 0x13, 0x52, 0x28, 0x2b, 0xd9, 0x70,
    0xfb, 0x90, 0x96, 0xfe, 0x24, 0xd2, 0x22, 0x48,
    0x73, 0xae, 0x73, 0x1e, 0x10, 0x07, 0x4b, 0x92,
    0x2a, 0xae, 0x1e, 0x7b, 0x7d, 0x06, 0xe2, 0x0f,
    0x80, 0x08, 0xc3, 0xa5, 0x09, 0x71, 0x57, 0x84,
    0x4a, 0xa8, 0x70, 0xe7, 0x61, 0x6b, 0x0c, 0x3c
};

typedef struct test_data_st {
    const char *alg;
    const uint8_t *in;
    size_t inlen;
    const uint8_t *out;
    size_t outlen;
    int default_xoflen;
    const char *param_n;
    const char *param_s;
} TEST_DATA;

static const TEST_DATA xof_test_data[] = {
    {
        "SHAKE256",
        shake256_input,
        sizeof(shake256_input),
        shake256_output,
        sizeof(shake256_output),
    },
    { "CSHAKE256",
        shake256_input, sizeof(shake256_input),
        shake256_output, sizeof(shake256_output),
        64 },
    { "CSHAKE256",
        shake256_input, sizeof(shake256_input),
        cshake256_output, sizeof(cshake256_output),
        64,
        "KMAC",
        "Custom" },
};

static const unsigned char shake256_largemsg_input[] = {
    0xb2, 0xd2, 0x38, 0x65, 0xaf, 0x8f, 0x25, 0x6e,
    0x64, 0x40, 0xe2, 0x0d, 0x49, 0x8e, 0x3e, 0x64,
    0x46, 0xd2, 0x03, 0xa4, 0x19, 0xe3, 0x7b, 0x80,
    0xf7, 0x2b, 0x32, 0xe2, 0x76, 0x01, 0xfe, 0xdd,
    0xaa, 0x33, 0x3d, 0xe4, 0x8e, 0xe1, 0x5e, 0x39,
    0xa6, 0x92, 0xa3, 0xa7, 0xe3, 0x81, 0x24, 0x74,
    0xc7, 0x38, 0x18, 0x92, 0xc9, 0x60, 0x50, 0x15,
    0xfb, 0xd8, 0x04, 0xea, 0xea, 0x04, 0xd2, 0xc5,
    0xc6, 0x68, 0x04, 0x5b, 0xc3, 0x75, 0x12, 0xd2,
    0xbe, 0xa2, 0x67, 0x75, 0x24, 0xbf, 0x68, 0xad,
    0x10, 0x86, 0xb3, 0x2c, 0xb3, 0x74, 0xa4, 0x6c,
    0xf9, 0xd7, 0x1e, 0x58, 0x69, 0x27, 0x88, 0x49,
    0x4e, 0x99, 0x15, 0x33, 0x14, 0xf2, 0x49, 0x21,
    0xf4, 0x99, 0xb9, 0xde, 0xd4, 0xf1, 0x12, 0xf5,
    0x68, 0xe5, 0x5c, 0xdc, 0x9e, 0xc5, 0x80, 0x6d,
    0x39, 0x50, 0x08, 0x95, 0xbb, 0x12, 0x27, 0x50,
    0x89, 0xf0, 0xf9, 0xd5, 0x4a, 0x01, 0x0b, 0x0d,
    0x90, 0x9f, 0x1e, 0x4a, 0xba, 0xbe, 0x28, 0x36,
    0x19, 0x7d, 0x9c, 0x0a, 0x51, 0xfb, 0xeb, 0x00,
    0x02, 0x6c, 0x4b, 0x0a, 0xa8, 0x6c, 0xb7, 0xc4,
    0xc0, 0x92, 0x37, 0xa7, 0x2d, 0x49, 0x61, 0x80,
    0xd9, 0xdb, 0x20, 0x21, 0x9f, 0xcf, 0xb4, 0x57,
    0x69, 0x75, 0xfa, 0x1c, 0x95, 0xbf, 0xee, 0x0d,
    0x9e, 0x52, 0x6e, 0x1e, 0xf8, 0xdd, 0x41, 0x8c,
    0x3b, 0xaa, 0x57, 0x13, 0x84, 0x73, 0x52, 0x62,
    0x18, 0x76, 0x46, 0xcc, 0x4b, 0xcb, 0xbd, 0x40,
    0xa1, 0xf6, 0xff, 0x7b, 0x32, 0xb9, 0x90, 0x7c,
    0x53, 0x2c, 0xf9, 0x38, 0x72, 0x0f, 0xcb, 0x90,
    0x42, 0x5e, 0xe2, 0x80, 0x19, 0x26, 0xe7, 0x99,
    0x96, 0x98, 0x18, 0xb1, 0x86, 0x5b, 0x4c, 0xd9,
    0x08, 0x27, 0x31, 0x8f, 0xf0, 0x90, 0xd9, 0x35,
    0x6a, 0x1f, 0x75, 0xc2, 0xe0, 0xa7, 0x60, 0xb8,
    0x1d, 0xd6, 0x5f, 0x56, 0xb2, 0x0b, 0x27, 0x0e,
    0x98, 0x67, 0x1f, 0x39, 0x18, 0x27, 0x68, 0x0a,
    0xe8, 0x31, 0x1b, 0xc0, 0x97, 0xec, 0xd1, 0x20,
    0x2a, 0x55, 0x69, 0x23, 0x08, 0x50, 0x05, 0xec,
    0x13, 0x3b, 0x56, 0xfc, 0x18, 0xc9, 0x1a, 0xa9,
    0x69, 0x0e, 0xe2, 0xcc, 0xc8, 0xd6, 0x19, 0xbb,
    0x87, 0x3b, 0x42, 0x77, 0xee, 0x77, 0x81, 0x26,
    0xdd, 0xf6, 0x5d, 0xc3, 0xb2, 0xb0, 0xc4, 0x14,
    0x6d, 0xb5, 0x4f, 0xdc, 0x13, 0x09, 0xc8, 0x53,
    0x50, 0xb3, 0xea, 0xd3, 0x5f, 0x11, 0x67, 0xd4,
    0x2f, 0x6e, 0x30, 0x1a, 0xbe, 0xd6, 0xf0, 0x2d,
    0xc9, 0x29, 0xd9, 0x0a, 0xa8, 0x6f, 0xa4, 0x18,
    0x74, 0x6b, 0xd3, 0x5d, 0x6a, 0x73, 0x3a, 0xf2,
    0x94, 0x7f, 0xbd, 0xb4, 0xa6, 0x7f, 0x5b, 0x3d,
    0x26, 0xf2, 0x6c, 0x13, 0xcf, 0xb4, 0x26, 0x1e,
    0x38, 0x17, 0x66, 0x60, 0xb1, 0x36, 0xae, 0xe0,
    0x6d, 0x86, 0x69, 0xe7, 0xe7, 0xae, 0x77, 0x6f,
    0x7e, 0x99, 0xe5, 0xd9, 0x62, 0xc9, 0xfc, 0xde,
    0xb4, 0xee, 0x7e, 0xc8, 0xe9, 0xb7, 0x2c, 0xe2,
    0x70, 0xe8, 0x8b, 0x2d, 0x94, 0xad, 0xe8, 0x54,
    0xa3, 0x2d, 0x9a, 0xe2, 0x50, 0x63, 0x87, 0xb3,
    0x56, 0x29, 0xea, 0xa8, 0x5e, 0x96, 0x53, 0x9f,
    0x23, 0x8a, 0xef, 0xa3, 0xd4, 0x87, 0x09, 0x5f,
    0xba, 0xc3, 0xd1, 0xd9, 0x1a, 0x7b, 0x5c, 0x5d,
    0x5d, 0x89, 0xed, 0xb6, 0x6e, 0x39, 0x73, 0xa5,
    0x64, 0x59, 0x52, 0x8b, 0x61, 0x8f, 0x66, 0x69,
    0xb9, 0xf0, 0x45, 0x0a, 0x57, 0xcd, 0xc5, 0x7f,
    0x5d, 0xd0, 0xbf, 0xcc, 0x0b, 0x48, 0x12, 0xe1,
    0xe2, 0xc2, 0xea, 0xcc, 0x09, 0xd9, 0x42, 0x2c,
    0xef, 0x4f, 0xa7, 0xe9, 0x32, 0x5c, 0x3f, 0x22,
    0xc0, 0x45, 0x0b, 0x67, 0x3c, 0x31, 0x69, 0x29,
    0xa3, 0x39, 0xdd, 0x6e, 0x2f, 0xbe, 0x10, 0xc9,
    0x7b, 0xff, 0x19, 0x8a, 0xe9, 0xea, 0xfc, 0x32,
    0x41, 0x33, 0x70, 0x2a, 0x9a, 0xa4, 0xe6, 0xb4,
    0x7e, 0xb4, 0xc6, 0x21, 0x49, 0x5a, 0xfc, 0x45,
    0xd2, 0x23, 0xb3, 0x28, 0x4d, 0x83, 0x60, 0xfe,
    0x70, 0x68, 0x03, 0x59, 0xd5, 0x15, 0xaa, 0x9e,
    0xa0, 0x2e, 0x36, 0xb5, 0x61, 0x0f, 0x61, 0x05,
    0x3c, 0x62, 0x00, 0xa0, 0x47, 0xf1, 0x86, 0xba,
    0x33, 0xb8, 0xca, 0x60, 0x2f, 0x3f, 0x0a, 0x67,
    0x09, 0x27, 0x2f, 0xa2, 0x96, 0x02, 0x52, 0x58,
    0x55, 0x68, 0x80, 0xf4, 0x4f, 0x47, 0xba, 0xff,
    0x41, 0x7a, 0x40, 0x4c, 0xfd, 0x9d, 0x10, 0x72,
    0x0e, 0x20, 0xa9, 0x7f, 0x9b, 0x9b, 0x14, 0xeb,
    0x8e, 0x61, 0x25, 0xcb, 0xf4, 0x58, 0xff, 0x47,
    0xa7, 0x08, 0xd6, 0x4e, 0x2b, 0xf1, 0xf9, 0x89,
    0xd7, 0x22, 0x0f, 0x8d, 0x35, 0x07, 0xa0, 0x54,
    0xab, 0x83, 0xd8, 0xee, 0x5a, 0x3e, 0x88, 0x74,
    0x46, 0x41, 0x6e, 0x3e, 0xb7, 0xc0, 0xb6, 0x55,
    0xe0, 0x36, 0xc0, 0x2b, 0xbf, 0xb8, 0x24, 0x8a,
    0x44, 0x82, 0xf4, 0xcb, 0xb5, 0xd7, 0x41, 0x48,
    0x51, 0x08, 0xe0, 0x14, 0x34, 0xd2, 0x6d, 0xe9,
    0x7a, 0xec, 0x91, 0x61, 0xa7, 0xe1, 0x81, 0x69,
    0x47, 0x1c, 0xc7, 0xf3
};

static const unsigned char shake256_largemsg_output[] = {
    0x64, 0xea, 0x24, 0x6a, 0xab, 0x80, 0x37, 0x9e,
    0x08, 0xe2, 0x19, 0x9e, 0x09, 0x69, 0xe2, 0xee,
    0x1a, 0x5d, 0xd1, 0x68, 0x68, 0xec, 0x8d, 0x42,
    0xd0, 0xf8, 0xb8, 0x44, 0x74, 0x54, 0x87, 0x3e
};

static const TEST_DATA large_msg_test_data[] = {
    {
        "SHAKE256",
        shake256_largemsg_input,
        sizeof(shake256_largemsg_input),
        shake256_largemsg_output,
        sizeof(shake256_largemsg_output),
    },
};

static EVP_MD_CTX *xof_digest_setup(const TEST_DATA *td)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    OSSL_PARAM params[3], *p = params;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, td->alg, NULL)))
        return NULL;

    if (!TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;
    if (td->param_n != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DIGEST_PARAM_FUNCTION_NAME, (char *)td->param_n, 0);
    if (td->param_s != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DIGEST_PARAM_CUSTOMIZATION, (char *)td->param_s, 0);
    *p = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_DigestInit_ex2(ctx, md, params)))
        goto err;
    EVP_MD_free(md);
    return ctx;
err:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    return NULL;
}

static int xof_kat_test(int tstid)
{
    const TEST_DATA *td = xof_test_data + tstid;
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    uint8_t out[2048];

    if (!TEST_size_t_le(td->outlen, sizeof(out)))
        return 0;
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    if (!TEST_true(EVP_DigestUpdate(ctx, td->in, td->inlen))
        || !TEST_true(EVP_DigestFinalXOF(ctx, out, td->outlen))
        || !TEST_mem_eq(out, td->outlen, td->out, td->outlen)
        /* Test that a second call to EVP_DigestFinalXOF fails */
        || !TEST_false(EVP_DigestFinalXOF(ctx, out, td->outlen))
        /* Test that a call to EVP_DigestSqueeze fails */
        || !TEST_false(EVP_DigestSqueeze(ctx, out, td->outlen)))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int xof_kat_digestfinal_test(int tstid)
{
    const TEST_DATA *td = xof_test_data + tstid;
    int ret = 0;
    unsigned int digest_length = 0;
    EVP_MD_CTX *ctx = NULL;
    uint8_t out[2048];

    if (!TEST_size_t_le(td->outlen, sizeof(out)))
        return 0;
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    if (!TEST_true(EVP_DigestUpdate(ctx, td->in, td->inlen)))
        goto err;
    if (td->default_xoflen == 0) {
        /*
         * Test that EVP_DigestFinal without setting XOFLEN fails for SHAKE
         * (The original code for SHAKE set the wrong default value which is
         * why the XOF needs to be set for this).
         */
        ERR_set_mark();
        if (!TEST_false(EVP_DigestFinal(ctx, out, &digest_length))) {
            ERR_clear_last_mark();
            goto err;
        }
        ERR_pop_to_mark();
    } else {
        /*
         * Test that EVP_DigestFinal without setting XOFLEN passes for CSHAKE
         * and correctly returns 2 * 256 = 512 bits (64 bytes) by default.
         */
        if (!TEST_true(EVP_DigestFinal(ctx, out, &digest_length))
            || !TEST_uint_eq(digest_length, td->default_xoflen)
            || !TEST_mem_eq(out, digest_length, td->out, digest_length))
            goto err;
    }
    EVP_MD_CTX_free(ctx);

    /* EVP_DigestFinalXOF must work */
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    if (!TEST_true(EVP_DigestUpdate(ctx, td->in, td->inlen)))
        goto err;
    if (!TEST_true(EVP_DigestFinalXOF(ctx, out, td->outlen))
        || !TEST_mem_eq(out, td->outlen, td->out, td->outlen)
        || !TEST_false(EVP_DigestFinalXOF(ctx, out, td->outlen)))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * Test that EVP_DigestFinal() returns the output length
 * set by the OSSL_DIGEST_PARAM_XOFLEN param.
 */
static int xof_kat_digestfinal_xoflen_test(int tstid)
{
    const TEST_DATA *td = xof_test_data + tstid;
    int ret = 0;
    unsigned int digest_length = 0;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md;
    OSSL_PARAM params[2];
    size_t sz = 12;
    uint8_t out[2048];

    if (!TEST_size_t_le(td->outlen, sizeof(out)))
        return 0;
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;

    md = EVP_MD_CTX_get0_md(ctx);

    memset(out, 0, td->outlen);
    params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &sz);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_int_eq(EVP_MD_CTX_size(ctx), td->default_xoflen == 0 ? -1 : td->default_xoflen)
        || !TEST_int_eq(EVP_MD_CTX_set_params(ctx, params), 1)
        || !TEST_int_eq(EVP_MD_CTX_size(ctx), (int)sz)
        || !TEST_int_eq(EVP_MD_get_size(md), td->default_xoflen)
        || !TEST_true(EVP_MD_xof(md))
        || !TEST_true(EVP_DigestUpdate(ctx, td->in, td->inlen))
        || !TEST_true(EVP_DigestFinal(ctx, out, &digest_length))
        || !TEST_uint_eq(digest_length, (unsigned int)sz)
        || !TEST_mem_eq(out, digest_length, td->out, digest_length)
        || !TEST_uchar_eq(out[digest_length], 0))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * Test that multiple absorb calls gives the expected result.
 * This is a nested test that uses multiple strides for the input.
 */
static int xof_absorb_test(int tstid)
{
    const TEST_DATA *td = large_msg_test_data + tstid;
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char out[2048];
    size_t total = td->inlen;
    size_t i, stride, sz;

    if (!TEST_size_t_le(td->outlen, sizeof(out)))
        return 0;
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;

    for (stride = 1; stride < total; ++stride) {
        sz = 0;
        for (i = 0; i < total; i += sz) {
            sz += stride;
            if ((i + sz) > total)
                sz = total - i;
            if (!TEST_true(EVP_DigestUpdate(ctx, td->in + i, sz)))
                goto err;
        }
        if (!TEST_true(EVP_DigestFinalXOF(ctx, out, td->outlen))
            || !TEST_mem_eq(out, td->outlen, td->out, td->outlen))
            goto err;
        if (!TEST_true(EVP_DigestInit_ex2(ctx, NULL, NULL)))
            goto err;
    }
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * Table containing the size of the output to squeeze for the
 * initially call, followed by a size for each subsequent call.
 */
typedef struct stride_test_data_st {
    size_t startsz, incsz;
} STRIDE_TEST_DATA;

static const STRIDE_TEST_DATA stride_test_data[] = {
    { 1, 1 },
    { 1, 136 },
    { 1, 136 / 2 },
    { 1, 136 / 2 - 1 },
    { 1, 136 / 2 + 1 },
    { 1, 136 * 3 },
    { 8, 8 },
    { 9, 9 },
    { 10, 10 },
    { 136 / 2 - 1, 136 },
    { 136 / 2 - 1, 136 - 1 },
    { 136 / 2 - 1, 136 + 1 },
    { 136 / 2, 136 },
    { 136 / 2, 136 - 1 },
    { 136 / 2, 136 + 1 },
    { 136 / 2 + 1, 136 },
    { 136 / 2 + 1, 136 - 1 },
    { 136 / 2 + 1, 136 + 1 },
    { 136, 2 },
    { 136, 136 },
    { 136 - 1, 136 },
    { 136 - 1, 136 - 1 },
    { 136 - 1, 136 + 1 },
    { 136 + 1, 136 },
    { 136 + 1, 136 - 1 },
    { 136 + 1, 136 + 1 },
    { 136 * 3, 136 },
    { 136 * 3, 136 + 1 },
    { 136 * 3, 136 - 1 },
    { 136 * 3, 136 / 2 },
    { 136 * 3, 136 / 2 + 1 },
    { 136 * 3, 136 / 2 - 1 },
};

/*
 * Helper to do multiple squeezes of output data using SHAKE256.
 * tst is an index into the stride_tests[] containing an initial starting
 * output length, followed by a second output length to use for all remaining
 * squeezes. expected_outlen contains the total number of bytes to squeeze.
 * in and inlen represent the input to absorb. expected_out and expected_outlen
 * represent the expected output.
 */
static int do_xof_squeeze_test(const TEST_DATA *td,
    const STRIDE_TEST_DATA *stride,
    const uint8_t *in, size_t inlen,
    const uint8_t *expected_out,
    size_t expected_outlen)
{
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *out = NULL;
    size_t i = 0, sz = stride->startsz;

    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    if (!TEST_ptr(out = OPENSSL_malloc(expected_outlen)))
        goto err;
    if (!TEST_true(EVP_DigestUpdate(ctx, in, inlen)))
        goto err;

    while (i < expected_outlen) {
        if ((i + sz) > expected_outlen)
            sz = expected_outlen - i;
        if (!TEST_true(EVP_DigestSqueeze(ctx, out + i, sz)))
            goto err;
        i += sz;
        sz = stride->incsz;
    }
    if (!TEST_mem_eq(out, expected_outlen, expected_out, expected_outlen))
        goto err;
    ret = 1;
err:
    OPENSSL_free(out);
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int xof_squeeze_kat_test(int tstid)
{
    const STRIDE_TEST_DATA *sd = stride_test_data + tstid;
    const TEST_DATA *td = xof_test_data + (tstid % (OSSL_NELEM(xof_test_data)));

    return do_xof_squeeze_test(td, sd, td->in, td->inlen, td->out, td->outlen);
}

/*
 * Generate some random input to absorb, and then
 * squeeze it out in one operation to get a expected
 * output. Use this to test that multiple squeeze calls
 * on the same input gives the same output.
 */
static int xof_squeeze_large_test(int tstid)
{
    const STRIDE_TEST_DATA *sd = stride_test_data + tstid;
    const TEST_DATA *td = xof_test_data + (tstid % (OSSL_NELEM(xof_test_data)));
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char msg[16];
    unsigned char out[2000];

    if (!TEST_int_gt(RAND_bytes(msg, sizeof(msg)), 0)
        || !TEST_ptr(ctx = xof_digest_setup(td))
        || !TEST_true(EVP_DigestUpdate(ctx, msg, sizeof(msg)))
        || !TEST_true(EVP_DigestFinalXOF(ctx, out, sizeof(out))))
        goto err;

    ret = do_xof_squeeze_test(td, sd, msg, sizeof(msg), out, sizeof(out));
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static const size_t dupoffset_test_data[] = {
    1, 135, 136, 137, 136 * 3 - 1, 136 * 3, 136 * 3 + 1
};

/* Helper function to test that EVP_MD_CTX_dup() copies the internal state */
static int do_xof_squeeze_dup_test(const TEST_DATA *td, size_t dupoffset,
    const uint8_t *in, size_t inlen,
    const uint8_t *expected_out, size_t expected_outlen)
{
    int ret = 0;
    EVP_MD_CTX *cur, *ctx = NULL, *dupctx = NULL;
    unsigned char *out = NULL;
    size_t i = 0, sz = 10;

    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    cur = ctx;
    if (!TEST_ptr(out = OPENSSL_malloc(expected_outlen)))
        goto err;
    if (!TEST_true(EVP_DigestUpdate(ctx, in, inlen)))
        goto err;

    while (i < expected_outlen) {
        if ((i + sz) > expected_outlen)
            sz = expected_outlen - i;
        if (!TEST_true(EVP_DigestSqueeze(cur, out + i, sz)))
            goto err;
        i += sz;
        /* At a certain offset we swap to a new ctx that copies the state */
        if (dupctx == NULL && i >= dupoffset) {
            if (!TEST_ptr(dupctx = EVP_MD_CTX_dup(ctx)))
                goto err;
            cur = dupctx;
        }
    }
    if (!TEST_mem_eq(out, expected_outlen, expected_out, expected_outlen))
        goto err;
    ret = 1;
err:
    OPENSSL_free(out);
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(dupctx);
    return ret;
}

/* Test that the internal state can be copied */
static int xof_squeeze_dup_test(int tstid)
{
    size_t dupoffset = dupoffset_test_data[tstid];
    const TEST_DATA *td = xof_test_data + (tstid % (OSSL_NELEM(xof_test_data)));
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char msg[16];
    unsigned char out[1000];

    if (!TEST_int_gt(RAND_bytes(msg, sizeof(msg)), 0)
        || !TEST_ptr(ctx = xof_digest_setup(td))
        || !TEST_true(EVP_DigestUpdate(ctx, msg, sizeof(msg)))
        || !TEST_true(EVP_DigestFinalXOF(ctx, out, sizeof(out))))
        goto err;

    ret = do_xof_squeeze_dup_test(td, dupoffset, msg, sizeof(msg),
        out, sizeof(out));
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/* Test that a squeeze without a preceding absorb works */
static int xof_squeeze_no_absorb_test(int tstid)
{
    const TEST_DATA *td = xof_test_data + tstid;
    int ret = 0;
    EVP_MD_CTX *ctx = NULL, *ctx2 = NULL;
    unsigned char out[1000];
    unsigned char out2[1000];

    memset(out, 0, sizeof(out));
    memset(out2, 0, sizeof(out2));
    if (!TEST_ptr(ctx = xof_digest_setup(td))
        || !TEST_ptr(ctx2 = EVP_MD_CTX_dup(ctx))
        || !TEST_true(EVP_DigestFinalXOF(ctx, out, sizeof(out)))
        || !TEST_true(EVP_DigestSqueeze(ctx2, out2, sizeof(out2) / 2))
        || !TEST_true(EVP_DigestSqueeze(ctx2, out2 + sizeof(out2) / 2,
            sizeof(out2) / 2))
        || !TEST_mem_eq(out2, sizeof(out2), out, sizeof(out)))
        goto err;
    ret = 1;

err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx2);
    return ret;
}

static int xof_fail_test(void)
{
    int ret;
    EVP_MD *md = NULL;

    ret = TEST_ptr(md = EVP_MD_fetch(NULL, "SHA256", NULL))
        && TEST_false(EVP_MD_xof(md));
    EVP_MD_free(md);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(xof_kat_test, OSSL_NELEM(xof_test_data));
    ADD_ALL_TESTS(xof_kat_digestfinal_test, OSSL_NELEM(xof_test_data));
    ADD_ALL_TESTS(xof_kat_digestfinal_xoflen_test, OSSL_NELEM(xof_test_data));
    ADD_ALL_TESTS(xof_squeeze_no_absorb_test, OSSL_NELEM(xof_test_data));
    ADD_ALL_TESTS(xof_absorb_test, OSSL_NELEM(large_msg_test_data));
    ADD_ALL_TESTS(xof_squeeze_kat_test, OSSL_NELEM(stride_test_data));
    ADD_ALL_TESTS(xof_squeeze_large_test, OSSL_NELEM(stride_test_data));
    ADD_ALL_TESTS(xof_squeeze_dup_test, OSSL_NELEM(dupoffset_test_data));
    ADD_TEST(xof_fail_test);
    return 1;
}
