/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Tests the EVP_MAC APIs */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "internal/nelem.h"
#include "testutil.h"

static const unsigned char hmac_input[] = "Sample message for keylen<blocklen";
static const unsigned char hmac_sha224_key[] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
    0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B
};
static const unsigned char hmac_sha224_expected[] = {
    0xE3,0xD2,0x49,0xA8,0xCF,0xB6,0x7E,0xF8,0xB7,0xA1,0x69,0xE9,0xA0,0xA5,0x99,
    0x71,0x4A,0x2C,0xEC,0xBA,0x65,0x99,0x9A,0x51,0xBE,0xB8,0xFB,0xBE
};

static const unsigned char kmac128_input[] = { 0x00, 0x01, 0x02, 0x03 };
static const unsigned char kmac128_key[] = {
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,
    0x4F,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,
    0x5E,0x5F
};
static const unsigned char kmac128_expected[] = {
    0xE5,0x78,0x0B,0x0D,0x3E,0xA6,0xF7,0xD3,0xA4,0x29,0xC5,0x70,0x6A,0xA4,0x3A,
    0x00,0xFA,0xDB,0xD7,0xD4,0x96,0x28,0x83,0x9E,0x31,0x87,0x24,0x3F,0x45,0x6E,
    0xE1,0x4E
};

static const unsigned char cmac_input[] = {
    0x02,0x06,0x83,0xE1,0xF0,0x39,0x2F,0x4C,0xAC,0x54,0x31,0x8B,0x60,0x29,0x25,
    0x9E,0x9C,0x55,0x3D,0xBC,0x4B,0x6A,0xD9,0x98,0xE6,0x4D,0x58,0xE4,0xE7,0xDC,
    0x2E,0x13
};
static const unsigned char cmac_key[] = {
    0x77,0xA7,0x7F,0xAF,0x29,0x0C,0x1F,0xA3,0x0C,0x68,0x3D,0xF1,0x6B,0xA7,0xA7,
    0x7B
};
static const unsigned char cmac_expected[] = {
    0xFB,0xFE,0xA4,0x1B,0xF9,0x74,0x0C,0xB5,0x01,0xF1,0x29,0x2C,0x21,0xCE,0xBB,
    0x40
};

static const unsigned char gmac_key[] = {
    0x77,0xBE,0x63,0x70,0x89,0x71,0xC4,0xE2,0x40,0xD1,0xCB,0x79,0xE8,0xD7,0x7F,
    0xEB
};
static const unsigned char gmac_iv[] = {
    0xE0,0xE0,0x0F,0x19,0xFE,0xD7,0xBA,0x01,0x36,0xA7,0x97,0xF3
};
static const unsigned char gmac_input[] = {
    0x7A,0x43,0xEC,0x1D,0x9C,0x0A,0x5A,0x78,0xA0,0xB1,0x65,0x33,0xA6,0x21,0x3C,
    0xAB
};
static const unsigned char gmac_expected[] = {
    0x20,0x9F,0xCC,0x8D,0x36,0x75,0xED,0x93,0x8E,0x9C,0x71,0x66,0x70,0x9D,0xD9,
    0x46
};

static const unsigned char siphash_key[] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
    0x0F
};
static const unsigned char siphash_input[] = { 00 };
static const unsigned char siphash_expected[] = {
    0xda,0x87,0xc1,0xd8,0x6b,0x99,0xaf,0x44,0x34,0x76,0x59,0x11,0x9b,0x22,0xfc,
    0x45
};

static const unsigned char poly1305_input[] = {
    0x48,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21
};
static const unsigned char poly1305_key[] = {
    0x74,0x68,0x69,0x73,0x20,0x69,0x73,0x20,0x33,0x32,0x2d,0x62,0x79,0x74,0x65,
    0x20,0x6b,0x65,0x79,0x20,0x66,0x6f,0x72,0x20,0x50,0x6f,0x6c,0x79,0x31,0x33,
    0x30,0x35
};
static const unsigned char poly1305_expected[] = {
    0xa6,0xf7,0x45,0x00,0x8f,0x81,0xc9,0x16,0xa2,0x0d,0xcc,0x74,0xee,0xf2,0xb2,
    0xf0
};

static const unsigned char blake2s_input[] = { 00 };
static const unsigned char blake2s_key[] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
    0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,
    0x1E,0x1F
};
static const unsigned char blake2s_expected[] = {
    0x40,0xd1,0x5f,0xee,0x7c,0x32,0x88,0x30,0x16,0x6a,0xc3,0xf9,0x18,0x65,0x0f,
    0x80,0x7e,0x7e,0x01,0xe1,0x77,0x25,0x8c,0xdc,0x0a,0x39,0xb1,0x1f,0x59,0x80,
    0x66,0xf1
};

static const unsigned char blake2b_input[] = { 0x00,0x01,0x02 };
static const unsigned char blake2b_key[] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
    0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,
    0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,
    0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,
    0x3c,0x3d,0x3e,0x3f
};
static const unsigned char blake2b_expected[] = {
    0x33,0xd0,0x82,0x5d,0xdd,0xf7,0xad,0xa9,0x9b,0x0e,0x7e,0x30,0x71,0x04,0xad,
    0x07,0xca,0x9c,0xfd,0x96,0x92,0x21,0x4f,0x15,0x61,0x35,0x63,0x15,0xe7,0x84,
    0xf3,0xe5,0xa1,0x7e,0x36,0x4a,0xe9,0xdb,0xb1,0x4c,0xb2,0x03,0x6d,0xf9,0x32,
    0xb7,0x7f,0x4b,0x29,0x27,0x61,0x36,0x5f,0xb3,0x28,0xde,0x7a,0xfd,0xc6,0xd8,
    0x99,0x8f,0x5f,0xc1
};

static const struct TEST_DATA {
    int mac_id;
    const unsigned char *in;
    size_t in_len;
    const unsigned char *key;
    size_t key_len;
    const unsigned char *expect;
    size_t expect_len;
    const char *cipher_name;
    const char *md_name;
    const unsigned char *iv;
    size_t iv_len;
} test_data[] = {
    {
        EVP_MAC_HMAC,
        hmac_input, sizeof(hmac_input) - 1,
        hmac_sha224_key, sizeof(hmac_sha224_key),
        hmac_sha224_expected, sizeof(hmac_sha224_expected),
        NULL, "SHA224",
    },
    {
        EVP_MAC_KMAC128,
        kmac128_input, sizeof(kmac128_input),
        kmac128_key, sizeof(kmac128_key),
        kmac128_expected, sizeof(kmac128_expected)
    },
    {
        EVP_MAC_GMAC,
        gmac_input, sizeof(gmac_input),
        gmac_key, sizeof(gmac_key),
        gmac_expected, sizeof(gmac_expected),
        "AES-128-GCM", NULL,
        gmac_iv, sizeof(gmac_iv),
    },
    {
        EVP_MAC_CMAC,
        cmac_input, sizeof(cmac_input),
        cmac_key, sizeof(cmac_key),
        cmac_expected, sizeof(cmac_expected),
        "AES-128-CBC"
    },
    {
        EVP_MAC_SIPHASH,
        siphash_input, sizeof(siphash_input),
        siphash_key, sizeof(siphash_key),
        siphash_expected, sizeof(siphash_expected)
    },
    {
        EVP_MAC_POLY1305,
        poly1305_input, sizeof(poly1305_input),
        poly1305_key, sizeof(poly1305_key),
        poly1305_expected, sizeof(poly1305_expected)
    },
    {
        EVP_MAC_BLAKE2S,
        blake2s_input, sizeof(blake2s_input),
        blake2s_key, sizeof(blake2s_key),
        blake2s_expected, sizeof(blake2s_expected)
    },
    {
        EVP_MAC_BLAKE2B,
        blake2b_input, sizeof(blake2b_input),
        blake2b_key, sizeof(blake2b_key),
        blake2b_expected, sizeof(blake2b_expected)
    }
};

static int do_test_copy_ctx(EVP_MAC_CTX *ctx, const struct TEST_DATA *t)
{
    int ret = 0;
    EVP_MAC_CTX *ctx_pre_init = NULL;
    EVP_MAC_CTX *ctx_post_init = NULL;
    EVP_MAC_CTX *ctx_post_update = NULL;
    unsigned char out[EVP_MAX_MD_SIZE];
    size_t len = 0;
    int mac_id = t->mac_id;


    if (!TEST_ptr(ctx_pre_init = EVP_MAC_CTX_new_id(mac_id))
            || !TEST_ptr(ctx_post_init = EVP_MAC_CTX_new_id(mac_id))
            || !TEST_ptr(ctx_post_update = EVP_MAC_CTX_new_id(mac_id)))
        goto err;

    if (!TEST_true(EVP_MAC_CTX_copy(ctx_pre_init, ctx))
            || !TEST_true(EVP_MAC_init(ctx))
            || !TEST_true(EVP_MAC_CTX_copy(ctx_post_init, ctx))
            || !TEST_true(EVP_MAC_update(ctx, t->in, t->in_len))
            || !TEST_true(EVP_MAC_CTX_copy(ctx_post_update, ctx))
            || !TEST_true(EVP_MAC_final(ctx, out, &len)))
        goto err;
    if (!TEST_mem_eq(out, len, t->expect, t->expect_len))
        goto err;
    memset(out, 0, sizeof(out));

    if (!TEST_true(EVP_MAC_init(ctx_pre_init))
            || !TEST_true(EVP_MAC_update(ctx_pre_init, t->in, t->in_len))
            || !TEST_true(EVP_MAC_final(ctx_pre_init, out, &len)))
        goto err;
    if (!TEST_mem_eq(out, len, t->expect, t->expect_len))
        goto err;
    memset(out, 0, sizeof(out));

    if (!TEST_true(EVP_MAC_update(ctx_post_init, t->in, t->in_len))
            || !TEST_true(EVP_MAC_final(ctx_post_init, out, &len)))
        goto err;
    if (!TEST_mem_eq(out, len, t->expect, t->expect_len))
        goto err;
    memset(out, 0, sizeof(out));

    if (!TEST_true(EVP_MAC_final(ctx_post_update, out, &len)))
        goto err;
    if (!TEST_mem_eq(out, len, t->expect, t->expect_len))
        goto err;
    memset(out, 0, sizeof(out));

    /* Calling Init/Update/Final multiple times should work */
    if (!TEST_true(EVP_MAC_init(ctx))
            || !TEST_true(EVP_MAC_update(ctx, t->in, t->in_len))
            || !TEST_true(EVP_MAC_final(ctx, out, &len)))
        goto err;
    if (!TEST_mem_eq(out, len, t->expect, t->expect_len))
        goto err;

    ret = 1;
err:
    EVP_MAC_CTX_free(ctx_post_update);
    EVP_MAC_CTX_free(ctx_post_init);
    EVP_MAC_CTX_free(ctx_pre_init);
    return ret;
}

static int do_set_mac_ctrl(EVP_MAC_CTX *ctx, const struct TEST_DATA *t)
{
    int ret = 0;
    const EVP_CIPHER *cipher = NULL;

    if (t->cipher_name != NULL) {
        /* Used by CMAC and GMAC */
        if (!TEST_ptr(cipher = EVP_get_cipherbyname(t->cipher_name)))
            goto err;
        if (!TEST_true(EVP_MAC_init(ctx) <= 0))
            goto err;
        if (!TEST_true(EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_CIPHER, cipher) > 0))
            goto err;
    }

    if (t->md_name != NULL) {
        /* Used by HMAC */
        if (!TEST_true(EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_MD,
                                    EVP_get_digestbyname(t->md_name)) > 0))
            goto err;
    }

    if (!TEST_true(EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_KEY, t->key,
                                t->key_len) > 0))
        goto err;

    if (t->iv != NULL) {
        /* Used by GMAC */
        if (!TEST_true(EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_IV, t->iv,
                                    t->iv_len) > 0))
            goto err;
    }
    ret = 1;
err:
    return ret;
}

static int test_mac_copy(int id)
{
    const struct TEST_DATA *t = &test_data[id];
    int ret = 0;
    EVP_MAC_CTX *ctx = NULL;

    TEST_note("%s:", OBJ_nid2sn(t->mac_id));

    if (!TEST_ptr(ctx = EVP_MAC_CTX_new_id(t->mac_id)))
        goto err;
    if (!do_set_mac_ctrl(ctx, t))
        goto err;

    if (!do_test_copy_ctx(ctx, t))
        goto err;

    ret = 1;
err:
    EVP_MAC_CTX_free(ctx);
    return ret;
}

static int test_mac_copy_to(int id)
{
    const struct TEST_DATA *t = &test_data[id];
    int i;
    int ret = 0;
    EVP_MAC_CTX *ctx_other_empty = NULL, *ctx_other = NULL;
    EVP_MAC_CTX *ctx_t_empty = NULL, *ctx_t_empty2 = NULL;
    EVP_MAC_CTX *ctx_t = NULL, *ctx_t2 = NULL;

    for (i = 0; i < (int)OSSL_NELEM(test_data); ++i) {
        const struct TEST_DATA *t_other = &test_data[i];

        TEST_note("Copy %s => %s", OBJ_nid2sn(t_other->mac_id),
                  OBJ_nid2sn(t->mac_id));
        if (!TEST_ptr(ctx_other_empty = EVP_MAC_CTX_new_id(t_other->mac_id)))
            goto err;
        if (!TEST_ptr(ctx_other = EVP_MAC_CTX_new_id(t_other->mac_id)))
            goto err;
        if (!do_set_mac_ctrl(ctx_other, t_other))
            goto err;
        if (!TEST_ptr(ctx_t_empty = EVP_MAC_CTX_new_id(t->mac_id)))
            goto err;
        if (!TEST_ptr(ctx_t_empty2 = EVP_MAC_CTX_new_id(t->mac_id)))
            goto err;
        if (!TEST_ptr(ctx_t = EVP_MAC_CTX_new_id(t->mac_id)))
            goto err;
        if (!TEST_ptr(ctx_t2 = EVP_MAC_CTX_new_id(t->mac_id)))
            goto err;
        if (!do_set_mac_ctrl(ctx_t, t))
            goto err;
        if (!do_set_mac_ctrl(ctx_t2, t))
            goto err;

        if (!TEST_true(EVP_MAC_CTX_copy(ctx_t_empty2, ctx_other) > 0))
            goto err;
        if (!do_test_copy_ctx(ctx_t_empty2, t_other))
            goto err;
        if (!TEST_true(EVP_MAC_CTX_copy(ctx_t2, ctx_other) > 0))
            goto err;
        if (!do_test_copy_ctx(ctx_t_empty2, t_other))
            goto err;

        if (!TEST_true(EVP_MAC_CTX_copy(ctx_t, ctx_other_empty) > 0))
            goto err;
        if (!do_set_mac_ctrl(ctx_t, t_other))
            goto err;
        if (!do_test_copy_ctx(ctx_t, t_other))
            goto err;

        if (!TEST_true(EVP_MAC_CTX_copy(ctx_t_empty, ctx_other_empty) > 0))
            goto err;
        if (!do_set_mac_ctrl(ctx_t_empty, t_other))
            goto err;
        if (!do_test_copy_ctx(ctx_t_empty, t_other))
            goto err;

        EVP_MAC_CTX_free(ctx_other_empty);
        EVP_MAC_CTX_free(ctx_other);
        EVP_MAC_CTX_free(ctx_t_empty);
        EVP_MAC_CTX_free(ctx_t_empty2);
        EVP_MAC_CTX_free(ctx_t);
        EVP_MAC_CTX_free(ctx_t2);
        ctx_other_empty = ctx_other = NULL;
        ctx_t_empty = ctx_t_empty2 = NULL;
        ctx_t = ctx_t2 = NULL;
    }
    ret = 1;
err:
    EVP_MAC_CTX_free(ctx_other_empty);
    EVP_MAC_CTX_free(ctx_other);
    EVP_MAC_CTX_free(ctx_t_empty);
    EVP_MAC_CTX_free(ctx_t_empty2);
    EVP_MAC_CTX_free(ctx_t);
    EVP_MAC_CTX_free(ctx_t2);

    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_mac_copy, OSSL_NELEM(test_data));
    ADD_ALL_TESTS(test_mac_copy_to, OSSL_NELEM(test_data));
    return 1;
}
