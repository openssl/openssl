/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/err.h>

#include "testutil.h"

#define MAX_CT_LEN 256

static const unsigned char ptext_pad[] = "The quick brown fox with a padding";
static const unsigned char key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

static const unsigned char cbc_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const unsigned char cbc_ct[48] = {
    0x99, 0x3f, 0x48, 0xc8, 0x17, 0x94, 0x6d, 0x0c, 0xcb, 0xa1, 0xd7, 0xc5, 0x38, 0x13, 0xcf, 0x84,
    0x85, 0x4f, 0x2b, 0xfe, 0x1b, 0xc5, 0xdb, 0x05, 0x45, 0x29, 0xde, 0x2b, 0x4d, 0x34, 0x3d, 0x77,
    0x45, 0xe6, 0x7d, 0xf6, 0x85, 0x17, 0xba, 0x81, 0xbd, 0x4c, 0xd2, 0x79, 0x4b, 0xfc, 0x13, 0x63
};

static const unsigned char gcm_iv[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
};
static const unsigned char gcm_aad[20] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};
static const unsigned char gcm_ct[35] = {
    0xf3, 0x4f, 0x8d, 0x50, 0x9e, 0x33, 0xb8, 0x18, 0xfd, 0xbe, 0x18, 0x09, 0xb8, 0x8f, 0xa1, 0xe0,
    0x61, 0x85, 0x58, 0xee, 0x62, 0x25, 0x4e, 0x7f, 0x10, 0x55, 0x85, 0x3b, 0x0c, 0x0b, 0xa5, 0xb4,
    0x5b, 0x0e, 0x93
};
static const unsigned char gcm_tag[16] = {
    0x7e, 0x7c, 0x34, 0x66, 0x77, 0x92, 0x2b, 0x36, 0xaf, 0xd1, 0xff, 0xdd, 0x48, 0x52, 0x19, 0x53
};

static EVP_CIPHER_CTX *new_ctx(const char *name, const unsigned char *iv, int enc)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *cipher = NULL;

    if (!TEST_ptr(ctx))
        goto err;
    cipher = EVP_CIPHER_fetch(NULL, name, NULL);
    if (!TEST_ptr(cipher))
        goto err;
    if (!TEST_int_eq(EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, NULL), 1))
        goto err;
    EVP_CIPHER_free(cipher);
    return ctx;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

static int test_roundtrip_cbc(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ct[MAX_CT_LEN], pt[MAX_CT_LEN];
    size_t ct_len = 0, pt_len = 0, n;
    int ok = 0;

    ctx = new_ctx("AES-256-CBC", cbc_iv, 1);
    if (ctx == NULL)
        goto err;

    if (!TEST_int_eq(EVP_EncryptUpdate_ex(ctx, ct, &n, sizeof(ct), ptext_pad, sizeof(ptext_pad)), 1))
        goto err;
    ct_len = n;
    if (!TEST_int_eq(EVP_EncryptFinal_ex2(ctx, ct + ct_len, &n, sizeof(ct) - ct_len), 1))
        goto err;
    ct_len += n;
    if (!TEST_size_t_eq(ct_len, sizeof(cbc_ct)))
        goto err;
    if (!TEST_mem_eq(ct, ct_len, cbc_ct, sizeof(cbc_ct)))
        goto err;
    EVP_CIPHER_CTX_free(ctx);

    ctx = new_ctx("AES-256-CBC", cbc_iv, 0);
    if (ctx == NULL)
        goto err;

    if (!TEST_int_eq(EVP_DecryptUpdate_ex(ctx, pt, &n, sizeof(pt), ct, ct_len), 1))
        goto err;
    pt_len = n;
    if (!TEST_int_eq(EVP_DecryptFinal_ex2(ctx, pt + pt_len, &n, sizeof(pt) - pt_len), 1))
        goto err;
    pt_len += n;

    if (!TEST_size_t_eq(pt_len, sizeof(ptext_pad)))
        goto err;
    if (!TEST_mem_eq(pt, pt_len, ptext_pad, sizeof(ptext_pad)))
        goto err;

    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_roundtrip_cipher_cbc(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ct[MAX_CT_LEN], pt[MAX_CT_LEN];
    size_t ct_len = 0, pt_len = 0, n;
    int ok = 0;

    ctx = new_ctx("AES-256-CBC", cbc_iv, 1);
    if (ctx == NULL)
        goto err;
    if (!TEST_int_eq(EVP_CipherUpdate_ex(ctx, ct, &n, sizeof(ct), ptext_pad, sizeof(ptext_pad)), 1))
        goto err;
    ct_len = n;
    if (!TEST_int_eq(EVP_CipherFinal_ex2(ctx, ct + ct_len, &n, sizeof(ct) - ct_len), 1))
        goto err;
    ct_len += n;
    if (!TEST_size_t_eq(ct_len, sizeof(cbc_ct)))
        goto err;
    if (!TEST_mem_eq(ct, ct_len, cbc_ct, sizeof(cbc_ct)))
        goto err;

    EVP_CIPHER_CTX_free(ctx);

    ctx = new_ctx("AES-256-CBC", cbc_iv, 0);
    if (ctx == NULL)
        goto err;

    if (!TEST_int_eq(EVP_CipherUpdate_ex(ctx, pt, &n, sizeof(pt), ct, ct_len), 1))
        goto err;
    pt_len = n;
    if (!TEST_int_eq(EVP_CipherFinal_ex2(ctx, pt + pt_len, &n, sizeof(pt) - pt_len), 1))
        goto err;
    pt_len += n;

    if (!TEST_mem_eq(pt, pt_len, ptext_pad, sizeof(ptext_pad)))
        goto err;

    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_roundtrip_gcm(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ct[MAX_CT_LEN], pt[MAX_CT_LEN], tag[16];
    size_t ct_len = 0, pt_len = 0, n;
    int ok = 0;

    ctx = new_ctx("AES-256-GCM", gcm_iv, 1);
    if (ctx == NULL)
        goto err;

    if (!TEST_int_eq(EVP_CipherUpdateAAD(ctx, gcm_aad, sizeof(gcm_aad)), 1))
        goto err;
    if (!TEST_int_eq(EVP_EncryptUpdate_ex(ctx, ct, &n, sizeof(ct), ptext_pad, sizeof(ptext_pad)), 1))
        goto err;
    ct_len = n;
    if (!TEST_int_eq(EVP_EncryptFinal_ex2(ctx, ct + ct_len, &n, sizeof(ct) - ct_len), 1))
        goto err;
    ct_len += n;

    if (!TEST_int_eq(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)sizeof(tag), tag), 1))
        goto err;
    if (!TEST_size_t_eq(ct_len, sizeof(gcm_ct)))
        goto err;
    if (!TEST_mem_eq(ct, ct_len, gcm_ct, sizeof(gcm_ct)))
        goto err;
    if (!TEST_size_t_eq(sizeof(tag), sizeof(gcm_tag)))
        goto err;
    if (!TEST_mem_eq(tag, sizeof(tag), gcm_tag, sizeof(gcm_tag)))
        goto err;
    EVP_CIPHER_CTX_free(ctx);

    /* Decrypt + verify */
    ctx = new_ctx("AES-256-GCM", gcm_iv, 0);
    if (ctx == NULL)
        goto err;
    if (!TEST_int_eq(EVP_CipherUpdateAAD(ctx, gcm_aad, sizeof(gcm_aad)), 1))
        goto err;
    if (!TEST_int_eq(EVP_DecryptUpdate_ex(ctx, pt, &n, sizeof(pt), ct, ct_len), 1))
        goto err;
    pt_len = n;
    if (!TEST_int_eq(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)sizeof(tag), tag), 1))
        goto err;
    if (!TEST_int_eq(EVP_DecryptFinal_ex2(ctx, pt + pt_len, &n, sizeof(pt) - pt_len), 1))
        goto err;
    pt_len += n;

    if (!TEST_size_t_eq(pt_len, sizeof(ptext_pad)))
        goto err;
    if (!TEST_mem_eq(pt, pt_len, ptext_pad, sizeof(ptext_pad)))
        goto err;

    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_rejected_gcm(void)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char buf[MAX_CT_LEN];
    size_t n;
    int ok = 0;

    ctx = new_ctx("AES-256-GCM", cbc_iv, 1);
    if (ctx == NULL)
        goto err;

    /* NULL in */
    if (!TEST_int_eq(EVP_CipherUpdateAAD(ctx, NULL, sizeof(gcm_aad)), 0))
        goto err;

    /* NULL out */
    if (!TEST_int_eq(EVP_EncryptUpdate_ex(ctx, NULL, &n, 0, ptext_pad, sizeof(ptext_pad)), 0))
        goto err;
    if (!TEST_int_eq(EVP_EncryptFinal_ex2(ctx, NULL, &n, 0), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherUpdate_ex(ctx, NULL, &n, 0, ptext_pad, sizeof(ptext_pad)), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherFinal_ex2(ctx, NULL, &n, 0), 0))
        goto err;

    /* NULL outl */
    if (!TEST_int_eq(EVP_EncryptUpdate_ex(ctx, buf, NULL, sizeof(buf), ptext_pad, sizeof(ptext_pad)), 0))
        goto err;
    if (!TEST_int_eq(EVP_EncryptFinal_ex2(ctx, buf, NULL, sizeof(buf)), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherUpdate_ex(ctx, buf, NULL, sizeof(buf), ptext_pad, sizeof(ptext_pad)), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherFinal_ex2(ctx, buf, NULL, sizeof(buf)), 0))
        goto err;

    /* NULL out, zero inl */
    if (!TEST_int_eq(EVP_EncryptUpdate_ex(ctx, NULL, &n, 0, NULL, 0), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherUpdate_ex(ctx, NULL, &n, 0, NULL, 0), 0))
        goto err;

    /* Decrypt function on an encryption context */
    if (!TEST_int_eq(EVP_DecryptUpdate_ex(ctx, buf, &n, sizeof(buf), ptext_pad, sizeof(ptext_pad)), 0))
        goto err;

    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);

    ctx = new_ctx("AES-256-GCM", cbc_iv, 0);
    if (ctx == NULL)
        goto err;

    /* NULL in */
    if (!TEST_int_eq(EVP_CipherUpdateAAD(ctx, NULL, sizeof(gcm_aad)), 0))
        goto err;

    /* NULL out */
    if (!TEST_int_eq(EVP_DecryptUpdate_ex(ctx, NULL, &n, 0, ptext_pad, sizeof(ptext_pad)), 0))
        goto err;
    if (!TEST_int_eq(EVP_DecryptFinal_ex2(ctx, NULL, &n, 0), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherUpdate_ex(ctx, NULL, &n, 0, ptext_pad, sizeof(ptext_pad)), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherFinal_ex2(ctx, NULL, &n, 0), 0))
        goto err;

    /* NULL outl */
    if (!TEST_int_eq(EVP_DecryptUpdate_ex(ctx, buf, NULL, sizeof(buf), ptext_pad, sizeof(ptext_pad)), 0))
        goto err;
    if (!TEST_int_eq(EVP_DecryptFinal_ex2(ctx, buf, NULL, sizeof(buf)), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherUpdate_ex(ctx, buf, NULL, sizeof(buf), ptext_pad, sizeof(ptext_pad)), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherFinal_ex2(ctx, buf, NULL, sizeof(buf)), 0))
        goto err;

    /* NULL out, zero inl */
    if (!TEST_int_eq(EVP_DecryptUpdate_ex(ctx, NULL, &n, 0, NULL, 0), 0))
        goto err;
    if (!TEST_int_eq(EVP_CipherUpdate_ex(ctx, NULL, &n, 0, NULL, 0), 0))
        goto err;

    /* Encrypt function on an decryption context */
    if (!TEST_int_eq(EVP_EncryptUpdate_ex(ctx, buf, &n, sizeof(buf), ptext_pad, sizeof(ptext_pad)), 0))
        goto err;

    ERR_clear_error();
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_short_buffer_cbc(void)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char ct[MAX_CT_LEN], pt[MAX_CT_LEN];
    size_t n;
    int ok = 0;

    ctx = new_ctx("AES-256-CBC", cbc_iv, 1);
    if (ctx == NULL)
        goto err;

    /* Write one block, limit out buffer, avoid padding */
    n = 0xdeadbeef;
    if (!TEST_int_eq(EVP_CIPHER_CTX_set_padding(ctx, 0), 1))
        goto err;
    if (!TEST_int_eq(EVP_EncryptUpdate_ex(ctx, ct, &n, 0, ptext_pad, 16), 0))
        goto err;
    if (!TEST_size_t_eq(n, 0))
        goto err;
    n = 0xdeadbeef;
    if (!TEST_int_eq(EVP_EncryptUpdate_ex(ctx, ct, &n, 15, ptext_pad, 16), 0))
        goto err;
    if (!TEST_size_t_eq(n, 0))
        goto err;

    /* Encrypt exactly one block */
    n = 0xdeadbeef;
    if (!TEST_int_eq(EVP_EncryptUpdate_ex(ctx, ct, &n, 16, ptext_pad, 16), 1))
        goto err;
    if (!TEST_size_t_eq(n, 16))
        goto err;
    if (!TEST_mem_eq(ct, 16, cbc_ct, 16))
        goto err;

    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);

    ctx = new_ctx("AES-256-CBC", cbc_iv, 0);
    if (ctx == NULL)
        goto err;

    /* Write one block, limit out buffer, avoid padding */
    n = 0xdeadbeef;
    if (!TEST_int_eq(EVP_CIPHER_CTX_set_padding(ctx, 0), 1))
        goto err;
    if (!TEST_int_eq(EVP_DecryptUpdate_ex(ctx, pt, &n, 0, ct, 16), 0))
        goto err;
    if (!TEST_size_t_eq(n, 0))
        goto err;
    n = 0xdeadbeef;
    if (!TEST_int_eq(EVP_DecryptUpdate_ex(ctx, pt, &n, 15, ct, 16), 0))
        goto err;
    if (!TEST_size_t_eq(n, 0))
        goto err;

    /* Encrypt exactly one block */
    n = 0xdeadbeef;
    if (!TEST_int_eq(EVP_DecryptUpdate_ex(ctx, pt, &n, 16, ct, 16), 1))
        goto err;
    if (!TEST_size_t_eq(n, 16))
        goto err;
    if (!TEST_mem_eq(pt, 16, ptext_pad, 16))
        goto err;

    ERR_clear_error();
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(test_roundtrip_cbc);
    ADD_TEST(test_roundtrip_cipher_cbc);
    ADD_TEST(test_roundtrip_gcm);
    ADD_TEST(test_rejected_gcm);
    ADD_TEST(test_short_buffer_cbc);
    return 1;
}
