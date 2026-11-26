/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "testutil.h"

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};
static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};
static const unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};
static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};
static const unsigned char gcm_ct[] = {
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
    0xb9, 0xf2, 0x17, 0x36
};
static const unsigned char gcm_tag[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};

static int do_encrypt(unsigned char *iv_gen, unsigned char *ct, int *ct_len,
    unsigned char *tag, int *tag_len)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int outlen;
    unsigned char outbuf[64];

    *tag_len = 16;
    ret = TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        && TEST_true(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL,
                         NULL)
            > 0)
        && TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key,
                         iv_gen != NULL ? NULL : gcm_iv)
            > 0)
        && TEST_true(EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad,
                         sizeof(gcm_aad))
            > 0)
        && TEST_true(EVP_EncryptUpdate(ctx, ct, ct_len, gcm_pt,
                         sizeof(gcm_pt))
            > 0)
        && TEST_true(EVP_EncryptFinal_ex(ctx, outbuf, &outlen) > 0)
        && TEST_int_eq(EVP_CIPHER_CTX_get_tag_length(ctx), 16)
        && TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                         tag)
            > 0)
        && TEST_true(iv_gen == NULL
            || EVP_CIPHER_CTX_get_original_iv(ctx, iv_gen, 12));
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int do_decrypt(const unsigned char *iv, const unsigned char *ct,
    int ct_len, const unsigned char *tag, int tag_len)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int outlen, ptlen;
    unsigned char pt[32];
    unsigned char outbuf[32];

    ret = TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        && TEST_true(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                         NULL, NULL)
            > 0)
        && TEST_true(EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, iv) > 0)
        && TEST_int_eq(EVP_CIPHER_CTX_get_tag_length(ctx), 16)
        && TEST_true(EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad,
                         sizeof(gcm_aad))
            > 0)
        && TEST_true(EVP_DecryptUpdate(ctx, pt, &ptlen, ct,
                         ct_len)
            > 0)
        && TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                         tag_len, (void *)tag)
            > 0)
        && TEST_true(EVP_DecryptFinal_ex(ctx, outbuf, &outlen) > 0)
        && TEST_mem_eq(gcm_pt, sizeof(gcm_pt), pt, ptlen);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int kat_test(void)
{
    unsigned char tag[32];
    unsigned char ct[32];
    int ctlen = 0, taglen = 0;

    return do_encrypt(NULL, ct, &ctlen, tag, &taglen)
        && TEST_mem_eq(gcm_ct, sizeof(gcm_ct), ct, ctlen)
        && TEST_mem_eq(gcm_tag, sizeof(gcm_tag), tag, taglen)
        && do_decrypt(gcm_iv, ct, ctlen, tag, taglen);
}

static int badkeylen_test(void)
{
    int ret;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher;

    ret = TEST_ptr(cipher = EVP_aes_192_gcm())
        && TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        && TEST_true(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        && TEST_int_le(EVP_CIPHER_CTX_set_key_length(ctx, 2), 0);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int ivgen_test(void)
{
    unsigned char iv_gen[16];
    unsigned char tag[32];
    unsigned char ct[32];
    int ctlen = 0, taglen = 0;

    return do_encrypt(iv_gen, ct, &ctlen, tag, &taglen)
        && do_decrypt(iv_gen, ct, ctlen, tag, taglen);
}

/*
 * inl > ctx->ivlen makes setivinv() compute ctx->iv + ctx->ivlen - inl,
 * which wraps, and inl == 0 points past the IV.  Both are rejected.
 */
static int setivinv_bounds_test(void)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char key[32] = { 0 };
    unsigned char fixed_iv[4] = { 0x01, 0x02, 0x03, 0x04 };
    unsigned char big_ivinv[64];
    unsigned char exact_ivinv[12];
    OSSL_PARAM params[2];

    memset(big_ivinv, 'A', sizeof(big_ivinv));
    memset(exact_ivinv, 'B', sizeof(exact_ivinv));

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)))
        goto err;

    if (!TEST_true(EVP_DecryptInit_ex2(ctx, cipher, key, NULL, NULL)))
        goto err;

    if (!TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED,
            (int)sizeof(fixed_iv), fixed_iv)))
        goto err;

    /* --- Negative: inl == 0 must be rejected --- */
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, big_ivinv, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_false(EVP_CIPHER_CTX_set_params(ctx, params)))
        goto err;

    /* --- Negative: inl > ivlen (64 > 12) must be rejected --- */
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV,
        big_ivinv, sizeof(big_ivinv));
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_false(EVP_CIPHER_CTX_set_params(ctx, params)))
        goto err;

    /* --- Positive: inl == ivlen (12 == 12) must be accepted --- */
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV,
        exact_ivinv, sizeof(exact_ivinv));
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx, params)))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/*
 * Byte-at-a-time updates use the scalar block/gmult hooks. Compare them to
 * bulk CTR/GHASH, including unaligned, in-place and partial-block updates.
 */
static int streaming_test(int idx)
{
    static const size_t lengths[] = { 0, 1, 15, 16, 17, 31, 32, 33,
        127, 128, 129, 255, 256, 257, 511, 512, 513, 527,
        639, 640, 641, 767, 768, 769, 1023, 1024, 1025,
        2047, 2048, 2049, 3071, 3072, 3073, 4095, 4096, 4097,
        4223, 4224, 4225, 4351, 4352, 4353, 8191, 8192, 8193 };
    static const size_t splits[] = { 0, 1, 15, 16, 17, 31, 32, 127,
        511, 512, 513, 1023, 3071, 3072, 3073, 4095, 4096, 4097,
        4351, 4352, 4353 };
    const EVP_CIPHER *cipher = idx == 0 ? EVP_aes_128_gcm()
        : idx == 1                      ? EVP_aes_192_gcm()
                                        : EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = NULL, *copy = NULL;
    unsigned char input[8195], reference[8195], actual[8195];
    unsigned char iv[20], aad[33], expected_tag[16], tag[16];
    size_t i, j, k, n, split, ivlen;
    int outlen, finallen, ret = 0, inplace;

    for (i = 0; i < sizeof(input); ++i)
        input[i] = (unsigned char)i;
    memset(iv, 0xa5, sizeof(iv));
    memset(aad, 0x5a, sizeof(aad));
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(copy = EVP_CIPHER_CTX_new()))
        goto end;

    for (ivlen = 12; ivlen <= sizeof(iv); ivlen += 8) {
        for (j = 0; j < OSSL_NELEM(lengths); ++j) {
            n = lengths[j];
            if (!TEST_true(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
                || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx,
                    EVP_CTRL_AEAD_SET_IVLEN, (int)ivlen, NULL))
                || !TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, iv)))
                goto end;
            for (i = 0; i < sizeof(aad); ++i) {
                if (!TEST_true(EVP_EncryptUpdate(ctx, NULL, &outlen, aad + i, 1)))
                    goto end;
            }
            for (i = 0; i < n; ++i) {
                if (!TEST_true(EVP_EncryptUpdate(ctx, reference + 1 + i,
                        &outlen, input + 1 + i, 1)))
                    goto end;
            }
            if (!TEST_true(EVP_EncryptFinal_ex(ctx, reference + 1 + n, &finallen))
                || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx,
                    EVP_CTRL_AEAD_GET_TAG, sizeof(expected_tag), expected_tag)))
                goto end;

            for (k = 0; k < OSSL_NELEM(splits); ++k) {
                split = splits[k] < n ? splits[k] : n;
                for (inplace = 0; inplace <= 1; ++inplace) {
                    memcpy(actual, input, sizeof(actual));
                    if (!TEST_true(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
                        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_AEAD_SET_IVLEN, (int)ivlen, NULL))
                        || !TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, iv))
                        || !TEST_true(EVP_EncryptUpdate(ctx, NULL, &outlen, aad, 1))
                        || !TEST_true(EVP_EncryptUpdate(ctx, NULL, &outlen,
                            aad + 1, sizeof(aad) - 1))
                        || !TEST_true(EVP_EncryptUpdate(ctx, actual + 1,
                            &outlen, inplace ? actual + 1 : input + 1, (int)split))
                        || !TEST_true(EVP_CIPHER_CTX_copy(copy, ctx))
                        || !TEST_true(EVP_CIPHER_CTX_reset(ctx))
                        || !TEST_true(EVP_EncryptUpdate(copy, actual + 1 + split,
                            &outlen, inplace ? actual + 1 + split : input + 1 + split,
                            (int)(n - split)))
                        || !TEST_true(EVP_EncryptFinal_ex(copy, actual + 1 + n, &finallen))
                        || !TEST_true(EVP_CIPHER_CTX_ctrl(copy,
                            EVP_CTRL_AEAD_GET_TAG, sizeof(tag), tag))
                        || !TEST_mem_eq(actual + 1, n, reference + 1, n)
                        || !TEST_mem_eq(tag, sizeof(tag), expected_tag, sizeof(expected_tag)))
                        goto end;

                    if (!TEST_true(EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
                        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_AEAD_SET_IVLEN, (int)ivlen, NULL))
                        || !TEST_true(EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, iv))
                        || !TEST_true(EVP_DecryptUpdate(ctx, NULL, &outlen, aad, sizeof(aad)))
                        || !TEST_true(EVP_DecryptUpdate(ctx, actual + 1, &outlen,
                            inplace ? actual + 1 : reference + 1, (int)split))
                        || !TEST_true(EVP_CIPHER_CTX_copy(copy, ctx))
                        || !TEST_true(EVP_CIPHER_CTX_reset(ctx))
                        || !TEST_true(EVP_DecryptUpdate(copy, actual + 1 + split, &outlen,
                            inplace ? actual + 1 + split : reference + 1 + split,
                            (int)(n - split)))
                        || !TEST_true(EVP_CIPHER_CTX_ctrl(copy,
                            EVP_CTRL_AEAD_SET_TAG, sizeof(tag), tag))
                        || !TEST_true(EVP_DecryptFinal_ex(copy, actual + 1 + n, &finallen))
                        || !TEST_mem_eq(actual + 1, n, input + 1, n))
                        goto end;

                    tag[0] ^= 1;
                    if (!TEST_true(EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
                        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_AEAD_SET_IVLEN, (int)ivlen, NULL))
                        || !TEST_true(EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, iv))
                        || !TEST_true(EVP_DecryptUpdate(ctx, NULL, &outlen, aad, sizeof(aad)))
                        || !TEST_true(EVP_DecryptUpdate(ctx, actual + 1, &outlen,
                            reference + 1, (int)n))
                        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_AEAD_SET_TAG, sizeof(tag), tag))
                        || !TEST_false(EVP_DecryptFinal_ex(ctx, actual + 1 + n, &finallen)))
                        goto end;
                }
            }
        }
    }
    ret = 1;
end:
    EVP_CIPHER_CTX_free(copy);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(kat_test);
    ADD_TEST(badkeylen_test);
    ADD_TEST(ivgen_test);
    ADD_TEST(setivinv_bounds_test);
    ADD_ALL_TESTS(streaming_test, 3);
    return 1;
}
