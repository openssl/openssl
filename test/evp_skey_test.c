/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "testutil.h"
#include "fake_cipherprov.h"

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *deflprov = NULL;

/* FIXME copied from crypto/evp/pmeth_gn.c */
static OSSL_CALLBACK ossl_pkey_todata_cb;

static int ossl_pkey_todata_cb(const OSSL_PARAM params[], void *arg)
{
    OSSL_PARAM **ret = arg;

    *ret = OSSL_PARAM_dup(params);
    return 1;
}

static int test_skey_cipher(void)
{
    int ret = 0;
    OSSL_PROVIDER *fake_prov = NULL;
    EVP_SKEY *key = NULL;
    EVP_CIPHER *fake_cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const OSSL_PARAM params[] = {{FAKE_CIPHER_PARAM_KEY_NAME, OSSL_PARAM_UTF8_STRING,
                                  "fake key name", 14, 0},
                                 OSSL_PARAM_END};
    OSSL_PARAM *export_params = NULL;
    unsigned char export[16];
    size_t max_len = sizeof(export);

    memset(export, 0, max_len);

    if (!TEST_ptr(fake_prov = fake_cipher_start(libctx)))
        return 0;

    /* Do a direct fetch to see it works */
    fake_cipher = EVP_CIPHER_fetch(libctx, "fake_cipher", FAKE_CIPHER_FETCH_PROPS);
    if (!TEST_ptr(fake_cipher))
        goto end;

    /* Create EVP_SKEY */
    key = EVP_SKEY_import(libctx, "fake_cipher", FAKE_CIPHER_FETCH_PROPS,
                          OSSL_SKEYMGMT_SELECT_ALL, params);
    if (!TEST_ptr(key))
        goto end;

    /* Init cipher */
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_int_gt(EVP_CipherInit_skey(ctx, fake_cipher, key, NULL, 0, 1, NULL), 0))
        goto end;

    /* Export params */
    if (!TEST_int_gt(EVP_SKEY_export(key, OSSL_SKEYMGMT_SELECT_ALL,
                                     ossl_pkey_todata_cb, &export_params), 0))
        goto end;

    /* Export raw key */
    if (!TEST_int_gt(EVP_SKEY_get_raw_key(key, export, &max_len), 0)
        || !TEST_int_eq(max_len, 1) || !TEST_int_eq(export[0], 121))
        goto end;

    ret = 1;

end:
    OSSL_PARAM_free(export_params);
    EVP_SKEY_free(key);
    EVP_CIPHER_free(fake_cipher);
    EVP_CIPHER_CTX_free(ctx);
    fake_cipher_finish(fake_prov);

    return ret;
}

#define KEY_SIZE 16
#define IV_SIZE 16
#define DATA_SIZE 32
static int test_aes_raw_skey(void)
{
    const unsigned char data[DATA_SIZE] = {
        0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
        0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
        0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
        0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2
    };
    unsigned char aes_key[KEY_SIZE], aes_iv[IV_SIZE], exported_key[2 * KEY_SIZE];
    unsigned char encrypted_skey[DATA_SIZE + IV_SIZE];
    unsigned char encrypted_raw[DATA_SIZE + IV_SIZE];
    int enc_len, fin_len;
    size_t export_length = 2 * KEY_SIZE;
    EVP_CIPHER *aes_cbc = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_SKEY *skey = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    deflprov = OSSL_PROVIDER_load(libctx, "default");
    if (!TEST_ptr(deflprov))
        return 0;

    memset(encrypted_skey, 0, sizeof(encrypted_skey));
    memset(encrypted_raw,  0, sizeof(encrypted_raw));
    memset(aes_key, 1, KEY_SIZE);
    memset(aes_iv, 2, IV_SIZE);
    memset(exported_key, 3, KEY_SIZE);

    /* Do a direct fetch to see it works */
    aes_cbc = EVP_CIPHER_fetch(libctx, "AES-128-CBC", "provider=default");
    if (!TEST_ptr(aes_cbc))
        goto end;

    /* Create EVP_SKEY */
    if ((tmpl = OSSL_PARAM_BLD_new()) == NULL
        || !OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_SKEY_PARAM_RAW_BYTES, aes_key, KEY_SIZE)
        || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL)
        goto end;

    skey = EVP_SKEY_import(libctx, "AES", NULL, OSSL_SKEYMGMT_SELECT_ALL, params);
    if (!TEST_ptr(skey))
        goto end;

    if (!TEST_int_gt(EVP_SKEY_get_raw_key(skey, exported_key, &export_length), 0)
        || !TEST_mem_eq(aes_key, KEY_SIZE, exported_key, KEY_SIZE)
        || !TEST_int_eq(export_length, KEY_SIZE))
        goto end;

    enc_len = sizeof(encrypted_skey);
    fin_len = 0;
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_int_gt(EVP_CipherInit_skey(ctx, aes_cbc, skey, aes_iv, IV_SIZE, 1, NULL), 0)
        || !TEST_int_gt(EVP_CipherUpdate(ctx, encrypted_skey, &enc_len, data, DATA_SIZE), 0)
        || !TEST_int_gt(EVP_CipherFinal(ctx, encrypted_skey + enc_len, &fin_len), 0))
        goto end;

    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();

    enc_len = sizeof(encrypted_raw);
    fin_len = 0;
    if (!TEST_int_gt(EVP_CipherInit_ex2(ctx, aes_cbc, aes_key, aes_iv, 1, NULL), 0)
        || !TEST_int_gt(EVP_CipherUpdate(ctx, encrypted_raw, &enc_len, data, DATA_SIZE), 0)
        || !TEST_int_gt(EVP_CipherFinal(ctx, encrypted_raw + enc_len, &fin_len), 0)
        || !TEST_mem_eq(encrypted_skey, DATA_SIZE + IV_SIZE, encrypted_raw, DATA_SIZE + IV_SIZE))
        goto end;

    ret = 1;
end:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    EVP_SKEY_free(skey);
    EVP_CIPHER_free(aes_cbc);
    EVP_CIPHER_CTX_free(ctx);
    OSSL_PROVIDER_unload(deflprov);
    return ret;
}

#ifndef OPENSSL_NO_DES
/* DES is used to test a "skey-unware" cipher provider */
# define DES_KEY_SIZE 24
# define DES_IV_SIZE 8
static int test_des_raw_skey(void)
{
    const unsigned char data[DATA_SIZE] = {
        0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
        0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
        0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
        0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2
    };
    unsigned char des_key[DES_KEY_SIZE], des_iv[DES_IV_SIZE], exported_key[2 * DES_KEY_SIZE];
    unsigned char encrypted_skey[DATA_SIZE + DES_IV_SIZE];
    unsigned char encrypted_raw[DATA_SIZE + DES_IV_SIZE];
    int enc_len, fin_len;
    size_t export_length = 2 * DES_KEY_SIZE;
    EVP_CIPHER *des_cbc = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_SKEY *skey = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    deflprov = OSSL_PROVIDER_load(libctx, "default");
    if (!TEST_ptr(deflprov))
        return 0;

    memset(encrypted_skey, 0, sizeof(encrypted_skey));
    memset(encrypted_raw,  0, sizeof(encrypted_raw));
    memset(des_key, 1, DES_KEY_SIZE);
    memset(des_iv, 2, DES_IV_SIZE);
    memset(exported_key, 3, DES_KEY_SIZE);

    /* Do a direct fetch to see it works */
    des_cbc = EVP_CIPHER_fetch(libctx, "DES-EDE3-CBC", "provider=default");
    if (!TEST_ptr(des_cbc))
        goto end;

    /* Create EVP_SKEY */
    if ((tmpl = OSSL_PARAM_BLD_new()) == NULL
        || !OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_SKEY_PARAM_RAW_BYTES,
                                             des_key, DES_KEY_SIZE)
        || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL)
        goto end;

    skey = EVP_SKEY_import(libctx, "GENERIC_SECRET", NULL, OSSL_SKEYMGMT_SELECT_ALL, params);
    if (!TEST_ptr(skey))
        goto end;

    if (!TEST_int_gt(EVP_SKEY_get_raw_key(skey, exported_key, &export_length), 0)
        || !TEST_mem_eq(des_key, DES_KEY_SIZE, exported_key, DES_KEY_SIZE)
        || !TEST_int_eq(export_length, DES_KEY_SIZE))
        goto end;

    enc_len = sizeof(encrypted_skey);
    fin_len = 0;
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_int_gt(EVP_CipherInit_skey(ctx, des_cbc, skey, des_iv, DES_IV_SIZE, 1, NULL), 0)
        || !TEST_int_gt(EVP_CipherUpdate(ctx, encrypted_skey, &enc_len, data, DATA_SIZE), 0)
        || !TEST_int_gt(EVP_CipherFinal(ctx, encrypted_skey + enc_len, &fin_len), 0))
        goto end;

    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();

    enc_len = sizeof(encrypted_raw);
    fin_len = 0;
    if (!TEST_int_gt(EVP_CipherInit_ex2(ctx, des_cbc, des_key, des_iv, 1, NULL), 0)
        || !TEST_int_gt(EVP_CipherUpdate(ctx, encrypted_raw, &enc_len, data, DATA_SIZE), 0)
        || !TEST_int_gt(EVP_CipherFinal(ctx, encrypted_raw + enc_len, &fin_len), 0)
        || !TEST_mem_eq(encrypted_skey, DATA_SIZE + DES_IV_SIZE, encrypted_raw,
                        DATA_SIZE + DES_IV_SIZE))
        goto end;

    ret = 1;
end:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    EVP_SKEY_free(skey);
    EVP_CIPHER_free(des_cbc);
    EVP_CIPHER_CTX_free(ctx);
    OSSL_PROVIDER_unload(deflprov);
    return ret;
}
#endif

int setup_tests(void)
{
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        return 0;

    ADD_TEST(test_skey_cipher);

    ADD_TEST(test_aes_raw_skey);
#ifndef OPENSSL_NO_DES
    ADD_TEST(test_des_raw_skey);
#endif

    return 1;
}

void cleanup_tests(void)
{
    OSSL_LIB_CTX_free(libctx);
}
