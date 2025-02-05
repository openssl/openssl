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
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "testutil.h"
#include "fake_cipherprov.h"

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *deflprov = NULL;

#define KEY_SIZE 16

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
    const unsigned char import_key[KEY_SIZE] = {
        0x53, 0x4B, 0x45, 0x59, 0x53, 0x4B, 0x45, 0x59,
        0x53, 0x4B, 0x45, 0x59, 0x53, 0x4B, 0x45, 0x59,
    };
    OSSL_PARAM params[3];
    OSSL_PARAM *export_params = NULL;
    const unsigned char *export;
    size_t export_len;

    if (!TEST_ptr(fake_prov = fake_cipher_start(libctx)))
        return 0;

    /* Do a direct fetch to see it works */
    fake_cipher = EVP_CIPHER_fetch(libctx, "fake_cipher", FAKE_CIPHER_FETCH_PROPS);
    if (!TEST_ptr(fake_cipher))
        goto end;

    /* Create EVP_SKEY */
    params[0] = OSSL_PARAM_construct_utf8_string(FAKE_CIPHER_PARAM_KEY_NAME,
                                                 "fake key name", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES,
                                                  (void *)import_key, KEY_SIZE);
    params[2] = OSSL_PARAM_construct_end();
    key = EVP_SKEY_import(libctx, "fake_cipher", FAKE_CIPHER_FETCH_PROPS,
                          OSSL_SKEYMGMT_SELECT_ALL, params);
    if (!TEST_ptr(key))
        goto end;

    /* Init cipher */
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_int_gt(EVP_CipherInit_SKEY(ctx, fake_cipher, key, NULL, 0, 1, NULL), 0))
        goto end;

    /* Export params */
    if (!TEST_int_gt(EVP_SKEY_export(key, OSSL_SKEYMGMT_SELECT_ALL,
                                     ossl_pkey_todata_cb, &export_params), 0))
        goto end;

    /* Export raw key */
    if (!TEST_int_gt(EVP_SKEY_get_raw_key(key, &export, &export_len), 0)
        || !TEST_mem_eq(export, export_len, import_key, sizeof(import_key)))
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

int setup_tests(void)
{
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        return 0;

    ADD_TEST(test_skey_cipher);

    return 1;
}

void cleanup_tests(void)
{
    OSSL_LIB_CTX_free(libctx);
}
