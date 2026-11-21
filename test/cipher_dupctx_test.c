/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Test that EVP_CIPHER_CTX_copy correctly deep-copies the tlsmac buffer
 * to prevent double-free when both contexts are freed.
 * See https://github.com/openssl/openssl/issues/30548
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/prov_ssl.h>
#include "testutil.h"

/*
 * Test that duplicating a cipher context with a heap-allocated tlsmac
 * buffer does not cause a double-free when both contexts are freed.
 *
 * The tlsmac buffer is allocated during TLS CBC decryption via
 * ossl_cipher_tlsunpadblock -> ssl3_cbc_copy_mac -> OPENSSL_malloc.
 * Without the fix, the shallow copy in dupctx causes both the original
 * and duplicated context to share the same pointer, leading to a
 * double-free in ossl_cipher_generic_reset_ctx. The ECB cases also exercise
 * duplication when unsupported TLS parameters are supplied to the setter.
 */
static int test_dupctx_tlsmac(int idx)
{
    static const char *cipher_names[] = {
        "AES-128-CBC",
        "AES-256-CBC",
        "AES-128-ECB",
        "AES-192-ECB",
        "AES-256-ECB"
    };
    const char *name = cipher_names[idx];
    EVP_CIPHER_CTX *ctx = NULL, *dupctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char buf[64];
    int outl = 0;
    int ret = 0;
    unsigned int tls_ver = TLS1_VERSION;
    size_t mac_size = 20; /* SHA1 */
    OSSL_PARAM params[3];

    cipher = EVP_CIPHER_fetch(NULL, name, NULL);
    if (!TEST_ptr(cipher))
        goto err;

    ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)))
        goto err;

    /* Set TLS parameters to trigger tlsmac allocation */
    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS_VERSION,
        &tls_ver);
    params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
        &mac_size);
    params[2] = OSSL_PARAM_construct_end();

    if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx, params)))
        goto err;

    /*
     * Perform a decrypt update with enough data to trigger tlsmac
     * allocation. Buffer needs at least: block_size + mac_size + 1.
     * For AES-CBC: 16 + 20 + 1 = 37 minimum. Use 64 for safety.
     * Last byte is padding length (0 = 1 byte of padding).
     */
    memset(buf, 0, sizeof(buf));
    ERR_clear_error();
    if (!EVP_DecryptUpdate(ctx, buf, &outl, buf, sizeof(buf)))
        ERR_clear_error();

    /*
     * Duplicate the context. Before the fix, this created a shallow
     * copy that shared the tlsmac pointer.
     */
    dupctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(dupctx))
        goto err;

    if (!TEST_true(EVP_CIPHER_CTX_copy(dupctx, ctx)))
        goto err;

    /*
     * Free both contexts. Without the fix, the second free triggers
     * a double-free on the shared tlsmac pointer.
     * With ASan enabled, this would be detected as "attempting double-free".
     */
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    EVP_CIPHER_CTX_free(dupctx);
    dupctx = NULL;

    ret = 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(dupctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/* TLS parameters must not change ECB initialization or subsequent updates. */
static int test_ecb_init_params(int idx)
{
    static const char *names[] = { "AES-128-ECB", "AES-192-ECB", "AES-256-ECB" };
    const int use_skey = (idx / 3) % 2;
    const int set_after_init = idx / 6;
    int ret = 0, outl = 0, finl = 0;
    unsigned int pad = 0, tls_version = TLS1_VERSION;
    size_t mac_size = 20;
    unsigned char key[32] = { 0 }, plaintext[64] = { 0 };
    unsigned char ciphertext[80], out[80];
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL, *dupctx = NULL;
    EVP_SKEY *skey = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, &pad),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, &tls_version),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, &mac_size),
        OSSL_PARAM_END
    };
    const OSSL_PARAM *settable;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(NULL, names[idx % 3], NULL))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(dupctx = EVP_CIPHER_CTX_new()))
        goto err;
    settable = EVP_CIPHER_settable_ctx_params(cipher);
    if (!TEST_ptr(OSSL_PARAM_locate_const(settable, OSSL_CIPHER_PARAM_PADDING))
        || !TEST_ptr_null(OSSL_PARAM_locate_const(settable, OSSL_CIPHER_PARAM_TLS_VERSION))
        || !TEST_ptr_null(OSSL_PARAM_locate_const(settable, OSSL_CIPHER_PARAM_TLS_MAC_SIZE))
        || !TEST_ptr_null(OSSL_PARAM_locate_const(settable, OSSL_CIPHER_PARAM_USE_BITS)))
        goto err;

    if (!TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, NULL, NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        || !TEST_true(EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, ciphertext + outl, &finl))
        || !TEST_int_eq(outl + finl, sizeof(plaintext))
        || !TEST_true(EVP_CIPHER_CTX_reset(ctx)))
        goto err;

    if (use_skey) {
        if (!TEST_ptr(skey = EVP_SKEY_import_raw_key(NULL, OSSL_SKEY_TYPE_AES,
                          key, EVP_CIPHER_get_key_length(cipher), NULL))
            || !TEST_true(EVP_CipherInit_SKEY(ctx, cipher, skey, NULL, 0, 0,
                set_after_init ? NULL : params)))
            goto err;
    } else if (!TEST_true(EVP_DecryptInit_ex2(ctx, cipher, key, NULL,
                   set_after_init ? NULL : params))) {
        goto err;
    }
    if (set_after_init && !TEST_true(EVP_CIPHER_CTX_set_params(ctx, params)))
        goto err;

    /* An in-place decrypt would take the TLS unpadding path if TLS leaked in. */
    memcpy(out, ciphertext, sizeof(plaintext));
    if (!TEST_true(EVP_DecryptUpdate(ctx, out, &outl, out, sizeof(plaintext)))
        || !TEST_true(EVP_CIPHER_CTX_copy(dupctx, ctx))
        || !TEST_true(EVP_DecryptFinal_ex(ctx, out + outl, &finl))
        || !TEST_int_eq(outl + finl, sizeof(plaintext))
        || !TEST_mem_eq(out, outl + finl, plaintext, sizeof(plaintext))
        || !TEST_true(EVP_DecryptFinal_ex(dupctx, out + outl, &finl))
        || !TEST_int_eq(finl, 0))
        goto err;
    ret = 1;
err:
    EVP_SKEY_free(skey);
    EVP_CIPHER_CTX_free(dupctx);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_dupctx_tlsmac, 5);
    ADD_ALL_TESTS(test_ecb_init_params, 12);
    return 1;
}
