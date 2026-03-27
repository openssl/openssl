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
 * double-free in ossl_cipher_generic_reset_ctx.
 */
static int test_dupctx_tlsmac(int idx)
{
    static const char *cipher_names[] = {
        "AES-128-CBC",
        "AES-256-CBC"
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

    if (!EVP_CIPHER_CTX_set_params(ctx, params)) {
        TEST_skip("Cipher %s does not support TLS params", name);
        ret = 1;
        goto err;
    }

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

    if (!EVP_CIPHER_CTX_copy(dupctx, ctx)) {
        TEST_skip("Cipher %s does not support context copy", name);
        ret = 1;
        goto err;
    }

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

int setup_tests(void)
{
    ADD_ALL_TESTS(test_dupctx_tlsmac, 2);
    return 1;
}
