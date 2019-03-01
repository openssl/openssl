/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "internal/evp_int.h"

/* typedef EVP_MAC_IMPL */
struct evp_mac_impl_st {
    const EVP_CIPHER *cipher; /* Cache GCM cipher */
    EVP_CIPHER_CTX *ctx;    /* Cipher context */
    ENGINE *engine;         /* Engine implementating the algorithm */
    unsigned char *key;
    size_t key_len;
    unsigned char *iv;
    size_t iv_len;
};

static void gmac_free(EVP_MAC_IMPL *gctx)
{
    if (gctx != NULL) {
        OPENSSL_clear_free(gctx->key, gctx->key_len);
        OPENSSL_clear_free(gctx->iv, gctx->iv_len);
        EVP_CIPHER_CTX_free(gctx->ctx);
        OPENSSL_free(gctx);
    }
}

static EVP_MAC_IMPL *gmac_new(void)
{
    EVP_MAC_IMPL *gctx;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) == NULL
        || (gctx->ctx = EVP_CIPHER_CTX_new()) == NULL) {
        gmac_free(gctx);
        return NULL;
    }
    return gctx;
}

static int gmac_copy(EVP_MAC_IMPL *gdst, EVP_MAC_IMPL *gsrc)
{
    gdst->cipher = gsrc->cipher;
    gdst->engine = gsrc->engine;
    OPENSSL_clear_free(gdst->key, gdst->key_len);
    gdst->key = NULL;
    gdst->key_len = 0;
    if (gsrc->key != NULL) {
        gdst->key = OPENSSL_memdup(gsrc->key, gsrc->key_len);
        gdst->key_len = gsrc->key_len;
        if (gdst->key == NULL)
            return 0;
    }
    OPENSSL_clear_free(gdst->iv, gdst->iv_len);
    gdst->iv = NULL;
    gdst->iv_len = 0;
    if (gsrc->iv != NULL) {
        gdst->iv = OPENSSL_memdup(gsrc->iv, gsrc->iv_len);
        gdst->iv_len = gsrc->iv_len;
        if (gdst->iv == NULL)
            return 0;
    }
    if (EVP_CIPHER_CTX_cipher(gsrc->ctx) != NULL)
        return EVP_CIPHER_CTX_copy(gdst->ctx, gsrc->ctx);
    return 1;
}

static size_t gmac_size(EVP_MAC_IMPL *gctx)
{
    return EVP_GCM_TLS_TAG_LEN;
}

static int gmac_init(EVP_MAC_IMPL *gctx)
{
    if (EVP_CIPHER_CTX_ctrl(gctx->ctx, EVP_CTRL_AEAD_SET_IVLEN, gctx->iv_len,
                            NULL) <= 0)
        return 0;

    return EVP_EncryptInit_ex(gctx->ctx, gctx->cipher, gctx->engine, gctx->key,
                              gctx->iv);
}

static int gmac_update(EVP_MAC_IMPL *gctx, const unsigned char *data,
                       size_t datalen)
{
    EVP_CIPHER_CTX *ctx = gctx->ctx;
    int outlen;

    while (datalen > INT_MAX) {
        if (!EVP_EncryptUpdate(ctx, NULL, &outlen, data, INT_MAX))
            return 0;

        data += INT_MAX;
        datalen -= INT_MAX;
    }
    return EVP_EncryptUpdate(ctx, NULL, &outlen, data, datalen);
}

static int gmac_final(EVP_MAC_IMPL *gctx, unsigned char *out)
{
    int hlen;

    if (!EVP_EncryptFinal_ex(gctx->ctx, out, &hlen)
        || !EVP_CIPHER_CTX_ctrl(gctx->ctx, EVP_CTRL_AEAD_GET_TAG,
                                gmac_size(gctx), out))
        return 0;
    return 1;
}

static int gmac_ctrl(EVP_MAC_IMPL *gctx, int cmd, va_list args)
{
    const unsigned char *p;
    size_t len;
    const EVP_CIPHER *cipher;
    ENGINE *engine;

    switch (cmd) {
    case EVP_MAC_CTRL_SET_CIPHER:
        cipher = va_arg(args, const EVP_CIPHER *);
        if (cipher == NULL)
            return 0;
        if (EVP_CIPHER_mode(cipher) != EVP_CIPH_GCM_MODE) {
            EVPerr(EVP_F_GMAC_CTRL, EVP_R_CIPHER_NOT_GCM_MODE);
            return 0;
        }
        gctx->cipher = cipher;
        return EVP_EncryptInit_ex(gctx->ctx, gctx->cipher, NULL, NULL, NULL);

    case EVP_MAC_CTRL_SET_KEY:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        if (gctx->cipher == NULL)
            return 0;
        if (len != (size_t)EVP_CIPHER_key_length(gctx->cipher)) {
            EVPerr(EVP_F_GMAC_CTRL, EVP_R_INVALID_KEY_LENGTH);
            return 0;
        }
        OPENSSL_clear_free(gctx->key, gctx->key_len);
        gctx->key = OPENSSL_memdup(p, len);
        gctx->key_len = len;
        return gctx->key != NULL;

    case EVP_MAC_CTRL_SET_IV:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        OPENSSL_clear_free(gctx->iv, gctx->iv_len);
        gctx->iv = OPENSSL_memdup(p, len);
        gctx->iv_len = len;
        return gctx->iv != NULL;

    case EVP_MAC_CTRL_SET_ENGINE:
        engine = va_arg(args, ENGINE *);
        gctx->engine = engine;
        break;

    default:
        return -2;
    }
    return 1;
}

static int gmac_ctrl_int(EVP_MAC_IMPL *gctx, int cmd, ...)
{
    int rv;
    va_list args;

    va_start(args, cmd);
    rv = gmac_ctrl(gctx, cmd, args);
    va_end(args);

    return rv;
}

static int gmac_ctrl_str_cb(void *gctx, int cmd, void *buf, size_t buflen)
{
    return gmac_ctrl_int(gctx, cmd, buf, buflen);
}

static int gmac_ctrl_str(EVP_MAC_IMPL *gctx, const char *type,
                         const char *value)
{
    if (!value)
        return 0;
    if (strcmp(type, "cipher") == 0) {
        const EVP_CIPHER *c = EVP_get_cipherbyname(value);

        if (c == NULL)
            return 0;
        return gmac_ctrl_int(gctx, EVP_MAC_CTRL_SET_CIPHER, c);
    }
    if (strcmp(type, "key") == 0)
        return EVP_str2ctrl(gmac_ctrl_str_cb, gctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    if (strcmp(type, "hexkey") == 0)
        return EVP_hex2ctrl(gmac_ctrl_str_cb, gctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    if (strcmp(type, "iv") == 0)
        return EVP_str2ctrl(gmac_ctrl_str_cb, gctx, EVP_MAC_CTRL_SET_IV,
                            value);
    if (strcmp(type, "hexiv") == 0)
        return EVP_hex2ctrl(gmac_ctrl_str_cb, gctx, EVP_MAC_CTRL_SET_IV,
                            value);
    return -2;
}

const EVP_MAC gmac_meth = {
    EVP_MAC_GMAC,
    gmac_new,
    gmac_copy,
    gmac_free,
    gmac_size,
    gmac_init,
    gmac_update,
    gmac_final,
    gmac_ctrl,
    gmac_ctrl_str
};
