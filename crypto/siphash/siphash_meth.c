/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "internal/siphash.h"
#include "siphash_local.h"
#include "internal/evp_int.h"

/* local SIPHASH structure is actually a SIPHASH */

struct evp_mac_impl_st {
    SIPHASH ctx;
    unsigned char *key;
    size_t key_len;
};

static EVP_MAC_IMPL *siphash_new(void)
{
    return OPENSSL_zalloc(sizeof(EVP_MAC_IMPL));
}

static void siphash_free(EVP_MAC_IMPL *sctx)
{
    OPENSSL_clear_free(sctx->key, sctx->key_len);
    OPENSSL_free(sctx);
}

static int siphash_copy(EVP_MAC_IMPL *sdst, EVP_MAC_IMPL *ssrc)
{
    sdst->ctx = ssrc->ctx;
    OPENSSL_clear_free(sdst->key, sdst->key_len);
    sdst->key = NULL;
    sdst->key_len  = 0;
    if (ssrc->key != NULL) {
        sdst->key = OPENSSL_memdup(ssrc->key, ssrc->key_len);
        sdst->key_len = ssrc->key_len;
        return sdst->key != NULL;
    }
    return 1;
}

static size_t siphash_size(EVP_MAC_IMPL *sctx)
{
    return SipHash_hash_size(&sctx->ctx);
}

static int siphash_init(EVP_MAC_IMPL *sctx)
{
    return SipHash_Init(&sctx->ctx, sctx->key, 0, 0);
}

static int siphash_update(EVP_MAC_IMPL *sctx, const unsigned char *data,
                       size_t datalen)
{
    SipHash_Update(&sctx->ctx, data, datalen);
    return 1;
}

static int siphash_final(EVP_MAC_IMPL *sctx, unsigned char *out)
{
    size_t hlen = siphash_size(sctx);

    return SipHash_Final(&sctx->ctx, out, hlen);
}

static int siphash_ctrl(EVP_MAC_IMPL *sctx, int cmd, va_list args)
{
    switch (cmd) {
    case EVP_MAC_CTRL_SET_SIZE:
        {
            size_t size = va_arg(args, size_t);

            return SipHash_set_hash_size(&sctx->ctx, size);
        }
        break;
    case EVP_MAC_CTRL_SET_KEY:
        {
            const unsigned char *key = va_arg(args, const unsigned char *);
            size_t keylen = va_arg(args, size_t);

            if (key == NULL || keylen != SIPHASH_KEY_SIZE)
                return 0;
            OPENSSL_clear_free(sctx->key, sctx->key_len);
            sctx->key = OPENSSL_memdup(key, keylen);
            sctx->key_len = keylen;
            return sctx->key != NULL;
        }
        break;
    default:
        return -2;
    }
    return 1;
}

static int siphash_ctrl_int(EVP_MAC_IMPL *sctx, int cmd, ...)
{
    int rv;
    va_list args;

    va_start(args, cmd);
    rv = siphash_ctrl(sctx, cmd, args);
    va_end(args);

    return rv;
}

static int siphash_ctrl_str_cb(void *ctx, int cmd, void *buf, size_t buflen)
{
    return siphash_ctrl_int(ctx, cmd, buf, buflen);
}

static int siphash_ctrl_str(EVP_MAC_IMPL *ctx,
                            const char *type, const char *value)
{
    if (value == NULL)
        return 0;
    if (strcmp(type, "digestsize") == 0) {
        size_t hash_size = atoi(value);

        return siphash_ctrl_int(ctx, EVP_MAC_CTRL_SET_SIZE, hash_size);
    }
    if (strcmp(type, "key") == 0)
        return EVP_str2ctrl(siphash_ctrl_str_cb, ctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    if (strcmp(type, "hexkey") == 0)
        return EVP_hex2ctrl(siphash_ctrl_str_cb, ctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    return -2;
}

const EVP_MAC siphash_meth = {
    EVP_MAC_SIPHASH,
    siphash_new,
    siphash_copy,
    siphash_free,
    siphash_size,
    siphash_init,
    siphash_update,
    siphash_final,
    siphash_ctrl,
    siphash_ctrl_str
};
