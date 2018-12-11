/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include "internal/evp_int.h"

/* local CMAC pkey structure */

/* typedef EVP_MAC_IMPL */
struct evp_mac_impl_st {
    /* tmpcipher and tmpengine are set to NULL after a CMAC_Init call */
    const EVP_CIPHER *tmpcipher; /* cached CMAC cipher */
    const ENGINE *tmpengine;     /* cached CMAC cipher engine */
    CMAC_CTX *ctx;
};

static EVP_MAC_IMPL *cmac_new(void)
{
    EVP_MAC_IMPL *cctx;

    if ((cctx = OPENSSL_zalloc(sizeof(*cctx))) == NULL
        || (cctx->ctx = CMAC_CTX_new()) == NULL) {
        OPENSSL_free(cctx);
        cctx = NULL;
    }

    return cctx;
}

static void cmac_free(EVP_MAC_IMPL *cctx)
{
    if (cctx != NULL) {
        CMAC_CTX_free(cctx->ctx);
        OPENSSL_free(cctx);
    }
}

static int cmac_copy(EVP_MAC_IMPL *cdst, EVP_MAC_IMPL *csrc)
{
    if (!CMAC_CTX_copy(cdst->ctx, csrc->ctx))
        return 0;

    cdst->tmpengine = csrc->tmpengine;
    cdst->tmpcipher = csrc->tmpcipher;
    return 1;
}

static size_t cmac_size(EVP_MAC_IMPL *cctx)
{
    return EVP_CIPHER_CTX_block_size(CMAC_CTX_get0_cipher_ctx(cctx->ctx));
}

static int cmac_init(EVP_MAC_IMPL *cctx)
{
    int rv = CMAC_Init(cctx->ctx, NULL, 0, cctx->tmpcipher,
                       (ENGINE *)cctx->tmpengine);
    cctx->tmpcipher = NULL;
    cctx->tmpengine = NULL;

    return rv;
}

static int cmac_update(EVP_MAC_IMPL *cctx, const unsigned char *data,
                       size_t datalen)
{
    return CMAC_Update(cctx->ctx, data, datalen);
}

static int cmac_final(EVP_MAC_IMPL *cctx, unsigned char *out)
{
    size_t hlen;

    return CMAC_Final(cctx->ctx, out, &hlen);
}

static int cmac_ctrl(EVP_MAC_IMPL *cctx, int cmd, va_list args)
{
    switch (cmd) {
    case EVP_MAC_CTRL_SET_KEY:
        {
            const unsigned char *key = va_arg(args, const unsigned char *);
            size_t keylen = va_arg(args, size_t);
            int rv = CMAC_Init(cctx->ctx, key, keylen, cctx->tmpcipher,
                               (ENGINE *)cctx->tmpengine);

            cctx->tmpcipher = NULL;
            cctx->tmpengine = NULL;

            return rv;
        }
        break;
    case EVP_MAC_CTRL_SET_CIPHER:
        cctx->tmpcipher = va_arg(args, const EVP_CIPHER *);
        break;
    case EVP_MAC_CTRL_SET_ENGINE:
        cctx->tmpengine = va_arg(args, const ENGINE *);
        break;
    default:
        return -2;
    }
    return 1;
}

static int cmac_ctrl_int(EVP_MAC_IMPL *hctx, int cmd, ...)
{
    int rv;
    va_list args;

    va_start(args, cmd);
    rv = cmac_ctrl(hctx, cmd, args);
    va_end(args);

    return rv;
}

static int cmac_ctrl_str_cb(void *hctx, int cmd, void *buf, size_t buflen)
{
    return cmac_ctrl_int(hctx, cmd, buf, buflen);
}

static int cmac_ctrl_str(EVP_MAC_IMPL *cctx, const char *type,
                         const char *value)
{
    if (!value)
        return 0;
    if (strcmp(type, "cipher") == 0) {
        const EVP_CIPHER *c = EVP_get_cipherbyname(value);

        if (c == NULL)
            return 0;
        return cmac_ctrl_int(cctx, EVP_MAC_CTRL_SET_CIPHER, c);
    }
    if (strcmp(type, "key") == 0)
        return EVP_str2ctrl(cmac_ctrl_str_cb, cctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    if (strcmp(type, "hexkey") == 0)
        return EVP_hex2ctrl(cmac_ctrl_str_cb, cctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    return -2;
}

const EVP_MAC cmac_meth = {
    EVP_MAC_CMAC,
    cmac_new,
    cmac_copy,
    cmac_free,
    cmac_size,
    cmac_init,
    cmac_update,
    cmac_final,
    cmac_ctrl,
    cmac_ctrl_str
};
