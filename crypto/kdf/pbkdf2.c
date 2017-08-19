/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "internal/evp_int.h"

#ifndef OPENSSL_NO_PBKDF2

typedef struct {
    const EVP_MD *md;
    unsigned char *pass;
    size_t pass_len;
    unsigned char *salt;
    size_t salt_len;
    int iter;
} PBKDF2_PKEY_CTX;

static int pkey_pbkdf2_init(EVP_PKEY_CTX *ctx)
{
    PBKDF2_PKEY_CTX *kctx;

    kctx = OPENSSL_zalloc(sizeof(*kctx));
    if (kctx == NULL)
        return 0;

    ctx->data = kctx;

    return 1;
}

static void pkey_pbkdf2_cleanup(EVP_PKEY_CTX *ctx)
{
    PBKDF2_PKEY_CTX *kctx = ctx->data;

    OPENSSL_clear_free(kctx->salt, kctx->salt_len);
    OPENSSL_clear_free(kctx->pass, kctx->pass_len);
    OPENSSL_free(kctx);
}

static int pkey_pbkdf2_set_membuf(unsigned char **buffer, size_t *buflen,
                                  const unsigned char *new_buffer,
                                  const int new_buflen)
{
    if (new_buffer == NULL)
        return 1;

    if (new_buflen < 0)
        return 0;

    if (*buffer != NULL)
        OPENSSL_clear_free(*buffer, *buflen);

    if (new_buflen > 0) {
        *buffer = OPENSSL_memdup(new_buffer, new_buflen);
    } else {
        *buffer = OPENSSL_malloc(1);
    }
    if (*buffer == NULL)
        return 0;

    *buflen = new_buflen;
    return 1;
}

static int pkey_pbkdf2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    PBKDF2_PKEY_CTX *kctx = ctx->data;

    switch (type) {
    case EVP_PKEY_CTRL_PBKDF2_MD:
        if (p2 == NULL) {
            KDFerr(KDF_F_PKEY_PBKDF2_CTRL, KDF_R_VALUE_MISSING);
            return 0;
        }
        kctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_PASS:
        return pkey_pbkdf2_set_membuf(&kctx->pass, &kctx->pass_len, p2, p1);

    case EVP_PKEY_CTRL_PBKDF2_SALT:
        return pkey_pbkdf2_set_membuf(&kctx->salt, &kctx->salt_len, p2, p1);

    case EVP_PKEY_CTRL_ITER:
        if (p1 < 1) {
            KDFerr(KDF_F_PKEY_PBKDF2_CTRL, KDF_R_VALUE_ERROR);
            return 0;
        }
        kctx->iter = p1;
        return 1;

    default:
        return -2;
    }
}

static int pkey_pbkdf2_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                                const char *value)
{
    if (value == NULL) {
        KDFerr(KDF_F_PKEY_PBKDF2_CTRL_STR, KDF_R_VALUE_MISSING);
        return 0;
    }

    if (strcmp(type, "md") == 0)
        return EVP_PKEY_CTX_md(ctx, EVP_PKEY_OP_DERIVE,
                               EVP_PKEY_CTRL_PBKDF2_MD, value);

    if (strcmp(type, "pass") == 0)
        return EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_PASS, value);

    if (strcmp(type, "hexpass") == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_PASS, value);

    if (strcmp(type, "salt") == 0)
        return EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_PBKDF2_SALT, value);

    if (strcmp(type, "hexsalt") == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_PBKDF2_SALT, value);

    if (strcmp(type, "iter") == 0)
        return pkey_pbkdf2_ctrl(ctx, EVP_PKEY_CTRL_ITER, atoi(value),
                                NULL);

    KDFerr(KDF_F_PKEY_PBKDF2_CTRL_STR, KDF_R_UNKNOWN_PARAMETER_TYPE);
    return -2;
}

static int pkey_pbkdf2_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                              size_t *keylen)
{
    PBKDF2_PKEY_CTX *kctx = ctx->data;

    if (kctx->md == NULL) {
        KDFerr(KDF_F_PKEY_PBKDF2_DERIVE, KDF_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }

    if (kctx->pass == NULL) {
        KDFerr(KDF_F_PKEY_PBKDF2_DERIVE, KDF_R_MISSING_PASS);
        return 0;
    }

    if (kctx->salt == NULL) {
        KDFerr(KDF_F_PKEY_PBKDF2_DERIVE, KDF_R_MISSING_SALT);
        return 0;
    }

    if (kctx->iter == 0) {
        KDFerr(KDF_F_PKEY_PBKDF2_DERIVE, KDF_R_MISSING_ITERATION_COUNT);
        return 0;
    }

    return PKCS5_PBKDF2_HMAC((char *)kctx->pass, kctx->pass_len, kctx->salt,
                             kctx->salt_len, kctx->iter, kctx->md,
                             *keylen, key);
}

const EVP_PKEY_METHOD pbkdf2_pkey_meth = {
    EVP_PKEY_PBKDF2,
    0,
    pkey_pbkdf2_init,
    0,
    pkey_pbkdf2_cleanup,

    0, 0,
    0, 0,

    0,
    0,

    0,
    0,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    0,
    pkey_pbkdf2_derive,
    pkey_pbkdf2_ctrl,
    pkey_pbkdf2_ctrl_str
};

#endif
