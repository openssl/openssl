/*
 * Copyright 2007-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include "internal/evp_int.h"

/* HMAC pkey context structure */

typedef struct {
    const EVP_MD *md;           /* MD for HMAC use */
    ASN1_OCTET_STRING ktmp;     /* Temp storage for key */
    EVP_MAC_CTX *ctx;
} HMAC_PKEY_CTX;

static int pkey_hmac_init(EVP_PKEY_CTX *ctx)
{
    HMAC_PKEY_CTX *hctx;

    if ((hctx = OPENSSL_zalloc(sizeof(*hctx))) == NULL) {
        CRYPTOerr(CRYPTO_F_PKEY_HMAC_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    hctx->ktmp.type = V_ASN1_OCTET_STRING;
    hctx->ctx = EVP_MAC_CTX_new(EVP_hmac());
    if (hctx->ctx == NULL) {
        OPENSSL_free(hctx);
        return 0;
    }

    ctx->data = hctx;
    ctx->keygen_info_count = 0;

    return 1;
}

static void pkey_hmac_cleanup(EVP_PKEY_CTX *ctx);

static int pkey_hmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    HMAC_PKEY_CTX *sctx, *dctx;

    if (!pkey_hmac_init(dst))
        return 0;
    sctx = EVP_PKEY_CTX_get_data(src);
    dctx = EVP_PKEY_CTX_get_data(dst);
    dctx->md = sctx->md;
    if (!EVP_MAC_CTX_copy(dctx->ctx, sctx->ctx)
        || (sctx->ktmp.data == NULL
            && !ASN1_OCTET_STRING_set(&dctx->ktmp,
                                      sctx->ktmp.data, sctx->ktmp.length))) {
        pkey_hmac_cleanup (dst);
        return 0;
    }
    return 1;
}

static void pkey_hmac_cleanup(EVP_PKEY_CTX *ctx)
{
    HMAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);

    if (hctx != NULL) {
        EVP_MAC_CTX_free(hctx->ctx);
        OPENSSL_clear_free(hctx->ktmp.data, hctx->ktmp.length);
        OPENSSL_free(hctx);
        EVP_PKEY_CTX_set_data(ctx, NULL);
    }
}

static int pkey_hmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *hkey = NULL;
    HMAC_PKEY_CTX *hctx = ctx->data;

    if (!hctx->ktmp.data)
        return 0;
    hkey = ASN1_OCTET_STRING_dup(&hctx->ktmp);
    if (!hkey)
        return 0;
    EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, hkey);

    return 1;
}

static int int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    HMAC_PKEY_CTX *hctx = EVP_MD_CTX_pkey_ctx(ctx)->data;

    if (!EVP_MAC_update(hctx->ctx, data, count))
        return 0;
    return 1;
}

static int pkey_hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    HMAC_PKEY_CTX *hctx = ctx->data;

    EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_FLAGS,
                 EVP_MD_CTX_test_flags(mctx, ~EVP_MD_CTX_FLAG_NO_INIT));
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    EVP_MD_CTX_set_update_fn(mctx, int_update);
    return 1;
}

static int pkey_hmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
                             size_t *siglen, EVP_MD_CTX *mctx)
{
    HMAC_PKEY_CTX *hctx = ctx->data;
    size_t hlen;
    int l = EVP_MD_CTX_size(mctx);

    if (l < 0)
        return 0;
    *siglen = l;
    if (!sig)
        return 1;

    if (!EVP_MAC_final(hctx->ctx, sig, &hlen))
        return 0;
    *siglen = hlen;
    return 1;
}

static int pkey_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    HMAC_PKEY_CTX *hctx = ctx->data;

    switch (type) {

    case EVP_PKEY_CTRL_SET_MAC_KEY:
        if ((!p2 && p1 > 0) || (p1 < -1))
            return 0;
        if (!ASN1_OCTET_STRING_set(&hctx->ktmp, p2, p1))
            return 0;
        break;

    case EVP_PKEY_CTRL_MD:
        hctx->md = p2;
        break;

    case EVP_PKEY_CTRL_DIGESTINIT:
        /* Ensure that we have attached the implementation */
        if (!EVP_MAC_init(hctx->ctx))
            return 0;
        {
            int rv;
            ASN1_OCTET_STRING *key = (ASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;

            if ((rv = EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_ENGINE,
                                   ctx->engine)) < 0
                || (rv = EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_MD,
                                   hctx->md)) < 0
                || (rv = EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_KEY,
                                      key->data, key->length)) < 0)
                return rv;
        }
        break;

    default:
        return -2;

    }
    return 1;
}

static int pkey_hmac_ctrl_str(EVP_PKEY_CTX *ctx,
                              const char *type, const char *value)
{
    HMAC_PKEY_CTX *hctx = ctx->data;

    return EVP_MAC_ctrl_str(hctx->ctx, type, value);
}

const EVP_PKEY_METHOD hmac_pkey_meth = {
    EVP_PKEY_HMAC,
    0,
    pkey_hmac_init,
    pkey_hmac_copy,
    pkey_hmac_cleanup,

    0, 0,

    0,
    pkey_hmac_keygen,

    0, 0,

    0, 0,

    0, 0,

    pkey_hmac_signctx_init,
    pkey_hmac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_hmac_ctrl,
    pkey_hmac_ctrl_str
};
