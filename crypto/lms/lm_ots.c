/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include "crypto/lms.h"
#include "internal/refcount.h"

static unsigned char D_PBLC[] = { 0x80, 0x80 };
static unsigned char D_MESG[] = { 0x81, 0x81 };

#define U16STR(out, in)                      \
out[0] = (unsigned char)((in >> 8) & 0xff);  \
out[1] = (unsigned char)(in & 0xff)

#define LM_OTS_TYPE_SHA256_N32_W1 0x00000001
#define LM_OTS_TYPE_SHA256_N32_W2 0x00000002
#define LM_OTS_TYPE_SHA256_N32_W4 0x00000003
#define LM_OTS_TYPE_SHA256_N32_W8 0x00000004
#define LM_OTS_TYPE_SHA256_N24_W1 0x00000005
#define LM_OTS_TYPE_SHA256_N24_W2 0x00000006
#define LM_OTS_TYPE_SHA256_N24_W4 0x00000007
#define LM_OTS_TYPE_SHA256_N24_W8 0x00000008
#define LM_OTS_TYPE_SHAKE_N32_W1  0x00000009
#define LM_OTS_TYPE_SHAKE_N32_W2  0x0000000A
#define LM_OTS_TYPE_SHAKE_N32_W4  0x0000000B
#define LM_OTS_TYPE_SHAKE_N32_W8  0x0000000C
#define LM_OTS_TYPE_SHAKE_N24_W1  0x0000000D
#define LM_OTS_TYPE_SHAKE_N24_W2  0x0000000E
#define LM_OTS_TYPE_SHAKE_N24_W4  0x0000000F
#define LM_OTS_TYPE_SHAKE_N24_W8  0x00000010

static const LM_OTS_PARAMS lm_ots_params[] = {
    { LM_OTS_TYPE_SHA256_N32_W1, "SHA256",     32, 1, 265 },
    { LM_OTS_TYPE_SHA256_N32_W2, "SHA256",     32, 2, 133 },
    { LM_OTS_TYPE_SHA256_N32_W4, "SHA256",     32, 4,  67 },
    { LM_OTS_TYPE_SHA256_N32_W8, "SHA256",     32, 8,  34 },
    { LM_OTS_TYPE_SHA256_N24_W1, "SHA256-192", 24, 1, 200 },
    { LM_OTS_TYPE_SHA256_N24_W2, "SHA256-192", 24, 2, 101 },
    { LM_OTS_TYPE_SHA256_N24_W4, "SHA256-192", 24, 4,  51 },
    { LM_OTS_TYPE_SHA256_N24_W8, "SHA256-192", 24, 8,  26 },
    { LM_OTS_TYPE_SHAKE_N32_W1,  "SHAKE-256",  32, 1, 265 },
    { LM_OTS_TYPE_SHAKE_N32_W2,  "SHAKE-256",  32, 2, 133 },
    { LM_OTS_TYPE_SHAKE_N32_W4,  "SHAKE-256",  32, 4,  67 },
    { LM_OTS_TYPE_SHAKE_N32_W8,  "SHAKE-256",  32, 8,  34 },
    /* SHAKE-256/192 */
    { LM_OTS_TYPE_SHAKE_N24_W1,  "SHAKE-256",  24, 1, 200 },
    { LM_OTS_TYPE_SHAKE_N24_W2,  "SHAKE-256",  24, 2, 101 },
    { LM_OTS_TYPE_SHAKE_N24_W4,  "SHAKE-256",  24, 4,  51 },
    { LM_OTS_TYPE_SHAKE_N24_W8,  "SHAKE-256",  24, 8,  26 },

    { 0, NULL, 0, 0, 0 },
};

const LM_OTS_PARAMS *ossl_lm_ots_params_get(uint32_t ots_type)
{
    const LM_OTS_PARAMS *p;

    for (p = lm_ots_params; p->lm_ots_type != 0; ++p) {
        if (p->lm_ots_type == ots_type)
            return p;
    }
    return NULL;
}

static int coef(const unsigned char *S, int i, int w)
{
    int bitmask = (1 << w) - 1;
    int id = (i * w) / 8;
    int shift = 8 - (w * (i % (8 / w)) + w);

    return (S[id] >> shift) & bitmask;
}

static int checksum(const LM_OTS_PARAMS *params, const unsigned char *S)
{
    int i, sum = 0;
    int bytes = 8 * params->n / params->w;
    int end = (1 << params->w) - 1;

    for (i = 0; i < bytes; ++i)
        sum += end - coef(S, i, params->w);
    return (sum << (8 - params->w));
}

static ossl_inline void INC16(unsigned char *tag)
{
    if ((tag[1] = tag[1] + 1) == 0)
        *tag = *tag + 1;
}

LM_OTS_CTX *ossl_lm_ots_ctx_new(void)
{
    LM_OTS_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->mdctx = EVP_MD_CTX_create();
    ctx->mdctxIq = EVP_MD_CTX_create();
    if (ctx->mdctx == NULL || ctx->mdctxIq == NULL) {
        ossl_lm_ots_ctx_free(ctx);
        return NULL;
    }
    return ctx;
}

void ossl_lm_ots_ctx_free(LM_OTS_CTX *ctx)
{
    if (ctx == NULL)
        return;
    EVP_MD_CTX_free(ctx->mdctxIq);
    EVP_MD_CTX_free(ctx->mdctx);
    OPENSSL_free(ctx);
}

LM_OTS_CTX *ossl_lm_ots_ctx_dup(LM_OTS_CTX *src)
{
    LM_OTS_CTX *ret = NULL;

    if (src == NULL)
        return NULL;

    ret = ossl_lm_ots_ctx_new();
    if (ret == NULL)
        return NULL;

    if (!EVP_MD_CTX_copy_ex(ret->mdctx, src->mdctx)
        || !EVP_MD_CTX_copy_ex(ret->mdctxIq, src->mdctxIq))
        goto err;
    return ret;
err:
    ossl_lm_ots_ctx_free(ret);
    return NULL;
}

/* Algorithm 4b */
int ossl_lm_ots_ctx_pubkey_init(LM_OTS_CTX *pctx,
                                 const EVP_MD *md,
                                 const LM_OTS_SIG *sig,
                                 const LM_OTS_PARAMS *pub,
                                 const unsigned char *I, uint32_t q)
{
    int ret = 0;
    EVP_MD_CTX *ctx, *ctxIq;
    unsigned char iq[LMS_ISIZE+4], *qbuf = &iq[LMS_ISIZE];

    if (sig->params != pub)
        return 0;

    memcpy(iq, I, LMS_ISIZE);
    U32STR(qbuf, q);

    pctx->sig = sig;
    ctx = pctx->mdctx;
    ctxIq = pctx->mdctxIq;

    if (!EVP_DigestInit_ex2(ctxIq, md, NULL)
        || !EVP_DigestUpdate(ctxIq, iq, sizeof(iq))
        || !EVP_MD_CTX_copy_ex(ctx, ctxIq))
        goto err;

    /* Q = H(I || u32str(q) || u16str(D_MESG) || C || ....) */
    if (!EVP_DigestUpdate(ctx, D_MESG, sizeof(D_MESG))
        || !EVP_DigestUpdate(ctx, sig->C, sig->params->n))
        goto err;
    ret = 1;
err:
    return ret;
}

/* Algorithm 4b */
int ossl_lm_ots_ctx_pubkey_update(LM_OTS_CTX *pctx,
                                   const unsigned char *msg, size_t msglen)
{
    return EVP_DigestUpdate(pctx->mdctx, msg, msglen) > 0;
}

/* Algorithm 4b */
int ossl_lm_ots_ctx_pubkey_final(LM_OTS_CTX *pctx, unsigned char *Kc)
{
    int ret = 0, i, j;
    EVP_MD_CTX *ctxKc = NULL;
    EVP_MD_CTX *ctx = pctx->mdctx;
    EVP_MD_CTX *ctxIq = pctx->mdctxIq;
    unsigned char tag[2 + 1], *tag2 = &tag[2];
    unsigned char Q[LMS_MAX_DIGEST_SIZE+2], *Qsum;
    unsigned char z[LMS_MAX_DIGEST_SIZE];
    uint16_t sum;
    const LM_OTS_PARAMS *params = pctx->sig->params;
    int n = params->n;
    int p = params->p;
    int w = params->w;
    int end = (1 << w) - 1;
    int a;
    unsigned char *y;

    ctxKc = EVP_MD_CTX_create();
    if (ctxKc == NULL)
        goto err;

    if (!EVP_DigestFinal_ex(ctx, Q, NULL))
        goto err;

    sum = checksum(pctx->sig->params, Q);
    Qsum = Q + n;
    /* Q || Cksm(Q) */
    U16STR(Qsum, sum);

    if (!(EVP_MD_CTX_copy_ex(ctxKc, ctxIq))
        || !EVP_DigestUpdate(ctxKc, D_PBLC, sizeof(D_PBLC)))
        goto err;

    y = pctx->sig->y;
    tag[0] = 0; tag[1] = 0;

    for (i = 0; i < p; ++i) {
        a = coef(Q, i, w);
        memcpy(z, y, n);
        y += n;
        for (j = a; j < end; ++j) {
            *tag2 = (j & 0xFF);
            if (!(EVP_MD_CTX_copy_ex(ctx, ctxIq)))
                goto err;
            if (!EVP_DigestUpdate(ctx, tag, sizeof(tag))
                || !EVP_DigestUpdate(ctx, z, n)
                || !EVP_DigestFinal_ex(ctx, z, NULL))
                goto err;
        }
        INC16(tag);
        if (!EVP_DigestUpdate(ctxKc, z, n))
            goto err;
    }

    /* Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1]) */
    if (!EVP_DigestFinal(ctxKc, Kc, NULL))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctxKc);
    return ret;
}
