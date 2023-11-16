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
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include "internal/refcount.h"
#include "crypto/hss.h"
#include "lms_local.h"

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

static const uint16_t D_PBLC = 0x8080;
static const uint16_t D_MESG = 0x8181;

static const LM_OTS_PARAMS lm_ots_params[] = {
    { LM_OTS_TYPE_SHA256_N32_W1, 32, 1, 265, "SHA256"},
    { LM_OTS_TYPE_SHA256_N32_W2, 32, 2, 133, "SHA256"},
    { LM_OTS_TYPE_SHA256_N32_W4, 32, 4,  67, "SHA256"},
    { LM_OTS_TYPE_SHA256_N32_W8, 32, 8,  34, "SHA256"},
    { LM_OTS_TYPE_SHA256_N24_W1, 24, 1, 200, "SHA256-192"},
    { LM_OTS_TYPE_SHA256_N24_W2, 24, 2, 101, "SHA256-192"},
    { LM_OTS_TYPE_SHA256_N24_W4, 24, 4,  51, "SHA256-192"},
    { LM_OTS_TYPE_SHA256_N24_W8, 24, 8,  26, "SHA256-192"},
    { LM_OTS_TYPE_SHAKE_N32_W1,  32, 1, 265, "SHAKE-256"},
    { LM_OTS_TYPE_SHAKE_N32_W2,  32, 2, 133, "SHAKE-256"},
    { LM_OTS_TYPE_SHAKE_N32_W4,  32, 4,  67, "SHAKE-256"},
    { LM_OTS_TYPE_SHAKE_N32_W8,  32, 8,  34, "SHAKE-256"},
    /* SHAKE-256/192 */
    { LM_OTS_TYPE_SHAKE_N24_W1,  24, 1, 200, "SHAKE-256"},
    { LM_OTS_TYPE_SHAKE_N24_W2,  24, 2, 101, "SHAKE-256"},
    { LM_OTS_TYPE_SHAKE_N24_W4,  24, 4,  51, "SHAKE-256"},
    { LM_OTS_TYPE_SHAKE_N24_W8,  24, 8,  26, "SHAKE-256"},

    { 0, NULL, 0, 0, 0 },
};

/*
 * From Appendix A.
 * x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED).
 *
 * So we store I || q || i || 0xFF || seed into a single ordered buffer
 * called priv_bytes.
 */

#define Q_OFFSET LMS_ISIZE
#define INDEX_OFFSET Q_OFFSET + 4
#define TAG_OFFSET INDEX_OFFSET + 2
#define SEED_OFFSET TAG_OFFSET + 1

#define J_OFFSET TAG_OFFSET

int ossl_lm_ots_init_private(LMS_KEY *key)
{
    if (key->priv_bytes == NULL) {
        uint32_t seedlen = key->ots_params->n;

        key->priv_bytes = OPENSSL_zalloc(SEED_OFFSET + seedlen);
        if (key->priv_bytes == NULL)
            return 0;
        key->priv_bytes[TAG_OFFSET] = 0xFF;
        key->I = key->priv_bytes;
        key->priv_seed = key->priv_bytes + SEED_OFFSET;
        if (RAND_priv_bytes(key->I, LMS_ISIZE) <= 0)
            return 0;
        if (!RAND_priv_bytes(key->priv_seed, seedlen))
            return 0;
        key->q = 0;
    }
    return 1;
}

static int Hash(EVP_MD_CTX *ctx,
                const unsigned char *in1, size_t in1len,
                const unsigned char *in2, size_t in2len,
                unsigned char *out)
{
    return EVP_DigestInit_ex2(ctx, NULL, NULL)
           && EVP_DigestUpdate(ctx, in1, in1len)
           && (in2 == NULL || EVP_DigestUpdate(ctx, in2, in2len))
           && EVP_DigestFinal_ex(ctx, out, NULL);
}

/*
 * Returns an element of the LM-OTS private keys x_q[i].
 * See Appendix A.
 *
 * i is 0..p (ots private key index)
 * q = 0..2^h (leaf index)
 *
 * x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)
 * The first call for a key to this function will allocate a buffer
 * to hold all parts of the above hash.
 */
int ossl_lm_ots_get_private_xq(LMS_KEY *key, uint32_t q, uint16_t index,
                               EVP_MD_CTX *mdctx,
                               unsigned char *out)
{
    uint32_t seedlen = key->ots_params->n;

    U32STR(key->priv_bytes + Q_OFFSET, q);
    U16STR(key->priv_bytes + INDEX_OFFSET, i);

    return Hash(mdctx, key->priv_bytes, SEED_OFFSET + seedlen, NULL, NULL, out);
}

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

int ossl_lm_ots_signature_gen(EVP_MD_CTX *mdctx, LMS_KEY *key,
                              const unsigned char *msg, size_t msglen,
                              LM_OTS_SIG *sig)
{
    unsigned char tmp[LMS_ISIZE + 4 + 2 + LMS_MAX_DIGEST_SIZE];
    unsigned char C[LMS_MAX_DIGEST_SIZE];
    unsigned char xqi[LMS_MAX_DIGEST_SIZE];
    unsigned char Q[LMS_MAX_DIGEST_SIZE];
    const LM_OTS_PARAMS *prms = key->ots_params;
    uint32_t n = prms->n;
    uint32_t i, j;
    int a;
    WPACKET pkt;
    size_t len;
    unsigned char *psig;

    if (sig->C == NULL) {
        /* Allocate space for C & y */
        sig->C = OPENSSL_malloc(n * (1 + prms->p));
        if (sig->C == NULL)
            return 0;
        sig->y = sig->C + n;
    }
    if (RAND_priv_bytes(sig->C, n) <= 0)
        return 0;

    if (!ossl_lm_ots_init_private(key))
        return 0;

    if (!WPACKET_init_static_len(pkt, tmp, sizeof(tmp), 0)
            || !WPACKET_memcpy(pkt, key->I, LMS_ISIZE)
            || !WPACKET_put_bytes_u32(pkt, key->q)
            || !WPACKET_put_bytes_u16(pkt, D_MESG)
            || !WPACKET_memcpy(pkt, sig->C, n)
            || !WPACKET_get_total_written(&pkt, &len)
            || !WPACKET_finish(&pkt))
        return 0;
    if (!Hash(mdctx, tmp, len, msg, msglen, Q))
        return 0;

    psig = sig->y;
    for (i = 0; i < prms->p; ++i) {

        a = coef(Q, i, prms->w);
        if (!ossl_lm_ots_get_private_xq(key, i, key->q, mdctx, psig))
            return 0;

        U16STR(tmp + INDEX_OFFSET, i);
        for (j = 0; j < a; ++j) {
            tmp[J_OFFSET] = j;
            if (!Hash(mdctx, tmp, J_OFFSET + 1, psig, n, psig)) {
                //Clear the sig here!
                return 0;
            }
        }
        psig += n;
    }
    return 1;
}

int WPACKET_backward(WPACKET *pkt, size_t len)
{
    if (len > pkt->written)
        return 0;
    pkt->curr -= len;
    pkt->written -= len;
    return 1;
}

int WPACKET_remaining(WPACKET *pkt)
{
    return pkt->maxsize - pkt->curr;
}

/*
 * Algorithm 1: Generate a LM-OTS public key from a Private Key
 * The Input key should contain:
 *    ots_params
 *    I
 *    q
 * The Output key will contain the following fields related to the public key:
 *    pub : The encoded key
 *    publen : Length of pub.
 *    pub_allocated : set to 1.
 *    K : is a pointer into pub which is the OTS_PUB_HASH[q] value.
 */
int ossl_lm_ots_pub_from_priv(LMS_KEY *key, uint32_t q, EVP_MD_CTX *mdctx)
{
    uint16_t i;
    const LM_OTS_PARAMS *prms = key->ots_params;
    uint8_t n = prms->n;
    uint16_t p = prms->p;
    WPACKET pkt, pubpkt, Kpkt;
    EVP_MD_CTX *ctxK = NULL;
    unsigned char tmpbuf[LMS_ISIZE + 4 + 2 + 1];
    unsigned char yi[LMS_MAX_DIGEST_SIZE];
    unsigned char *K = yi;
    uint8_t j, end = (1 << prms->w) - 1;
    size_t len;

    /* tmpbuf[] = I || q || D_PBLC */
    if (!WPACKET_init_static_len(pkt, tmpbuf, sizeof(tmpbuf), 0)
            || !WPACKET_memcpy(pkt, key->I, LMS_ISIZE)
            || !WPACKET_put_bytes_u32(pkt, q)
            || !WPACKET_put_bytes_u16(pkt, D_PBLC)
            || !WPACKET_get_total_written(pkt, &len))
        return 0;

    /* K partial = H(I || q || D_PBLC */
    ctxK = EVP_MD_CTX_dup(mdctx);
    EVP_DigestInit_ex2(ctxK, NULL, NULL);
    EVP_DigestUpdate(ctxK, tmpbuf, len);

    WPACKET_backward(pkt, 2);
    for (i = 0; i < p; ++i) {
        if (!WPACKET_put_bytes_u16(pkt, i))
            goto err;
        /* y[i] = x[i] */
        ossl_lm_ots_get_private_xq(key, i, q, mdctx, yi);
        for (j = 0; j < end; ++j) {
            WPACKET_put_bytes_u8(pkt, j);
            /* y[i] = H(I || q || i || j || y[i]) */
            Hash(mdctx, tmpbuf, len + 1, yi, n, yi);
            WPACKET_backward(pkt, 1);
        }
        /* K = H(I || q || D_PBLC || y[i] || .. || y[p-1]) */
        EVP_DigestUpdate(ctxK, yi, n);

        WPACKET_backward(pkt, 2);
    }
    /* key->pub[] = ots_type || I || q || K */
    key->publen = 4 + LMS_ISIZE + 4 + n;
    key->pub = OPENSSL_malloc(key->publen);
    key->pub_allocated = 1;
    WPACKET_init_static_len(&pubpkt, key->pub, key->publen, 0);
    WPACKET_put_bytes_u32(&pubpkt, prms->lm_ots_type);
    WPACKET_memcpy(&pubpkt, key->I, LMS_ISIZE);
    WPACKET_put_bytes_u32(&pubpkt, q);
    key->K = WPACKET_get_curr(pubpkt);
    assert(WPACKET_remaining(&pubpkt) == n);
    EVP_DigestFinal_ex(ctxK, key->K, NULL);
err:
    WPACKET_finish(&pkt);
    WPACKET_finish(&pubpkt);
    EVP_MD_CTX_free(ctxK);
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
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_PARAM *p = NULL;

    if (sig->params != pub)
        return 0;

    memcpy(iq, I, LMS_ISIZE);
    U32STR(qbuf, q);

    ctx = pctx->mdctx;
    ctxIq = pctx->mdctxIq;

    if (strncmp(sig->params->digestname, "SHAKE", 5) == 0) {
        size_t len = sig->params->n;

        params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &len);
        p = params;
    }

    if (!EVP_DigestInit_ex2(ctxIq, md, p)
            || !EVP_DigestUpdate(ctxIq, iq, sizeof(iq))
            || !EVP_MD_CTX_copy_ex(ctx, ctxIq))
        goto err;

    /* Q = H(I || u32str(q) || u16str(D_MESG) || C || ....) */
    if (!EVP_DigestUpdate(ctx, D_MESG, sizeof(D_MESG))
            || !EVP_DigestUpdate(ctx, sig->C, sig->params->n))
        goto err;
    pctx->sig = sig;
    return 1;
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
            if (!(EVP_MD_CTX_copy_ex(ctx, ctxIq))
                    || !EVP_DigestUpdate(ctx, tag, sizeof(tag))
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
