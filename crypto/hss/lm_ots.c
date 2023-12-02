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
#include <openssl/rand.h>
#include "internal/refcount.h"
#include "crypto/hss.h"
#include "lms_local.h"

#define U16STR(out, in)                        \
(out)[0] = (unsigned char)((in >> 8) & 0xff);  \
(out)[1] = (unsigned char)(in & 0xff)


/*
 * Appendix A: OTS Private Key generation
 *
 * Returns an element of the LM-OTS private keys x_q[i].
 *
 * i is 0..p (ots private key index)
 * q = 0..2^h (leaf index)
 *
 * x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)
 * The first call for a key to this function will allocate a buffer
 * to hold all parts of the above hash.
 */
static int ossl_lm_ots_get_private_xq(LMS_KEY *key, uint32_t q, uint16_t i,
                                      EVP_MD_CTX *mdctx,
                                      unsigned char *out)
{
    uint32_t seedlen = key->ots_params->n;

    U32STR(key->priv.data + LMS_OFFSET_q, q);
    U16STR(key->priv.data + LMS_OFFSET_i, i);

    return ossl_lms_hash(mdctx, key->priv.data, LMS_OFFSET_SEED + seedlen,
                         NULL, 0, out);
}

/*
 * Section 3.1.3: Strings of w-bit Elements
 *
 * w: Is one of {1,2,4,8}
 */
static uint8_t coef(const unsigned char *S, uint16_t i, uint8_t w)
{
    uint8_t bitmask = (1 << w) - 1;
    uint8_t shift = 8 - (w * (i % (8 / w)) + w);
    int id = (i * w) / 8;

    return (S[id] >> shift) & bitmask;
}

/*
 * Section 4.4 Checksum
 */
static uint16_t checksum(const LM_OTS_PARAMS *params, const unsigned char *S)
{
    uint16_t sum = 0;
    uint16_t i;
    /* Largest size is 8 * 32 / 1 = 256 (which doesnt quite fit into 8 bits) */
    uint16_t bytes = (8 * params->n / params->w );
    uint16_t end = (1 << params->w) - 1;

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

/*
 * Section 4.3. OTS Public Key
 * Algorithm 1 (Steps 1..4)
 *
 * Generate a LM-OTS public key from a Private Key
 *
 * Params:
 *   key: Contains OTS params and private key related data
 *   q: Index of the OTS private key (0 ... 2^h - 1)
 *   outK: The output OTS public key K (of size n bytes) associated with the
 *         private key
 */
int ossl_lm_ots_pubK_from_priv(LMS_KEY *key, uint32_t q, unsigned char *outK)
{
    int ret = 0;
    uint16_t i;
    const LM_OTS_PARAMS *prms = key->ots_params;
    uint8_t n = prms->n;
    uint16_t p = prms->p;
    WPACKET pkt;
    EVP_MD_CTX *ctxK = NULL;
    /*
     * This function uses the following data for its Hash function H()
     *   I || u32str(q) || u16str(i)      || u8str(j) || ....
     *   I || u32str(q) || u16str(D_PBLC) || ....
     * So we use a buffer to store the above parts.
     */
    unsigned char tmpbuf[LMS_SIZE_I + LMS_SIZE_q + LMS_SIZE_i + LMS_SIZE_j];
    unsigned char yi[LMS_MAX_DIGEST_SIZE];
    uint8_t j, end = (1 << prms->w) - 1;
    size_t len;

    /* tmpbuf[] = I || q || D_PBLC */
    if (!WPACKET_init_static_len(&pkt, tmpbuf, sizeof(tmpbuf), 0)
            || !WPACKET_memcpy(&pkt, key->I, LMS_SIZE_I)
            || !WPACKET_put_bytes_u32(&pkt, q)
            || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_PBLC)
            || !WPACKET_get_total_written(&pkt, &len))
        return 0;

    /* K partial = H(I || q || D_PBLC */
    ctxK = EVP_MD_CTX_dup(key->mdctx);
    if (ctxK == NULL
            || !EVP_DigestInit_ex2(ctxK, NULL, NULL)
            || !EVP_DigestUpdate(ctxK, tmpbuf, len)
            /* Rewind the tmpbuf back to I || u32str(q) */
            || !WPACKET_backward(&pkt, LMS_SIZE_DTAG))
        goto err;

    for (i = 0; i < p; ++i) {
        if (!ossl_lm_ots_get_private_xq(key, q, i, key->mdctx, yi) /* y[i] = x[i] */
                || !WPACKET_put_bytes_u16(&pkt, i))
            goto err;
        for (j = 0; j < end; ++j) {
            /* y[i] = H(I || q || i || j || y[i]) */
            if (!WPACKET_put_bytes_u8(&pkt, j)
                    || !ossl_lms_hash(key->mdctx, tmpbuf, len + 1, yi, n, yi)
                    || !WPACKET_backward(&pkt, LMS_SIZE_j))
                    goto err;
        }
        /* K = H(I || q || D_PBLC || y[i] || .. || y[p-1]) */
        if (!EVP_DigestUpdate(ctxK, yi, n))
            goto err;

        if (!WPACKET_backward(&pkt, LMS_SIZE_i))
            goto err;
    }
    if (!EVP_DigestFinal_ex(ctxK, outK, NULL))
        goto err;
    ret = 1;
err:
    WPACKET_finish(&pkt);
    EVP_MD_CTX_free(ctxK);
    return ret;
}

/*
 * Section 4.5 OTS Signature Generation
 * Algorithm 3: Generate a LM-OTS signature from a private key and message
 */
int ossl_lm_ots_signature_gen(LMS_KEY *key,
                              const unsigned char *msg, size_t msglen,
                              LM_OTS_SIG *sig)
{
    const LM_OTS_PARAMS *prms = key->ots_params;
    uint32_t n = prms->n;
    unsigned char tmp[LMS_SIZE_I + LMS_SIZE_q + LMS_SIZE_DTAG + LMS_MAX_DIGEST_SIZE];
    unsigned char Q[LMS_MAX_DIGEST_SIZE + LMS_SIZE_CHECKSUM], *Qsum = Q + n;
    uint8_t j, a;
    uint16_t i;
    WPACKET pkt;
    size_t len;
    unsigned char *psig;

    if (sig->C == NULL) {
        /* Allocate space for C & y[] */
        sig->C = OPENSSL_malloc(n * (1 + prms->p));
        if (sig->C == NULL)
            return 0;
        sig->y = sig->C + n;
    }
    if (!WPACKET_init_static_len(&pkt, tmp, sizeof(tmp), 0)
            || !WPACKET_memcpy(&pkt, key->I, LMS_SIZE_I)
            || !WPACKET_put_bytes_u32(&pkt, key->q)
            || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_C)
            || !WPACKET_put_bytes_u8(&pkt, 0xFF)
            || !WPACKET_get_total_written(&pkt, &len))
        return 0;
    if (!ossl_lms_hash(key->mdctx, tmp, len, key->priv.seed, n, sig->C))
        return 0;


    if (!WPACKET_backward(&pkt, 3)
            || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_MESG)
            || !WPACKET_memcpy(&pkt, sig->C, n)
            || !WPACKET_get_total_written(&pkt, &len)
            || !WPACKET_backward(&pkt, n))
        return 0;
    if (!ossl_lms_hash(key->mdctx, tmp, len, msg, msglen, Q))
        return 0;

    /* Q || Cksm(Q) */
    U16STR(Qsum, checksum(prms, Q));

    psig = sig->y;
    for (i = 0; i < prms->p; ++i) {
        a = coef(Q, i, prms->w);
        /* get psig = x_q[i] */
        if (!ossl_lm_ots_get_private_xq(key, key->q, i, key->mdctx, psig))
            return 0;

        WPACKET_backward(&pkt, 2);
        WPACKET_put_bytes_u16(&pkt, i);
        for (j = 0; j < a; ++j) {
            WPACKET_put_bytes_u8(&pkt, j);
            if (!ossl_lms_hash(key->mdctx, tmp, LMS_OFFSET_SEED, psig, n, psig)) {
                // Clear the sig here!
                return 0;
            }
            WPACKET_backward(&pkt, 1);
        }
        psig += n;
    }
    return 1;
}

/*
 * Section 4.6 Signature Verification
 * Algorithm 4b: Compute a Public Key Candidate Kc from a signature, message,
 * and public key parameters.
 *
 * The function has been broken into 3 parts in order to deal with streaming
 * messages.
 *  (1) ossl_lm_ots_ctx_pubkey_init()
 *  (2) ossl_lm_ots_ctx_pubkey_update()
 *  (3) ossl_lm_ots_ctx_pubkey_final()
 *  Part (2) is the stage that allows the input message to be streamed.
 *
 * ossl_lm_ots_ctx_pubkey_init() sets up the initial part of Q
 * Q = H(I || u32str(q) || u16str(D_MESG) || C)
 */
int ossl_lm_ots_ctx_pubkey_init(LM_OTS_CTX *pctx,
                                const EVP_MD *md,
                                const LM_OTS_SIG *sig,
                                const LM_OTS_PARAMS *pub,
                                const unsigned char *I, uint32_t q)
{
    int ret = 0;
    EVP_MD_CTX *ctx, *ctxIq;
    unsigned char iq[LMS_SIZE_I + LMS_SIZE_q], *qbuf = &iq[LMS_SIZE_I];
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_PARAM *p = NULL;

    if (sig->params != pub)
        return 0;

    memcpy(iq, I, LMS_SIZE_I);
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
            || !EVP_MD_CTX_copy_ex(ctx, ctxIq)
            /* Q = H(I || u32str(q) || u16str(D_MESG) || C || ....) */
            || !EVP_DigestUpdate(ctx, &OSSL_LMS_D_MESG, sizeof(OSSL_LMS_D_MESG))
            || !EVP_DigestUpdate(ctx, sig->C, sig->params->n))
        goto err;
    pctx->sig = sig;
    ret = 1;
err:
    return ret;
}

/*
 * Section 4.3 Signature Verification
 * Algorithm 4b - Part 2
 *
 * update the msg part of
 * Q = H(.... || msg)
 */
int ossl_lm_ots_ctx_pubkey_update(LM_OTS_CTX *pctx,
                                  const unsigned char *msg, size_t msglen)
{
    return EVP_DigestUpdate(pctx->mdctx, msg, msglen) > 0;
}

#define LMS_SIZE_QSUM 2


/*
 * Section 4.3 Signature Verification
 * Algorithm 4b - Part 3
 * Steps 3 (Finalizes Q) and 4
 */
int ossl_lm_ots_ctx_pubkey_final(LM_OTS_CTX *pctx, unsigned char *Kc)
{
    int ret = 0, i;
    EVP_MD_CTX *ctxKc = NULL;
    EVP_MD_CTX *ctx = pctx->mdctx;
    EVP_MD_CTX *ctxIq = pctx->mdctxIq;
    unsigned char tag[2 + 1], *tag2 = &tag[2];
    unsigned char Q[LMS_MAX_DIGEST_SIZE + LMS_SIZE_QSUM], *Qsum;
    unsigned char z[LMS_MAX_DIGEST_SIZE];
    uint16_t sum;
    const LM_OTS_PARAMS *params = pctx->sig->params;
    int n = params->n;
    int p = params->p;
    uint8_t j, w = params->w, end = (1 << w) - 1;
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
            || !EVP_DigestUpdate(ctxKc, &OSSL_LMS_D_PBLC, sizeof(OSSL_LMS_D_PBLC)))
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
