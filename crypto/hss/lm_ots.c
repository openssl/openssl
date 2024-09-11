/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/common.h"
#include "crypto/hss.h"
#include "lms_local.h"

#define U16STR(out, in)                            \
    (out)[0] = (unsigned char)((in >> 8) & 0xff);  \
    (out)[1] = (unsigned char)(in & 0xff)

/**
 * @brief OTS private key generation
 * See RFC 8554 Appendix A: OTS Private Key generation
 *
 * Returns an element of the LM-OTS private keys x_q[i].
 * x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)
 *
 * @param key The private key.
 * @param q is a leaf index 0..2^h
 * @param i is the OTS private key index 0..p
 * @param mdctx A EVP_MD_CTX object that already has a EVP_MD digest set.
 * @param out The output buffer. It is assumed this is the correct size.
 * @returns 1 on success, or 0 otherwise.
 */
static int lm_ots_get_private_xq(LMS_KEY *key, uint32_t q, uint16_t i,
                                 EVP_MD_CTX *mdctx, unsigned char *out)
{
    uint32_t seedlen = key->ots_params->n;

    /* See lms_privkey_reset() which sets key->priv.data[] initially */
    U32STR(key->priv.data + LMS_OFFSET_q, q);
    U16STR(key->priv.data + LMS_OFFSET_i, i);

    return ossl_lms_hash(mdctx, key->priv.data, LMS_OFFSET_SEED + seedlen,
                         NULL, 0, out);
}

/*
 * See RFC 8554 Section 3.1.3: Strings of w-bit Elements
 * w: Is one of {1,2,4,8}
 */
static uint8_t coef(const unsigned char *S, uint16_t i, uint8_t w)
{
    uint8_t bitmask = (1 << w) - 1;
    uint8_t shift = 8 - (w * (i % (8 / w)) + w);
    int id = (i * w) / 8;

    return (S[id] >> shift) & bitmask;
}

/* See RFC 8554 Section 4.4 Checksum */
static uint16_t checksum(const LM_OTS_PARAMS *params, const unsigned char *S)
{
    uint16_t sum = 0;
    uint16_t i;
    /* Largest size is 8 * 32 / 1 = 256 (which doesnt quite fit into 8 bits) */
    uint16_t bytes = (8 * params->n / params->w);
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

/**
 * @brief Generate a LM-OTS public key from a private key.
 * See RFC 8554 Section 4.3. OTS Public Key Algorithm 1 (Steps 1..4)
 *
 * @param key Contains OTS params and private key related data
 * @param q Index of the OTS private key (0 ... 2^h - 1)
 * @param outK The output OTS public key K (of size n bytes) associated with the
 *             private key
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_lm_ots_pubK_from_priv(LMS_KEY *privkey, uint32_t q, unsigned char *outK)
{
    int ret = 0;
    uint16_t i;
    const LM_OTS_PARAMS *prms = privkey->ots_params;
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
            || !WPACKET_memcpy(&pkt, privkey->Id, LMS_SIZE_I)
            || !WPACKET_put_bytes_u32(&pkt, q)
            || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_PBLC)
            || !WPACKET_get_total_written(&pkt, &len))
        return 0;

    /* K partial = H(I || q || D_PBLC */
    ctxK = EVP_MD_CTX_dup(privkey->mdctx);
    if (ctxK == NULL
            || !EVP_DigestInit_ex2(ctxK, NULL, NULL)
            || !EVP_DigestUpdate(ctxK, tmpbuf, len)
            /* Rewind the tmpbuf back to I || u32str(q) */
            || !WPACKET_backward(&pkt, LMS_SIZE_DTAG))
        goto err;

    for (i = 0; i < p; ++i) {
        /* y[i] = x[i] */
        if (!lm_ots_get_private_xq(privkey, q, i, privkey->mdctx, yi)
                || !WPACKET_put_bytes_u16(&pkt, i))
            goto err;
        for (j = 0; j < end; ++j) {
            /* y[i] = H(I || q || i || j || y[i]) */
            if (!WPACKET_put_bytes_u8(&pkt, j)
                    || !ossl_lms_hash(privkey->mdctx, tmpbuf, len + 1, yi, n, yi)
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

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)

/**
 * @brief OTS signature generation
 * See RFC 8554 Section 4.5 OTS Signature Generation
 * Algorithm 3: Generate a LM-OTS signature from a private key and message
 *
 * The algorithm has been broken into 3 parts, in order to allow message
 * streaming.
 *
 * @param privkey A private key
 * @param msg A message to sign
 * @param msglen The size of |msg|
 * @param sig An object to store the signature into.
 * @returns 1 if the signature is successfully generated, or 0 otherwise.
 */
int ossl_lm_ots_signature_gen(LMS_KEY *privkey,
                              const unsigned char *msg, size_t msglen,
                              LM_OTS_SIG *sig)
{
    return ossl_lm_ots_signature_gen_init(privkey, sig)
        && ossl_lm_ots_signature_gen_update(privkey, msg, msglen)
        && ossl_lm_ots_signature_gen_final(privkey, sig);
}

/**
 * @brief OTS signature generation initialization phase.
 */
int ossl_lm_ots_signature_gen_init(LMS_KEY *key, LM_OTS_SIG *sig)
{
    int ret = 0;
    const LM_OTS_PARAMS *prms = key->ots_params;
    uint32_t n = prms->n;
    unsigned char tmp[LMS_SIZE_I + LMS_SIZE_q + LMS_SIZE_DTAG + LMS_MAX_DIGEST_SIZE];
    WPACKET pkt;
    size_t len;

    if (sig->C == NULL) {
        /* Allocate space for C & y */
        sig->C = OPENSSL_malloc(n * (1 + prms->p));
        if (sig->C == NULL)
            return 0;
        sig->allocated = 1;
        sig->y = sig->C + n;
    }
    if (!ossl_assert(key->q < (uint32_t)(1 << key->lms_params->h)))
        return 0;
    if (!WPACKET_init_static_len(&pkt, tmp, sizeof(tmp), 0)
            || !WPACKET_memcpy(&pkt, key->Id, LMS_SIZE_I)
            || !WPACKET_put_bytes_u32(&pkt, key->q)
            || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_C)
            || !WPACKET_put_bytes_u8(&pkt, 0xFF)
            || !WPACKET_get_total_written(&pkt, &len))
        goto err;
    /*
     * Note that this implementation generates a deterministic value for C
     * based on I and SEED.
     * C = H(I || q || 0xFFFD || 0xFF || SEED)
     * According to SP800-208 Section 6.1, hardware implementations should
     * use a Approved RBG to generate this value.
     */
    if (!ossl_lms_hash(key->mdctx, tmp, len, key->priv.seed, n, sig->C))
        goto err;

    if (!WPACKET_backward(&pkt, 3)
            || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_MESG)
            || !WPACKET_memcpy(&pkt, sig->C, n)
            || !WPACKET_get_total_written(&pkt, &len))
        goto err;

    /* mdctx = H(I || q || 0x8181 || C) */
    ret =  EVP_DigestInit_ex2(key->mdctx, NULL, NULL)
        && EVP_DigestUpdate(key->mdctx, tmp, len);
err:
    WPACKET_finish(&pkt);
    WPACKET_close(&pkt);
    return ret;
}

/**
 * @brief OTS signature generation update phase.
 * This may be called multiple times.
 */
int ossl_lm_ots_signature_gen_update(LMS_KEY *key,
                                     const unsigned char *msg, size_t msglen)
{
    /* mdctx = H(I || q || 0x8181 || C || msg) */
    return EVP_DigestUpdate(key->mdctx, msg, msglen) > 0;
}

/**
 * @brief OTS signature generation final phase.
 */
int ossl_lm_ots_signature_gen_final(LMS_KEY *key, LM_OTS_SIG *sig)
{
    int ret = 0;
    const LM_OTS_PARAMS *prms = key->ots_params;
    uint32_t n = prms->n;
    unsigned char tmp[LMS_SIZE_I + LMS_SIZE_q + LMS_SIZE_i + LMS_SIZE_j];
    unsigned char Q[LMS_MAX_DIGEST_SIZE + LMS_SIZE_CHECKSUM], *Qsum = Q + n;
    unsigned char *psig;
    uint16_t i;
    uint8_t j, a;
    WPACKET pkt;

    /* Q = H(I || q || 0x8181 || C || msg) */
    if (!EVP_DigestFinal_ex(key->mdctx, Q, NULL))
        return 0;

    /* Q || Cksm(Q) */
    U16STR(Qsum, checksum(prms, Q));

    if (!WPACKET_init_static_len(&pkt, tmp, sizeof(tmp), 0)
            || !WPACKET_memcpy(&pkt, key->Id, LMS_SIZE_I)
            || !WPACKET_put_bytes_u32(&pkt, key->q))
        goto err;

    psig = sig->y;
    for (i = 0; i < prms->p; ++i) {
        a = coef(Q, i, prms->w);
        /* psig = x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED) */
        if (!lm_ots_get_private_xq(key, key->q, i, key->mdctx, psig))
            goto err;

        WPACKET_put_bytes_u16(&pkt, i);
        for (j = 0; j < a; ++j) {
            WPACKET_put_bytes_u8(&pkt, j);
            if (!ossl_lms_hash(key->mdctx, tmp, LMS_OFFSET_SEED, psig, n, psig)) {
                goto err;
            }
            WPACKET_backward(&pkt, 1);
        }
        WPACKET_backward(&pkt, 2);
        psig += n;
    }
    ret = 1;
err:
    if (ret == 0)
        OPENSSL_cleanse(sig->y, prms->p * n);
    WPACKET_finish(&pkt);
    WPACKET_close(&pkt);
    return ret;
}

#endif /* OPENSSL_NO_HSS_GEN */

/**
 * @brief OTS Signature verification initialization phase.
 *
 * See RFC 8554 Section 4.6 Signature Verification
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
 *
 * @param pctx A LM_OTS_CTX object.
 * @param md The digest to use for the operation (H())
 * @param sig An LM_OTS_SIG object that contains C and y
 * @param pub The public key parameters
 * @param I A 16 byte indentifier associated with a LMS tree
 * @param q The leaf index of the LMS tree.
 * @returns 1 on success, or 0 otherwise.
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

    /* The OpenSSL SHAKE implementation requires the xoflen to be set */
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
 * @brief OTS signature verification update phase
 * This may be called more than once.
 *
 * See RFC 8554 Section 4.3 Signature Verification
 * Algorithm 4b - Part 2
 *
 * Update the msg part of
 * Q = H(.... || msg)
 *
 * @param pctx A LM_OTS_CTX that contains the EVP_MD_CTX used for hashing
 * @msg A message to verify
 * @msglen The size of |msg|
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_lm_ots_ctx_pubkey_update(LM_OTS_CTX *pctx,
                                  const unsigned char *msg, size_t msglen)
{
    return EVP_DigestUpdate(pctx->mdctx, msg, msglen) > 0;
}

/*
 * @brief OTS signature verification final phase
 * See RFC 8554 Section 4.3 Signature Verification
 * Algorithm 4b - Part 3
 * Step 3 (Finalizes Q) and 4
 *
 * @param pctx A LM_OTS_CTX object.
 * @param Kc The computed public key. It is assumed the size is n.
 * @returns 1 on success, or 0 otherwise.
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
    tag[0] = 0;
    tag[1] = 0;

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
