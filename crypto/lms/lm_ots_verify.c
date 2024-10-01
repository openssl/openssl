/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "crypto/lms_sig.h"
#include "crypto/lms_util.h"

static int lm_ots_compute_pubkey_final(EVP_MD_CTX *ctx, EVP_MD_CTX *ctxIq,
                                       const LM_OTS_SIG *sig, unsigned char *Kc);

/**
 * @brief OTS Signature verification.
 *
 * See RFC 8554 Section 4.6 Signature Verification
 * Algorithm 4b: Compute a Public Key Candidate |Kc| from a signature, message
 * and public key parameters.
 *
 * @param ctx A temporary working EVP_MD_CTX object.
 * @param ctxIq A EVP_MD_CTX object that has been initialized with a digest,
 *              that returns a non finalized value of H(I || q)
 * @param sig An LM_OTS_SIG object that contains C and y
 * @param pub The public key LM_OTS_PARAMS
 * @param Id A 16 byte indentifier (I) associated with a LMS tree
 * @param q The leaf index of the LMS tree.
 * @param msg A message to verify
 * @param msglen The size of |msg|
 * @param Kc The computed public key candidate. It is assumed the size is n.
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_lm_ots_compute_pubkey(EVP_MD_CTX *ctx, EVP_MD_CTX *ctxIq,
                               const LM_OTS_SIG *sig, const LM_OTS_PARAMS *pub,
                               const unsigned char *Id, uint32_t q,
                               const unsigned char *msg, size_t msglen,
                               unsigned char *Kc)
{
    int ret = 0;
    unsigned char qbuf[LMS_SIZE_q];

    if (sig->params != pub)
        return 0;

    U32STR(qbuf, q);

    if (!EVP_DigestUpdate(ctxIq, Id, LMS_SIZE_I)
            || !EVP_DigestUpdate(ctxIq, qbuf, sizeof(qbuf))
            || !EVP_MD_CTX_copy_ex(ctx, ctxIq)
            /* Q = H(I || u32str(q) || u16str(D_MESG) || C || msg) */
            || !EVP_DigestUpdate(ctx, &OSSL_LMS_D_MESG, sizeof(OSSL_LMS_D_MESG))
            || !EVP_DigestUpdate(ctx, sig->C, sig->params->n)
            || !EVP_DigestUpdate(ctx, msg, msglen)
            || !lm_ots_compute_pubkey_final(ctx, ctxIq, sig, Kc))
        goto err;
    ret = 1;
err:
    return ret;
}

/**
 * @brief simple function to increment a 16 bit counter by 1.
 * It assumes checking for overflow is not required.
 */
static ossl_inline void INC16(unsigned char *tag)
{
    if ((tag[1] = tag[1] + 1) == 0)
        *tag = *tag + 1;
}

/*
 * @brief OTS signature verification final phase
 * See RFC 8554 Section 4.3 Signature Verification
 * Algorithm 4b - Part 3
 * Step 3 (Finalizes Q) and 4
 *
 * @param ctx A EVP_MD_CTX object that contains a non finalized value of
 *            Q = H(I || u32str(q) || u16str(D_MESG) || C || msg)
 *            This ctx is reused for other calculations.
 * @param ctxIq A EVP_MD_CTX object that contains a non finalized value of H(I || q).
 * @param Kc The computed public key. It is assumed the size is n.
 * @returns 1 on success, or 0 otherwise.
 */
static int lm_ots_compute_pubkey_final(EVP_MD_CTX *ctx, EVP_MD_CTX *ctxIq,
                                       const LM_OTS_SIG *sig, unsigned char *Kc)
{
    int ret = 0, i;
    EVP_MD_CTX *ctxKc = NULL;
    unsigned char tag[2 + 1], *tag2 = &tag[2];
    unsigned char Q[LMS_MAX_DIGEST_SIZE + LMS_SIZE_QSUM], *Qsum;
    unsigned char z[LMS_MAX_DIGEST_SIZE];
    uint16_t sum;
    const LM_OTS_PARAMS *params = sig->params;
    int n = params->n;
    int p = params->p;
    uint8_t j, w = params->w, end = (1 << w) - 1;
    int a;
    unsigned char *y;

    if (!EVP_DigestFinal_ex(ctx, Q, NULL))
        goto err;

    ctxKc = EVP_MD_CTX_create();
    if (ctxKc == NULL)
        goto err;
    sum = ossl_lm_ots_params_checksum(params, Q);
    Qsum = Q + n;
    /* Q || Cksm(Q) */
    U16STR(Qsum, sum);

    if (!(EVP_MD_CTX_copy_ex(ctxKc, ctxIq))
            || !EVP_DigestUpdate(ctxKc, &OSSL_LMS_D_PBLC, sizeof(OSSL_LMS_D_PBLC)))
        goto err;

    y = sig->y;
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
