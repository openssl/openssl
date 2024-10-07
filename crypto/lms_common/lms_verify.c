/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/lms_sig.h"
#include "crypto/lms_util.h"
#include "internal/common.h"

const uint16_t OSSL_LMS_D_PBLC          = 0x8080;
const uint16_t OSSL_LMS_D_MESG          = 0x8181;
const uint16_t OSSL_LMS_D_LEAF          = 0x8282;
const uint16_t OSSL_LMS_D_INTR          = 0x8383;

static
int lms_sig_compute_tc_from_path(const unsigned char *paths, uint32_t n,
                                 uint32_t node_num,
                                 EVP_MD_CTX *ctx, EVP_MD_CTX *ctxI,
                                 unsigned char *Tc)
{
    int ret = 0;
    unsigned char qbuf[4];
    const unsigned char *path = paths;

    /* Calculate the public key Tc using the path */
    while (node_num > 1) {
        int odd = node_num & 1;

        node_num = node_num >> 1;
        U32STR(qbuf, node_num);

        if (!EVP_MD_CTX_copy_ex(ctx, ctxI)
                || !EVP_DigestUpdate(ctx, qbuf, sizeof(qbuf))
                || !EVP_DigestUpdate(ctx,
                                     &OSSL_LMS_D_INTR, sizeof(OSSL_LMS_D_INTR)))
            goto err;

        if (odd) {
            if (!EVP_DigestUpdate(ctx, path, n)
                || !EVP_DigestUpdate(ctx, Tc, n))
                goto err;
        } else {
            if (!EVP_DigestUpdate(ctx, Tc, n)
                || !EVP_DigestUpdate(ctx, path, n))
                goto err;
        }
        if (!EVP_DigestFinal_ex(ctx, Tc, NULL))
            goto err;
        path += n;
    }
    ret = 1;
err:
    return ret;
}

/*
 * @brief LMS signature validation.
 * The passed in |ctx->sig| and |ctx->pub| need to exist until
 * ossl_lms_sig_verify_final() is called, since the final may be delayed until
 * some later time,
 *
 * @param ctx A LMS_VALIDATE_CTX object used to store the input and outputs of
 *            a streaming LMS verification operation
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_lms_sig_verify(const LMS_SIG *lms_sig, const LMS_KEY *pub,
                        const EVP_MD *md,
                        const unsigned char *msg, size_t msglen)
{
    int ret = 0;
    EVP_MD_CTX *ctx = NULL, *ctxIq = NULL;
    EVP_MD_CTX *ctxI;
    unsigned char Kc[LMS_MAX_DIGEST_SIZE];
    unsigned char Tc[LMS_MAX_DIGEST_SIZE];
    unsigned char qbuf[4];
    const LMS_PARAMS *lms_params = pub->lms_params;
    uint32_t n = lms_params->n;
    uint32_t node_num;

    ctx = EVP_MD_CTX_create();
    ctxIq = EVP_MD_CTX_create();
    if (ctx == NULL || ctxIq == NULL)
        goto err;

    if (!evp_md_ctx_init(ctxIq, md, lms_sig->params))
        goto err;
    if (!ossl_lm_ots_compute_pubkey(ctx, ctxIq, &lms_sig->sig,
                                    pub->ots_params, pub->Id,
                                    lms_sig->q, msg, msglen, Kc))
        goto err;

    /* Compute the candidate LMS root value Tc */
    if (!ossl_assert(lms_sig->q < (uint32_t)(1 << lms_params->h)))
        return 0;
    node_num = (1 << lms_params->h) + lms_sig->q;

    U32STR(qbuf, node_num);
    ctxI = ctxIq;
    if (!EVP_DigestInit_ex2(ctx, NULL, NULL)
            || !EVP_DigestUpdate(ctx, pub->Id, LMS_SIZE_I)
            || !EVP_MD_CTX_copy_ex(ctxI, ctx)
            || !EVP_DigestUpdate(ctx, qbuf, sizeof(qbuf))
            || !EVP_DigestUpdate(ctx, &OSSL_LMS_D_LEAF, sizeof(OSSL_LMS_D_LEAF))
            || !EVP_DigestUpdate(ctx, Kc, n)
            || !EVP_DigestFinal_ex(ctx, Tc, NULL)
            || !lms_sig_compute_tc_from_path(lms_sig->paths, n, node_num,
                                             ctx, ctxI, Tc))
        goto err;
    ret = (memcmp(pub->pub.K, Tc, n) == 0);
err:
    EVP_MD_CTX_free(ctxIq);
    EVP_MD_CTX_free(ctx);
    return ret;
}
