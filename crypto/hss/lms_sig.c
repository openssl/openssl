/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/hss.h"
#include "lms_local.h"

/**
 * @brief Create a new LMS_SIG object
 */
LMS_SIG *ossl_lms_sig_new(void)
{
    return OPENSSL_zalloc(sizeof(LMS_SIG));
}

/**
 * @brief Destroy an existing LMS_SIG object
 */
void ossl_lms_sig_free(LMS_SIG *sig)
{
    /*
     * Only free C, y and path if they were allocated.
     * In some cases they are just pointer to existing data.
     */
    if (sig->paths_allocated)
        OPENSSL_free(sig->paths);
    if (sig->sig.allocated) {
        OPENSSL_free(sig->sig.C);
        /* Check if the sig.y was allocated as part of sig.C */
        if (sig->sig.y != sig->sig.C + sig->params->n)
            OPENSSL_free(sig->sig.y);
    }
    OPENSSL_free(sig);
}

/**
 * @brief Decode a byte array containing XDR signature data into a LMS_SIG object.
 *
 * This is used for LMS Signature Verification.
 * This function may be called multiple times when decoding a HSS signature.
 * See RFC 8554 Algorithm 6a: Steps 1 and 2.
 * It uses shallow copies for C, y and path.
 *
 * @param pkt Contains the signature data to decode. There may still be data
 *            remaining in pkt after decoding.
 * @param pub A  public key that contains LMS_PARAMS and LM_OTS_PARAMS associated
 *            with the signature.
 * @returns The created LMS_SIG object is successful, or NULL on failure. A
 *          failure may occur if the passed in LMS public key |pub| is not
 *          compatible with the decoded LMS_SIG object,
 */
LMS_SIG *ossl_lms_sig_from_pkt(PACKET *pkt, const LMS_KEY *pub)
{
    uint32_t sig_ots_type = 0, sig_lms_type = 0;
    const LMS_PARAMS *lparams = pub->lms_params;
    const LM_OTS_PARAMS *pub_ots_params = pub->ots_params;
    const LM_OTS_PARAMS *sig_params;
    LMS_SIG *lsig = NULL;

    lsig = OPENSSL_zalloc(sizeof(*lsig));
    if (lsig == NULL)
        return NULL;

    if (!PACKET_get_4_len(pkt, &lsig->q)    /* q = Leaf Index */
            || !PACKET_get_4_len(pkt, &sig_ots_type)
            || pub_ots_params->lm_ots_type != sig_ots_type)
        goto err;
    sig_params = pub_ots_params;
    lsig->sig.params = sig_params;
    lsig->params = lparams;

    if (!PACKET_get_bytes_shallow(pkt, &lsig->sig.C, sig_params->n)
            || !PACKET_get_bytes_shallow(pkt, &lsig->sig.y,
                                         sig_params->p * sig_params->n)
            || !PACKET_get_4_len(pkt, &sig_lms_type)
            || (lparams->lms_type != sig_lms_type)
            || HASH_NOT_MATCHED(lparams, sig_params)
            || lsig->q >= (uint32_t)(1 << lparams->h)
            || !PACKET_get_bytes_shallow(pkt, &lsig->paths,
                                         lparams->h * lparams->n))
        goto err;
    return lsig;
err:
    ossl_lms_sig_free(lsig);
    return NULL;
}

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)

/**
 * @brief Encode a LMS_SIG object to a XDR representation.
 * This consists of writing the concatenated values of
 * q[4] || ots_type[4] || C[n] || y[p][n] || lms_type[4] || path[h][n]
 * See RFC 8554 Section 5.4. "LMS Signature"
 *
 * @params sig The LMS_SIG object to encode.
 * @params out The output buffer to write to. It may be NULL.
 * @params outlen The max size of the buffer on input, and returns the number
 *                of bytes written.
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_lms_sig_xdr_encode(LMS_SIG *sig, unsigned char *out, size_t *outlen)
{
    int ret;
    WPACKET pkt;
    const LM_OTS_PARAMS *prms = sig->sig.params;
    const LMS_PARAMS *lprms = sig->params;
    size_t out_maxlen = *outlen;

    if (out != NULL) {
        /* Just calculate the size */
        if (!WPACKET_init_static_len(&pkt, out, out_maxlen, 0))
            return 0;
    } else {
        if (!WPACKET_init_null(&pkt, out_maxlen))
            return 0;
    }
    ret = WPACKET_put_bytes_u32(&pkt, sig->q)
        && WPACKET_put_bytes_u32(&pkt, prms->lm_ots_type)
        && WPACKET_memcpy(&pkt, sig->sig.C, prms->n)
        && WPACKET_memcpy(&pkt, sig->sig.y, prms->n * prms->p)
        && WPACKET_put_bytes_u32(&pkt, lprms->lms_type)
        && WPACKET_memcpy(&pkt, sig->paths, lprms->h * lprms->n)
        && WPACKET_get_total_written(&pkt, outlen);
    WPACKET_finish(&pkt);
    if (out != NULL && ret != 1)
        OPENSSL_cleanse(out, out_maxlen);
    return ret;
}

/**
 * @brief Create a copy of an existing LMS_SIG object.
 * This does a deep copy of the elements.
 * This function is required if we split a HSS_KEY used for signing into 2
 * parts using ossl_hss_key_reserve() and ossl_hss_key_advance().
 * Special care must be taken by the caller to ensure that the OTS keys are not
 * used more than once.
 *
 * @param src The LMS_SIG object to copy.
 * @returns The duplicate LMS_SIG object on success or NULL if the copy failed.
 */
LMS_SIG *ossl_lms_sig_deep_copy(const LMS_SIG *src)
{
    LMS_SIG *dst;
    const LM_OTS_PARAMS *prms;
    const LMS_PARAMS *lprms;

    if (src == NULL)
        return NULL;
    dst = ossl_lms_sig_new();
    if (dst == NULL)
        return NULL;

    prms = src->sig.params;
    lprms = src->params;

    dst->q = src->q;
    dst->params = lprms;
    dst->sig.params = prms;
    if (src->sig.C != NULL) {
        dst->sig.C = OPENSSL_memdup(src->sig.C, lprms->n);
        if (dst->sig.C == NULL)
            goto err;
    }
    dst->sig.allocated = 1;
    if (src->sig.y != NULL) {
        dst->sig.y = OPENSSL_memdup(src->sig.y, lprms->n * prms->p);
        if (dst->sig.y == NULL)
            goto err;
    }
    if (src->paths != NULL) {
        dst->paths = OPENSSL_memdup(src->paths, lprms->n * lprms->h);
        if (dst->paths == NULL)
            goto err;
        dst->paths_allocated = 1;
    }
    return dst;
err:
    ossl_lms_sig_free(dst);
    return NULL;
}
#endif /*  OPENSSL_NO_HSS_GEN */
