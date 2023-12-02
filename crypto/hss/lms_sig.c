/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/hss.h"
#include "lms_local.h"

int ossl_lms_sig_encode(LMS_SIG *sig, unsigned char *out, size_t *outlen)
{
    int ret;
    WPACKET pkt;
    const LM_OTS_PARAMS *prms = sig->sig.params;
    const LMS_PARAMS *lprms = sig->params;

    if (out != NULL) {
        if (!WPACKET_init_static_len(&pkt, out, *outlen, 0))
            return 0;
    } else {
        if (!WPACKET_init_null(&pkt, *outlen))
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
    return ret;
}

LMS_SIG *ossl_lms_sig_new(void)
{
    return OPENSSL_zalloc(sizeof(LMS_SIG));
}

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
    if (src->sig.y != NULL) {
        dst->sig.y = OPENSSL_memdup(src->sig.y, lprms->n * prms->p);
        if (dst->sig.y == NULL)
            goto err;
    }
    if (src->paths != NULL) {
        dst->paths = OPENSSL_memdup(src->paths, lprms->n * lprms->h);
        if (dst->paths == NULL)
            goto err;
    }
    return dst;
err:
    OPENSSL_free(dst->sig.C);
    OPENSSL_free(dst->sig.y);
    OPENSSL_free(dst->paths);
    ossl_lms_sig_free(dst);
    return NULL;
}


/*
 * Create an LMS_SIG object from a HSS signature byte array in |pkt|.
 * An error is returned if the passed in LMS public key |pub| is not compatible
 * with the decoded LMS_SIG object,
 *
 * This function may be called multiple times when parsing a HSS signature.
 * See RFC 8554 Algorithm 6a: Steps 1 and 2
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


void ossl_lms_sig_free(LMS_SIG *sig)
{
    OPENSSL_free(sig);
}

