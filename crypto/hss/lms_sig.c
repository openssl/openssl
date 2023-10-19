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
#include <openssl/proverr.h>
#include "crypto/hss.h"
#include "internal/refcount.h"
#include "lms_local.h"

LMS_SIG *ossl_lms_sig_new(void)
{
    LMS_SIG *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    if (!CRYPTO_NEW_REF(&ret->references, 1)) {
        OPENSSL_free(ret);
        ret = NULL;
    }
    return ret;
}

void ossl_lms_sig_free(LMS_SIG *sig)
{
    int i;

    if (sig == NULL)
        return;

    CRYPTO_DOWN_REF(&sig->references, &i);
    REF_PRINT_COUNT("LMS_SIG", sig);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    CRYPTO_FREE_REF(&sig->references);
    OPENSSL_free(sig);
}

int ossl_lms_sig_up_ref(LMS_SIG *sig)
{
    int i;

    if (CRYPTO_UP_REF(&sig->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("LMS_SIG", sig);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
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

    lsig = ossl_lms_sig_new();
    if (lsig == NULL)
        return NULL;

    if (!PACKET_get_4_len(pkt, &lsig->q)    /* q = Leaf Index */
            || !PACKET_get_4_len(pkt, &sig_ots_type)
            || pub_ots_params->lm_ots_type != sig_ots_type)
        goto err;
    sig_params = pub_ots_params;
    lsig->sig.params = sig_params;

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
