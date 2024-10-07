/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/hss.h"
#include "crypto/hss_sig.h"
#include "crypto/lms_util.h"

/**
 * @brief Decode a byte array of signature data and add it to list.
 * A new LMS_SIG object is created to store the signature data into.
 *
 * @param pkt Contains the signature data to decode. There may still be data
 *            remaining in pkt after decoding.
 * @param key A public key that contains LMS_PARAMS and LM_OTS_PARAMS associated
 *            with the signature.
 * @param siglist A list to add the decoded signature to.
 * @returns 1 if the LMS_SIG object is successfully added to the list,
 *          or 0 on failure.
 */
static int add_decoded_sig(PACKET *pkt, const LMS_KEY *key,
                           STACK_OF(LMS_SIG) *siglist)
{
    LMS_SIG *s;

    s = ossl_lms_sig_from_pkt(pkt, key);
    if (s == NULL)
        return 0;

    if (sk_LMS_SIG_push(siglist, s) <= 0) {
        ossl_lms_sig_free(s);
        return 0;
    }
    return 1;
}

/**
 * @brief Decode a byte array of public key data and add it to list.
 * A new LMS_KEY object is created to store the public key into.
 *
 * @param pkt Contains the public key data to decode. There may still be data
 *            remaining in pkt after decoding.
 * @param keylist A list to add the decoded public key to.
 * @returns 1 if the LMS_KEY object is successfully added to the list,
 *          or 0 on failure.
 */
static LMS_KEY *add_decoded_pubkey(PACKET *pkt, STACK_OF(LMS_KEY) *keylist,
                                   OSSL_LIB_CTX *libctx)
{
    LMS_KEY *key;

    key = ossl_lms_key_new(libctx);
    if (key == NULL)
        return NULL;

    if (!ossl_lms_pubkey_from_pkt(pkt, key)
            || (sk_LMS_KEY_push(keylist, key) <= 0)) {
        ossl_lms_key_free(key);
        key = NULL;
    }
    return key;
}

/**
 * @brief Decode a byte array of HSS signature data.
 * The signature is decoded into lists of LMS_KEY and LMS_SIG objects.
 *
 * This function does not duplicate any of the byte data contained within
 * |sig|, so it is expected that sig will exist for the duration of the |ctx|.
 *
 * @param ctx Used to store lists of LMS_KEY and LMS_SIG objects.
 * @param pub A HSS_KEY containing a root public LMS key
 * @param L The number of levels in the HSS tree.
 * @param sig A input byte array of signature data.
 * @param siglen The size of sig.
 * @returns 1 if the signature is successfully decoded and added,
 *          otherwise it returns 0.
 */
int ossl_hss_sig_decode(HSS_SIG *sigs, HSS_KEY *hsskey, uint32_t L,
                        const unsigned char *sig, size_t siglen)
{
    int ret = 0;
    uint32_t Nspk, i;
    LMS_KEY *key;
    PACKET pkt;

    if (L < HSS_MIN_L || L > HSS_MAX_L)
        return 0;
    if (hsskey == NULL)
        return 0;
    key = ossl_hss_key_get_public(hsskey);
    if (key == NULL)
        return 0;
    /*
     * Decode the number of signed public keys
     * and check that it is one less than the number of HSS levels (L)
     */
    if (!PACKET_buf_init(&pkt, sig, siglen)
            || !PACKET_get_4_len(&pkt, &Nspk)
            || Nspk != (L - 1))
        return 0;

    /*
     * Decode the LMS signature and public key for each subsequent level.
     *
     * The signature uses the parents private key to sign the encoded
     * public key of the next level).
     */
    for (i = 0; i < Nspk; ++i) {
        /* Decode signature for the public key */
        if (!add_decoded_sig(&pkt, key, sigs->lmssigs))
            goto err;
        /* Decode the public key */
        key = add_decoded_pubkey(&pkt, sigs->lmskeys, key->libctx);
        if (key == NULL)
            goto err;
    }
    /*
     * Decode the final signature
     * (This signature uses the private key of the leaf tree to sign
     * an actual message).
     */
    if (!add_decoded_sig(&pkt, key, sigs->lmssigs))
        goto err;
    /* Fail if there are trailing bytes */
    if (PACKET_remaining(&pkt) > 0)
        goto err;
    ret = 1;
err:
    return ret;
}
