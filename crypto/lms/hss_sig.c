/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "internal/common.h"
#include "crypto/hss_sig.h"
#include "crypto/lms_util.h"

HSS_SIG *ossl_hss_sig_new(void)
{
    HSS_SIG *ret = NULL;

    ret = OPENSSL_zalloc(sizeof(HSS_SIG));
    if (ret != NULL) {
        ret->lmskeys = sk_LMS_KEY_new_null();
        ret->lmssigs = sk_LMS_SIG_new_null();
        if (ret->lmskeys == NULL || ret->lmssigs == NULL) {
            sk_LMS_SIG_free(ret->lmssigs);
            sk_LMS_KEY_free(ret->lmskeys);
            OPENSSL_free(ret);
            ret = NULL;
        }
    }
    return ret;
}

/*
 * @brief Destroys the list of LMS signatures, and LMS keys.
 */
void ossl_hss_sig_free(HSS_SIG *hss_sig)
{
    if (hss_sig == NULL)
        return;
    sk_LMS_SIG_pop_free(hss_sig->lmssigs, ossl_lms_sig_free);
    sk_LMS_KEY_pop_free(hss_sig->lmskeys, ossl_lms_key_free);
    OPENSSL_free(hss_sig);
}

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
 * @param libctx Used for fetching algorithms.
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
 * @param pub A HSS_LMS_KEY containing a root public LMS key
 * @param L The number of levels in the HSS tree.
 * @param sig A input byte array of signature data.
 * @param siglen The size of sig.
 * @returns 1 if the signature is successfully decoded and added,
 *          otherwise it returns 0.
 */
int ossl_hss_sig_decode(HSS_SIG *sigs, HSS_LMS_KEY *hsskey, uint32_t L,
    const unsigned char *sig, size_t siglen)
{
    int ret = 0;
    uint32_t Nspk = 0, i;
    const LMS_KEY *key;
    PACKET pkt;

    if (L < HSS_MIN_L || L > HSS_MAX_L)
        return 0;
    if (hsskey == NULL)
        return 0;
    key = ossl_hss_lms_key_get_public(hsskey);
    if (key == NULL)
        return 0;
    /*
     * Decode the number of signed public keys
     * and check that it is one less than the number of HSS levels (L)
     */
    if (!PACKET_buf_init(&pkt, sig, siglen))
        return 0;

    /* If this is a simple LMS signature it does not have a Nspk field */
    if (L != HSS_MIN_L || siglen != ossl_lms_key_get_sig_len(key)) {
        if (!PACKET_get_net_4_len_u32(&pkt, &Nspk)
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

/*
 * @brief HSS signature validation.
 * Note that this also works for LMS.
 *
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_hss_sig_verify(const HSS_SIG *hss_sig,
    const HSS_LMS_KEY *hsskey, const EVP_MD *md,
    const unsigned char *msg, size_t msglen)
{
    int ret = 0;
    const LMS_KEY *next;
    const LMS_KEY *pub = ossl_hss_lms_key_get_public(hsskey);
    int i, nspk = ossl_hss_sig_get_lmssigcount(hss_sig) - 1;

    /* Verify the signed public keys, nspk is 0 for LMS */
    for (i = 0; i < nspk; ++i) {
        next = ossl_hss_sig_get_lmskey(hss_sig, i);
        if (next == NULL)
            goto err;
        if (ossl_lms_sig_verify(ossl_hss_sig_get_lmssig(hss_sig, i), pub, md,
                next->pub.encoded, next->pub.encodedlen)
            != 1)
            goto err;
        pub = next;
    }
    /* Verify the message using the public key of the leaf tree */
    if (ossl_lms_sig_verify(ossl_hss_sig_get_lmssig(hss_sig, i), pub, md,
            msg, msglen)
        != 1)
        goto err;
    ret = 1;
err:
    return ret;
}
