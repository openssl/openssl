/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/hss.h>
#include "internal/common.h"
#include "crypto/hss.h"
#include "lms_local.h"

/**
 * @brief One shot function to generate a HSS signature
 * See RFC 8554 Algorithm 8: Generating a HSS signature
 *
 * @param hsskey An object containing HSS LMS OTS keypairs
 * @param msg The message to sign
 * @param msglen The size of the |msg|
 * @param outsig A buffer to write the signature to. It may be NULL.
 * @param outsiglen The returned size of the signature
 * @param outsigmaxlen The maximimum size of the |outsig| buffer.
 * @returns 1 if the signature was generated, or 0 otherwise.
 */
int ossl_hss_sign(HSS_KEY *hsskey, const unsigned char *msg, size_t msglen,
                  unsigned char *outsig, size_t *outsiglen, size_t outsigmaxlen)
{
    return ossl_hss_sign_init(hsskey)
        && ossl_hss_sign_update(hsskey, msg, msglen)
        && ossl_hss_sign_final(hsskey, outsig, outsiglen, outsigmaxlen);
}

/**
 * @brief The initial phase for the streaming variant of the ossl_hss_sign()
 */
int ossl_hss_sign_init(HSS_KEY *hsskey)
{
    int ret = 0;
    LMS_KEY *lmskey;
    LMS_SIG *lmssig;
    uint32_t L = hsskey->L;

    /*
     * If the top level tree is exhausted then we can no longer perform
     * signature generation operations since this is a N time OTS scheme.
     * So return an error.
     */
    if (hsskey->remaining == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OTS_KEYS_EXHAUSTED);
        return 0;
    }

    /*
     * Delay doing the signature generation here until ossl_hss_sign_final()
     * is called.
     */
    lmskey = LMS_KEY_get(hsskey, L - 1);
    lmssig = LMS_SIG_get(hsskey, L - 1);
    if (!ossl_lms_signature_gen_init(lmskey, lmssig))
        goto err;

    ret = 1;
err:
    return ret;
}

/**
 * @brief The update phase for the streaming variant of the ossl_hss_sign()
 * This may be called multiple times.
 */
int ossl_hss_sign_update(HSS_KEY *hsskey,
                         const unsigned char *msg, size_t msglen)
{
    LMS_KEY *lmskey = LMS_KEY_get(hsskey, hsskey->L - 1);

    return ossl_lms_signature_gen_update(lmskey, msg, msglen);
}

/**
 * @brief The final phase for the streaming variant of the ossl_hss_sign()
 */
int ossl_hss_sign_final(HSS_KEY *hsskey, unsigned char *outsig,
                        size_t *outsiglen, size_t outsigmaxlen)
{
    int ret = 0;
    uint32_t i, L = hsskey->L;
    LMS_KEY *lmskey = LMS_KEY_get(hsskey, L - 1);
    LMS_SIG *lmssig = LMS_SIG_get(hsskey, L - 1);
    WPACKET pkt;
    /*
     * The signature buffer size allows for
     * q[4] || ots_type[4] || C[n] || y[p][n] || lms_type[4] || path[h][n]
     * (where n <= LMS_MAX_DIGEST_SIZE, p <= 265 and h <= 25).
     */
    unsigned char sigbuf[3 * 4 + LMS_MAX_DIGEST_SIZE * (1 + 265 + 25)];
    unsigned char *sigdata = (outsig != NULL) ? sigbuf : NULL;
    size_t len;

    if (outsig == NULL) {
        if (!WPACKET_init_null(&pkt, outsigmaxlen))
            goto err;
    } else {
        if (!ossl_lms_signature_gen_final(lmskey, lmssig))
            goto err;
        if (!WPACKET_init_static_len(&pkt, outsig, outsigmaxlen, 0))
            goto err;
    }

    if (!WPACKET_put_bytes_u32(&pkt, L - 1))
        goto err;
    for (i = 0; i < L - 1; ++i) {
        /* Write out signed public keys */
        lmssig = LMS_SIG_get(hsskey, i);
        lmskey = LMS_KEY_get(hsskey, i + 1);
        len = sizeof(sigbuf);
        if (!ossl_lms_sig_xdr_encode(lmssig, sigdata, &len)
                || !WPACKET_memcpy(&pkt, sigdata, len)
                || !WPACKET_memcpy(&pkt, lmskey->pub.encoded,
                                   lmskey->pub.encodedlen))
            goto err;
    }
    /* Write out the signed message */
    len = sizeof(sigbuf);
    lmssig = LMS_SIG_get(hsskey, L - 1);
    if (!ossl_lms_sig_xdr_encode(lmssig, sigdata, &len)
            || !WPACKET_memcpy(&pkt, sigdata, len)
            || !WPACKET_get_total_written(&pkt, &len))
        goto err;

    /*
     * SP800-208 Section 8.1 has a requirement that OTS keys are not reused.
     * It does this by incrementing 'q' as the signatures are generated.
     * For hardware this index must be stored in non volatile storage before
     * exporting a signature value.
     *
     * Since this implementation only returns HSS signatures, we delay the
     * update of q for each LMS level to this function. If this process fails
     * the signature is not output. (Updating q early for non leaf trees made
     * the code very confusing). ossl_hss_key_advance() would be the function
     * where the q values would need to stored in non volatile storage.
     */
    /* If we fail to update 'q' then clear out the signature */
    if (outsig != NULL
            && !ossl_hss_key_advance(hsskey, 1))
        goto err;

    *outsiglen = len;
    ret = 1;
 err:
    WPACKET_finish(&pkt);
    if (ret != 1 && outsig != NULL)
        OPENSSL_cleanse(outsig, outsigmaxlen);
    return ret;
}

/*
 * @brief Move the HSS key |q| index forward by count, and update active trees.
 *
 * Only 1 active tree is maintained for each level in the hierarchy, so this
 * function must regenerate new active trees in any become exhausted.
 * We add count to the q of the leaf tree, and if that tree is exhausted then
 * we need to keep going upwards updating the parent active tree q value.
 * For any non leaf trees that have a new q value, a new signature needs to be
 * calculated. For new active trees a new signature is calculated by signing the
 * new encoded public key with the parent trees private key.
 *
 * Most of the time this code just updates the q of the leaf node, without
 * having to generate new active trees or signatures.
 */
int ossl_hss_key_advance(HSS_KEY *hsskey, uint64_t count)
{
    LMS_SIG *lmssig;
    uint32_t oldq[OSSL_HSS_MAX_L] = { 0 };
    uint32_t newq[OSSL_HSS_MAX_L] = { 0 };
    uint32_t d, L = hsskey->L;
    LMS_KEY *key = NULL, *parent = NULL;
    uint64_t index = 0;

    /*
     * As we use this to function to increment q by 1 at the end of a sign,
     * it just returns 1 if the tree is exhausted.
     * It should not get here during hss_reserve if ossl_hss_key_reserve()
     * is called first.
     */
    if (count > hsskey->remaining) {
        hsskey->remaining = 0;
        return 1;
    }
    /* Special case for a simple LMS tree (only only level) */
    if (L == 1) {
        key = LMS_KEY_get(hsskey, 0);
        if (key == NULL)
            return 0;
        key->q += (uint32_t)count;
        goto end;
    }
    index = hsskey->index + count;
    /* Calculate the new 'q' value for each level in the tree */
    for (d = L; d > 0; --d) {
        key = LMS_KEY_get(hsskey, d - 1);
        if (key == NULL)
            return 0;

        oldq[d - 1] = key->q;
        newq[d - 1] = index & ((1 << key->lms_params->h) - 1);
        index = index >> key->lms_params->h;
    }
    /* If the index is too large then do not advance */
    if (index > 0) {
        hsskey->index += count;
        hsskey->remaining -= count;
        /* sanity check that there are no remaining nodes */
        if (!ossl_assert(hsskey->remaining == 0))
            return 0;
        return 1;
    }

    /* sanity check that the root tree is exhausted */
    if (!ossl_assert(newq[0] < (uint32_t)(1 << key->lms_params->h)))
        return 0;
    /* sanity check that we never go backwards */
    if (!ossl_assert(newq[0] >= oldq[0]))
        return 0;

    parent = LMS_KEY_get(hsskey, 0);
    for (d = 1; d < L; ++d) {
        key = LMS_KEY_get(hsskey, d);
        /*
         * If the parent key has changed then we need to
         * create a new active child tree, and then sign the new child's
         * encoded public key with the parents private key.
         */
        if (oldq[d - 1] != newq[d - 1]) {
            parent->q = newq[d - 1];
            if (!ossl_lms_key_reset(key, parent->q, hsskey->gen_type, parent))
                return 0;
            key->q = newq[d];
            if (!ossl_lms_pubkey_compute(key))
                return 0;
            lmssig = LMS_SIG_get(hsskey, d - 1);
            if (!ossl_lms_signature_gen(parent,
                                        key->pub.encoded,
                                        key->pub.encodedlen, lmssig))
                return 0;
        } else {
            key->q = newq[d];
        }
        parent = key;
    }
end:
    hsskey->index += count;
    hsskey->remaining -= count;
    return 1;
}
