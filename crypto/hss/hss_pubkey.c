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
 * @brief Calculate the size of a public key in XDR format.
 *
 * @param data A byte array of XDR data for a HSS public key.
 *             The first 8 bytes are looked at.
 * @param datalen The size of |data|.
 * @returns The calculated size, or 0 on error.
 */
size_t ossl_hss_pubkey_length(const unsigned char *data, size_t datalen)
{
    PACKET pkt;
    uint32_t L, lms_type;
    const LMS_PARAMS *params;

    if (!PACKET_buf_init(&pkt, data, datalen)
            || !PACKET_get_4_len(&pkt, &L)
            || !PACKET_get_4_len(&pkt, &lms_type)
            || (params = ossl_lms_params_get(lms_type)) == NULL)
        return 0;
    return HSS_SIZE_PUB_L + LMS_SIZE_PUB_LMS_TYPE + LMS_SIZE_PUB_OTS_TYPE
        + LMS_SIZE_I + params->n;
}

/**
 * @brief Decode a byte array of public key data in XDR format into a HSS_KEY
 * The XDR format is L[4] || lms_type[4] || ots_type[4] || I[16] || K[n].
 * This function will fail if the |hsskey| contains OTS private keys, unless
 * the decoded key matches the existing public root key. It will replace the
 * key if it previously contained just a public key.
 *
 * @param pub A byte array of public key data in XDR format.
 * @param publen The size of |pub|.
 * @param hsskey The HSS_KEY object to store the public key into.
 * @param lms_only Set to 1 for a LMS key, or 0 for a HSS key.
 * @returns 1 on success, or 0 on failure. A failure may occur if L, lms_type or
 * ots_type are invalid, OR if there are trailing bytes in |pub|.
 */
int ossl_hss_pubkey_decode(const unsigned char *pub, size_t publen,
                           HSS_KEY *hsskey, int lms_only)
{
    PACKET pkt;
    LMS_KEY *lmskey, *curkey;

    if (!PACKET_buf_init(&pkt, pub, publen))
        return 0;
    if (!lms_only) {
        if (!PACKET_get_4_len(&pkt, &hsskey->L)
                || hsskey->L < OSSL_HSS_MIN_L
                || hsskey->L > OSSL_HSS_MAX_L)
            return 0;
    }
    lmskey = ossl_lms_key_new();
    if (lmskey == NULL)
        return 0;
    if (!ossl_lms_pubkey_decode(pkt.curr, pkt.remaining, lmskey))
        goto err;

    /* Check if there is an existing key */
    curkey = LMS_KEY_get(hsskey, 0);
    if (curkey != NULL) {
        if (curkey->pub.encoded != NULL) {
            if (curkey->pub.encodedlen == lmskey->pub.encodedlen
                    && memcmp(curkey->pub.encoded, lmskey->pub.encoded,
                              lmskey->pub.encodedlen) == 0) {
                /* If the key matches then there is no need to copy it */
                ossl_lms_key_free(lmskey);
                return 1;
            }
        }
        /* Do not allow the user to trash existing OTS private keys */
        if (curkey->priv.data != NULL)
            return 0;
        /* Clear the lists if the public key is different */
        if (!ossl_hss_lists_init(&hsskey->lists))
            goto err;
    }
    if (!LMS_KEY_add(hsskey, lmskey))
        goto err;
    return 1;
 err:
    ossl_lms_key_free(lmskey);
    return 0;
}

/**
 * @brief Encode the root public key in a HSS_KEY into a byte array in XDR format.
 * The XDR format is L[4] || lms_type[4] || ots_type[4] || I[16] || K[n].
 *
 * @param hsskey The HSS_KEY object containing public key info.
 * @param pub The output buffer. May be NULL.
 * @param publen The size of |pub|.
 * @returns 1 if the public key successfully encodes, or 0 on failure.
 */
int ossl_hss_pubkey_encode(HSS_KEY *hsskey, unsigned char *pub, size_t *publen)
{
    WPACKET pkt;
    LMS_KEY *lmskey;
    int ret;

    if (hsskey == NULL
            || ((lmskey = LMS_KEY_get(hsskey, 0)) == NULL))
        return 0;

    if (pub == NULL) {
        if (publen == NULL)
            return 0;
        *publen = LMS_SIZE_L + ossl_lms_pubkey_encode_len(lmskey);
        return 1;
    }
    ret = WPACKET_init_static_len(&pkt, pub, *publen, 0)
            && WPACKET_put_bytes_u32(&pkt, hsskey->L)
            && ossl_lms_pubkey_to_pkt(&pkt, lmskey);
    WPACKET_finish(&pkt);
    WPACKET_close(&pkt);
    return ret;
}

/**
 * @brief Load a public key from OSSL_PARAM data.
 *
 * @param params An array of OSSL_PARAM
 * @param hsskey The HSS_KEY to load the public key data into.
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_hss_pubkey_from_params(const OSSL_PARAM params[], HSS_KEY *hsskey)
{
    const OSSL_PARAM *p = NULL, *pl = NULL;
    uint32_t L = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    pl = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_HSS_L);
    if (p != NULL) {
        if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (pl != NULL) {
            if (!OSSL_PARAM_get_uint32(pl, &L))
                return 0;
            if (hsskey->L > 0 && L != hsskey->L)
                return 0;
            hsskey->L = L;
        }
        if (!ossl_hss_pubkey_decode(p->data, p->data_size, hsskey, pl != NULL))
            return 0;
    }
    return 1;
}
