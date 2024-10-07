/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include "crypto/hss.h"
#include "crypto/lms_util.h"

/**
 * @brief Calculate the size of a HSS public key in XDR format.
 *
 * @param data A byte array of XDR data for a HSS public key.
 *             The first 8 bytes are looked at.
 * @param datalen The size of |data|.
 * @returns The calculated size, or 0 on error.
 */
size_t ossl_hss_pubkey_length(const unsigned char *data, size_t datalen)
{
    size_t len;

    if (datalen < (HSS_SIZE_L + LMS_SIZE_LMS_TYPE))
        return 0;
    len = ossl_lms_pubkey_length(data + HSS_SIZE_L, datalen - HSS_SIZE_L);
    return (len == 0 ? 0 : HSS_SIZE_L + len);
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
 * @param lms_only Set to 1 for a LMS key data, or 0 for HSS key data.
 * @returns 1 on success, or 0 on failure. A failure may occur if L, lms_type or
 * ots_type are invalid, OR if there are trailing bytes in |pub|.
 */
int ossl_hss_pubkey_decode(const unsigned char *pub, size_t publen,
                           HSS_KEY *hsskey, int lms_only)
{
    PACKET pkt;
    LMS_KEY *lmskey;

    if (!PACKET_buf_init(&pkt, pub, publen))
        return 0;
    if (!lms_only) {
        if (!PACKET_get_4_len(&pkt, &hsskey->L)
                || hsskey->L < HSS_MIN_L
                || hsskey->L > HSS_MAX_L)
            return 0;
    }
    lmskey = ossl_lms_key_new(hsskey->libctx);
    if (lmskey == NULL)
        return 0;
    if (!ossl_lms_pubkey_decode(pkt.curr, pkt.remaining, lmskey))
        goto err;

    if (!ossl_hss_key_set_public(hsskey, lmskey))
        goto err;
    return 1;
 err:
    ossl_lms_key_free(lmskey);
    return 0;
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
