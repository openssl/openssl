/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include "crypto/lms.h"
#include "crypto/lms_util.h"
#include "internal/nelem.h"

/*
 * Contains the length of XDR format public keys with and without
 * the 4 byte HSS header. A HSS public key includes the header,
 * and a LMS key can optionally include the header if it is set to
 * 00 00 00 01.
 */
static const HSS_LMS_INFO hss_lms_info[] = {
    { 60, 1, 32 },
    { 56, 0, 32 },
    { 52, 1, 24 },
    { 48, 0, 24 },
};

const HSS_LMS_INFO *ossl_hss_lms_getinfo(size_t len)
{
    int i;

    for (i = 0; i < (int)OSSL_NELEM(hss_lms_info); ++i) {
        if (len == (size_t)hss_lms_info[i].len)
            return hss_lms_info + i;
    }
    return NULL;
}

static int lms_pubkey_from_pkt(PACKET *pkt, LMS_KEY *lmskey)
{
    uint32_t lms_type;
    uint32_t ots_type;
    HSS_LMS_PUB_KEY *key = &lmskey->pub;

    if (!PACKET_get_net_4_len_u32(pkt, &lms_type))
        goto err;
    lmskey->lms_params = ossl_lms_params_get(lms_type);
    if (lmskey->lms_params == NULL
        || !PACKET_get_net_4_len_u32(pkt, &ots_type))
        goto err;
    lmskey->ots_params = ossl_lm_ots_params_get(ots_type);
    if (lmskey->ots_params == NULL)
        goto err;

    /* The digest used must be the same */
    if (HASH_NOT_MATCHED(lmskey->ots_params, lmskey->lms_params)
        || !PACKET_get_bytes(pkt, (const unsigned char **)&lmskey->Id,
            LMS_SIZE_I)
        || !PACKET_get_bytes(pkt, (const unsigned char **)&key->K,
            lmskey->lms_params->n))
        goto err;
    key->encodedlen = (unsigned char *)PACKET_data(pkt) - key->encoded;
    return 1;
err:
    return 0;
}

static int hss_pubkey_from_pkt(PACKET *pkt, HSS_LMS_KEY *hsskey)
{
    HSS_LMS_PUB_KEY *pkey = &hsskey->public.pub;

    pkey->encoded = (unsigned char *)PACKET_data(pkt);
    if (!PACKET_get_net_4_len_u32(pkt, &hsskey->L)
        || hsskey->L == 0 || hsskey->L > HSS_MAX_L) {
        return 0;
    }
    return lms_pubkey_from_pkt(pkt, &hsskey->public);
}

int ossl_lms_pubkey_from_pkt(PACKET *pkt, LMS_KEY *lmskey)
{
    lmskey->pub.encoded = (unsigned char *)PACKET_data(pkt);
    return lms_pubkey_from_pkt(pkt, lmskey);
}

/*
 * @brief Decode HSS/LMS public key data in XDR format into a HSS_LMS_KEY object.
 * Used by the HSS/LMS public key decoder.
 * The XDR format is {L[4]} || lms_type[4] || ots_type[4] || I[16] || K[n]
 * The public key keeps an 'encoded' buffer, which I and K just point to.
 *
 * @param info If this is NULL then it checks |publen| is the correct size,
 *    otherwise it uses the associated 'hss' field to determine if the encoding
 *    contains the optional L value.
 * @param pub byte array of public key data in XDR format.
 * @param publen is the size of |pub|.
 * @param hsskey The HSS_LMS_KEY object to store the public key into.
 * @returns 1 on success, or 0 otherwise. 0 is returned if either |pub| is
 * invalid or |publen| is not the correct size (i.e. trailing data is not allowed)
 */
int ossl_hss_lms_pubkey_decode(const HSS_LMS_INFO *info,
    const unsigned char *pub, size_t publen, HSS_LMS_KEY *hsskey)
{
    HSS_LMS_PUB_KEY *pkey = &hsskey->public.pub;
    PACKET pkt;

    if (info == NULL) {
        /* Check if the public key is the correct size */
        info = ossl_hss_lms_getinfo(publen);
        if (info == NULL)
            return 0;
    }
    if (pkey->encoded != NULL && pkey->encodedlen != publen) {
        OPENSSL_free(pkey->encoded);
        pkey->encoded = NULL;
        pkey->encodedlen = 0;
    }
    if (pkey->encoded == NULL) {
        pkey->encoded = OPENSSL_memdup(pub, publen);
        if (pkey->encoded == NULL)
            return 0;
        pkey->allocated = 1; /* Flag that 'encoded' needs to be freed */
    }
    if (!PACKET_buf_init(&pkt, pkey->encoded, publen))
        goto err;
    if (info->hss) {
        if (!hss_pubkey_from_pkt(&pkt, hsskey))
            goto err;
    } else {
        if (!lms_pubkey_from_pkt(&pkt, &hsskey->public))
            goto err;
    }
    pkey->encodedlen = publen;
    return 1;
err:
    OPENSSL_free(pkey->encoded);
    pkey->encoded = NULL;
    pkey->allocated = 0;
    return 0;
}

/**
 * @brief Load a HSS/LMS public key from OSSL_PARAM data.
 *
 * @param pub a encoded XDR public key with or without a 4 byte header for l
 * @param l An optional number of levels for a HSS key
 * @param hss The HSS_LMS_KEY to load the public key data into.
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_hss_lms_pubkey_from_params(const OSSL_PARAM *pub, const OSSL_PARAM *l,
    HSS_LMS_KEY *hss)
{
    if (pub != NULL) {
        if (pub->data == NULL
            || pub->data_type != OSSL_PARAM_OCTET_STRING
            || !ossl_hss_lms_pubkey_decode(NULL, pub->data, pub->data_size, hss))
            return 0;
        if (l != NULL) {
            uint32_t L = 1;

            if (!OSSL_PARAM_get_uint32(l, &L) || L != hss->L)
                return 0;
        }
    }
    return 1;
}
