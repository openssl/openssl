/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
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
#include "crypto/hss.h"
#include "lms_local.h"

#define HSS_MIN_L 1
#define HSS_MAX_L 8

HSS_KEY *ossl_hss_key_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    HSS_KEY *key = OPENSSL_zalloc(sizeof(*key));

    if (key == NULL)
        return NULL;
    if (!CRYPTO_NEW_REF(&key->lms_pub.references, 1)) {
        OPENSSL_free(key);
        return NULL;
    }
    return key;
}

int ossl_hss_key_up_ref(HSS_KEY *key)
{
    return ossl_lms_key_up_ref(&key->lms_pub);
}

void ossl_hss_key_free(HSS_KEY *key)
{
    ossl_lms_key_free(&key->lms_pub);
}

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
    return 4 + 4 + 4 + LMS_ISIZE + params->n;
}

int ossl_hss_pubkey_from_data(const unsigned char *pub, size_t publen,
                              HSS_KEY *key)
{
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, pub, publen)
            || !PACKET_get_4_len(&pkt, &key->L)
            || key->L < HSS_MIN_L
            || key->L > HSS_MAX_L)
        return 0;

    return ossl_lms_pubkey_from_data(pkt.curr, pkt.remaining, &key->lms_pub);
}

int ossl_hss_pubkey_from_params(const OSSL_PARAM params[], HSS_KEY *key)
{
    const OSSL_PARAM *p = NULL, *pl = NULL;
    int ok = 0;

    pl = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_HSS_L);
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            goto err;
        if (pl != NULL) {
            if (!OSSL_PARAM_get_uint32(pl, &key->L)
                    || !ossl_lms_pubkey_from_data(p->data, p->data_size,
                                                  &key->lms_pub))
                goto err;
        } else {
            if (!ossl_hss_pubkey_from_data(p->data, p->data_size, key))
                goto err;
        }
    }
    ok = 1;
 err:
    return ok;
}
