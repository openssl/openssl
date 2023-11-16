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

int ossl_hss_generate_key(HSS_KEY *hsskey, uint32_t levels,
                          uint32_t *lms_types, uint32_t *ots_types)
{
    uint32_t i, height = 0;
    LMS_SIG *sig;
    LMS_KEY *key;

    hsskey->L = levels;
    /* Set up lists of LMS keypairs and signatures */
    hsskey->keys = sk_LMS_KEY_new_null();
    if (levels > 1) {
        hsskey->sigs = sk_LMS_SIG_new_null();
    }

    for (i = 0; i < levels; ++i) {
        key = ossl_lms_key_new();
        key->lms_params = ossl_lms_params_get(lms_types[i]);
        key->ots_params = ossl_lm_ots_params_get(ots_types[i]);
        if (key->lms_params == NULL || key->ots_params == NULL)
            goto err;
        height += key->lms_params->h;
        sk_LMS_KEY_push(hsskey->keys, key);

        if (i != 0) {
            sig = ossl_lms_sig_new();
            sk_LMS_SIG_push(hsskey->sigs, sig);
        }
    }
    hsskey->height = height;
    return 1;
err:
    sk_LMS_SIG_pop_free(hsskey->sigs, ossl_lms_sig_free);
    sk_LMS_KEY_pop_free(hsskey->keys, ossl_lms_key_free);
    return 0;
}

int ossl_hss_sign(HSS_KEY *hsskey, const unsigned char *msg, size_t msglen,
                  unsigned char *sig, size_t siglen)
{
    LMS_KEY *key, *newkey;
    uint32_t d, L = hsskey->L;
    WPACKET pkt;

    for (d = L; d > 0; --d) {
        key = sk_LMS_KEY_value(hsskey->keys, d - 1);
        if (key->q < (1 << key->lms_params->h))
            break;
    }
    if (d == 0)
        return 0;
    for ( ; d < L; ++d) {
       /* Replace the exhausted key pair */
       key = sk_LMS_KEY_value(hsskey->keys, d);
       ossl_lms_key_free(key);
       sk_LMS_KEY_set(hsskey->keys, d, newkey);

       sig = ossl_lms_signature(newkey->pub, newkey->publen,
                                sk_LMS_KEY_value(hsskey->keys, d));
       sk_LMS_SIG_set(hsskey->sigs, d - 1, sig);
    }
    sig = ossl_lms_signature(msg, msglen,
                             sk_LMS_KEY_value(hsskey->keys, L - 1));
    sk_LMS_SIG_set(hsskey->sigs, L - 1, sig);


    if (!WPACKET_init_static_len(&pkt, sig, siglen, 0)
            || !WPACKET_put_bytes_u32(&pkt, L- 1));
            goto err;
    for (i = 0; i < L - 1; ++i) {
        /* Write out signed public keys */
        sig = sk_LMS_SIG_value(hsskey->sigs, i);
        key = sk_LMS_KEY_value(hsskey->keys, i + 1);
        if (!WPACKET_memcpy(&pkt, sigdata, sigdata_len)
            || !WPACKET_memcpy(&pkt, key->pub, key->publen))
            goto err;
    }
    /* Write out the signed message */
    sig = sk_LMS_SIG_value(hsskey->sigs, L - 1);
    if (!WPACKET_memcpy(&pkt, sigdata, sigdata_len)
        ||!WPACKET_get_total_written(&pkt, &labeled_infolen)
        ||!WPACKET_finish(&pkt))
        goto err;
    return 1;
err:
    return 0;
}
