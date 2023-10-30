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

LMS_KEY *ossl_lms_key_new(void)
{
    LMS_KEY *key = OPENSSL_zalloc(sizeof(*key));

    if (key == NULL)
        return NULL;
    if (!CRYPTO_NEW_REF(&key->references, 1)) {
        OPENSSL_free(key);
        return NULL;
    }
    return key;
}

int ossl_lms_key_up_ref(LMS_KEY *key)
{
    int i;

    if (CRYPTO_UP_REF(&key->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("LMS_KEY", key);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

void ossl_lms_key_free(LMS_KEY *key)
{
    int i;

    if (key == NULL)
        return;

    CRYPTO_DOWN_REF(&key->references, &i);
    REF_PRINT_COUNT("LMS_KEY", key);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (key->pub_allocated)
        OPENSSL_free(key->pub);
    CRYPTO_FREE_REF(&key->references);
    OPENSSL_free(key);
}

/*
 * RFC 8554 Algorithm 6: Steps 1 & 2.
 * Steps that involve checking the size of the public key data are
 * done indirectly by checking the return result of PACKET_get API's.
 * This function may be called multiple times when parsing a HSS signature.
 * It is also used by ossl_lms_pubkey_from_data() to load a pubkey.
 */
int ossl_lms_pubkey_from_pkt(PACKET *pkt, LMS_KEY *key)
{
    uint32_t lms_type;
    uint32_t ots_type;

    key->pub = (unsigned char *)pkt->curr;
    if (!PACKET_get_4_len(pkt, &lms_type))
        goto err;
    key->lms_params = ossl_lms_params_get(lms_type);
    if (key->lms_params == NULL
            || !PACKET_get_4_len(pkt, &ots_type))
        goto err;
    key->ots_params = ossl_lm_ots_params_get(ots_type);
    if (key->ots_params == NULL)
        goto err;

    /* The digest used must be the same */
    if (HASH_NOT_MATCHED(key->ots_params, key->lms_params)
            || !PACKET_get_bytes_shallow(pkt, &key->I, LMS_ISIZE)
            || !PACKET_get_bytes_shallow(pkt, &key->K, key->lms_params->n))
        goto err;
    key->publen = pkt->curr - key->pub;
    return 1;
err:
    return 0;
}

/*
 * Load a public LMS_KEY from a |pub| byte array of size |publen|.
 * An error is returned if either |pub| is invalid or |publen| is
 * not the correct size (i.e. trailing data is not allowed)
 */
int ossl_lms_pubkey_from_data(const unsigned char *pub, size_t publen,
                              LMS_KEY *key)
{
    PACKET pkt;

    key->pub = OPENSSL_memdup(pub, publen);
    if (key->pub == NULL)
        return 0;

    key->publen = publen;
    key->pub_allocated = 1;

    if (!PACKET_buf_init(&pkt, key->pub, key->publen)
            || !ossl_lms_pubkey_from_pkt(&pkt, key)
            || (PACKET_remaining(&pkt) > 0))
        goto err;
    return 1;
err:
    OPENSSL_free(key->pub);
    key->pub = NULL;
    return 0;
}
