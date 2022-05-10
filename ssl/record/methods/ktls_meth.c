/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "../../ssl_local.h"
#include "../record_local.h"
#include "recmethod_local.h"

/* TODO(RECLAYER): Handle OPENSSL_NO_COMP */
static int ktls_set_crypto_state(OSSL_RECORD_LAYER *rl, int level,
                                 unsigned char *key, size_t keylen,
                                 unsigned char *iv, size_t ivlen,
                                 unsigned char *mackey, size_t mackeylen,
                                 const EVP_CIPHER *ciph,
                                 size_t taglen,
                                 /* TODO(RECLAYER): This probably should not be an int */
                                 int mactype,
                                 const EVP_MD *md,
                                 const SSL_COMP *comp,
                                 /* TODO(RECLAYER): Remove me */
                                 SSL_CONNECTION *s)
{
    void *rl_sequence;
    ktls_crypto_info_t crypto_info;

    /* Check if we are suitable for KTLS */

    if (comp != NULL)
        return 0;

    /* ktls supports only the maximum fragment size */
    if (ssl_get_max_send_fragment(s) != SSL3_RT_MAX_PLAIN_LENGTH)
        return 0;

    /* check that cipher is supported */
    if (!ktls_check_supported_cipher(s, ciph, taglen))
        return 0;

    /*
     * TODO(RECLAYER): For the write side we need to add a check for
     * use of s->record_padding_cb
     */

    /* All future data will get encrypted by ktls. Flush the BIO or skip ktls */
    if (rl->direction == OSSL_RECORD_DIRECTION_WRITE) {
       if (BIO_flush(rl->bio) <= 0)
           return 0;
    }

    if (rl->direction == OSSL_RECORD_DIRECTION_WRITE)
        rl_sequence = RECORD_LAYER_get_write_sequence(&s->rlayer);
    else
        rl_sequence = RECORD_LAYER_get_read_sequence(&s->rlayer);

    if (!ktls_configure_crypto(s, ciph, rl_sequence, &crypto_info,
                               rl->direction == OSSL_RECORD_DIRECTION_WRITE,
                               iv, ivlen, key, keylen, mackey, mackeylen))
       return 0;

    if (!BIO_set_ktls(rl->bio, &crypto_info, rl->direction))
        return 0;

    return 1;
}

static int ktls_cipher(OSSL_RECORD_LAYER *rl, SSL3_RECORD *inrecs, size_t n_recs,
                       int sending, SSL_MAC_BUF *mac, size_t macsize,
                       /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s)
{
    return 1;
}

struct record_functions_st ossl_ktls_funcs = {
    ktls_set_crypto_state,
    ktls_cipher,
    NULL
};
