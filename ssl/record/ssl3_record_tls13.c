/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl_locl.h"
#include "record_locl.h"

/*-
 * tls13_enc encrypts/decrypts |n_recs| in |recs|.
 *
 * Returns:
 *    0: (in non-constant time) if the record is publically invalid (i.e. too
 *        short etc).
 *    1: if the record encryption was successful.
 *   -1: if the record's AEAD-authenticator is invalid or, if sending,
 *       an internal error occurred.
 */
int tls13_enc(SSL *s, SSL3_RECORD *recs, size_t n_recs, int send)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    size_t ivlen, offset, loop;
    unsigned char *staticiv;
    unsigned char *seq;
    int lenu, lenf;
    SSL3_RECORD *rec = &recs[0];

    if (n_recs != 1) {
        /* Should not happen */
        /* TODO(TLS1.3): Support pipelining */
        return -1;
    }

    if (send) {
        ctx = s->enc_write_ctx;
        staticiv = s->write_iv;
        seq = RECORD_LAYER_get_write_sequence(&s->rlayer);
    } else {
        ctx = s->enc_read_ctx;
        staticiv = s->read_iv;
        seq = RECORD_LAYER_get_read_sequence(&s->rlayer);
    }

    if (ctx == NULL) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
        return 1;
    }
    ivlen = EVP_CIPHER_CTX_iv_length(ctx);

    if (!send) {
        /*
         * Take off tag. There must be at least one byte of content type as
         * well as the tag
         */
        /*
         * TODO(TLS1.3): We're going to need to figure out the tag len based on
         * the cipher. For now we just support GCM tags.
         * TODO(TLS1.3): When we've swapped over the record layer to TLSv1.3
         * then the length must be 1 + the tag len to account for the content
         * byte that we know must have been encrypted.
         */
        if (rec->length < EVP_GCM_TLS_TAG_LEN)
            return 0;
        rec->length -= EVP_GCM_TLS_TAG_LEN;
    }

    /* Set up IV */
    if (ivlen < SEQ_NUM_SIZE) {
        /* Should not happen */
        return -1;
    }
    offset = ivlen - SEQ_NUM_SIZE;
    memcpy(iv, staticiv, offset);
    for (loop = 0; loop < SEQ_NUM_SIZE; loop++)
        iv[offset + loop] = staticiv[offset + loop] ^ seq[loop];

    /* Increment the sequence counter */
    for (loop = SEQ_NUM_SIZE; loop > 0; loop--) {
        ++seq[loop - 1];
        if (seq[loop - 1] != 0)
            break;
    }
    if (loop == 0) {
        /* Sequence has wrapped */
        return -1;
    }

    /* TODO(size_t): lenu/lenf should be a size_t but EVP doesn't support it */
    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, send) <= 0
            || EVP_CipherUpdate(ctx, rec->data, &lenu, rec->input,
                                (unsigned int)rec->length) <= 0
            || (!send && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                             EVP_GCM_TLS_TAG_LEN,
                                             rec->data + rec->length) <= 0)
            || EVP_CipherFinal_ex(ctx, rec->data + lenu, &lenf) <= 0
            || (size_t)(lenu + lenf) != rec->length) {
        return -1;
    }

    if (send) {
        /* Add the tag */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, EVP_GCM_TLS_TAG_LEN,
                                rec->data + rec->length) <= 0)
            return -1;
        rec->length += EVP_GCM_TLS_TAG_LEN;
    }

    return 1;
}
