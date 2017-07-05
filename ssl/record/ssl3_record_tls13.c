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
#include "internal/cryptlib.h"

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
int tls13_enc(SSL *s, SSL3_RECORD *recs, size_t n_recs, int sending)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    size_t ivlen, taglen, offset, loop;
    unsigned char *staticiv;
    unsigned char *seq;
    int lenu, lenf;
    SSL3_RECORD *rec = &recs[0];
    uint32_t alg_enc;

    if (n_recs != 1) {
        /* Should not happen */
        /* TODO(TLS1.3): Support pipelining */
        return -1;
    }

    if (sending) {
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

    if (s->early_data_state == SSL_EARLY_DATA_WRITING
            || s->early_data_state == SSL_EARLY_DATA_WRITE_RETRY) {
        if (s->session != NULL && s->session->ext.max_early_data > 0)
            alg_enc = s->session->cipher->algorithm_enc;
        else
            alg_enc = s->psksession->cipher->algorithm_enc;
    } else {
        /*
         * To get here we must have selected a ciphersuite - otherwise ctx would
         * be NULL
         */
        if (!ossl_assert(s->s3->tmp.new_cipher != NULL))
            return -1;
        alg_enc = s->s3->tmp.new_cipher->algorithm_enc;
    }

    if (alg_enc & SSL_AESCCM) {
        if (alg_enc & (SSL_AES128CCM8 | SSL_AES256CCM8))
            taglen = EVP_CCM8_TLS_TAG_LEN;
         else
            taglen = EVP_CCM_TLS_TAG_LEN;
         if (sending && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen,
                                         NULL) <= 0)
            return -1;
    } else if (alg_enc & SSL_AESGCM) {
        taglen = EVP_GCM_TLS_TAG_LEN;
    } else if (alg_enc & SSL_CHACHA20) {
        taglen = EVP_CHACHAPOLY_TLS_TAG_LEN;
    } else {
        return -1;
    }

    if (!sending) {
        /*
         * Take off tag. There must be at least one byte of content type as
         * well as the tag
         */
        if (rec->length < taglen + 1)
            return 0;
        rec->length -= taglen;
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
    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, sending) <= 0
            || (!sending && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                             taglen,
                                             rec->data + rec->length) <= 0)
            || EVP_CipherUpdate(ctx, rec->data, &lenu, rec->input,
                                (unsigned int)rec->length) <= 0
            || EVP_CipherFinal_ex(ctx, rec->data + lenu, &lenf) <= 0
            || (size_t)(lenu + lenf) != rec->length) {
        return -1;
    }
    if (sending) {
        /* Add the tag */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen,
                                rec->data + rec->length) <= 0)
            return -1;
        rec->length += taglen;
    }

    return 1;
}
