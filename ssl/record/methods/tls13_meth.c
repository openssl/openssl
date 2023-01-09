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

static int tls13_set_crypto_state(OSSL_RECORD_LAYER *rl, int level,
                                  unsigned char *key, size_t keylen,
                                  unsigned char *iv, size_t ivlen,
                                  unsigned char *mackey, size_t mackeylen,
                                  const EVP_CIPHER *ciph,
                                  size_t taglen,
                                  int mactype,
                                  const EVP_MD *md,
                                  COMP_METHOD *comp)
{
    EVP_CIPHER_CTX *ciph_ctx;
    int mode;
    int enc = (rl->direction == OSSL_RECORD_DIRECTION_WRITE) ? 1 : 0;

    if (ivlen > sizeof(rl->iv)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return OSSL_RECORD_RETURN_FATAL;
    }
    memcpy(rl->iv, iv, ivlen);

    ciph_ctx = rl->enc_ctx = EVP_CIPHER_CTX_new();
    if (ciph_ctx == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return OSSL_RECORD_RETURN_FATAL;
    }

    mode = EVP_CIPHER_get_mode(ciph);

    if (EVP_CipherInit_ex(ciph_ctx, ciph, NULL, NULL, NULL, enc) <= 0
        || EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen,
                               NULL) <= 0
        || (mode == EVP_CIPH_CCM_MODE
            && EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_TAG, taglen,
                                   NULL) <= 0)
        || EVP_CipherInit_ex(ciph_ctx, NULL, NULL, key, NULL, enc) <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return OSSL_RECORD_RETURN_FATAL;
    }

    return OSSL_RECORD_RETURN_SUCCESS;
}

static int tls13_cipher(OSSL_RECORD_LAYER *rl, TLS_RL_RECORD *recs,
                        size_t n_recs, int sending, SSL_MAC_BUF *mac,
                        size_t macsize)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH], recheader[SSL3_RT_HEADER_LENGTH];
    size_t ivlen, offset, loop, hdrlen;
    unsigned char *staticiv;
    unsigned char *seq = rl->sequence;
    int lenu, lenf;
    TLS_RL_RECORD *rec = &recs[0];
    WPACKET wpkt;
    const EVP_CIPHER *cipher;
    int mode;

    if (n_recs != 1) {
        /* Should not happen */
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ctx = rl->enc_ctx;
    staticiv = rl->iv;

    cipher = EVP_CIPHER_CTX_get0_cipher(ctx);
    if (cipher == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    mode = EVP_CIPHER_get_mode(cipher);

    /*
     * If we're sending an alert and ctx != NULL then we must be forcing
     * plaintext alerts. If we're reading and ctx != NULL then we allow
     * plaintext alerts at certain points in the handshake. If we've got this
     * far then we have already validated that a plaintext alert is ok here.
     */
    if (ctx == NULL || rec->type == SSL3_RT_ALERT) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
        return 1;
    }

    ivlen = EVP_CIPHER_CTX_get_iv_length(ctx);

    if (!sending) {
        /*
         * Take off tag. There must be at least one byte of content type as
         * well as the tag
         */
        if (rec->length < rl->taglen + 1)
            return 0;
        rec->length -= rl->taglen;
    }

    /* Set up IV */
    if (ivlen < SEQ_NUM_SIZE) {
        /* Should not happen */
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    offset = ivlen - SEQ_NUM_SIZE;
    memcpy(iv, staticiv, offset);
    for (loop = 0; loop < SEQ_NUM_SIZE; loop++)
        iv[offset + loop] = staticiv[offset + loop] ^ seq[loop];

    if (!tls_increment_sequence_ctr(rl)) {
        /* RLAYERfatal already called */
        return 0;
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, sending) <= 0
            || (!sending && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                                rl->taglen,
                                                rec->data + rec->length) <= 0)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Set up the AAD */
    if (!WPACKET_init_static_len(&wpkt, recheader, sizeof(recheader), 0)
            || !WPACKET_put_bytes_u8(&wpkt, rec->type)
            || !WPACKET_put_bytes_u16(&wpkt, rec->rec_version)
            || !WPACKET_put_bytes_u16(&wpkt, rec->length + rl->taglen)
            || !WPACKET_get_total_written(&wpkt, &hdrlen)
            || hdrlen != SSL3_RT_HEADER_LENGTH
            || !WPACKET_finish(&wpkt)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        WPACKET_cleanup(&wpkt);
        return 0;
    }

    /*
     * For CCM we must explicitly set the total plaintext length before we add
     * any AAD.
     */
    if ((mode == EVP_CIPH_CCM_MODE
                 && EVP_CipherUpdate(ctx, NULL, &lenu, NULL,
                                     (unsigned int)rec->length) <= 0)
            || EVP_CipherUpdate(ctx, NULL, &lenu, recheader,
                                sizeof(recheader)) <= 0
            || EVP_CipherUpdate(ctx, rec->data, &lenu, rec->input,
                                (unsigned int)rec->length) <= 0
            || EVP_CipherFinal_ex(ctx, rec->data + lenu, &lenf) <= 0
            || (size_t)(lenu + lenf) != rec->length) {
        return 0;
    }
    if (sending) {
        /* Add the tag */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, rl->taglen,
                                rec->data + rec->length) <= 0) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        rec->length += rl->taglen;
    }

    return 1;
}

static int tls13_validate_record_header(OSSL_RECORD_LAYER *rl,
                                        TLS_RL_RECORD *rec)
{
    if (rec->type != SSL3_RT_APPLICATION_DATA
            && (rec->type != SSL3_RT_CHANGE_CIPHER_SPEC
                || !rl->is_first_handshake)
            && (rec->type != SSL3_RT_ALERT || !rl->allow_plain_alerts)) {
        RLAYERfatal(rl, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_BAD_RECORD_TYPE);
        return 0;
    }

    if (rec->rec_version != TLS1_2_VERSION) {
        RLAYERfatal(rl, SSL_AD_DECODE_ERROR, SSL_R_WRONG_VERSION_NUMBER);
        return 0;
    }

    if (rec->length > SSL3_RT_MAX_TLS13_ENCRYPTED_LENGTH) {
        RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW,
                    SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
        return 0;
    }
    return 1;
}

static int tls13_post_process_record(OSSL_RECORD_LAYER *rl, TLS_RL_RECORD *rec)
{
    /* Skip this if we've received a plaintext alert */
    if (rec->type != SSL3_RT_ALERT) {
        size_t end;

        if (rec->length == 0
                || rec->type != SSL3_RT_APPLICATION_DATA) {
            RLAYERfatal(rl, SSL_AD_UNEXPECTED_MESSAGE,
                        SSL_R_BAD_RECORD_TYPE);
            return 0;
        }

        /* Strip trailing padding */
        for (end = rec->length - 1; end > 0 && rec->data[end] == 0; end--)
            continue;

        rec->length = end;
        rec->type = rec->data[end];
    }

    if (rec->length > SSL3_RT_MAX_PLAIN_LENGTH) {
        RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW, SSL_R_DATA_LENGTH_TOO_LONG);
        return 0;
    }

    if (!tls13_common_post_process_record(rl, rec)) {
        /* RLAYERfatal already called */
        return 0;
    }

    return 1;
}

static unsigned int tls13_get_record_type(OSSL_RECORD_LAYER *rl,
                                          OSSL_RECORD_TEMPLATE *template)
{
    if (rl->allow_plain_alerts && template->type == SSL3_RT_ALERT)
        return  SSL3_RT_ALERT;

    /*
     * Aside from the above case we always use the application data record type
     * when encrypting in TLSv1.3. The "inner" record type encodes the "real"
     * record type from the template.
     */
    return SSL3_RT_APPLICATION_DATA;
}

static int tls13_add_record_padding(OSSL_RECORD_LAYER *rl,
                                    OSSL_RECORD_TEMPLATE *thistempl,
                                    WPACKET *thispkt,
                                    TLS_RL_RECORD *thiswr)
{
    size_t rlen;

    /* Nothing to be done in the case of a plaintext alert */
    if (rl->allow_plain_alerts && thistempl->type != SSL3_RT_ALERT)
        return 1;

    if (!WPACKET_put_bytes_u8(thispkt, thistempl->type)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    TLS_RL_RECORD_add_length(thiswr, 1);

    /* Add TLS1.3 padding */
    rlen = TLS_RL_RECORD_get_length(thiswr);
    if (rlen < rl->max_frag_len) {
        size_t padding = 0;
        size_t max_padding = rl->max_frag_len - rlen;

        if (rl->padding != NULL) {
            padding = rl->padding(rl->cbarg, thistempl->type, rlen);
        } else if (rl->block_padding > 0) {
            size_t mask = rl->block_padding - 1;
            size_t remainder;

            /* optimize for power of 2 */
            if ((rl->block_padding & mask) == 0)
                remainder = rlen & mask;
            else
                remainder = rlen % rl->block_padding;
            /* don't want to add a block of padding if we don't have to */
            if (remainder == 0)
                padding = 0;
            else
                padding = rl->block_padding - remainder;
        }
        if (padding > 0) {
            /* do not allow the record to exceed max plaintext length */
            if (padding > max_padding)
                padding = max_padding;
            if (!WPACKET_memset(thispkt, 0, padding)) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR,
                            ERR_R_INTERNAL_ERROR);
                return 0;
            }
            TLS_RL_RECORD_add_length(thiswr, padding);
        }
    }

    return 1;
}

struct record_functions_st tls_1_3_funcs = {
    tls13_set_crypto_state,
    tls13_cipher,
    NULL,
    tls_default_set_protocol_version,
    tls_default_read_n,
    tls_get_more_records,
    tls13_validate_record_header,
    tls13_post_process_record,
    tls_get_max_records_default,
    tls_write_records_default,
    tls_allocate_write_buffers_default,
    tls_initialise_write_packets_default,
    tls13_get_record_type,
    tls_prepare_record_header_default,
    tls13_add_record_padding,
    tls_prepare_for_encryption_default,
    tls_post_encryption_processing_default,
    NULL
};
