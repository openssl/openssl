/* ssl/record/ssl3_record.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "../ssl_locl.h"

void SSL3_RECORD_clear(SSL3_RECORD *r)
{
    memset(r->seq_num, 0, sizeof(r->seq_num));
}

void SSL3_RECORD_release(SSL3_RECORD *r)
{
    if (r->comp != NULL)
        OPENSSL_free(r->comp);
    r->comp = NULL;
}

int SSL3_RECORD_setup(SSL3_RECORD *r, size_t len)
{
    if (r->comp == NULL)
        r->comp = (unsigned char *) OPENSSL_malloc(len);
    if (r->comp == NULL)
        return 0;
    return 1;
}

void SSL3_RECORD_set_seq_num(SSL3_RECORD *r, const unsigned char *seq_num)
{
    memcpy(r->seq_num, seq_num, 8);
}

/*
 * MAX_EMPTY_RECORDS defines the number of consecutive, empty records that
 * will be processed per call to ssl3_get_record. Without this limit an
 * attacker could send empty records at a faster rate than we can process and
 * cause ssl3_get_record to loop forever.
 */
#define MAX_EMPTY_RECORDS 32

/*-
 * Call this to get a new input record.
 * It will return <= 0 if more data is needed, normally due to an error
 * or non-blocking IO.
 * When it finishes, one packet has been decoded and can be found in
 * ssl->s3->rrec.type    - is the type of record
 * ssl->s3->rrec.data,   - data
 * ssl->s3->rrec.length, - number of bytes
 */
/* used only by ssl3_read_bytes */
int ssl3_get_record(SSL *s)
{
    int ssl_major, ssl_minor, al;
    int enc_err, n, i, ret = -1;
    SSL3_RECORD *rr;
    SSL_SESSION *sess;
    unsigned char *p;
    unsigned char md[EVP_MAX_MD_SIZE];
    short version;
    unsigned mac_size;
    size_t extra;
    unsigned empty_record_count = 0;

    rr = RECORD_LAYER_get_rrec(&s->rlayer);
    sess = s->session;

    if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER)
        extra = SSL3_RT_MAX_EXTRA;
    else
        extra = 0;
    if (extra && !s->s3->init_extra) {
        /*
         * An application error: SLS_OP_MICROSOFT_BIG_SSLV3_BUFFER set after
         * ssl3_setup_buffers() was done
         */
        SSLerr(SSL_F_SSL3_GET_RECORD, ERR_R_INTERNAL_ERROR);
        return -1;
    }

 again:
    /* check if we have the header */
    if ((s->rstate != SSL_ST_READ_BODY) ||
        (s->packet_length < SSL3_RT_HEADER_LENGTH)) {
        n = ssl3_read_n(s, SSL3_RT_HEADER_LENGTH,
            SSL3_BUFFER_get_len(RECORD_LAYER_get_rbuf(&s->rlayer)), 0);
        if (n <= 0)
            return (n);         /* error or non-blocking */
        s->rstate = SSL_ST_READ_BODY;

        p = s->packet;
        if (s->msg_callback)
            s->msg_callback(0, 0, SSL3_RT_HEADER, p, 5, s,
                            s->msg_callback_arg);

        /* Pull apart the header into the SSL3_RECORD */
        rr->type = *(p++);
        ssl_major = *(p++);
        ssl_minor = *(p++);
        version = (ssl_major << 8) | ssl_minor;
        n2s(p, rr->length);

        /* Lets check version */
        if (!s->first_packet) {
            if (version != s->version) {
                SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_WRONG_VERSION_NUMBER);
                if ((s->version & 0xFF00) == (version & 0xFF00)
                    && !s->enc_write_ctx && !s->write_hash)
                    /*
                     * Send back error using their minor version number :-)
                     */
                    s->version = (unsigned short)version;
                al = SSL_AD_PROTOCOL_VERSION;
                goto f_err;
            }
        }

        if ((version >> 8) != SSL3_VERSION_MAJOR) {
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_WRONG_VERSION_NUMBER);
            goto err;
        }

        if (rr->length >
                SSL3_BUFFER_get_len(RECORD_LAYER_get_rbuf(&s->rlayer))
                - SSL3_RT_HEADER_LENGTH) {
            al = SSL_AD_RECORD_OVERFLOW;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_PACKET_LENGTH_TOO_LONG);
            goto f_err;
        }

        /* now s->rstate == SSL_ST_READ_BODY */
    }

    /* s->rstate == SSL_ST_READ_BODY, get and decode the data */

    if (rr->length > s->packet_length - SSL3_RT_HEADER_LENGTH) {
        /* now s->packet_length == SSL3_RT_HEADER_LENGTH */
        i = rr->length;
        n = ssl3_read_n(s, i, i, 1);
        if (n <= 0)
            return (n);         /* error or non-blocking io */
        /*
         * now n == rr->length, and s->packet_length == SSL3_RT_HEADER_LENGTH
         * + rr->length
         */
    }

    s->rstate = SSL_ST_READ_HEADER; /* set state for later operations */

    /*
     * At this point, s->packet_length == SSL3_RT_HEADER_LNGTH + rr->length,
     * and we have that many bytes in s->packet
     */
    rr->input = &(s->packet[SSL3_RT_HEADER_LENGTH]);

    /*
     * ok, we can now read from 's->packet' data into 'rr' rr->input points
     * at rr->length bytes, which need to be copied into rr->data by either
     * the decryption or by the decompression When the data is 'copied' into
     * the rr->data buffer, rr->input will be pointed at the new buffer
     */

    /*
     * We now have - encrypted [ MAC [ compressed [ plain ] ] ] rr->length
     * bytes of encrypted compressed stuff.
     */

    /* check is not needed I believe */
    if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH + extra) {
        al = SSL_AD_RECORD_OVERFLOW;
        SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
        goto f_err;
    }

    /* decrypt in place in 'rr->input' */
    rr->data = rr->input;
    rr->orig_len = rr->length;
    /*
     * If in encrypt-then-mac mode calculate mac from encrypted record. All
     * the details below are public so no timing details can leak.
     */
    if (SSL_USE_ETM(s) && s->read_hash) {
        unsigned char *mac;
        mac_size = EVP_MD_CTX_size(s->read_hash);
        OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);
        if (rr->length < mac_size) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        rr->length -= mac_size;
        mac = rr->data + rr->length;
        i = s->method->ssl3_enc->mac(s, md, 0 /* not send */ );
        if (i < 0 || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0) {
            al = SSL_AD_BAD_RECORD_MAC;
            SSLerr(SSL_F_SSL3_GET_RECORD,
                   SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
            goto f_err;
        }
    }

    enc_err = s->method->ssl3_enc->enc(s, 0);
    /*-
     * enc_err is:
     *    0: (in non-constant time) if the record is publically invalid.
     *    1: if the padding is valid
     *    -1: if the padding is invalid
     */
    if (enc_err == 0) {
        al = SSL_AD_DECRYPTION_FAILED;
        SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_BLOCK_CIPHER_PAD_IS_WRONG);
        goto f_err;
    }
#ifdef TLS_DEBUG
    printf("dec %d\n", rr->length);
    {
        unsigned int z;
        for (z = 0; z < rr->length; z++)
            printf("%02X%c", rr->data[z], ((z + 1) % 16) ? ' ' : '\n');
    }
    printf("\n");
#endif

    /* r->length is now the compressed data plus mac */
    if ((sess != NULL) &&
        (s->enc_read_ctx != NULL) &&
        (EVP_MD_CTX_md(s->read_hash) != NULL) && !SSL_USE_ETM(s)) {
        /* s->read_hash != NULL => mac_size != -1 */
        unsigned char *mac = NULL;
        unsigned char mac_tmp[EVP_MAX_MD_SIZE];
        mac_size = EVP_MD_CTX_size(s->read_hash);
        OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);

        /*
         * orig_len is the length of the record before any padding was
         * removed. This is public information, as is the MAC in use,
         * therefore we can safely process the record in a different amount
         * of time if it's too short to possibly contain a MAC.
         */
        if (rr->orig_len < mac_size ||
            /* CBC records must have a padding length byte too. */
            (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
             rr->orig_len < mac_size + 1)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }

        if (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE) {
            /*
             * We update the length so that the TLS header bytes can be
             * constructed correctly but we need to extract the MAC in
             * constant time from within the record, without leaking the
             * contents of the padding bytes.
             */
            mac = mac_tmp;
            ssl3_cbc_copy_mac(mac_tmp, rr, mac_size);
            rr->length -= mac_size;
        } else {
            /*
             * In this case there's no padding, so |rec->orig_len| equals
             * |rec->length| and we checked that there's enough bytes for
             * |mac_size| above.
             */
            rr->length -= mac_size;
            mac = &rr->data[rr->length];
        }

        i = s->method->ssl3_enc->mac(s, md, 0 /* not send */ );
        if (i < 0 || mac == NULL
            || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0)
            enc_err = -1;
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH + extra + mac_size)
            enc_err = -1;
    }

    if (enc_err < 0) {
        /*
         * A separate 'decryption_failed' alert was introduced with TLS 1.0,
         * SSL 3.0 only has 'bad_record_mac'.  But unless a decryption
         * failure is directly visible from the ciphertext anyway, we should
         * not reveal which kind of error occurred -- this might become
         * visible to an attacker (e.g. via a logfile)
         */
        al = SSL_AD_BAD_RECORD_MAC;
        SSLerr(SSL_F_SSL3_GET_RECORD,
               SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
        goto f_err;
    }

    /* r->length is now just compressed */
    if (s->expand != NULL) {
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH + extra) {
            al = SSL_AD_RECORD_OVERFLOW;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_COMPRESSED_LENGTH_TOO_LONG);
            goto f_err;
        }
        if (!ssl3_do_uncompress(s)) {
            al = SSL_AD_DECOMPRESSION_FAILURE;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_BAD_DECOMPRESSION);
            goto f_err;
        }
    }

    if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH + extra) {
        al = SSL_AD_RECORD_OVERFLOW;
        SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_DATA_LENGTH_TOO_LONG);
        goto f_err;
    }

    rr->off = 0;
    /*-
     * So at this point the following is true
     * ssl->s3->rrec.type   is the type of record
     * ssl->s3->rrec.length == number of bytes in record
     * ssl->s3->rrec.off    == offset to first valid byte
     * ssl->s3->rrec.data   == where to take bytes from, increment
     *                         after use :-).
     */

    /* we have pulled in a full packet so zero things */
    s->packet_length = 0;

    /* just read a 0 length packet */
    if (rr->length == 0) {
        empty_record_count++;
        if (empty_record_count > MAX_EMPTY_RECORDS) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_RECORD_TOO_SMALL);
            goto f_err;
        }
        goto again;
    }

    return (1);

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return (ret);
}

int ssl3_do_uncompress(SSL *ssl)
{
#ifndef OPENSSL_NO_COMP
    int i;
    SSL3_RECORD *rr;

    rr = RECORD_LAYER_get_rrec(&ssl->rlayer);
    i = COMP_expand_block(ssl->expand, rr->comp,
                          SSL3_RT_MAX_PLAIN_LENGTH, rr->data,
                          (int)rr->length);
    if (i < 0)
        return (0);
    else
        rr->length = i;
    rr->data = rr->comp;
#endif
    return (1);
}

int ssl3_do_compress(SSL *ssl)
{
#ifndef OPENSSL_NO_COMP
    int i;
    SSL3_RECORD *wr;

    wr = RECORD_LAYER_get_wrec(&ssl->rlayer);
    i = COMP_compress_block(ssl->compress, wr->data,
                            SSL3_RT_MAX_COMPRESSED_LENGTH,
                            wr->input, (int)wr->length);
    if (i < 0)
        return (0);
    else
        wr->length = i;

    wr->input = wr->data;
#endif
    return (1);
}

int dtls1_process_record(SSL *s)
{
    int i, al;
    int enc_err;
    SSL_SESSION *sess;
    SSL3_RECORD *rr;
    unsigned int mac_size;
    unsigned char md[EVP_MAX_MD_SIZE];

    rr = RECORD_LAYER_get_rrec(&s->rlayer);
    sess = s->session;

    /*
     * At this point, s->packet_length == SSL3_RT_HEADER_LNGTH + rr->length,
     * and we have that many bytes in s->packet
     */
    rr->input = &(s->packet[DTLS1_RT_HEADER_LENGTH]);

    /*
     * ok, we can now read from 's->packet' data into 'rr' rr->input points
     * at rr->length bytes, which need to be copied into rr->data by either
     * the decryption or by the decompression When the data is 'copied' into
     * the rr->data buffer, rr->input will be pointed at the new buffer
     */

    /*
     * We now have - encrypted [ MAC [ compressed [ plain ] ] ] rr->length
     * bytes of encrypted compressed stuff.
     */

    /* check is not needed I believe */
    if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
        al = SSL_AD_RECORD_OVERFLOW;
        SSLerr(SSL_F_DTLS1_PROCESS_RECORD, SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
        goto f_err;
    }

    /* decrypt in place in 'rr->input' */
    rr->data = rr->input;
    rr->orig_len = rr->length;

    enc_err = s->method->ssl3_enc->enc(s, 0);
    /*-
     * enc_err is:
     *    0: (in non-constant time) if the record is publically invalid.
     *    1: if the padding is valid
     *   -1: if the padding is invalid
     */
    if (enc_err == 0) {
        /* For DTLS we simply ignore bad packets. */
        rr->length = 0;
        s->packet_length = 0;
        goto err;
    }
#ifdef TLS_DEBUG
    printf("dec %d\n", rr->length);
    {
        unsigned int z;
        for (z = 0; z < rr->length; z++)
            printf("%02X%c", rr->data[z], ((z + 1) % 16) ? ' ' : '\n');
    }
    printf("\n");
#endif

    /* r->length is now the compressed data plus mac */
    if ((sess != NULL) &&
        (s->enc_read_ctx != NULL) && (EVP_MD_CTX_md(s->read_hash) != NULL)) {
        /* s->read_hash != NULL => mac_size != -1 */
        unsigned char *mac = NULL;
        unsigned char mac_tmp[EVP_MAX_MD_SIZE];
        mac_size = EVP_MD_CTX_size(s->read_hash);
        OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);

        /*
         * orig_len is the length of the record before any padding was
         * removed. This is public information, as is the MAC in use,
         * therefore we can safely process the record in a different amount
         * of time if it's too short to possibly contain a MAC.
         */
        if (rr->orig_len < mac_size ||
            /* CBC records must have a padding length byte too. */
            (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
             rr->orig_len < mac_size + 1)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_DTLS1_PROCESS_RECORD, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }

        if (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE) {
            /*
             * We update the length so that the TLS header bytes can be
             * constructed correctly but we need to extract the MAC in
             * constant time from within the record, without leaking the
             * contents of the padding bytes.
             */
            mac = mac_tmp;
            ssl3_cbc_copy_mac(mac_tmp, rr, mac_size);
            rr->length -= mac_size;
        } else {
            /*
             * In this case there's no padding, so |rec->orig_len| equals
             * |rec->length| and we checked that there's enough bytes for
             * |mac_size| above.
             */
            rr->length -= mac_size;
            mac = &rr->data[rr->length];
        }

        i = s->method->ssl3_enc->mac(s, md, 0 /* not send */ );
        if (i < 0 || mac == NULL
            || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0)
            enc_err = -1;
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH + mac_size)
            enc_err = -1;
    }

    if (enc_err < 0) {
        /* decryption failed, silently discard message */
        rr->length = 0;
        s->packet_length = 0;
        goto err;
    }

    /* r->length is now just compressed */
    if (s->expand != NULL) {
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH) {
            al = SSL_AD_RECORD_OVERFLOW;
            SSLerr(SSL_F_DTLS1_PROCESS_RECORD,
                   SSL_R_COMPRESSED_LENGTH_TOO_LONG);
            goto f_err;
        }
        if (!ssl3_do_uncompress(s)) {
            al = SSL_AD_DECOMPRESSION_FAILURE;
            SSLerr(SSL_F_DTLS1_PROCESS_RECORD, SSL_R_BAD_DECOMPRESSION);
            goto f_err;
        }
    }

    if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH) {
        al = SSL_AD_RECORD_OVERFLOW;
        SSLerr(SSL_F_DTLS1_PROCESS_RECORD, SSL_R_DATA_LENGTH_TOO_LONG);
        goto f_err;
    }

    rr->off = 0;
    /*-
     * So at this point the following is true
     * ssl->s3->rrec.type   is the type of record
     * ssl->s3->rrec.length == number of bytes in record
     * ssl->s3->rrec.off    == offset to first valid byte
     * ssl->s3->rrec.data   == where to take bytes from, increment
     *                         after use :-).
     */

    /* we have pulled in a full packet so zero things */
    s->packet_length = 0;
    return (1);

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return (0);
}


/*
 * retrieve a buffered record that belongs to the current epoch, ie,
 * processed
 */
#define dtls1_get_processed_record(s) \
                   dtls1_retrieve_buffered_record((s), \
                   &((s)->d1->processed_rcds))

/*-
 * Call this to get a new input record.
 * It will return <= 0 if more data is needed, normally due to an error
 * or non-blocking IO.
 * When it finishes, one packet has been decoded and can be found in
 * ssl->s3->rrec.type    - is the type of record
 * ssl->s3->rrec.data,   - data
 * ssl->s3->rrec.length, - number of bytes
 */
/* used only by dtls1_read_bytes */
int dtls1_get_record(SSL *s)
{
    int ssl_major, ssl_minor;
    int i, n;
    SSL3_RECORD *rr;
    unsigned char *p = NULL;
    unsigned short version;
    DTLS1_BITMAP *bitmap;
    unsigned int is_next_epoch;

    rr = RECORD_LAYER_get_rrec(&s->rlayer);

    /*
     * The epoch may have changed.  If so, process all the pending records.
     * This is a non-blocking operation.
     */
    if (dtls1_process_buffered_records(s) < 0)
        return -1;

    /* if we're renegotiating, then there may be buffered records */
    if (dtls1_get_processed_record(s))
        return 1;

    /* get something from the wire */
 again:
    /* check if we have the header */
    if ((s->rstate != SSL_ST_READ_BODY) ||
        (s->packet_length < DTLS1_RT_HEADER_LENGTH)) {
        n = ssl3_read_n(s, DTLS1_RT_HEADER_LENGTH,
            SSL3_BUFFER_get_len(RECORD_LAYER_get_rbuf(&s->rlayer)), 0);
        /* read timeout is handled by dtls1_read_bytes */
        if (n <= 0)
            return (n);         /* error or non-blocking */

        /* this packet contained a partial record, dump it */
        if (s->packet_length != DTLS1_RT_HEADER_LENGTH) {
            s->packet_length = 0;
            goto again;
        }

        s->rstate = SSL_ST_READ_BODY;

        p = s->packet;

        if (s->msg_callback)
            s->msg_callback(0, 0, SSL3_RT_HEADER, p, DTLS1_RT_HEADER_LENGTH,
                            s, s->msg_callback_arg);

        /* Pull apart the header into the DTLS1_RECORD */
        rr->type = *(p++);
        ssl_major = *(p++);
        ssl_minor = *(p++);
        version = (ssl_major << 8) | ssl_minor;

        /* sequence number is 64 bits, with top 2 bytes = epoch */
        n2s(p, rr->epoch);

        memcpy(&(s->s3->read_sequence[2]), p, 6);
        p += 6;

        n2s(p, rr->length);

        /* Lets check version */
        if (!s->first_packet) {
            if (version != s->version) {
                /* unexpected version, silently discard */
                rr->length = 0;
                s->packet_length = 0;
                goto again;
            }
        }

        if ((version & 0xff00) != (s->version & 0xff00)) {
            /* wrong version, silently discard record */
            rr->length = 0;
            s->packet_length = 0;
            goto again;
        }

        if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
            /* record too long, silently discard it */
            rr->length = 0;
            s->packet_length = 0;
            goto again;
        }

        /* now s->rstate == SSL_ST_READ_BODY */
    }

    /* s->rstate == SSL_ST_READ_BODY, get and decode the data */

    if (rr->length > s->packet_length - DTLS1_RT_HEADER_LENGTH) {
        /* now s->packet_length == DTLS1_RT_HEADER_LENGTH */
        i = rr->length;
        n = ssl3_read_n(s, i, i, 1);
        /* this packet contained a partial record, dump it */
        if (n != i) {
            rr->length = 0;
            s->packet_length = 0;
            goto again;
        }

        /*
         * now n == rr->length, and s->packet_length ==
         * DTLS1_RT_HEADER_LENGTH + rr->length
         */
    }
    s->rstate = SSL_ST_READ_HEADER; /* set state for later operations */

    /* match epochs.  NULL means the packet is dropped on the floor */
    bitmap = dtls1_get_bitmap(s, rr, &is_next_epoch);
    if (bitmap == NULL) {
        rr->length = 0;
        s->packet_length = 0;   /* dump this record */
        goto again;             /* get another record */
    }
#ifndef OPENSSL_NO_SCTP
    /* Only do replay check if no SCTP bio */
    if (!BIO_dgram_is_sctp(SSL_get_rbio(s))) {
#endif
        /*
         * Check whether this is a repeat, or aged record. Don't check if
         * we're listening and this message is a ClientHello. They can look
         * as if they're replayed, since they arrive from different
         * connections and would be dropped unnecessarily.
         */
        if (!(s->d1->listen && rr->type == SSL3_RT_HANDSHAKE &&
              s->packet_length > DTLS1_RT_HEADER_LENGTH &&
              s->packet[DTLS1_RT_HEADER_LENGTH] == SSL3_MT_CLIENT_HELLO) &&
            !dtls1_record_replay_check(s, bitmap)) {
            rr->length = 0;
            s->packet_length = 0; /* dump this record */
            goto again;         /* get another record */
        }
#ifndef OPENSSL_NO_SCTP
    }
#endif

    /* just read a 0 length packet */
    if (rr->length == 0)
        goto again;

    /*
     * If this record is from the next epoch (either HM or ALERT), and a
     * handshake is currently in progress, buffer it since it cannot be
     * processed at this time. However, do not buffer anything while
     * listening.
     */
    if (is_next_epoch) {
        if ((SSL_in_init(s) || s->in_handshake) && !s->d1->listen) {
            if (dtls1_buffer_record
                (s, &(s->d1->unprocessed_rcds), rr->seq_num) < 0)
                return -1;
            /* Mark receipt of record. */
            dtls1_record_bitmap_update(s, bitmap);
        }
        rr->length = 0;
        s->packet_length = 0;
        goto again;
    }

    if (!dtls1_process_record(s)) {
        rr->length = 0;
        s->packet_length = 0;   /* dump this record */
        goto again;             /* get another record */
    }
    dtls1_record_bitmap_update(s, bitmap); /* Mark receipt of record. */

    return (1);

}

