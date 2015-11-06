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
#include "internal/constant_time_locl.h"
#include <openssl/rand.h>
#include "record_locl.h"

static const unsigned char ssl3_pad_1[48] = {
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

static const unsigned char ssl3_pad_2[48] = {
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
};

/*
 * Clear the contents of an SSL3_RECORD but retain any memory allocated
 */
void SSL3_RECORD_clear(SSL3_RECORD *r)
{
    unsigned char *comp = r->comp;

    memset(r, 0, sizeof(*r));
    r->comp = comp;
}

void SSL3_RECORD_release(SSL3_RECORD *r)
{
    OPENSSL_free(r->comp);
    r->comp = NULL;
}

int SSL3_RECORD_setup(SSL3_RECORD *r)
{
    if (r->comp == NULL)
        r->comp = (unsigned char *)
            OPENSSL_malloc(SSL3_RT_MAX_ENCRYPTED_LENGTH);
    if (r->comp == NULL)
        return 0;
    return 1;
}

void SSL3_RECORD_set_seq_num(SSL3_RECORD *r, const unsigned char *seq_num)
{
    memcpy(r->seq_num, seq_num, SEQ_NUM_SIZE);
}

/*
 * MAX_EMPTY_RECORDS defines the number of consecutive, empty records that
 * will be processed per call to ssl3_get_record. Without this limit an
 * attacker could send empty records at a faster rate than we can process and
 * cause ssl3_get_record to loop forever.
 */
#define MAX_EMPTY_RECORDS 32

#define SSL2_RT_HEADER_LENGTH   2
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
    if ((RECORD_LAYER_get_rstate(&s->rlayer) != SSL_ST_READ_BODY) ||
        (RECORD_LAYER_get_packet_length(&s->rlayer) < SSL3_RT_HEADER_LENGTH)) {
        n = ssl3_read_n(s, SSL3_RT_HEADER_LENGTH,
            SSL3_BUFFER_get_len(&s->rlayer.rbuf), 0);
        if (n <= 0)
            return (n);         /* error or non-blocking */
        RECORD_LAYER_set_rstate(&s->rlayer, SSL_ST_READ_BODY);

        p = RECORD_LAYER_get_packet(&s->rlayer);

        /*
         * Check whether this is a regular record or an SSLv2 style record. The
         * latter is only used in an initial ClientHello for old clients. We
         * check s->read_hash and s->enc_read_ctx to ensure this does not apply
         * during renegotiation
         */
        if (s->first_packet && s->server && !s->read_hash && !s->enc_read_ctx
                && (p[0] & 0x80) && (p[2] == SSL2_MT_CLIENT_HELLO)) {
            /* SSLv2 style record */
            rr->type = SSL3_RT_HANDSHAKE;
            rr->rec_version = SSL2_VERSION;

            rr->length = ((p[0] & 0x7f) << 8) | p[1];

            if (rr->length > SSL3_BUFFER_get_len(&s->rlayer.rbuf)
                                    - SSL2_RT_HEADER_LENGTH) {
                al = SSL_AD_RECORD_OVERFLOW;
                SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_PACKET_LENGTH_TOO_LONG);
                goto f_err;
            }

            if (rr->length < MIN_SSL2_RECORD_LEN) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_LENGTH_TOO_SHORT);
                goto f_err;
            }
        } else {
            /* SSLv3+ style record */
            if (s->msg_callback)
                s->msg_callback(0, 0, SSL3_RT_HEADER, p, 5, s,
                                s->msg_callback_arg);

            /* Pull apart the header into the SSL3_RECORD */
            rr->type = *(p++);
            ssl_major = *(p++);
            ssl_minor = *(p++);
            version = (ssl_major << 8) | ssl_minor;
            rr->rec_version = version;
            n2s(p, rr->length);

            /* Lets check version */
            if (!s->first_packet && version != s->version) {
                SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_WRONG_VERSION_NUMBER);
                if ((s->version & 0xFF00) == (version & 0xFF00)
                    && !s->enc_write_ctx && !s->write_hash) {
                    if (rr->type == SSL3_RT_ALERT) {
                        /*
                         * The record is using an incorrect version number, but
                         * what we've got appears to be an alert. We haven't
                         * read the body yet to check whether its a fatal or
                         * not - but chances are it is. We probably shouldn't
                         * send a fatal alert back. We'll just end.
                         */
                         goto err;
                    }
                    /*
                     * Send back error using their minor version number :-)
                     */
                    s->version = (unsigned short)version;
                }
                al = SSL_AD_PROTOCOL_VERSION;
                goto f_err;
            }

            if ((version >> 8) != SSL3_VERSION_MAJOR) {
                SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_WRONG_VERSION_NUMBER);
                goto err;
            }

            if (rr->length >
                    SSL3_BUFFER_get_len(&s->rlayer.rbuf)
                    - SSL3_RT_HEADER_LENGTH) {
                al = SSL_AD_RECORD_OVERFLOW;
                SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_PACKET_LENGTH_TOO_LONG);
                goto f_err;
            }
        }

        /* now s->rlayer.rstate == SSL_ST_READ_BODY */
    }

    /*
     * s->rlayer.rstate == SSL_ST_READ_BODY, get and decode the data.
     * Calculate how much more data we need to read for the rest of the record
     */
    if (rr->rec_version == SSL2_VERSION) {
        i = rr->length + SSL2_RT_HEADER_LENGTH - SSL3_RT_HEADER_LENGTH;
    } else {
        i = rr->length;
    }
    if (i > 0) {
        /* now s->packet_length == SSL3_RT_HEADER_LENGTH */

        n = ssl3_read_n(s, i, i, 1);
        if (n <= 0)
            return (n);         /* error or non-blocking io */
    }

    /* set state for later operations */
    RECORD_LAYER_set_rstate(&s->rlayer, SSL_ST_READ_HEADER);

    /*
     * At this point, s->packet_length == SSL3_RT_HEADER_LENGTH + rr->length,
     * or s->packet_length == SSL2_RT_HEADER_LENGTH + rr->length
     * and we have that many bytes in s->packet
     */
    if(rr->rec_version == SSL2_VERSION) {
        rr->input = &(RECORD_LAYER_get_packet(&s->rlayer)[SSL2_RT_HEADER_LENGTH]);
    } else {
        rr->input = &(RECORD_LAYER_get_packet(&s->rlayer)[SSL3_RT_HEADER_LENGTH]);
    }

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
    RECORD_LAYER_reset_packet_length(&s->rlayer);

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

/*-
 * ssl3_enc encrypts/decrypts the record in |s->wrec| / |s->rrec|, respectively.
 *
 * Returns:
 *   0: (in non-constant time) if the record is publically invalid (i.e. too
 *       short etc).
 *   1: if the record's padding is valid / the encryption was successful.
 *   -1: if the record's padding is invalid or, if sending, an internal error
 *       occurred.
 */
int ssl3_enc(SSL *s, int send)
{
    SSL3_RECORD *rec;
    EVP_CIPHER_CTX *ds;
    unsigned long l;
    int bs, i, mac_size = 0;
    const EVP_CIPHER *enc;

    if (send) {
        ds = s->enc_write_ctx;
        rec = RECORD_LAYER_get_wrec(&s->rlayer);
        if (s->enc_write_ctx == NULL)
            enc = NULL;
        else
            enc = EVP_CIPHER_CTX_cipher(s->enc_write_ctx);
    } else {
        ds = s->enc_read_ctx;
        rec = RECORD_LAYER_get_rrec(&s->rlayer);
        if (s->enc_read_ctx == NULL)
            enc = NULL;
        else
            enc = EVP_CIPHER_CTX_cipher(s->enc_read_ctx);
    }

    if ((s->session == NULL) || (ds == NULL) || (enc == NULL)) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
    } else {
        l = rec->length;
        bs = EVP_CIPHER_block_size(ds->cipher);

        /* COMPRESS */

        if ((bs != 1) && send) {
            i = bs - ((int)l % bs);

            /* we need to add 'i-1' padding bytes */
            l += i;
            /*
             * the last of these zero bytes will be overwritten with the
             * padding length.
             */
            memset(&rec->input[rec->length], 0, i);
            rec->length += i;
            rec->input[l - 1] = (i - 1);
        }

        if (!send) {
            if (l == 0 || l % bs != 0)
                return 0;
            /* otherwise, rec->length >= bs */
        }

        if (EVP_Cipher(ds, rec->data, rec->input, l) < 1)
            return -1;

        if (EVP_MD_CTX_md(s->read_hash) != NULL)
            mac_size = EVP_MD_CTX_size(s->read_hash);
        if ((bs != 1) && !send)
            return ssl3_cbc_remove_padding(s, rec, bs, mac_size);
    }
    return (1);
}

/*-
 * tls1_enc encrypts/decrypts the record in |s->wrec| / |s->rrec|, respectively.
 *
 * Returns:
 *   0: (in non-constant time) if the record is publically invalid (i.e. too
 *       short etc).
 *   1: if the record's padding is valid / the encryption was successful.
 *   -1: if the record's padding/AEAD-authenticator is invalid or, if sending,
 *       an internal error occurred.
 */
int tls1_enc(SSL *s, int send)
{
    SSL3_RECORD *rec;
    EVP_CIPHER_CTX *ds;
    unsigned long l;
    int bs, i, j, k, pad = 0, ret, mac_size = 0;
    const EVP_CIPHER *enc;

    if (send) {
        if (EVP_MD_CTX_md(s->write_hash)) {
            int n = EVP_MD_CTX_size(s->write_hash);
            OPENSSL_assert(n >= 0);
        }
        ds = s->enc_write_ctx;
        rec = RECORD_LAYER_get_wrec(&s->rlayer);
        if (s->enc_write_ctx == NULL)
            enc = NULL;
        else {
            int ivlen;
            enc = EVP_CIPHER_CTX_cipher(s->enc_write_ctx);
            /* For TLSv1.1 and later explicit IV */
            if (SSL_USE_EXPLICIT_IV(s)
                && EVP_CIPHER_mode(enc) == EVP_CIPH_CBC_MODE)
                ivlen = EVP_CIPHER_iv_length(enc);
            else
                ivlen = 0;
            if (ivlen > 1) {
                if (rec->data != rec->input)
                    /*
                     * we can't write into the input stream: Can this ever
                     * happen?? (steve)
                     */
                    fprintf(stderr,
                            "%s:%d: rec->data != rec->input\n",
                            __FILE__, __LINE__);
                else if (RAND_bytes(rec->input, ivlen) <= 0)
                    return -1;
            }
        }
    } else {
        if (EVP_MD_CTX_md(s->read_hash)) {
            int n = EVP_MD_CTX_size(s->read_hash);
            OPENSSL_assert(n >= 0);
        }
        ds = s->enc_read_ctx;
        rec = RECORD_LAYER_get_rrec(&s->rlayer);
        if (s->enc_read_ctx == NULL)
            enc = NULL;
        else
            enc = EVP_CIPHER_CTX_cipher(s->enc_read_ctx);
    }

    if ((s->session == NULL) || (ds == NULL) || (enc == NULL)) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
        ret = 1;
    } else {
        l = rec->length;
        bs = EVP_CIPHER_block_size(ds->cipher);

        if (EVP_CIPHER_flags(ds->cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
            unsigned char buf[EVP_AEAD_TLS1_AAD_LEN], *seq;

            seq = send ? RECORD_LAYER_get_write_sequence(&s->rlayer)
                : RECORD_LAYER_get_read_sequence(&s->rlayer);

            if (SSL_IS_DTLS(s)) {
                unsigned char dtlsseq[9], *p = dtlsseq;

                s2n(send ? DTLS_RECORD_LAYER_get_w_epoch(&s->rlayer) :
                    DTLS_RECORD_LAYER_get_r_epoch(&s->rlayer), p);
                memcpy(p, &seq[2], 6);
                memcpy(buf, dtlsseq, 8);
            } else {
                memcpy(buf, seq, 8);
                for (i = 7; i >= 0; i--) { /* increment */
                    ++seq[i];
                    if (seq[i] != 0)
                        break;
                }
            }

            buf[8] = rec->type;
            buf[9] = (unsigned char)(s->version >> 8);
            buf[10] = (unsigned char)(s->version);
            buf[11] = rec->length >> 8;
            buf[12] = rec->length & 0xff;
            pad = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TLS1_AAD,
                                      EVP_AEAD_TLS1_AAD_LEN, buf);
            if (pad <= 0)
                return -1;
            if (send) {
                l += pad;
                rec->length += pad;
            }
        } else if ((bs != 1) && send) {
            i = bs - ((int)l % bs);

            /* Add weird padding of upto 256 bytes */

            /* we need to add 'i' padding bytes of value j */
            j = i - 1;
            for (k = (int)l; k < (int)(l + i); k++)
                rec->input[k] = j;
            l += i;
            rec->length += i;
        }

        if (!send) {
            if (l == 0 || l % bs != 0)
                return 0;
        }

        i = EVP_Cipher(ds, rec->data, rec->input, l);
        if ((EVP_CIPHER_flags(ds->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER)
            ? (i < 0)
            : (i == 0))
            return -1;          /* AEAD can fail to verify MAC */
        if (send == 0) {
            if (EVP_CIPHER_mode(enc) == EVP_CIPH_GCM_MODE) {
                rec->data += EVP_GCM_TLS_EXPLICIT_IV_LEN;
                rec->input += EVP_GCM_TLS_EXPLICIT_IV_LEN;
                rec->length -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            } else if (EVP_CIPHER_mode(enc) == EVP_CIPH_CCM_MODE) {
                rec->data += EVP_CCM_TLS_EXPLICIT_IV_LEN;
                rec->input += EVP_CCM_TLS_EXPLICIT_IV_LEN;
                rec->length -= EVP_CCM_TLS_EXPLICIT_IV_LEN;
            }
        }

        ret = 1;
        if (!SSL_USE_ETM(s) && EVP_MD_CTX_md(s->read_hash) != NULL)
            mac_size = EVP_MD_CTX_size(s->read_hash);
        if ((bs != 1) && !send)
            ret = tls1_cbc_remove_padding(s, rec, bs, mac_size);
        if (pad && !send)
            rec->length -= pad;
    }
    return ret;
}

int n_ssl3_mac(SSL *ssl, unsigned char *md, int send)
{
    SSL3_RECORD *rec;
    unsigned char *mac_sec, *seq;
    EVP_MD_CTX md_ctx;
    const EVP_MD_CTX *hash;
    unsigned char *p, rec_char;
    size_t md_size;
    int npad;
    int t;

    if (send) {
        rec = RECORD_LAYER_get_wrec(&ssl->rlayer);
        mac_sec = &(ssl->s3->write_mac_secret[0]);
        seq = RECORD_LAYER_get_write_sequence(&ssl->rlayer);
        hash = ssl->write_hash;
    } else {
        rec = RECORD_LAYER_get_rrec(&ssl->rlayer);
        mac_sec = &(ssl->s3->read_mac_secret[0]);
        seq = RECORD_LAYER_get_read_sequence(&ssl->rlayer);
        hash = ssl->read_hash;
    }

    t = EVP_MD_CTX_size(hash);
    if (t < 0)
        return -1;
    md_size = t;
    npad = (48 / md_size) * md_size;

    if (!send &&
        EVP_CIPHER_CTX_mode(ssl->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
        ssl3_cbc_record_digest_supported(hash)) {
        /*
         * This is a CBC-encrypted record. We must avoid leaking any
         * timing-side channel information about how many blocks of data we
         * are hashing because that gives an attacker a timing-oracle.
         */

        /*-
         * npad is, at most, 48 bytes and that's with MD5:
         *   16 + 48 + 8 (sequence bytes) + 1 + 2 = 75.
         *
         * With SHA-1 (the largest hash speced for SSLv3) the hash size
         * goes up 4, but npad goes down by 8, resulting in a smaller
         * total size.
         */
        unsigned char header[75];
        unsigned j = 0;
        memcpy(header + j, mac_sec, md_size);
        j += md_size;
        memcpy(header + j, ssl3_pad_1, npad);
        j += npad;
        memcpy(header + j, seq, 8);
        j += 8;
        header[j++] = rec->type;
        header[j++] = rec->length >> 8;
        header[j++] = rec->length & 0xff;

        /* Final param == is SSLv3 */
        if (ssl3_cbc_digest_record(hash,
                                   md, &md_size,
                                   header, rec->input,
                                   rec->length + md_size, rec->orig_len,
                                   mac_sec, md_size, 1) <= 0)
            return -1;
    } else {
        unsigned int md_size_u;
        /* Chop the digest off the end :-) */
        EVP_MD_CTX_init(&md_ctx);

        rec_char = rec->type;
        p = md;
        s2n(rec->length, p);
        if (EVP_MD_CTX_copy_ex(&md_ctx, hash) <= 0
                || EVP_DigestUpdate(&md_ctx, mac_sec, md_size) <= 0
                || EVP_DigestUpdate(&md_ctx, ssl3_pad_1, npad) <= 0
                || EVP_DigestUpdate(&md_ctx, seq, 8) <= 0
                || EVP_DigestUpdate(&md_ctx, &rec_char, 1) <= 0
                || EVP_DigestUpdate(&md_ctx, md, 2) <= 0
                || EVP_DigestUpdate(&md_ctx, rec->input, rec->length) <= 0
                || EVP_DigestFinal_ex(&md_ctx, md, NULL) <= 0
                || EVP_MD_CTX_copy_ex(&md_ctx, hash) <= 0
                || EVP_DigestUpdate(&md_ctx, mac_sec, md_size) <= 0
                || EVP_DigestUpdate(&md_ctx, ssl3_pad_2, npad) <= 0
                || EVP_DigestUpdate(&md_ctx, md, md_size) <= 0
                || EVP_DigestFinal_ex(&md_ctx, md, &md_size_u) <= 0) {
            EVP_MD_CTX_cleanup(&md_ctx);
            return -1;
        }
        md_size = md_size_u;

        EVP_MD_CTX_cleanup(&md_ctx);
    }

    ssl3_record_sequence_update(seq);
    return (md_size);
}

int tls1_mac(SSL *ssl, unsigned char *md, int send)
{
    SSL3_RECORD *rec;
    unsigned char *seq;
    EVP_MD_CTX *hash;
    size_t md_size;
    int i;
    EVP_MD_CTX hmac, *mac_ctx;
    unsigned char header[13];
    int stream_mac = (send ? (ssl->mac_flags & SSL_MAC_FLAG_WRITE_MAC_STREAM)
                      : (ssl->mac_flags & SSL_MAC_FLAG_READ_MAC_STREAM));
    int t;

    if (send) {
        rec = RECORD_LAYER_get_wrec(&ssl->rlayer);
        seq = RECORD_LAYER_get_write_sequence(&ssl->rlayer);
        hash = ssl->write_hash;
    } else {
        rec = RECORD_LAYER_get_rrec(&ssl->rlayer);
        seq = RECORD_LAYER_get_read_sequence(&ssl->rlayer);
        hash = ssl->read_hash;
    }

    t = EVP_MD_CTX_size(hash);
    OPENSSL_assert(t >= 0);
    md_size = t;

    /* I should fix this up TLS TLS TLS TLS TLS XXXXXXXX */
    if (stream_mac) {
        mac_ctx = hash;
    } else {
        if (!EVP_MD_CTX_copy(&hmac, hash))
            return -1;
        mac_ctx = &hmac;
    }

    if (SSL_IS_DTLS(ssl)) {
        unsigned char dtlsseq[8], *p = dtlsseq;

        s2n(send ? DTLS_RECORD_LAYER_get_w_epoch(&ssl->rlayer) :
            DTLS_RECORD_LAYER_get_r_epoch(&ssl->rlayer), p);
        memcpy(p, &seq[2], 6);

        memcpy(header, dtlsseq, 8);
    } else
        memcpy(header, seq, 8);

    header[8] = rec->type;
    header[9] = (unsigned char)(ssl->version >> 8);
    header[10] = (unsigned char)(ssl->version);
    header[11] = (rec->length) >> 8;
    header[12] = (rec->length) & 0xff;

    if (!send && !SSL_USE_ETM(ssl) &&
        EVP_CIPHER_CTX_mode(ssl->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
        ssl3_cbc_record_digest_supported(mac_ctx)) {
        /*
         * This is a CBC-encrypted record. We must avoid leaking any
         * timing-side channel information about how many blocks of data we
         * are hashing because that gives an attacker a timing-oracle.
         */
        /* Final param == not SSLv3 */
        if (ssl3_cbc_digest_record(mac_ctx,
                                   md, &md_size,
                                   header, rec->input,
                                   rec->length + md_size, rec->orig_len,
                                   ssl->s3->read_mac_secret,
                                   ssl->s3->read_mac_secret_size, 0) <= 0) {
            if (!stream_mac)
                EVP_MD_CTX_cleanup(&hmac);
            return -1;
        }
    } else {
        if (EVP_DigestSignUpdate(mac_ctx, header, sizeof(header)) <= 0
                || EVP_DigestSignUpdate(mac_ctx, rec->input, rec->length) <= 0
                || EVP_DigestSignFinal(mac_ctx, md, &md_size) <= 0) {
            if (!stream_mac)
                EVP_MD_CTX_cleanup(&hmac);
            return -1;
        }
        if (!send && !SSL_USE_ETM(ssl) && FIPS_mode())
            tls_fips_digest_extra(ssl->enc_read_ctx,
                                  mac_ctx, rec->input,
                                  rec->length, rec->orig_len);
    }

    if (!stream_mac)
        EVP_MD_CTX_cleanup(&hmac);

#ifdef TLS_DEBUG
    fprintf(stderr, "seq=");
    {
        int z;
        for (z = 0; z < 8; z++)
            fprintf(stderr, "%02X ", seq[z]);
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "rec=");
    {
        unsigned int z;
        for (z = 0; z < rec->length; z++)
            fprintf(stderr, "%02X ", rec->data[z]);
        fprintf(stderr, "\n");
    }
#endif

    if (!SSL_IS_DTLS(ssl)) {
        for (i = 7; i >= 0; i--) {
            ++seq[i];
            if (seq[i] != 0)
                break;
        }
    }
#ifdef TLS_DEBUG
    {
        unsigned int z;
        for (z = 0; z < md_size; z++)
            fprintf(stderr, "%02X ", md[z]);
        fprintf(stderr, "\n");
    }
#endif
    return (md_size);
}

/*-
 * ssl3_cbc_remove_padding removes padding from the decrypted, SSLv3, CBC
 * record in |rec| by updating |rec->length| in constant time.
 *
 * block_size: the block size of the cipher used to encrypt the record.
 * returns:
 *   0: (in non-constant time) if the record is publicly invalid.
 *   1: if the padding was valid
 *  -1: otherwise.
 */
int ssl3_cbc_remove_padding(const SSL *s,
                            SSL3_RECORD *rec,
                            unsigned block_size, unsigned mac_size)
{
    unsigned padding_length, good;
    const unsigned overhead = 1 /* padding length byte */  + mac_size;

    /*
     * These lengths are all public so we can test them in non-constant time.
     */
    if (overhead > rec->length)
        return 0;

    padding_length = rec->data[rec->length - 1];
    good = constant_time_ge(rec->length, padding_length + overhead);
    /* SSLv3 requires that the padding is minimal. */
    good &= constant_time_ge(block_size, padding_length + 1);
    rec->length -= good & (padding_length + 1);
    return constant_time_select_int(good, 1, -1);
}

/*-
 * tls1_cbc_remove_padding removes the CBC padding from the decrypted, TLS, CBC
 * record in |rec| in constant time and returns 1 if the padding is valid and
 * -1 otherwise. It also removes any explicit IV from the start of the record
 * without leaking any timing about whether there was enough space after the
 * padding was removed.
 *
 * block_size: the block size of the cipher used to encrypt the record.
 * returns:
 *   0: (in non-constant time) if the record is publicly invalid.
 *   1: if the padding was valid
 *  -1: otherwise.
 */
int tls1_cbc_remove_padding(const SSL *s,
                            SSL3_RECORD *rec,
                            unsigned block_size, unsigned mac_size)
{
    unsigned padding_length, good, to_check, i;
    const unsigned overhead = 1 /* padding length byte */  + mac_size;
    /* Check if version requires explicit IV */
    if (SSL_USE_EXPLICIT_IV(s)) {
        /*
         * These lengths are all public so we can test them in non-constant
         * time.
         */
        if (overhead + block_size > rec->length)
            return 0;
        /* We can now safely skip explicit IV */
        rec->data += block_size;
        rec->input += block_size;
        rec->length -= block_size;
        rec->orig_len -= block_size;
    } else if (overhead > rec->length)
        return 0;

    padding_length = rec->data[rec->length - 1];

    if (EVP_CIPHER_flags(s->enc_read_ctx->cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
        /* padding is already verified */
        rec->length -= padding_length + 1;
        return 1;
    }

    good = constant_time_ge(rec->length, overhead + padding_length);
    /*
     * The padding consists of a length byte at the end of the record and
     * then that many bytes of padding, all with the same value as the length
     * byte. Thus, with the length byte included, there are i+1 bytes of
     * padding. We can't check just |padding_length+1| bytes because that
     * leaks decrypted information. Therefore we always have to check the
     * maximum amount of padding possible. (Again, the length of the record
     * is public information so we can use it.)
     */
    to_check = 255;             /* maximum amount of padding. */
    if (to_check > rec->length - 1)
        to_check = rec->length - 1;

    for (i = 0; i < to_check; i++) {
        unsigned char mask = constant_time_ge_8(padding_length, i);
        unsigned char b = rec->data[rec->length - 1 - i];
        /*
         * The final |padding_length+1| bytes should all have the value
         * |padding_length|. Therefore the XOR should be zero.
         */
        good &= ~(mask & (padding_length ^ b));
    }

    /*
     * If any of the final |padding_length+1| bytes had the wrong value, one
     * or more of the lower eight bits of |good| will be cleared.
     */
    good = constant_time_eq(0xff, good & 0xff);
    rec->length -= good & (padding_length + 1);

    return constant_time_select_int(good, 1, -1);
}

/*-
 * ssl3_cbc_copy_mac copies |md_size| bytes from the end of |rec| to |out| in
 * constant time (independent of the concrete value of rec->length, which may
 * vary within a 256-byte window).
 *
 * ssl3_cbc_remove_padding or tls1_cbc_remove_padding must be called prior to
 * this function.
 *
 * On entry:
 *   rec->orig_len >= md_size
 *   md_size <= EVP_MAX_MD_SIZE
 *
 * If CBC_MAC_ROTATE_IN_PLACE is defined then the rotation is performed with
 * variable accesses in a 64-byte-aligned buffer. Assuming that this fits into
 * a single or pair of cache-lines, then the variable memory accesses don't
 * actually affect the timing. CPUs with smaller cache-lines [if any] are
 * not multi-core and are not considered vulnerable to cache-timing attacks.
 */
#define CBC_MAC_ROTATE_IN_PLACE

void ssl3_cbc_copy_mac(unsigned char *out,
                       const SSL3_RECORD *rec, unsigned md_size)
{
#if defined(CBC_MAC_ROTATE_IN_PLACE)
    unsigned char rotated_mac_buf[64 + EVP_MAX_MD_SIZE];
    unsigned char *rotated_mac;
#else
    unsigned char rotated_mac[EVP_MAX_MD_SIZE];
#endif

    /*
     * mac_end is the index of |rec->data| just after the end of the MAC.
     */
    unsigned mac_end = rec->length;
    unsigned mac_start = mac_end - md_size;
    /*
     * scan_start contains the number of bytes that we can ignore because the
     * MAC's position can only vary by 255 bytes.
     */
    unsigned scan_start = 0;
    unsigned i, j;
    unsigned div_spoiler;
    unsigned rotate_offset;

    OPENSSL_assert(rec->orig_len >= md_size);
    OPENSSL_assert(md_size <= EVP_MAX_MD_SIZE);

#if defined(CBC_MAC_ROTATE_IN_PLACE)
    rotated_mac = rotated_mac_buf + ((0 - (size_t)rotated_mac_buf) & 63);
#endif

    /* This information is public so it's safe to branch based on it. */
    if (rec->orig_len > md_size + 255 + 1)
        scan_start = rec->orig_len - (md_size + 255 + 1);
    /*
     * div_spoiler contains a multiple of md_size that is used to cause the
     * modulo operation to be constant time. Without this, the time varies
     * based on the amount of padding when running on Intel chips at least.
     * The aim of right-shifting md_size is so that the compiler doesn't
     * figure out that it can remove div_spoiler as that would require it to
     * prove that md_size is always even, which I hope is beyond it.
     */
    div_spoiler = md_size >> 1;
    div_spoiler <<= (sizeof(div_spoiler) - 1) * 8;
    rotate_offset = (div_spoiler + mac_start - scan_start) % md_size;

    memset(rotated_mac, 0, md_size);
    for (i = scan_start, j = 0; i < rec->orig_len; i++) {
        unsigned char mac_started = constant_time_ge_8(i, mac_start);
        unsigned char mac_ended = constant_time_ge_8(i, mac_end);
        unsigned char b = rec->data[i];
        rotated_mac[j++] |= b & mac_started & ~mac_ended;
        j &= constant_time_lt(j, md_size);
    }

    /* Now rotate the MAC */
#if defined(CBC_MAC_ROTATE_IN_PLACE)
    j = 0;
    for (i = 0; i < md_size; i++) {
        /* in case cache-line is 32 bytes, touch second line */
        ((volatile unsigned char *)rotated_mac)[rotate_offset ^ 32];
        out[j++] = rotated_mac[rotate_offset++];
        rotate_offset &= constant_time_lt(rotate_offset, md_size);
    }
#else
    memset(out, 0, md_size);
    rotate_offset = md_size - rotate_offset;
    rotate_offset &= constant_time_lt(rotate_offset, md_size);
    for (i = 0; i < md_size; i++) {
        for (j = 0; j < md_size; j++)
            out[j] |= rotated_mac[i] & constant_time_eq_8(j, rotate_offset);
        rotate_offset++;
        rotate_offset &= constant_time_lt(rotate_offset, md_size);
    }
#endif
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
    rr->input = &(RECORD_LAYER_get_packet(&s->rlayer)[DTLS1_RT_HEADER_LENGTH]);

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
        RECORD_LAYER_reset_packet_length(&s->rlayer);
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
        RECORD_LAYER_reset_packet_length(&s->rlayer);
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
    RECORD_LAYER_reset_packet_length(&s->rlayer);
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
                   &(DTLS_RECORD_LAYER_get_processed_rcds(&s->rlayer)))

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
    if ((RECORD_LAYER_get_rstate(&s->rlayer) != SSL_ST_READ_BODY) ||
        (RECORD_LAYER_get_packet_length(&s->rlayer) < DTLS1_RT_HEADER_LENGTH)) {
        n = ssl3_read_n(s, DTLS1_RT_HEADER_LENGTH,
            SSL3_BUFFER_get_len(&s->rlayer.rbuf), 0);
        /* read timeout is handled by dtls1_read_bytes */
        if (n <= 0)
            return (n);         /* error or non-blocking */

        /* this packet contained a partial record, dump it */
        if (RECORD_LAYER_get_packet_length(&s->rlayer) != DTLS1_RT_HEADER_LENGTH) {
            RECORD_LAYER_reset_packet_length(&s->rlayer);
            goto again;
        }

        RECORD_LAYER_set_rstate(&s->rlayer, SSL_ST_READ_BODY);

        p = RECORD_LAYER_get_packet(&s->rlayer);

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

        memcpy(&(RECORD_LAYER_get_read_sequence(&s->rlayer)[2]), p, 6);
        p += 6;

        n2s(p, rr->length);

        /* Lets check version */
        if (!s->first_packet) {
            if (version != s->version) {
                /* unexpected version, silently discard */
                rr->length = 0;
                RECORD_LAYER_reset_packet_length(&s->rlayer);
                goto again;
            }
        }

        if ((version & 0xff00) != (s->version & 0xff00)) {
            /* wrong version, silently discard record */
            rr->length = 0;
            RECORD_LAYER_reset_packet_length(&s->rlayer);
            goto again;
        }

        if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
            /* record too long, silently discard it */
            rr->length = 0;
            RECORD_LAYER_reset_packet_length(&s->rlayer);
            goto again;
        }

        /* now s->rlayer.rstate == SSL_ST_READ_BODY */
    }

    /* s->rlayer.rstate == SSL_ST_READ_BODY, get and decode the data */

    if (rr->length >
        RECORD_LAYER_get_packet_length(&s->rlayer) - DTLS1_RT_HEADER_LENGTH) {
        /* now s->packet_length == DTLS1_RT_HEADER_LENGTH */
        i = rr->length;
        n = ssl3_read_n(s, i, i, 1);
        /* this packet contained a partial record, dump it */
        if (n != i) {
            rr->length = 0;
            RECORD_LAYER_reset_packet_length(&s->rlayer);
            goto again;
        }

        /*
         * now n == rr->length, and s->packet_length ==
         * DTLS1_RT_HEADER_LENGTH + rr->length
         */
    }
    /* set state for later operations */
    RECORD_LAYER_set_rstate(&s->rlayer, SSL_ST_READ_HEADER);

    /* match epochs.  NULL means the packet is dropped on the floor */
    bitmap = dtls1_get_bitmap(s, rr, &is_next_epoch);
    if (bitmap == NULL) {
        rr->length = 0;
        RECORD_LAYER_reset_packet_length(&s->rlayer);   /* dump this record */
        goto again;             /* get another record */
    }
#ifndef OPENSSL_NO_SCTP
    /* Only do replay check if no SCTP bio */
    if (!BIO_dgram_is_sctp(SSL_get_rbio(s))) {
#endif
        /* Check whether this is a repeat, or aged record. */
        if (!dtls1_record_replay_check(s, bitmap)) {
            rr->length = 0;
            RECORD_LAYER_reset_packet_length(&s->rlayer); /* dump this record */
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
     * processed at this time.
     */
    if (is_next_epoch) {
        if ((SSL_in_init(s) || ossl_statem_get_in_handshake(s))) {
            if (dtls1_buffer_record
                (s, &(DTLS_RECORD_LAYER_get_unprocessed_rcds(&s->rlayer)),
                rr->seq_num) < 0)
                return -1;
            /* Mark receipt of record. */
            dtls1_record_bitmap_update(s, bitmap);
        }
        rr->length = 0;
        RECORD_LAYER_reset_packet_length(&s->rlayer);
        goto again;
    }

    if (!dtls1_process_record(s)) {
        rr->length = 0;
        RECORD_LAYER_reset_packet_length(&s->rlayer);   /* dump this record */
        goto again;             /* get another record */
    }
    dtls1_record_bitmap_update(s, bitmap); /* Mark receipt of record. */

    return (1);

}
