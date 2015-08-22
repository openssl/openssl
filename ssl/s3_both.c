/* ssl/s3_both.c */
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
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/*
 * send s->init_buf in records of type 'type' (SSL3_RT_HANDSHAKE or
 * SSL3_RT_CHANGE_CIPHER_SPEC)
 */
int ssl3_do_write(SSL *s, int type)
{
    int ret;

    ret = ssl3_write_bytes(s, type, &s->init_buf->data[s->init_off],
                           s->init_num);
    if (ret < 0)
        return (-1);
    if (type == SSL3_RT_HANDSHAKE)
        /*
         * should not be done for 'Hello Request's, but in that case we'll
         * ignore the result anyway
         */
        ssl3_finish_mac(s, (unsigned char *)&s->init_buf->data[s->init_off],
                        ret);

    if (ret == s->init_num) {
        if (s->msg_callback)
            s->msg_callback(1, s->version, type, s->init_buf->data,
                            (size_t)(s->init_off + s->init_num), s,
                            s->msg_callback_arg);
        return (1);
    }
    s->init_off += ret;
    s->init_num -= ret;
    return (0);
}

int ssl3_send_finished(SSL *s, int a, int b, const char *sender, int slen)
{
    unsigned char *p;
    int i;
    unsigned long l;

    if (s->state == a) {
        p = ssl_handshake_start(s);

        i = s->method->ssl3_enc->final_finish_mac(s,
                                                  sender, slen,
                                                  s->s3->tmp.finish_md);
        if (i <= 0)
            return 0;
        s->s3->tmp.finish_md_len = i;
        memcpy(p, s->s3->tmp.finish_md, i);
        l = i;

        /*
         * Copy the finished so we can use it for renegotiation checks
         */
        if (s->type == SSL_ST_CONNECT) {
            OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
            memcpy(s->s3->previous_client_finished, s->s3->tmp.finish_md, i);
            s->s3->previous_client_finished_len = i;
        } else {
            OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
            memcpy(s->s3->previous_server_finished, s->s3->tmp.finish_md, i);
            s->s3->previous_server_finished_len = i;
        }

        if (!ssl_set_handshake_header(s, SSL3_MT_FINISHED, l)) {
            SSLerr(SSL_F_SSL3_SEND_FINISHED, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        s->state = b;
    }

    /* SSL3_ST_SEND_xxxxxx_HELLO_B */
    return ssl_do_write(s);
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * ssl3_take_mac calculates the Finished MAC for the handshakes messages seen
 * to far.
 */
static void ssl3_take_mac(SSL *s)
{
    const char *sender;
    int slen;
    /*
     * If no new cipher setup return immediately: other functions will set
     * the appropriate error.
     */
    if (s->s3->tmp.new_cipher == NULL)
        return;
    if (s->state & SSL_ST_CONNECT) {
        sender = s->method->ssl3_enc->server_finished_label;
        slen = s->method->ssl3_enc->server_finished_label_len;
    } else {
        sender = s->method->ssl3_enc->client_finished_label;
        slen = s->method->ssl3_enc->client_finished_label_len;
    }

    s->s3->tmp.peer_finish_md_len = s->method->ssl3_enc->final_finish_mac(s,
                                                                          sender,
                                                                          slen,
                                                                          s->s3->tmp.peer_finish_md);
}
#endif

int ssl3_get_change_cipher_spec(SSL *s, int a, int b)
{
    int ok, al;
    long n;

    n = s->method->ssl_get_message(s, a, b, SSL3_MT_CHANGE_CIPHER_SPEC, 1, &ok);

    if (!ok)
        return ((int)n);

    /*
     * 'Change Cipher Spec' is just a single byte, which should already have
     * been consumed by ssl_get_message() so there should be no bytes left,
     * unless we're using DTLS1_BAD_VER, which has an extra 2 bytes
     */
    if (SSL_IS_DTLS(s)) {
        if ((s->version == DTLS1_BAD_VER && n != DTLS1_CCS_HEADER_LENGTH + 1)
                    || (s->version != DTLS1_BAD_VER
                        && n != DTLS1_CCS_HEADER_LENGTH - 1)) {
                al = SSL_AD_ILLEGAL_PARAMETER;
                SSLerr(SSL_F_SSL3_GET_CHANGE_CIPHER_SPEC, SSL_R_BAD_CHANGE_CIPHER_SPEC);
                goto f_err;
        }
    } else {
        if (n != 0) {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_CHANGE_CIPHER_SPEC, SSL_R_BAD_CHANGE_CIPHER_SPEC);
            goto f_err;
        }
    }

    /* Check we have a cipher to change to */
    if (s->s3->tmp.new_cipher == NULL) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_CHANGE_CIPHER_SPEC, SSL_R_CCS_RECEIVED_EARLY);
        goto f_err;
    }

    s->s3->change_cipher_spec = 1;
    if (!ssl3_do_change_cipher_spec(s)) {
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_GET_CHANGE_CIPHER_SPEC, ERR_R_INTERNAL_ERROR);
        goto f_err;
    }

    if (SSL_IS_DTLS(s)) {
        dtls1_reset_seq_numbers(s, SSL3_CC_READ);

        if (s->version == DTLS1_BAD_VER)
            s->d1->handshake_read_seq++;

#ifndef OPENSSL_NO_SCTP
        /*
         * Remember that a CCS has been received, so that an old key of
         * SCTP-Auth can be deleted when a CCS is sent. Will be ignored if no
         * SCTP is used
         */
        BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD, 1, NULL);
#endif
    }

    return 1;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    return 0;
}


int ssl3_get_finished(SSL *s, int a, int b)
{
    int al, i, ok;
    long n;
    unsigned char *p;

#ifdef OPENSSL_NO_NEXTPROTONEG
    /*
     * the mac has already been generated when we received the change cipher
     * spec message and is in s->s3->tmp.peer_finish_md
     */
#endif

    /* 64 argument should actually be 36+4 :-) */
    n = s->method->ssl_get_message(s, a, b, SSL3_MT_FINISHED, 64, &ok);

    if (!ok)
        return ((int)n);

    /* If this occurs, we have missed a message */
    if (!s->s3->change_cipher_spec) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_FINISHED, SSL_R_GOT_A_FIN_BEFORE_A_CCS);
        goto f_err;
    }
    s->s3->change_cipher_spec = 0;

    p = (unsigned char *)s->init_msg;
    i = s->s3->tmp.peer_finish_md_len;

    if (i != n) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_FINISHED, SSL_R_BAD_DIGEST_LENGTH);
        goto f_err;
    }

    if (CRYPTO_memcmp(p, s->s3->tmp.peer_finish_md, i) != 0) {
        al = SSL_AD_DECRYPT_ERROR;
        SSLerr(SSL_F_SSL3_GET_FINISHED, SSL_R_DIGEST_CHECK_FAILED);
        goto f_err;
    }

    /*
     * Copy the finished so we can use it for renegotiation checks
     */
    if (s->type == SSL_ST_ACCEPT) {
        OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
        memcpy(s->s3->previous_client_finished, s->s3->tmp.peer_finish_md, i);
        s->s3->previous_client_finished_len = i;
    } else {
        OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
        memcpy(s->s3->previous_server_finished, s->s3->tmp.peer_finish_md, i);
        s->s3->previous_server_finished_len = i;
    }

    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    return (0);
}

/*-
 * for these 2 messages, we need to
 * ssl->enc_read_ctx                    re-init
 * ssl->rlayer.read_sequence            zero
 * ssl->s3->read_mac_secret             re-init
 * ssl->session->read_sym_enc           assign
 * ssl->session->read_compression       assign
 * ssl->session->read_hash              assign
 */
int ssl3_send_change_cipher_spec(SSL *s, int a, int b)
{
    unsigned char *p;

    if (s->state == a) {
        p = (unsigned char *)s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;

        s->state = b;
    }

    /* SSL3_ST_CW_CHANGE_B */
    return (ssl3_do_write(s, SSL3_RT_CHANGE_CIPHER_SPEC));
}

unsigned long ssl3_output_cert_chain(SSL *s, CERT_PKEY *cpk)
{
    unsigned char *p;
    unsigned long l = 3 + SSL_HM_HEADER_LENGTH(s);

    if (!ssl_add_cert_chain(s, cpk, &l))
        return 0;

    l -= 3 + SSL_HM_HEADER_LENGTH(s);
    p = ssl_handshake_start(s);
    l2n3(l, p);
    l += 3;

    if (!ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE, l)) {
        SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return l + SSL_HM_HEADER_LENGTH(s);
}

/*
 * Obtain handshake message of message type 'mt' (any if mt == -1), maximum
 * acceptable body length 'max'. The first four bytes (msg_type and length)
 * are read in state 'st1', the body is read in state 'stn'.
 */
long ssl3_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok)
{
    unsigned char *p;
    unsigned long l;
    long n;
    int i, al, recvd_type;

    if (s->s3->tmp.reuse_message) {
        s->s3->tmp.reuse_message = 0;
        if ((mt >= 0) && (s->s3->tmp.message_type != mt)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }
        *ok = 1;
        s->state = stn;
        s->init_msg = s->init_buf->data + SSL3_HM_HEADER_LENGTH;
        s->init_num = (int)s->s3->tmp.message_size;
        return s->init_num;
    }

    p = (unsigned char *)s->init_buf->data;

    if (s->state == st1) {
        /* s->init_num < SSL3_HM_HEADER_LENGTH */
        int skip_message;

        do {
            while (s->init_num < SSL3_HM_HEADER_LENGTH) {
                i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE, &recvd_type,
                    &p[s->init_num], SSL3_HM_HEADER_LENGTH - s->init_num, 0);
                if (i <= 0) {
                    s->rwstate = SSL_READING;
                    *ok = 0;
                    return i;
                }
                if (s->init_num == 0
                        && recvd_type == SSL3_RT_CHANGE_CIPHER_SPEC
                        && (mt < 0 || mt == SSL3_MT_CHANGE_CIPHER_SPEC)) {
                    if (*p != SSL3_MT_CCS) {
                        al = SSL_AD_UNEXPECTED_MESSAGE;
                        SSLerr(SSL_F_SSL3_GET_MESSAGE,
                               SSL_R_UNEXPECTED_MESSAGE);
                        goto f_err;
                    }
                    s->init_num = i - 1;
                    s->init_msg = p + 1;
                    s->s3->tmp.message_type = SSL3_MT_CHANGE_CIPHER_SPEC;
                    s->s3->tmp.message_size = i - 1;
                    s->state = stn;
                    *ok = 1;
                    if (s->msg_callback)
                        s->msg_callback(0, s->version,
                                        SSL3_RT_CHANGE_CIPHER_SPEC, p, 1, s,
                                        s->msg_callback_arg);
                    return i - 1;
                } else if (recvd_type != SSL3_RT_HANDSHAKE) {
                    al = SSL_AD_UNEXPECTED_MESSAGE;
                    SSLerr(SSL_F_SSL3_GET_MESSAGE, SSL_R_CCS_RECEIVED_EARLY);
                    goto f_err;
                }
                s->init_num += i;
            }

            skip_message = 0;
            if (!s->server)
                if (p[0] == SSL3_MT_HELLO_REQUEST)
                    /*
                     * The server may always send 'Hello Request' messages --
                     * we are doing a handshake anyway now, so ignore them if
                     * their format is correct. Does not count for 'Finished'
                     * MAC.
                     */
                    if (p[1] == 0 && p[2] == 0 && p[3] == 0) {
                        s->init_num = 0;
                        skip_message = 1;

                        if (s->msg_callback)
                            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                                            p, SSL3_HM_HEADER_LENGTH, s,
                                            s->msg_callback_arg);
                    }
        } while (skip_message);
        /* s->init_num == SSL3_HM_HEADER_LENGTH */

        if ((mt >= 0) && (*p != mt)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }

        s->s3->tmp.message_type = *(p++);

        if(RECORD_LAYER_is_sslv2_record(&s->rlayer)) {
            /*
             * Only happens with SSLv3+ in an SSLv2 backward compatible
             * ClientHello
             */
             /*
              * Total message size is the remaining record bytes to read
              * plus the SSL3_HM_HEADER_LENGTH bytes that we already read
              */
            l = RECORD_LAYER_get_rrec_length(&s->rlayer)
                + SSL3_HM_HEADER_LENGTH;
            if (l && !BUF_MEM_grow_clean(s->init_buf, (int)l)) {
                SSLerr(SSL_F_SSL3_GET_MESSAGE, ERR_R_BUF_LIB);
                goto err;
            }
            s->s3->tmp.message_size = l;
            s->state = stn;

            s->init_msg = s->init_buf->data;
            s->init_num = SSL3_HM_HEADER_LENGTH;
        } else {
            n2l3(p, l);
            if (l > (unsigned long)max) {
                al = SSL_AD_ILLEGAL_PARAMETER;
                SSLerr(SSL_F_SSL3_GET_MESSAGE, SSL_R_EXCESSIVE_MESSAGE_SIZE);
                goto f_err;
            }
            /* BUF_MEM_grow takes an 'int' parameter */
            if (l > (INT_MAX - SSL3_HM_HEADER_LENGTH)) {
                al = SSL_AD_ILLEGAL_PARAMETER;
                SSLerr(SSL_F_SSL3_GET_MESSAGE, SSL_R_EXCESSIVE_MESSAGE_SIZE);
                goto f_err;
            }
            if (l && !BUF_MEM_grow_clean(s->init_buf,
                                        (int)l + SSL3_HM_HEADER_LENGTH)) {
                SSLerr(SSL_F_SSL3_GET_MESSAGE, ERR_R_BUF_LIB);
                goto err;
            }
            s->s3->tmp.message_size = l;
            s->state = stn;

            s->init_msg = s->init_buf->data + SSL3_HM_HEADER_LENGTH;
            s->init_num = 0;
        }
    }

    /* next state (stn) */
    p = s->init_msg;
    n = s->s3->tmp.message_size - s->init_num;
    while (n > 0) {
        i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE, NULL,
                                      &p[s->init_num], n, 0);
        if (i <= 0) {
            s->rwstate = SSL_READING;
            *ok = 0;
            return i;
        }
        s->init_num += i;
        n -= i;
    }

#ifndef OPENSSL_NO_NEXTPROTONEG
    /*
     * If receiving Finished, record MAC of prior handshake messages for
     * Finished verification.
     */
    if (*s->init_buf->data == SSL3_MT_FINISHED)
        ssl3_take_mac(s);
#endif

    /* Feed this message into MAC computation. */
    if(RECORD_LAYER_is_sslv2_record(&s->rlayer)) {
        ssl3_finish_mac(s, (unsigned char *)s->init_buf->data, s->init_num);
        if (s->msg_callback)
            s->msg_callback(0, SSL2_VERSION, 0,  s->init_buf->data,
                            (size_t)s->init_num, s, s->msg_callback_arg);
    } else {
        ssl3_finish_mac(s, (unsigned char *)s->init_buf->data,
            s->init_num + SSL3_HM_HEADER_LENGTH);
        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, s->init_buf->data,
                            (size_t)s->init_num + SSL3_HM_HEADER_LENGTH, s,
                            s->msg_callback_arg);
    }

    *ok = 1;
    return s->init_num;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    *ok = 0;
    return (-1);
}

int ssl_cert_type(X509 *x, EVP_PKEY *pkey)
{
    EVP_PKEY *pk;
    int ret = -1, i;

    if (pkey == NULL)
        pk = X509_get_pubkey(x);
    else
        pk = pkey;
    if (pk == NULL)
        goto err;

    i = pk->type;
    if (i == EVP_PKEY_RSA) {
        ret = SSL_PKEY_RSA_ENC;
    } else if (i == EVP_PKEY_DSA) {
        ret = SSL_PKEY_DSA_SIGN;
    }
#ifndef OPENSSL_NO_EC
    else if (i == EVP_PKEY_EC) {
        ret = SSL_PKEY_ECC;
    }
#endif
    else if (i == NID_id_GostR3410_2001) {
        ret = SSL_PKEY_GOST01;
    } else if (x && (i == EVP_PKEY_DH || i == EVP_PKEY_DHX)) {
        /*
         * For DH two cases: DH certificate signed with RSA and DH
         * certificate signed with DSA.
         */
        i = X509_certificate_type(x, pk);
        if (i & EVP_PKS_RSA)
            ret = SSL_PKEY_DH_RSA;
        else if (i & EVP_PKS_DSA)
            ret = SSL_PKEY_DH_DSA;
    }

 err:
    if (!pkey)
        EVP_PKEY_free(pk);
    return (ret);
}

int ssl_verify_alarm_type(long type)
{
    int al;

    switch (type) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_CRL:
    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
        al = SSL_AD_UNKNOWN_CA;
        break;
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CERT_UNTRUSTED:
    case X509_V_ERR_CERT_REJECTED:
        al = SSL_AD_BAD_CERTIFICATE;
        break;
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        al = SSL_AD_DECRYPT_ERROR;
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CRL_HAS_EXPIRED:
        al = SSL_AD_CERTIFICATE_EXPIRED;
        break;
    case X509_V_ERR_CERT_REVOKED:
        al = SSL_AD_CERTIFICATE_REVOKED;
        break;
    case X509_V_ERR_OUT_OF_MEM:
        al = SSL_AD_INTERNAL_ERROR;
        break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    case X509_V_ERR_INVALID_CA:
        al = SSL_AD_UNKNOWN_CA;
        break;
    case X509_V_ERR_APPLICATION_VERIFICATION:
        al = SSL_AD_HANDSHAKE_FAILURE;
        break;
    case X509_V_ERR_INVALID_PURPOSE:
        al = SSL_AD_UNSUPPORTED_CERTIFICATE;
        break;
    default:
        al = SSL_AD_CERTIFICATE_UNKNOWN;
        break;
    }
    return (al);
}

int ssl_allow_compression(SSL *s)
{
    if (s->options & SSL_OP_NO_COMPRESSION)
        return 0;
    return ssl_security(s, SSL_SECOP_COMPRESSION, 0, 0, NULL);
}
