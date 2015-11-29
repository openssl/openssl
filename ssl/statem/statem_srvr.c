/* ssl/statem/statem_srvr.c -*- mode:C; c-file-style: "eay" -*- */
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
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */


#include <stdio.h>
#include "../ssl_locl.h"
#include "statem_locl.h"
#include "internal/constant_time_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#include <openssl/bn.h>
#include <openssl/md5.h>

static STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list(SSL *s,
                                                      PACKET *cipher_suites,
                                                      STACK_OF(SSL_CIPHER) **skp,
                                                      int sslv2format, int *al);

/*
 * server_read_transition() encapsulates the logic for the allowed handshake
 * state transitions when the server is reading messages from the client. The
 * message type that the client has sent is provided in |mt|. The current state
 * is in |s->statem.hand_state|.
 *
 *  Valid return values are:
 *  1: Success (transition allowed)
 *  0: Error (transition not allowed)
 */
int ossl_statem_server_read_transition(SSL *s, int mt)
{
    OSSL_STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_BEFORE:
    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        if (mt == SSL3_MT_CLIENT_HELLO) {
            st->hand_state = TLS_ST_SR_CLNT_HELLO;
            return 1;
        }
        break;

    case TLS_ST_SW_SRVR_DONE:
        /*
         * If we get a CKE message after a ServerDone then either
         * 1) We didn't request a Certificate
         * OR
         * 2) If we did request one then
         *      a) We allow no Certificate to be returned
         *      AND
         *      b) We are running SSL3 (in TLS1.0+ the client must return a 0
         *         list if we requested a certificate)
         */
        if (mt == SSL3_MT_CLIENT_KEY_EXCHANGE
                && (!s->s3->tmp.cert_request
                    || (!((s->verify_mode & SSL_VERIFY_PEER) &&
                          (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))
                        && (s->version == SSL3_VERSION)))) {
            st->hand_state = TLS_ST_SR_KEY_EXCH;
            return 1;
        } else if (s->s3->tmp.cert_request) {
            if (mt == SSL3_MT_CERTIFICATE) {
                st->hand_state = TLS_ST_SR_CERT;
                return 1;
            } 
        }
        break;

    case TLS_ST_SR_CERT:
        if (mt == SSL3_MT_CLIENT_KEY_EXCHANGE) {
            st->hand_state = TLS_ST_SR_KEY_EXCH;
            return 1;
        }
        break;

    case TLS_ST_SR_KEY_EXCH:
        /*
         * We should only process a CertificateVerify message if we have
         * received a Certificate from the client. If so then |s->session->peer|
         * will be non NULL. In some instances a CertificateVerify message is
         * not required even if the peer has sent a Certificate (e.g. such as in
         * the case of static DH). In that case |st->no_cert_verify| should be
         * set.
         */
        if (s->session->peer == NULL || st->no_cert_verify) {
            if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
                /*
                 * For the ECDH ciphersuites when the client sends its ECDH
                 * pub key in a certificate, the CertificateVerify message is
                 * not sent. Also for GOST ciphersuites when the client uses
                 * its key from the certificate for key exchange.
                 */
                st->hand_state = TLS_ST_SR_CHANGE;
                return 1;
            }
        } else {
            if (mt == SSL3_MT_CERTIFICATE_VERIFY) {
                st->hand_state = TLS_ST_SR_CERT_VRFY;
                return 1;
            }
        }
        break;

    case TLS_ST_SR_CERT_VRFY:
        if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_SR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_SR_CHANGE:
#ifndef OPENSSL_NO_NEXTPROTONEG
        if (s->s3->next_proto_neg_seen) {
            if (mt == SSL3_MT_NEXT_PROTO) {
                st->hand_state = TLS_ST_SR_NEXT_PROTO;
                return 1;
            }
        } else {
#endif
            if (mt == SSL3_MT_FINISHED) {
                st->hand_state = TLS_ST_SR_FINISHED;
                return 1;
            }
#ifndef OPENSSL_NO_NEXTPROTONEG
        }
#endif
        break;

#ifndef OPENSSL_NO_NEXTPROTONEG
    case TLS_ST_SR_NEXT_PROTO:
        if (mt == SSL3_MT_FINISHED) {
            st->hand_state = TLS_ST_SR_FINISHED;
            return 1;
        }
        break;
#endif

    case TLS_ST_SW_FINISHED:
        if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_SR_CHANGE;
            return 1;
        }
        break;

    default:
        break;
    }

    /* No valid transition found */
    return 0;
}

/*
 * Should we send a ServerKeyExchange message?
 *
 * Valid return values are:
 *   1: Yes
 *   0: No
 */
static int send_server_key_exchange(SSL *s)
{
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    /*
     * only send a ServerKeyExchange if DH, fortezza or RSA but we have a
     * sign only certificate PSK: may send PSK identity hints For
     * ECC ciphersuites, we send a serverKeyExchange message only if
     * the cipher suite is either ECDH-anon or ECDHE. In other cases,
     * the server certificate contains the server's public key for
     * key exchange.
     */
    if (   (alg_k & SSL_kDHE)
        || (alg_k & SSL_kECDHE)
        || ((alg_k & SSL_kRSA)
            && (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL
                || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)
                    && EVP_PKEY_size(s->cert->pkeys
                                     [SSL_PKEY_RSA_ENC].privatekey) *
                    8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)
                   )
               )
           )
        /*
         * PSK: send ServerKeyExchange if PSK identity hint if
         * provided
         */
#ifndef OPENSSL_NO_PSK
        /* Only send SKE if we have identity hint for plain PSK */
        || ((alg_k & (SSL_kPSK | SSL_kRSAPSK))
            && s->cert->psk_identity_hint)
        /* For other PSK always send SKE */
        || (alg_k & (SSL_PSK & (SSL_kDHEPSK | SSL_kECDHEPSK)))
#endif
#ifndef OPENSSL_NO_SRP
        /* SRP: send ServerKeyExchange */
        || (alg_k & SSL_kSRP)
#endif
       ) {
        return 1;
    }

    return 0;
}

/*
 * Should we send a CertificateRequest message?
 *
 * Valid return values are:
 *   1: Yes
 *   0: No
 */
static int send_certificate_request(SSL *s)
{
    if (
           /* don't request cert unless asked for it: */
           s->verify_mode & SSL_VERIFY_PEER
           /*
            * if SSL_VERIFY_CLIENT_ONCE is set, don't request cert
            * during re-negotiation:
            */
           && ((s->session->peer == NULL) ||
               !(s->verify_mode & SSL_VERIFY_CLIENT_ONCE))
           /*
            * never request cert in anonymous ciphersuites (see
            * section "Certificate request" in SSL 3 drafts and in
            * RFC 2246):
            */
           && (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)
           /*
            * ... except when the application insists on
            * verification (against the specs, but s3_clnt.c accepts
            * this for SSL 3)
            */
               || (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))
           /* don't request certificate for SRP auth */
           && !(s->s3->tmp.new_cipher->algorithm_auth & SSL_aSRP)
           /*
            * With normal PSK Certificates and Certificate Requests
            * are omitted
            */
           && !(s->s3->tmp.new_cipher->algorithm_auth & SSL_aPSK)) {
        return 1;
    }

    return 0;
}

/*
 * server_write_transition() works out what handshake state to move to next
 * when the server is writing messages to be sent to the client.
 */
WRITE_TRAN ossl_statem_server_write_transition(SSL *s)
{
    OSSL_STATEM *st = &s->statem;

    switch(st->hand_state) {
        case TLS_ST_BEFORE:
            /* Just go straight to trying to read from the client */;
            return WRITE_TRAN_FINISHED;

        case TLS_ST_OK:
            /* We must be trying to renegotiate */
            st->hand_state = TLS_ST_SW_HELLO_REQ;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_HELLO_REQ:
            st->hand_state = TLS_ST_OK;
            ossl_statem_set_in_init(s, 0);
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SR_CLNT_HELLO:
            if (SSL_IS_DTLS(s) && !s->d1->cookie_verified
                    && (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE))
                st->hand_state = DTLS_ST_SW_HELLO_VERIFY_REQUEST;
            else
                st->hand_state = TLS_ST_SW_SRVR_HELLO;
            return WRITE_TRAN_CONTINUE;

        case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
            return WRITE_TRAN_FINISHED;

        case TLS_ST_SW_SRVR_HELLO:
            if (s->hit) {
                if (s->tlsext_ticket_expected)
                    st->hand_state = TLS_ST_SW_SESSION_TICKET;
                else
                    st->hand_state = TLS_ST_SW_CHANGE;
            } else {
                /* Check if it is anon DH or anon ECDH, */
                /* normal PSK or SRP */
                if (!(s->s3->tmp.new_cipher->algorithm_auth &
                     (SSL_aNULL | SSL_aSRP | SSL_aPSK))) {
                    st->hand_state = TLS_ST_SW_CERT;
                } else if (send_server_key_exchange(s)) {
                    st->hand_state = TLS_ST_SW_KEY_EXCH;
                } else if (send_certificate_request(s)) {
                    st->hand_state = TLS_ST_SW_CERT_REQ;
                } else {
                    st->hand_state = TLS_ST_SW_SRVR_DONE;
                }
            }
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_CERT:
            if (s->tlsext_status_expected) {
                st->hand_state = TLS_ST_SW_CERT_STATUS;
                return WRITE_TRAN_CONTINUE;
            }
            /* Fall through */

        case TLS_ST_SW_CERT_STATUS:
            if (send_server_key_exchange(s)) {
                st->hand_state = TLS_ST_SW_KEY_EXCH;
                return WRITE_TRAN_CONTINUE;
            }
            /* Fall through */

        case TLS_ST_SW_KEY_EXCH:
            if (send_certificate_request(s)) {
                st->hand_state = TLS_ST_SW_CERT_REQ;
                return WRITE_TRAN_CONTINUE;
            }
            /* Fall through */

        case TLS_ST_SW_CERT_REQ:
            st->hand_state = TLS_ST_SW_SRVR_DONE;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_SRVR_DONE:
            return WRITE_TRAN_FINISHED;

        case TLS_ST_SR_FINISHED:
            if (s->hit) {
                st->hand_state = TLS_ST_OK;
                ossl_statem_set_in_init(s, 0);
                return WRITE_TRAN_CONTINUE;
            } else if (s->tlsext_ticket_expected) {
                st->hand_state = TLS_ST_SW_SESSION_TICKET;
            } else {
                st->hand_state = TLS_ST_SW_CHANGE;
            }
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_SESSION_TICKET:
            st->hand_state = TLS_ST_SW_CHANGE;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_CHANGE:
            st->hand_state = TLS_ST_SW_FINISHED;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_FINISHED:
            if (s->hit) {
                return WRITE_TRAN_FINISHED;
            }
            st->hand_state = TLS_ST_OK;
            ossl_statem_set_in_init(s, 0);
            return WRITE_TRAN_CONTINUE;

        default:
            /* Shouldn't happen */
            return WRITE_TRAN_ERROR;
    }
}

/*
 * Perform any pre work that needs to be done prior to sending a message from
 * the server to the client.
 */
WORK_STATE ossl_statem_server_pre_work(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_SW_HELLO_REQ:
        s->shutdown = 0;
        if (SSL_IS_DTLS(s))
            dtls1_clear_record_buffer(s);
        break;

    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        s->shutdown = 0;
        if (SSL_IS_DTLS(s)) {
            dtls1_clear_record_buffer(s);
            /* We don't buffer this message so don't use the timer */
            st->use_timer = 0;
        }
        break;

    case TLS_ST_SW_SRVR_HELLO:
        if (SSL_IS_DTLS(s)) {
            /*
             * Messages we write from now on should be bufferred and
             * retransmitted if necessary, so we need to use the timer now
             */
            st->use_timer = 1;
        }
        break;

    case TLS_ST_SW_SRVR_DONE:
#ifndef OPENSSL_NO_SCTP
        if (SSL_IS_DTLS(s) && BIO_dgram_is_sctp(SSL_get_wbio(s)))
            return dtls_wait_for_dry(s);
#endif
        return WORK_FINISHED_CONTINUE;

    case TLS_ST_SW_SESSION_TICKET:
        if (SSL_IS_DTLS(s)) {
            /*
             * We're into the last flight. We don't retransmit the last flight
             * unless we need to, so we don't use the timer
             */
            st->use_timer = 0;
        }
        break;

    case TLS_ST_SW_CHANGE:
        s->session->cipher = s->s3->tmp.new_cipher;
        if (!s->method->ssl3_enc->setup_key_block(s)) {
            ossl_statem_set_error(s);
            return WORK_ERROR;
        }
        if (SSL_IS_DTLS(s)) {
            /*
             * We're into the last flight. We don't retransmit the last flight
             * unless we need to, so we don't use the timer. This might have
             * already been set to 0 if we sent a NewSessionTicket message,
             * but we'll set it again here in case we didn't.
             */
            st->use_timer = 0;
        }
        return WORK_FINISHED_CONTINUE;

    case TLS_ST_OK:
        return tls_finish_handshake(s, wst);

    default:
        /* No pre work to be done */
        break;
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Perform any work that needs to be done after sending a message from the
 * server to the client.
 */
WORK_STATE ossl_statem_server_post_work(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    s->init_num = 0;

    switch(st->hand_state) {
    case TLS_ST_SW_HELLO_REQ:
        if (statem_flush(s) != 1)
            return WORK_MORE_A;
        ssl3_init_finished_mac(s);
        break;

    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        if (statem_flush(s) != 1)
            return WORK_MORE_A;
        /* HelloVerifyRequest resets Finished MAC */
        if (s->version != DTLS1_BAD_VER)
            ssl3_init_finished_mac(s);
        /*
         * The next message should be another ClientHello which we need to
         * treat like it was the first packet
         */
        s->first_packet = 1;
        break;

    case TLS_ST_SW_SRVR_HELLO:
#ifndef OPENSSL_NO_SCTP
        if (SSL_IS_DTLS(s) && s->hit) {
            unsigned char sctpauthkey[64];
            char labelbuffer[sizeof(DTLS1_SCTP_AUTH_LABEL)];

            /*
             * Add new shared key for SCTP-Auth, will be ignored if no
             * SCTP used.
             */
            memcpy(labelbuffer, DTLS1_SCTP_AUTH_LABEL,
                   sizeof(DTLS1_SCTP_AUTH_LABEL));

            if (SSL_export_keying_material(s, sctpauthkey,
                    sizeof(sctpauthkey), labelbuffer,
                    sizeof(labelbuffer), NULL, 0, 0) <= 0) {
                ossl_statem_set_error(s);
                return WORK_ERROR;
            }

            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                     sizeof(sctpauthkey), sctpauthkey);
        }
#endif
        break;

    case TLS_ST_SW_CHANGE:
#ifndef OPENSSL_NO_SCTP
        if (SSL_IS_DTLS(s) && !s->hit) {
            /*
             * Change to new shared key of SCTP-Auth, will be ignored if
             * no SCTP used.
             */
            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                     0, NULL);
        }
#endif
        if (!s->method->ssl3_enc->change_cipher_state(s,
                SSL3_CHANGE_CIPHER_SERVER_WRITE)) {
            ossl_statem_set_error(s);
            return WORK_ERROR;
        }

        if (SSL_IS_DTLS(s))
            dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
        break;

    case TLS_ST_SW_SRVR_DONE:
        if (statem_flush(s) != 1)
            return WORK_MORE_A;
        break;

    case TLS_ST_SW_FINISHED:
        if (statem_flush(s) != 1)
            return WORK_MORE_A;
#ifndef OPENSSL_NO_SCTP
        if (SSL_IS_DTLS(s) && s->hit) {
            /*
             * Change to new shared key of SCTP-Auth, will be ignored if
             * no SCTP used.
             */
            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                     0, NULL);
        }
#endif
        break;

    default:
        /* No post work to be done */
        break;
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Construct a message to be sent from the server to the client.
 *
 * Valid return values are:
 *   1: Success
 *   0: Error
 */
int ossl_statem_server_construct_message(SSL *s)
{
    OSSL_STATEM *st = &s->statem;

    switch(st->hand_state) {
    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        return dtls_construct_hello_verify_request(s);

    case TLS_ST_SW_HELLO_REQ:
        return tls_construct_hello_request(s);

    case TLS_ST_SW_SRVR_HELLO:
        return tls_construct_server_hello(s);

    case TLS_ST_SW_CERT:
        return tls_construct_server_certificate(s);

    case TLS_ST_SW_KEY_EXCH:
        return tls_construct_server_key_exchange(s);

    case TLS_ST_SW_CERT_REQ:
        return tls_construct_certificate_request(s);

    case TLS_ST_SW_SRVR_DONE:
        return tls_construct_server_done(s);

    case TLS_ST_SW_SESSION_TICKET:
        return tls_construct_new_session_ticket(s);

    case TLS_ST_SW_CERT_STATUS:
        return tls_construct_cert_status(s);

    case TLS_ST_SW_CHANGE:
        if (SSL_IS_DTLS(s))
            return dtls_construct_change_cipher_spec(s);
        else
            return tls_construct_change_cipher_spec(s);

    case TLS_ST_SW_FINISHED:
        return tls_construct_finished(s,
                                      s->method->
                                      ssl3_enc->server_finished_label,
                                      s->method->
                                      ssl3_enc->server_finished_label_len);

    default:
        /* Shouldn't happen */
        break;
    }

    return 0;
}

#define CLIENT_KEY_EXCH_MAX_LENGTH      2048
#define NEXT_PROTO_MAX_LENGTH           514

/*
 * Returns the maximum allowed length for the current message that we are
 * reading. Excludes the message header.
 */
unsigned long ossl_statem_server_max_message_size(SSL *s)
{
    OSSL_STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_SR_CLNT_HELLO:
        return SSL3_RT_MAX_PLAIN_LENGTH;

    case TLS_ST_SR_CERT:
        return s->max_cert_list;

    case TLS_ST_SR_KEY_EXCH:
        return CLIENT_KEY_EXCH_MAX_LENGTH;

    case TLS_ST_SR_CERT_VRFY:
        return SSL3_RT_MAX_PLAIN_LENGTH;

#ifndef OPENSSL_NO_NEXTPROTONEG
    case TLS_ST_SR_NEXT_PROTO:
        return NEXT_PROTO_MAX_LENGTH;
#endif

    case TLS_ST_SR_CHANGE:
        return CCS_MAX_LENGTH;

    case TLS_ST_SR_FINISHED:
        return FINISHED_MAX_LENGTH;

    default:
        /* Shouldn't happen */
        break;
    }

    return 0;
}

/*
 * Process a message that the server has received from the client.
 */
MSG_PROCESS_RETURN ossl_statem_server_process_message(SSL *s, PACKET *pkt)
{
    OSSL_STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_SR_CLNT_HELLO:
        return tls_process_client_hello(s, pkt);

    case TLS_ST_SR_CERT:
        return tls_process_client_certificate(s, pkt);

    case TLS_ST_SR_KEY_EXCH:
        return tls_process_client_key_exchange(s, pkt);

    case TLS_ST_SR_CERT_VRFY:
        return tls_process_cert_verify(s, pkt);

#ifndef OPENSSL_NO_NEXTPROTONEG
    case TLS_ST_SR_NEXT_PROTO:
        return tls_process_next_proto(s, pkt);
#endif

    case TLS_ST_SR_CHANGE:
        return tls_process_change_cipher_spec(s, pkt);

    case TLS_ST_SR_FINISHED:
        return tls_process_finished(s, pkt);

    default:
        /* Shouldn't happen */
        break;
    }

    return MSG_PROCESS_ERROR;
}

/*
 * Perform any further processing required following the receipt of a message
 * from the client
 */
WORK_STATE ossl_statem_server_post_process_message(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_SR_CLNT_HELLO:
        return tls_post_process_client_hello(s, wst);

    case TLS_ST_SR_KEY_EXCH:
        return tls_post_process_client_key_exchange(s, wst);

    case TLS_ST_SR_CERT_VRFY:
#ifndef OPENSSL_NO_SCTP
        if (    /* Is this SCTP? */
                BIO_dgram_is_sctp(SSL_get_wbio(s))
                /* Are we renegotiating? */
                && s->renegotiate
                && BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
            s->s3->in_read_app_data = 2;
            s->rwstate = SSL_READING;
            BIO_clear_retry_flags(SSL_get_rbio(s));
            BIO_set_retry_read(SSL_get_rbio(s));
            ossl_statem_set_sctp_read_sock(s, 1);
            return WORK_MORE_A;
        } else {
            ossl_statem_set_sctp_read_sock(s, 0);
        }
#endif
        return WORK_FINISHED_CONTINUE;

    default:
        break;
    }

    /* Shouldn't happen */
    return WORK_ERROR;
}

#ifndef OPENSSL_NO_SRP
static int ssl_check_srp_ext_ClientHello(SSL *s, int *al)
{
    int ret = SSL_ERROR_NONE;

    *al = SSL_AD_UNRECOGNIZED_NAME;

    if ((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kSRP) &&
        (s->srp_ctx.TLS_ext_srp_username_callback != NULL)) {
        if (s->srp_ctx.login == NULL) {
            /*
             * RFC 5054 says SHOULD reject, we do so if There is no srp
             * login name
             */
            ret = SSL3_AL_FATAL;
            *al = SSL_AD_UNKNOWN_PSK_IDENTITY;
        } else {
            ret = SSL_srp_server_param_with_username(s, al);
        }
    }
    return ret;
}
#endif

int tls_construct_hello_request(SSL *s)
{
    if (!ssl_set_handshake_header(s, SSL3_MT_HELLO_REQUEST, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_HELLO_REQUEST, ERR_R_INTERNAL_ERROR);
        ossl_statem_set_error(s);
        return 0;
    }

    return 1;
}

unsigned int dtls_raw_hello_verify_request(unsigned char *buf,
                                            unsigned char *cookie,
                                            unsigned char cookie_len)
{
    unsigned int msg_len;
    unsigned char *p;

    p = buf;
    /* Always use DTLS 1.0 version: see RFC 6347 */
    *(p++) = DTLS1_VERSION >> 8;
    *(p++) = DTLS1_VERSION & 0xFF;

    *(p++) = (unsigned char)cookie_len;
    memcpy(p, cookie, cookie_len);
    p += cookie_len;
    msg_len = p - buf;

    return msg_len;
}

int dtls_construct_hello_verify_request(SSL *s)
{
    unsigned int len;
    unsigned char *buf;

    buf = (unsigned char *)s->init_buf->data;

    if (s->ctx->app_gen_cookie_cb == NULL ||
        s->ctx->app_gen_cookie_cb(s, s->d1->cookie,
                                  &(s->d1->cookie_len)) == 0 ||
        s->d1->cookie_len > 255) {
        SSLerr(SSL_F_DTLS_CONSTRUCT_HELLO_VERIFY_REQUEST,
               SSL_R_COOKIE_GEN_CALLBACK_FAILURE);
        ossl_statem_set_error(s);
        return 0;
    }

    len = dtls_raw_hello_verify_request(&buf[DTLS1_HM_HEADER_LENGTH],
                                         s->d1->cookie, s->d1->cookie_len);

    dtls1_set_message_header(s, buf, DTLS1_MT_HELLO_VERIFY_REQUEST, len, 0,
                             len);
    len += DTLS1_HM_HEADER_LENGTH;

    /* number of bytes to write */
    s->init_num = len;
    s->init_off = 0;

    return 1;
}

MSG_PROCESS_RETURN tls_process_client_hello(SSL *s, PACKET *pkt)
{
    int i, al = SSL_AD_INTERNAL_ERROR;
    unsigned int j, complen = 0;
    unsigned long id;
    SSL_CIPHER *c;
#ifndef OPENSSL_NO_COMP
    SSL_COMP *comp = NULL;
#endif
    STACK_OF(SSL_CIPHER) *ciphers = NULL;
    int protverr = 1;
    /* |cookie| will only be initialized for DTLS. */
    PACKET session_id, cipher_suites, compression, extensions, cookie;
    int is_v2_record;

    is_v2_record = RECORD_LAYER_is_sslv2_record(&s->rlayer);

    PACKET_null_init(&cookie);
    /* First lets get s->client_version set correctly */
    if (is_v2_record) {
        unsigned int version;
        unsigned int mt;
        /*-
         * An SSLv3/TLSv1 backwards-compatible CLIENT-HELLO in an SSLv2
         * header is sent directly on the wire, not wrapped as a TLS
         * record. Our record layer just processes the message length and passes
         * the rest right through. Its format is:
         * Byte  Content
         * 0-1   msg_length - decoded by the record layer
         * 2     msg_type - s->init_msg points here
         * 3-4   version
         * 5-6   cipher_spec_length
         * 7-8   session_id_length
         * 9-10  challenge_length
         * ...   ...
         */

        if (!PACKET_get_1(pkt, &mt)
                || mt != SSL2_MT_CLIENT_HELLO) {
            /*
             * Should never happen. We should have tested this in the record
             * layer in order to have determined that this is a SSLv2 record
             * in the first place
             */
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (!PACKET_get_net_2(pkt, &version)) {
            /* No protocol version supplied! */
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_UNKNOWN_PROTOCOL);
            goto err;
        }
        if (version == 0x0002) {
            /* This is real SSLv2. We don't support it. */
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_UNKNOWN_PROTOCOL);
            goto err;
        } else if ((version & 0xff00) == (SSL3_VERSION_MAJOR << 8)) {
            /* SSLv3/TLS */
            s->client_version = version;
        } else {
            /* No idea what protocol this is */
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_UNKNOWN_PROTOCOL);
            goto err;
        }
    } else {
        /*
         * use version from inside client hello, not from record header (may
         * differ: see RFC 2246, Appendix E, second paragraph)
         */
        if(!PACKET_get_net_2(pkt, (unsigned int *)&s->client_version)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
    }

    /* Do SSL/TLS version negotiation if applicable */
    if (!SSL_IS_DTLS(s)) {
        if (s->version != TLS_ANY_VERSION) {
            if (s->client_version >= s->version) {
                protverr = 0;
            }
        } else if (s->client_version >= SSL3_VERSION) {
            switch(s->client_version) {
            default:
            case TLS1_2_VERSION:
                if(!(s->options & SSL_OP_NO_TLSv1_2)) {
                    s->version = TLS1_2_VERSION;
                    s->method = TLSv1_2_server_method();
                    protverr = 0;
                    break;
                }
                /* Deliberately fall through */
            case TLS1_1_VERSION:
                if(!(s->options & SSL_OP_NO_TLSv1_1)) {
                    s->version = TLS1_1_VERSION;
                    s->method = TLSv1_1_server_method();
                    protverr = 0;
                    break;
                }
                /* Deliberately fall through */
            case TLS1_VERSION:
                if(!(s->options & SSL_OP_NO_TLSv1)) {
                    s->version = TLS1_VERSION;
                    s->method = TLSv1_server_method();
                    protverr = 0;
                    break;
                }
                /* Deliberately fall through */
            case SSL3_VERSION:
#ifndef OPENSSL_NO_SSL3
                if(!(s->options & SSL_OP_NO_SSLv3)) {
                    s->version = SSL3_VERSION;
                    s->method = SSLv3_server_method();
                    protverr = 0;
                    break;
                }
#else
                break;
#endif
            }
        }
    } else if (s->client_version <= s->version
                || s->method->version == DTLS_ANY_VERSION) {
        /*
         * For DTLS we just check versions are potentially compatible. Version
         * negotiation comes later.
         */
        protverr = 0;
    }

    if (protverr) {
        SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_UNKNOWN_PROTOCOL);
        if ((!s->enc_write_ctx && !s->write_hash)) {
            /*
             * similar to ssl3_get_record, send alert using remote version
             * number
             */
            s->version = s->client_version;
        }
        al = SSL_AD_PROTOCOL_VERSION;
        goto f_err;
    }

    /* Parse the message and load client random. */
    if (is_v2_record) {
        /*
         * Handle an SSLv2 backwards compatible ClientHello
         * Note, this is only for SSLv3+ using the backward compatible format.
         * Real SSLv2 is not supported, and is rejected above.
         */
        unsigned int cipher_len, session_id_len, challenge_len;
        PACKET challenge;

        if (!PACKET_get_net_2(pkt, &cipher_len)
                || !PACKET_get_net_2(pkt, &session_id_len)
                || !PACKET_get_net_2(pkt, &challenge_len)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO,
                   SSL_R_RECORD_LENGTH_MISMATCH);
            al = SSL_AD_DECODE_ERROR;
            goto f_err;
        }

        if (!PACKET_get_sub_packet(pkt, &cipher_suites, cipher_len)
            || !PACKET_get_sub_packet(pkt, &session_id, session_id_len)
            || !PACKET_get_sub_packet(pkt, &challenge, challenge_len)
            /* No extensions. */
            || PACKET_remaining(pkt) != 0) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO,
                   SSL_R_RECORD_LENGTH_MISMATCH);
            al = SSL_AD_DECODE_ERROR;
            goto f_err;
        }

        /* Load the client random */
        challenge_len = challenge_len > SSL3_RANDOM_SIZE ? SSL3_RANDOM_SIZE :
            challenge_len;
        memset(s->s3->client_random, 0, SSL3_RANDOM_SIZE);
        if (!PACKET_copy_bytes(&challenge,
                               s->s3->client_random + SSL3_RANDOM_SIZE -
                               challenge_len, challenge_len)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }

        PACKET_null_init(&compression);
        PACKET_null_init(&extensions);
    } else {
        /* Regular ClientHello. */
        if (!PACKET_copy_bytes(pkt, s->s3->client_random, SSL3_RANDOM_SIZE)
            || !PACKET_get_length_prefixed_1(pkt, &session_id)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }

        if (SSL_IS_DTLS(s)) {
            if (!PACKET_get_length_prefixed_1(pkt, &cookie)) {
                al = SSL_AD_DECODE_ERROR;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_LENGTH_MISMATCH);
                goto f_err;
            }
            /*
             * If we require cookies and this ClientHello doesn't contain one,
             * just return since we do not want to allocate any memory yet.
             * So check cookie length...
             */
            if (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE) {
                if (PACKET_remaining(&cookie) == 0)
                return 1;
            }
        }

        if (!PACKET_get_length_prefixed_2(pkt, &cipher_suites)
            || !PACKET_get_length_prefixed_1(pkt, &compression)) {
                al = SSL_AD_DECODE_ERROR;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_LENGTH_MISMATCH);
                goto f_err;
        }
        /* Could be empty. */
        extensions = *pkt;
    }

    s->hit = 0;

    /*
     * We don't allow resumption in a backwards compatible ClientHello.
     * TODO(openssl-team): in TLS1.1+, session_id MUST be empty.
     *
     * Versions before 0.9.7 always allow clients to resume sessions in
     * renegotiation. 0.9.7 and later allow this by default, but optionally
     * ignore resumption requests with flag
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION (it's a new flag rather
     * than a change to default behavior so that applications relying on
     * this for security won't even compile against older library versions).
     * 1.0.1 and later also have a function SSL_renegotiate_abbreviated() to
     * request renegotiation but not a new session (s->new_session remains
     * unset): for servers, this essentially just means that the
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION setting will be
     * ignored.
     */
    if (is_v2_record ||
        (s->new_session &&
         (s->options & SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION))) {
        if (!ssl_get_new_session(s, 1))
            goto err;
    } else {
        i = ssl_get_prev_session(s, &extensions, &session_id);
        /*
         * Only resume if the session's version matches the negotiated
         * version.
         * RFC 5246 does not provide much useful advice on resumption
         * with a different protocol version. It doesn't forbid it but
         * the sanity of such behaviour would be questionable.
         * In practice, clients do not accept a version mismatch and
         * will abort the handshake with an error.
         */
        if (i == 1 && s->version == s->session->ssl_version) {
            /* previous session */
            s->hit = 1;
        } else if (i == -1) {
            goto err;
        } else {
            /* i == 0 */
            if (!ssl_get_new_session(s, 1))
                goto err;
        }
    }

    if (SSL_IS_DTLS(s)) {
        /* Empty cookie was already handled above by returning early. */
        if (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE) {
            if (s->ctx->app_verify_cookie_cb != NULL) {
                if (s->ctx->app_verify_cookie_cb(s, PACKET_data(&cookie),
                                                 PACKET_remaining(&cookie)) == 0) {
                    al = SSL_AD_HANDSHAKE_FAILURE;
                    SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO,
                           SSL_R_COOKIE_MISMATCH);
                    goto f_err;
                    /* else cookie verification succeeded */
                }
            /* default verification */
            } else if (!PACKET_equal(&cookie, s->d1->cookie,
                                     s->d1->cookie_len)) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_COOKIE_MISMATCH);
                goto f_err;
            }
            s->d1->cookie_verified = 1;
        }
        if (s->method->version == DTLS_ANY_VERSION) {
            /* Select version to use */
            if (s->client_version <= DTLS1_2_VERSION &&
                !(s->options & SSL_OP_NO_DTLSv1_2)) {
                s->version = DTLS1_2_VERSION;
                s->method = DTLSv1_2_server_method();
            } else if (tls1_suiteb(s)) {
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO,
                       SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
                s->version = s->client_version;
                al = SSL_AD_PROTOCOL_VERSION;
                goto f_err;
            } else if (s->client_version <= DTLS1_VERSION &&
                       !(s->options & SSL_OP_NO_DTLSv1)) {
                s->version = DTLS1_VERSION;
                s->method = DTLSv1_server_method();
            } else {
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO,
                       SSL_R_WRONG_VERSION_NUMBER);
                s->version = s->client_version;
                al = SSL_AD_PROTOCOL_VERSION;
                goto f_err;
            }
            s->session->ssl_version = s->version;
        }
    }

    if (ssl_bytes_to_cipher_list(s, &cipher_suites, &(ciphers),
                                 is_v2_record, &al) == NULL) {
        goto f_err;
    }

    /* If it is a hit, check that the cipher is in the list */
    if (s->hit) {
        j = 0;
        id = s->session->cipher->id;

#ifdef CIPHER_DEBUG
        fprintf(stderr, "client sent %d ciphers\n",
                sk_SSL_CIPHER_num(ciphers));
#endif
        for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
            c = sk_SSL_CIPHER_value(ciphers, i);
#ifdef CIPHER_DEBUG
            fprintf(stderr, "client [%2d of %2d]:%s\n",
                    i, sk_SSL_CIPHER_num(ciphers), SSL_CIPHER_get_name(c));
#endif
            if (c->id == id) {
                j = 1;
                break;
            }
        }
        if (j == 0) {
            /*
             * we need to have the cipher in the cipher list if we are asked
             * to reuse it
             */
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO,
                   SSL_R_REQUIRED_CIPHER_MISSING);
            goto f_err;
        }
    }

    complen = PACKET_remaining(&compression);
    for (j = 0; j < complen; j++) {
        if (PACKET_data(&compression)[j] == 0)
            break;
    }

    if (j >= complen) {
        /* no compress */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_NO_COMPRESSION_SPECIFIED);
        goto f_err;
    }
    
    /* TLS extensions */
    if (s->version >= SSL3_VERSION) {
        if (!ssl_parse_clienthello_tlsext(s, &extensions)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_PARSE_TLSEXT);
            goto err;
        }
    }

    /*
     * Check if we want to use external pre-shared secret for this handshake
     * for not reused session only. We need to generate server_random before
     * calling tls_session_secret_cb in order to allow SessionTicket
     * processing to use it in key derivation.
     */
    {
        unsigned char *pos;
        pos = s->s3->server_random;
        if (ssl_fill_hello_random(s, 1, pos, SSL3_RANDOM_SIZE) <= 0) {
            goto f_err;
        }
    }

    if (!s->hit && s->version >= TLS1_VERSION && s->tls_session_secret_cb) {
        SSL_CIPHER *pref_cipher = NULL;

        s->session->master_key_length = sizeof(s->session->master_key);
        if (s->tls_session_secret_cb(s, s->session->master_key,
                                     &s->session->master_key_length, ciphers,
                                     &pref_cipher,
                                     s->tls_session_secret_cb_arg)) {
            s->hit = 1;
            s->session->ciphers = ciphers;
            s->session->verify_result = X509_V_OK;

            ciphers = NULL;

            /* check if some cipher was preferred by call back */
            pref_cipher =
                pref_cipher ? pref_cipher : ssl3_choose_cipher(s,
                                                               s->
                                                               session->ciphers,
                                                               SSL_get_ciphers
                                                               (s));
            if (pref_cipher == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_NO_SHARED_CIPHER);
                goto f_err;
            }

            s->session->cipher = pref_cipher;
            sk_SSL_CIPHER_free(s->cipher_list);
            s->cipher_list = sk_SSL_CIPHER_dup(s->session->ciphers);
            sk_SSL_CIPHER_free(s->cipher_list_by_id);
            s->cipher_list_by_id = sk_SSL_CIPHER_dup(s->session->ciphers);
        }
    }

    /*
     * Worst case, we will use the NULL compression, but if we have other
     * options, we will now look for them.  We have complen-1 compression
     * algorithms from the client, starting at q.
     */
    s->s3->tmp.new_compression = NULL;
#ifndef OPENSSL_NO_COMP
    /* This only happens if we have a cache hit */
    if (s->session->compress_meth != 0) {
        int m, comp_id = s->session->compress_meth;
        unsigned int k;
        /* Perform sanity checks on resumed compression algorithm */
        /* Can't disable compression */
        if (!ssl_allow_compression(s)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO,
                   SSL_R_INCONSISTENT_COMPRESSION);
            goto f_err;
        }
        /* Look for resumed compression method */
        for (m = 0; m < sk_SSL_COMP_num(s->ctx->comp_methods); m++) {
            comp = sk_SSL_COMP_value(s->ctx->comp_methods, m);
            if (comp_id == comp->id) {
                s->s3->tmp.new_compression = comp;
                break;
            }
        }
        if (s->s3->tmp.new_compression == NULL) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO,
                   SSL_R_INVALID_COMPRESSION_ALGORITHM);
            goto f_err;
        }
        /* Look for resumed method in compression list */
        for (k = 0; k < complen; k++) {
            if (PACKET_data(&compression)[k] == comp_id)
                break;
        }
        if (k >= complen) {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO,
                   SSL_R_REQUIRED_COMPRESSSION_ALGORITHM_MISSING);
            goto f_err;
        }
    } else if (s->hit)
        comp = NULL;
    else if (ssl_allow_compression(s) && s->ctx->comp_methods) {
        /* See if we have a match */
        int m, nn, v, done = 0;
        unsigned int o;

        nn = sk_SSL_COMP_num(s->ctx->comp_methods);
        for (m = 0; m < nn; m++) {
            comp = sk_SSL_COMP_value(s->ctx->comp_methods, m);
            v = comp->id;
            for (o = 0; o < complen; o++) {
                if (v == PACKET_data(&compression)[o]) {
                    done = 1;
                    break;
                }
            }
            if (done)
                break;
        }
        if (done)
            s->s3->tmp.new_compression = comp;
        else
            comp = NULL;
    }
#else
    /*
     * If compression is disabled we'd better not try to resume a session
     * using compression.
     */
    if (s->session->compress_meth != 0) {
        SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_INCONSISTENT_COMPRESSION);
        goto f_err;
    }
#endif

    /*
     * Given s->session->ciphers and SSL_get_ciphers, we must pick a cipher
     */

    if (!s->hit) {
#ifdef OPENSSL_NO_COMP
        s->session->compress_meth = 0;
#else
        s->session->compress_meth = (comp == NULL) ? 0 : comp->id;
#endif
        sk_SSL_CIPHER_free(s->session->ciphers);
        s->session->ciphers = ciphers;
        if (ciphers == NULL) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }
        ciphers = NULL;
        if (!tls1_set_server_sigalgs(s)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
            goto err;
        }
    }

    sk_SSL_CIPHER_free(ciphers);
    return MSG_PROCESS_CONTINUE_PROCESSING;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    ossl_statem_set_error(s);

    sk_SSL_CIPHER_free(ciphers);
    return MSG_PROCESS_ERROR;

}

WORK_STATE tls_post_process_client_hello(SSL *s, WORK_STATE wst)
{
    int al = SSL_AD_HANDSHAKE_FAILURE;
    SSL_CIPHER *cipher;

    if (wst == WORK_MORE_A) {
        if (!s->hit) {
            /* Let cert callback update server certificates if required */
            if (s->cert->cert_cb) {
                int rv = s->cert->cert_cb(s, s->cert->cert_cb_arg);
                if (rv == 0) {
                    al = SSL_AD_INTERNAL_ERROR;
                    SSLerr(SSL_F_TLS_POST_PROCESS_CLIENT_HELLO, SSL_R_CERT_CB_ERROR);
                    goto f_err;
                }
                if (rv < 0) {
                    s->rwstate = SSL_X509_LOOKUP;
                    return WORK_MORE_A;
                }
                s->rwstate = SSL_NOTHING;
            }
            cipher = ssl3_choose_cipher(s, s->session->ciphers, SSL_get_ciphers(s));

            if (cipher == NULL) {
                SSLerr(SSL_F_TLS_POST_PROCESS_CLIENT_HELLO, SSL_R_NO_SHARED_CIPHER);
                goto f_err;
            }
            s->s3->tmp.new_cipher = cipher;
            /* check whether we should disable session resumption */
            if (s->not_resumable_session_cb != NULL)
                s->session->not_resumable = s->not_resumable_session_cb(s,
                    ((cipher->algorithm_mkey & (SSL_kDHE | SSL_kECDHE)) != 0));
            if (s->session->not_resumable)
                /* do not send a session ticket */
                s->tlsext_ticket_expected = 0;
        } else {
            /* Session-id reuse */
            s->s3->tmp.new_cipher = s->session->cipher;
        }

        if (!(s->verify_mode & SSL_VERIFY_PEER)) {
            if (!ssl3_digest_cached_records(s, 0)) {
                al = SSL_AD_INTERNAL_ERROR;
                goto f_err;
            }
        }

        /*-
         * we now have the following setup.
         * client_random
         * cipher_list          - our prefered list of ciphers
         * ciphers              - the clients prefered list of ciphers
         * compression          - basically ignored right now
         * ssl version is set   - sslv3
         * s->session           - The ssl session has been setup.
         * s->hit               - session reuse flag
         * s->s3->tmp.new_cipher- the new cipher to use.
         */

        /* Handles TLS extensions that we couldn't check earlier */
        if (s->version >= SSL3_VERSION) {
            if (ssl_check_clienthello_tlsext_late(s) <= 0) {
                SSLerr(SSL_F_TLS_POST_PROCESS_CLIENT_HELLO,
                       SSL_R_CLIENTHELLO_TLSEXT);
                goto f_err;
            }
        }

        wst = WORK_MORE_B;
    }
#ifndef OPENSSL_NO_SRP
    if (wst == WORK_MORE_B) {
        int ret;
        if ((ret = ssl_check_srp_ext_ClientHello(s, &al)) < 0) {
            /*
             * callback indicates further work to be done
             */
            s->rwstate = SSL_X509_LOOKUP;
            return WORK_MORE_B;
        }
        if (ret != SSL_ERROR_NONE) {
            /*
             * This is not really an error but the only means to for
             * a client to detect whether srp is supported.
             */
            if (al != TLS1_AD_UNKNOWN_PSK_IDENTITY)
                SSLerr(SSL_F_TLS_POST_PROCESS_CLIENT_HELLO,
                           SSL_R_CLIENTHELLO_TLSEXT);
            goto f_err;
        }
    }
#endif
    s->renegotiate = 2;

    return WORK_FINISHED_STOP;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    ossl_statem_set_error(s);
    return WORK_ERROR;
}

int tls_construct_server_hello(SSL *s)
{
    unsigned char *buf;
    unsigned char *p, *d;
    int i, sl;
    int al = 0;
    unsigned long l;

    buf = (unsigned char *)s->init_buf->data;

    /* Do the message type and length last */
    d = p = ssl_handshake_start(s);

    *(p++) = s->version >> 8;
    *(p++) = s->version & 0xff;

    /*
     * Random stuff. Filling of the server_random takes place in
     * tls_process_client_hello()
     */
    memcpy(p, s->s3->server_random, SSL3_RANDOM_SIZE);
    p += SSL3_RANDOM_SIZE;

    /*-
     * There are several cases for the session ID to send
     * back in the server hello:
     * - For session reuse from the session cache,
     *   we send back the old session ID.
     * - If stateless session reuse (using a session ticket)
     *   is successful, we send back the client's "session ID"
     *   (which doesn't actually identify the session).
     * - If it is a new session, we send back the new
     *   session ID.
     * - However, if we want the new session to be single-use,
     *   we send back a 0-length session ID.
     * s->hit is non-zero in either case of session reuse,
     * so the following won't overwrite an ID that we're supposed
     * to send back.
     */
    if (s->session->not_resumable ||
        (!(s->ctx->session_cache_mode & SSL_SESS_CACHE_SERVER)
         && !s->hit))
        s->session->session_id_length = 0;

    sl = s->session->session_id_length;
    if (sl > (int)sizeof(s->session->session_id)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
        ossl_statem_set_error(s);
        return 0;
    }
    *(p++) = sl;
    memcpy(p, s->session->session_id, sl);
    p += sl;

    /* put the cipher */
    i = ssl3_put_cipher_by_char(s->s3->tmp.new_cipher, p);
    p += i;

    /* put the compression method */
#ifdef OPENSSL_NO_COMP
    *(p++) = 0;
#else
    if (s->s3->tmp.new_compression == NULL)
        *(p++) = 0;
    else
        *(p++) = s->s3->tmp.new_compression->id;
#endif

    if (ssl_prepare_serverhello_tlsext(s) <= 0) {
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_HELLO, SSL_R_SERVERHELLO_TLSEXT);
        ossl_statem_set_error(s);
        return 0;
    }
    if ((p =
         ssl_add_serverhello_tlsext(s, p, buf + SSL3_RT_MAX_PLAIN_LENGTH,
                                    &al)) == NULL) {
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
        ossl_statem_set_error(s);
        return 0;
    }

    /* do the header */
    l = (p - d);
    if (!ssl_set_handshake_header(s, SSL3_MT_SERVER_HELLO, l)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
        ossl_statem_set_error(s);
        return 0;
    }

    return 1;
}

int tls_construct_server_done(SSL *s)
{
    if (!ssl_set_handshake_header(s, SSL3_MT_SERVER_DONE, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_DONE, ERR_R_INTERNAL_ERROR);
        ossl_statem_set_error(s);
        return 0;
    }

    if (!s->s3->tmp.cert_request) {
        if (!ssl3_digest_cached_records(s, 0)) {
            ossl_statem_set_error(s);
        }
    }

    return 1;
}

int tls_construct_server_key_exchange(SSL *s)
{
#ifndef OPENSSL_NO_RSA
    RSA *rsa;
#endif
#ifndef OPENSSL_NO_DH
    DH *dh = NULL, *dhp;
#endif
#ifndef OPENSSL_NO_EC
    EC_KEY *ecdh = NULL, *ecdhp;
    unsigned char *encodedPoint = NULL;
    int encodedlen = 0;
    int curve_id = 0;
    BN_CTX *bn_ctx = NULL;
#endif
    EVP_PKEY *pkey;
    const EVP_MD *md = NULL;
    unsigned char *p, *d;
    int al, i;
    unsigned long type;
    int n;
    CERT *cert;
    BIGNUM *r[4];
    int nr[4], kn;
    BUF_MEM *buf;
    EVP_MD_CTX md_ctx;

    EVP_MD_CTX_init(&md_ctx);

    type = s->s3->tmp.new_cipher->algorithm_mkey;
    cert = s->cert;

    buf = s->init_buf;

    r[0] = r[1] = r[2] = r[3] = NULL;
    n = 0;
#ifndef OPENSSL_NO_PSK
    if (type & SSL_PSK) {
        /*
         * reserve size for record length and PSK identity hint
         */
        n += 2;
        if (s->cert->psk_identity_hint)
            n += strlen(s->cert->psk_identity_hint);
    }
    /* Plain PSK or RSAPSK nothing to do */
    if (type & (SSL_kPSK | SSL_kRSAPSK)) {
    } else
#endif                          /* !OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_RSA
    if (type & SSL_kRSA) {
        rsa = cert->rsa_tmp;
        if ((rsa == NULL) && (s->cert->rsa_tmp_cb != NULL)) {
            rsa = s->cert->rsa_tmp_cb(s,
                                      SSL_C_IS_EXPORT(s->s3->
                                                      tmp.new_cipher),
                                      SSL_C_EXPORT_PKEYLENGTH(s->s3->
                                                              tmp.new_cipher));
            if (rsa == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                       SSL_R_ERROR_GENERATING_TMP_RSA_KEY);
                goto f_err;
            }
            RSA_up_ref(rsa);
            cert->rsa_tmp = rsa;
        }
        if (rsa == NULL) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   SSL_R_MISSING_TMP_RSA_KEY);
            goto f_err;
        }
        r[0] = rsa->n;
        r[1] = rsa->e;
        s->s3->tmp.use_rsa_tmp = 1;
    } else
#endif
#ifndef OPENSSL_NO_DH
    if (type & (SSL_kDHE | SSL_kDHEPSK)) {
        if (s->cert->dh_tmp_auto) {
            dhp = ssl_get_auto_dh(s);
            if (dhp == NULL) {
                al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto f_err;
            }
        } else
            dhp = cert->dh_tmp;
        if ((dhp == NULL) && (s->cert->dh_tmp_cb != NULL))
            dhp = s->cert->dh_tmp_cb(s,
                                     SSL_C_IS_EXPORT(s->s3->
                                                     tmp.new_cipher),
                                     SSL_C_EXPORT_PKEYLENGTH(s->s3->
                                                             tmp.new_cipher));
        if (dhp == NULL) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   SSL_R_MISSING_TMP_DH_KEY);
            goto f_err;
        }
        if (!ssl_security(s, SSL_SECOP_TMP_DH,
                          DH_security_bits(dhp), 0, dhp)) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   SSL_R_DH_KEY_TOO_SMALL);
            goto f_err;
        }
        if (s->s3->tmp.dh != NULL) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (s->cert->dh_tmp_auto)
            dh = dhp;
        else if ((dh = DHparams_dup(dhp)) == NULL) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);
            goto err;
        }

        s->s3->tmp.dh = dh;
        if ((dhp->pub_key == NULL ||
             dhp->priv_key == NULL ||
             (s->options & SSL_OP_SINGLE_DH_USE))) {
            if (!DH_generate_key(dh)) {
                SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);
                goto err;
            }
        } else {
            dh->pub_key = BN_dup(dhp->pub_key);
            dh->priv_key = BN_dup(dhp->priv_key);
            if ((dh->pub_key == NULL) || (dh->priv_key == NULL)) {
                SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);
                goto err;
            }
        }
        r[0] = dh->p;
        r[1] = dh->g;
        r[2] = dh->pub_key;
    } else
#endif
#ifndef OPENSSL_NO_EC
    if (type & (SSL_kECDHE | SSL_kECDHEPSK)) {
        const EC_GROUP *group;

        ecdhp = cert->ecdh_tmp;
        if (s->cert->ecdh_tmp_auto) {
            /* Get NID of appropriate shared curve */
            int nid = tls1_shared_curve(s, -2);
            if (nid != NID_undef)
                ecdhp = EC_KEY_new_by_curve_name(nid);
        } else if ((ecdhp == NULL) && s->cert->ecdh_tmp_cb) {
            ecdhp = s->cert->ecdh_tmp_cb(s,
                                         SSL_C_IS_EXPORT(s->s3->
                                                         tmp.new_cipher),
                                         SSL_C_EXPORT_PKEYLENGTH(s->
                                                                 s3->tmp.new_cipher));
        }
        if (ecdhp == NULL) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   SSL_R_MISSING_TMP_ECDH_KEY);
            goto f_err;
        }

        if (s->s3->tmp.ecdh != NULL) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   ERR_R_INTERNAL_ERROR);
            goto err;
        }

        /* Duplicate the ECDH structure. */
        if (ecdhp == NULL) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);
            goto err;
        }
        if (s->cert->ecdh_tmp_auto)
            ecdh = ecdhp;
        else if ((ecdh = EC_KEY_dup(ecdhp)) == NULL) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);
            goto err;
        }

        s->s3->tmp.ecdh = ecdh;
        if ((EC_KEY_get0_public_key(ecdh) == NULL) ||
            (EC_KEY_get0_private_key(ecdh) == NULL) ||
            (s->options & SSL_OP_SINGLE_ECDH_USE)) {
            if (!EC_KEY_generate_key(ecdh)) {
                SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                       ERR_R_ECDH_LIB);
                goto err;
            }
        }

        if (((group = EC_KEY_get0_group(ecdh)) == NULL) ||
            (EC_KEY_get0_public_key(ecdh) == NULL) ||
            (EC_KEY_get0_private_key(ecdh) == NULL)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);
            goto err;
        }

        if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
            (EC_GROUP_get_degree(group) > 163)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER);
            goto err;
        }

        /*
         * XXX: For now, we only support ephemeral ECDH keys over named
         * (not generic) curves. For supported named curves, curve_id is
         * non-zero.
         */
        if ((curve_id =
             tls1_ec_nid2curve_id(EC_GROUP_get_curve_name(group)))
            == 0) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   SSL_R_UNSUPPORTED_ELLIPTIC_CURVE);
            goto err;
        }

        /*
         * Encode the public key. First check the size of encoding and
         * allocate memory accordingly.
         */
        encodedlen = EC_POINT_point2oct(group,
                                        EC_KEY_get0_public_key(ecdh),
                                        POINT_CONVERSION_UNCOMPRESSED,
                                        NULL, 0, NULL);

        encodedPoint = (unsigned char *)
            OPENSSL_malloc(encodedlen * sizeof(unsigned char));
        bn_ctx = BN_CTX_new();
        if ((encodedPoint == NULL) || (bn_ctx == NULL)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   ERR_R_MALLOC_FAILURE);
            goto err;
        }

        encodedlen = EC_POINT_point2oct(group,
                                        EC_KEY_get0_public_key(ecdh),
                                        POINT_CONVERSION_UNCOMPRESSED,
                                        encodedPoint, encodedlen, bn_ctx);

        if (encodedlen == 0) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);
            goto err;
        }

        BN_CTX_free(bn_ctx);
        bn_ctx = NULL;

        /*
         * XXX: For now, we only support named (not generic) curves in
         * ECDH ephemeral key exchanges. In this situation, we need four
         * additional bytes to encode the entire ServerECDHParams
         * structure.
         */
        n += 4 + encodedlen;

        /*
         * We'll generate the serverKeyExchange message explicitly so we
         * can set these to NULLs
         */
        r[0] = NULL;
        r[1] = NULL;
        r[2] = NULL;
        r[3] = NULL;
    } else
#endif                          /* !OPENSSL_NO_EC */
#ifndef OPENSSL_NO_SRP
    if (type & SSL_kSRP) {
        if ((s->srp_ctx.N == NULL) ||
            (s->srp_ctx.g == NULL) ||
            (s->srp_ctx.s == NULL) || (s->srp_ctx.B == NULL)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   SSL_R_MISSING_SRP_PARAM);
            goto err;
        }
        r[0] = s->srp_ctx.N;
        r[1] = s->srp_ctx.g;
        r[2] = s->srp_ctx.s;
        r[3] = s->srp_ctx.B;
    } else
#endif
    {
        al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
               SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
        goto f_err;
    }
    for (i = 0; i < 4 && r[i] != NULL; i++) {
        nr[i] = BN_num_bytes(r[i]);
#ifndef OPENSSL_NO_SRP
        if ((i == 2) && (type & SSL_kSRP))
            n += 1 + nr[i];
        else
#endif
            n += 2 + nr[i];
    }

    if (!(s->s3->tmp.new_cipher->algorithm_auth & (SSL_aNULL|SSL_aSRP))
        && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_PSK)) {
        if ((pkey = ssl_get_sign_pkey(s, s->s3->tmp.new_cipher, &md))
            == NULL) {
            al = SSL_AD_DECODE_ERROR;
            goto f_err;
        }
        kn = EVP_PKEY_size(pkey);
    } else {
        pkey = NULL;
        kn = 0;
    }

    if (!BUF_MEM_grow_clean(buf, n + SSL_HM_HEADER_LENGTH(s) + kn)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_LIB_BUF);
        goto err;
    }
    d = p = ssl_handshake_start(s);

#ifndef OPENSSL_NO_PSK
    if (type & SSL_PSK) {
        /* copy PSK identity hint */
        if (s->cert->psk_identity_hint) {
            s2n(strlen(s->cert->psk_identity_hint), p);
            strncpy((char *)p, s->cert->psk_identity_hint,
                    strlen(s->cert->psk_identity_hint));
            p += strlen(s->cert->psk_identity_hint);
        } else {
            s2n(0, p);
        }
    }
#endif

    for (i = 0; i < 4 && r[i] != NULL; i++) {
#ifndef OPENSSL_NO_SRP
        if ((i == 2) && (type & SSL_kSRP)) {
            *p = nr[i];
            p++;
        } else
#endif
            s2n(nr[i], p);
        BN_bn2bin(r[i], p);
        p += nr[i];
    }

#ifndef OPENSSL_NO_EC
    if (type & (SSL_kECDHE | SSL_kECDHEPSK)) {
        /*
         * XXX: For now, we only support named (not generic) curves. In
         * this situation, the serverKeyExchange message has: [1 byte
         * CurveType], [2 byte CurveName] [1 byte length of encoded
         * point], followed by the actual encoded point itself
         */
        *p = NAMED_CURVE_TYPE;
        p += 1;
        *p = 0;
        p += 1;
        *p = curve_id;
        p += 1;
        *p = encodedlen;
        p += 1;
        memcpy(p, encodedPoint, encodedlen);
        OPENSSL_free(encodedPoint);
        encodedPoint = NULL;
        p += encodedlen;
    }
#endif

    /* not anonymous */
    if (pkey != NULL) {
        /*
         * n is the length of the params, they start at &(d[4]) and p
         * points to the space at the end.
         */
        if (md) {
            /* send signature algorithm */
            if (SSL_USE_SIGALGS(s)) {
                if (!tls12_get_sigandhash(p, pkey, md)) {
                    /* Should never happen */
                    al = SSL_AD_INTERNAL_ERROR;
                    SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    goto f_err;
                }
                p += 2;
            }
#ifdef SSL_DEBUG
            fprintf(stderr, "Using hash %s\n", EVP_MD_name(md));
#endif
            if (EVP_SignInit_ex(&md_ctx, md, NULL) <= 0
                    || EVP_SignUpdate(&md_ctx, &(s->s3->client_random[0]),
                                      SSL3_RANDOM_SIZE) <= 0
                    || EVP_SignUpdate(&md_ctx, &(s->s3->server_random[0]),
                                      SSL3_RANDOM_SIZE) <= 0
                    || EVP_SignUpdate(&md_ctx, d, n) <= 0
                    || EVP_SignFinal(&md_ctx, &(p[2]),
                               (unsigned int *)&i, pkey) <= 0) {
                SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_LIB_EVP);
                al = SSL_AD_INTERNAL_ERROR;
                goto f_err;
            }
            s2n(i, p);
            n += i + 2;
            if (SSL_USE_SIGALGS(s))
                n += 2;
        } else {
            /* Is this error check actually needed? */
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                   SSL_R_UNKNOWN_PKEY_TYPE);
            goto f_err;
        }
    }

    if (!ssl_set_handshake_header(s, SSL3_MT_SERVER_KEY_EXCHANGE, n)) {
        al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
        goto f_err;
    }

    EVP_MD_CTX_cleanup(&md_ctx);
    return 1;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
#ifndef OPENSSL_NO_EC
    OPENSSL_free(encodedPoint);
    BN_CTX_free(bn_ctx);
#endif
    EVP_MD_CTX_cleanup(&md_ctx);
    ossl_statem_set_error(s);
    return 0;
}

int tls_construct_certificate_request(SSL *s)
{
    unsigned char *p, *d;
    int i, j, nl, off, n;
    STACK_OF(X509_NAME) *sk = NULL;
    X509_NAME *name;
    BUF_MEM *buf;

    buf = s->init_buf;

    d = p = ssl_handshake_start(s);

    /* get the list of acceptable cert types */
    p++;
    n = ssl3_get_req_cert_type(s, p);
    d[0] = n;
    p += n;
    n++;

    if (SSL_USE_SIGALGS(s)) {
        const unsigned char *psigs;
        unsigned char *etmp = p;
        nl = tls12_get_psigalgs(s, &psigs);
        /* Skip over length for now */
        p += 2;
        nl = tls12_copy_sigalgs(s, p, psigs, nl);
        /* Now fill in length */
        s2n(nl, etmp);
        p += nl;
        n += nl + 2;
    }

    off = n;
    p += 2;
    n += 2;

    sk = SSL_get_client_CA_list(s);
    nl = 0;
    if (sk != NULL) {
        for (i = 0; i < sk_X509_NAME_num(sk); i++) {
            name = sk_X509_NAME_value(sk, i);
            j = i2d_X509_NAME(name, NULL);
            if (!BUF_MEM_grow_clean
                (buf, SSL_HM_HEADER_LENGTH(s) + n + j + 2)) {
                SSLerr(SSL_F_TLS_CONSTRUCT_CERTIFICATE_REQUEST,
                       ERR_R_BUF_LIB);
                goto err;
            }
            p = ssl_handshake_start(s) + n;
            s2n(j, p);
            i2d_X509_NAME(name, &p);
            n += 2 + j;
            nl += 2 + j;
        }
    }
    /* else no CA names */
    p = ssl_handshake_start(s) + off;
    s2n(nl, p);

    if (!ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE_REQUEST, n)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CERTIFICATE_REQUEST, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    s->s3->tmp.cert_request = 1;

    return 1;
 err:
    ossl_statem_set_error(s);
    return 0;
}

MSG_PROCESS_RETURN tls_process_client_key_exchange(SSL *s, PACKET *pkt)
{
    int al;
    unsigned int i;
    unsigned long alg_k;
#ifndef OPENSSL_NO_RSA
    RSA *rsa = NULL;
    EVP_PKEY *pkey = NULL;
#endif
#ifndef OPENSSL_NO_DH
    BIGNUM *pub = NULL;
    DH *dh_srvr, *dh_clnt = NULL;
#endif
#ifndef OPENSSL_NO_EC
    EC_KEY *srvr_ecdh = NULL;
    EVP_PKEY *clnt_pub_pkey = NULL;
    EC_POINT *clnt_ecpoint = NULL;
    BN_CTX *bn_ctx = NULL;
#endif
    PACKET enc_premaster;
    unsigned char *data, *rsa_decrypt = NULL;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

#ifndef OPENSSL_NO_PSK
    /* For PSK parse and retrieve identity, obtain PSK key */
    if (alg_k & SSL_PSK) {
        unsigned char psk[PSK_MAX_PSK_LEN];
        size_t psklen;
        PACKET psk_identity;

        if (!PACKET_get_length_prefixed_2(pkt, &psk_identity)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }
        if (PACKET_remaining(&psk_identity) > PSK_MAX_IDENTITY_LEN) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            goto f_err;
        }
        if (s->psk_server_callback == NULL) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                   SSL_R_PSK_NO_SERVER_CB);
            goto f_err;
        }

        if (!PACKET_strndup(&psk_identity, &s->session->psk_identity)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }

        psklen = s->psk_server_callback(s, s->session->psk_identity,
                                         psk, sizeof(psk));

        if (psklen > PSK_MAX_PSK_LEN) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto f_err;
        } else if (psklen == 0) {
            /*
             * PSK related to the given identity not found
             */
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                   SSL_R_PSK_IDENTITY_NOT_FOUND);
            al = SSL_AD_UNKNOWN_PSK_IDENTITY;
            goto f_err;
        }

        OPENSSL_free(s->s3->tmp.psk);
        s->s3->tmp.psk = BUF_memdup(psk, psklen);
        OPENSSL_cleanse(psk, psklen);

        if (s->s3->tmp.psk == NULL) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }

        s->s3->tmp.psklen = psklen;
    }
    if (alg_k & SSL_kPSK) {
        /* Identity extracted earlier: should be nothing left */
        if (PACKET_remaining(pkt) != 0) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }
        /* PSK handled by ssl_generate_master_secret */
        if (!ssl_generate_master_secret(s, NULL, 0, 0)) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }
    } else
#endif
#ifndef OPENSSL_NO_RSA
    if (alg_k & (SSL_kRSA | SSL_kRSAPSK)) {
        unsigned char rand_premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];
        int decrypt_len;
        unsigned char decrypt_good, version_good;
        size_t j;

        /* FIX THIS UP EAY EAY EAY EAY */
        if (s->s3->tmp.use_rsa_tmp) {
            if ((s->cert != NULL) && (s->cert->rsa_tmp != NULL))
                rsa = s->cert->rsa_tmp;
            /*
             * Don't do a callback because rsa_tmp should be sent already
             */
            if (rsa == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_TMP_RSA_PKEY);
                goto f_err;

            }
        } else {
            pkey = s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey;
            if ((pkey == NULL) ||
                (pkey->type != EVP_PKEY_RSA) || (pkey->pkey.rsa == NULL)) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_RSA_CERTIFICATE);
                goto f_err;
            }
            rsa = pkey->pkey.rsa;
        }

        /* SSLv3 and pre-standard DTLS omit the length bytes. */
        if (s->version == SSL3_VERSION || s->version == DTLS1_BAD_VER) {
            enc_premaster = *pkt;
        } else {
            PACKET orig = *pkt;
            if (!PACKET_get_length_prefixed_2(pkt, &enc_premaster)
                || PACKET_remaining(pkt) != 0) {
                /* Try SSLv3 behaviour for TLS. */
                if (s->options & SSL_OP_TLS_D5_BUG) {
                    enc_premaster = orig;
                } else {
                    al = SSL_AD_DECODE_ERROR;
                    SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                           SSL_R_LENGTH_MISMATCH);
                    goto f_err;
                }
            }
        }

        /*
         * We want to be sure that the plaintext buffer size makes it safe to
         * iterate over the entire size of a premaster secret
         * (SSL_MAX_MASTER_KEY_LENGTH). Reject overly short RSA keys because
         * their ciphertext cannot accommodate a premaster secret anyway.
         */
        if (RSA_size(rsa) < SSL_MAX_MASTER_KEY_LENGTH) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                   RSA_R_KEY_SIZE_TOO_SMALL);
            goto f_err;
        }

        rsa_decrypt = OPENSSL_malloc(RSA_size(rsa));
        if (rsa_decrypt == NULL) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }

        /*
         * We must not leak whether a decryption failure occurs because of
         * Bleichenbacher's attack on PKCS #1 v1.5 RSA padding (see RFC 2246,
         * section 7.4.7.1). The code follows that advice of the TLS RFC and
         * generates a random premaster secret for the case that the decrypt
         * fails. See https://tools.ietf.org/html/rfc5246#section-7.4.7.1
         */

        if (RAND_bytes(rand_premaster_secret,
                       sizeof(rand_premaster_secret)) <= 0) {
            goto err;
        }

        decrypt_len = RSA_private_decrypt(PACKET_remaining(&enc_premaster),
                                          PACKET_data(&enc_premaster),
                                          rsa_decrypt, rsa, RSA_PKCS1_PADDING);
        ERR_clear_error();

        /*
         * decrypt_len should be SSL_MAX_MASTER_KEY_LENGTH. decrypt_good will
         * be 0xff if so and zero otherwise.
         */
        decrypt_good =
            constant_time_eq_int_8(decrypt_len, SSL_MAX_MASTER_KEY_LENGTH);

        /*
         * If the version in the decrypted pre-master secret is correct then
         * version_good will be 0xff, otherwise it'll be zero. The
         * Klima-Pokorny-Rosa extension of Bleichenbacher's attack
         * (http://eprint.iacr.org/2003/052/) exploits the version number
         * check as a "bad version oracle". Thus version checks are done in
         * constant time and are treated like any other decryption error.
         */
        version_good =
            constant_time_eq_8(rsa_decrypt[0],
                               (unsigned)(s->client_version >> 8));
        version_good &=
            constant_time_eq_8(rsa_decrypt[1],
                               (unsigned)(s->client_version & 0xff));

        /*
         * The premaster secret must contain the same version number as the
         * ClientHello to detect version rollback attacks (strangely, the
         * protocol does not offer such protection for DH ciphersuites).
         * However, buggy clients exist that send the negotiated protocol
         * version instead if the server does not support the requested
         * protocol version. If SSL_OP_TLS_ROLLBACK_BUG is set, tolerate such
         * clients.
         */
        if (s->options & SSL_OP_TLS_ROLLBACK_BUG) {
            unsigned char workaround_good;
            workaround_good =
                constant_time_eq_8(rsa_decrypt[0], (unsigned)(s->version >> 8));
            workaround_good &=
                constant_time_eq_8(rsa_decrypt[1],
                                   (unsigned)(s->version & 0xff));
            version_good |= workaround_good;
        }

        /*
         * Both decryption and version must be good for decrypt_good to
         * remain non-zero (0xff).
         */
        decrypt_good &= version_good;

        /*
         * Now copy rand_premaster_secret over from p using
         * decrypt_good_mask. If decryption failed, then p does not
         * contain valid plaintext, however, a check above guarantees
         * it is still sufficiently large to read from.
         */
        for (j = 0; j < sizeof(rand_premaster_secret); j++) {
            rsa_decrypt[j] =
                constant_time_select_8(decrypt_good, rsa_decrypt[j],
                                       rand_premaster_secret[j]);
        }

        if (!ssl_generate_master_secret(s, rsa_decrypt,
                                        sizeof(rand_premaster_secret), 0)) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }
        OPENSSL_free(rsa_decrypt);
        rsa_decrypt = NULL;
    } else
#endif
#ifndef OPENSSL_NO_DH
    if (alg_k & (SSL_kDHE | SSL_kDHr | SSL_kDHd | SSL_kDHEPSK)) {
        int idx = -1;
        EVP_PKEY *skey = NULL;
        PACKET bookmark = *pkt;
        unsigned char shared[(OPENSSL_DH_MAX_MODULUS_BITS + 7) / 8];

        if (!PACKET_get_net_2(pkt, &i)) {
            if (alg_k & (SSL_kDHE | SSL_kDHEPSK)) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG);
                goto f_err;
            }
            i = 0;
        }
        if (PACKET_remaining(pkt) != i) {
            if (!(s->options & SSL_OP_SSLEAY_080_CLIENT_DH_BUG)) {
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG);
                goto err;
            } else {
                *pkt = bookmark;
                i = PACKET_remaining(pkt);
            }
        }
        if (alg_k & SSL_kDHr)
            idx = SSL_PKEY_DH_RSA;
        else if (alg_k & SSL_kDHd)
            idx = SSL_PKEY_DH_DSA;
        if (idx >= 0) {
            skey = s->cert->pkeys[idx].privatekey;
            if ((skey == NULL) ||
                (skey->type != EVP_PKEY_DH) || (skey->pkey.dh == NULL)) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_RSA_CERTIFICATE);
                goto f_err;
            }
            dh_srvr = skey->pkey.dh;
        } else if (s->s3->tmp.dh == NULL) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                   SSL_R_MISSING_TMP_DH_KEY);
            goto f_err;
        } else
            dh_srvr = s->s3->tmp.dh;

        if (PACKET_remaining(pkt) == 0L) {
            /* Get pubkey from cert */
            EVP_PKEY *clkey = X509_get_pubkey(s->session->peer);
            if (clkey) {
                if (EVP_PKEY_cmp_parameters(clkey, skey) == 1)
                    dh_clnt = EVP_PKEY_get1_DH(clkey);
            }
            if (dh_clnt == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_TMP_DH_KEY);
                goto f_err;
            }
            EVP_PKEY_free(clkey);
            pub = dh_clnt->pub_key;
        } else {
            if (!PACKET_get_bytes(pkt, &data, i)) {
                /* We already checked we have enough data */
                al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto f_err;
            }
            pub = BN_bin2bn(data, i, NULL);
        }
        if (pub == NULL) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, SSL_R_BN_LIB);
            goto err;
        }

        i = DH_compute_key(shared, pub, dh_srvr);

        if (i <= 0) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
            BN_clear_free(pub);
            goto err;
        }

        DH_free(s->s3->tmp.dh);
        s->s3->tmp.dh = NULL;
        if (dh_clnt)
            DH_free(dh_clnt);
        else
            BN_clear_free(pub);
        pub = NULL;
        if (!ssl_generate_master_secret(s, shared, i, 0)) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }
        if (dh_clnt) {
            s->statem.no_cert_verify = 1;
            return MSG_PROCESS_CONTINUE_PROCESSING;
        }
    } else
#endif

#ifndef OPENSSL_NO_EC
    if (alg_k & (SSL_kECDHE | SSL_kECDHr | SSL_kECDHe | SSL_kECDHEPSK)) {
        int field_size = 0;
        const EC_KEY *tkey;
        const EC_GROUP *group;
        const BIGNUM *priv_key;
        unsigned char *shared;

        /* initialize structures for server's ECDH key pair */
        if ((srvr_ecdh = EC_KEY_new()) == NULL) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* Let's get server private key and group information */
        if (alg_k & (SSL_kECDHr | SSL_kECDHe)) {
            /* use the certificate */
            tkey = s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec;
        } else {
            /*
             * use the ephermeral values we saved when generating the
             * ServerKeyExchange msg.
             */
            tkey = s->s3->tmp.ecdh;
        }

        group = EC_KEY_get0_group(tkey);
        priv_key = EC_KEY_get0_private_key(tkey);

        if (!EC_KEY_set_group(srvr_ecdh, group) ||
            !EC_KEY_set_private_key(srvr_ecdh, priv_key)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
            goto err;
        }

        /* Let's get client's public key */
        if ((clnt_ecpoint = EC_POINT_new(group)) == NULL) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (PACKET_remaining(pkt) == 0L) {
            /* Client Publickey was in Client Certificate */

            if (alg_k & (SSL_kECDHE | SSL_kECDHEPSK)) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_TMP_ECDH_KEY);
                goto f_err;
            }
            if (((clnt_pub_pkey = X509_get_pubkey(s->session->peer))
                 == NULL) || (clnt_pub_pkey->type != EVP_PKEY_EC)) {
                /*
                 * XXX: For now, we do not support client authentication
                 * using ECDH certificates so this branch (n == 0L) of the
                 * code is never executed. When that support is added, we
                 * ought to ensure the key received in the certificate is
                 * authorized for key agreement. ECDH_compute_key implicitly
                 * checks that the two ECDH shares are for the same group.
                 */
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       SSL_R_UNABLE_TO_DECODE_ECDH_CERTS);
                goto f_err;
            }

            if (EC_POINT_copy(clnt_ecpoint,
                              EC_KEY_get0_public_key(clnt_pub_pkey->
                                                     pkey.ec)) == 0) {
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                goto err;
            }
            s->statem.no_cert_verify = 1;
        } else {
            /*
             * Get client's public key from encoded point in the
             * ClientKeyExchange message.
             */
            if ((bn_ctx = BN_CTX_new()) == NULL) {
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }

            /* Get encoded point length */
            if (!PACKET_get_1(pkt, &i)) {
                al = SSL_AD_DECODE_ERROR;
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                       SSL_R_LENGTH_MISMATCH);
                goto f_err;
            }
            if (!PACKET_get_bytes(pkt, &data, i)
                    || PACKET_remaining(pkt) != 0) {
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                goto err;
            }
            if (EC_POINT_oct2point(group, clnt_ecpoint, data, i, bn_ctx) == 0) {
                SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                goto err;
            }
        }

        /* Compute the shared pre-master secret */
        field_size = EC_GROUP_get_degree(group);
        if (field_size <= 0) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
            goto err;
        }
        shared = OPENSSL_malloc((field_size + 7) / 8);
        if (shared == NULL) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        i = ECDH_compute_key(shared, (field_size + 7) / 8, clnt_ecpoint,
                             srvr_ecdh, NULL);
        if (i <= 0) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
            OPENSSL_free(shared);
            goto err;
        }

        EVP_PKEY_free(clnt_pub_pkey);
        EC_POINT_free(clnt_ecpoint);
        EC_KEY_free(srvr_ecdh);
        BN_CTX_free(bn_ctx);
        EC_KEY_free(s->s3->tmp.ecdh);
        s->s3->tmp.ecdh = NULL;

        if (!ssl_generate_master_secret(s, shared, i, 1)) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }
        return MSG_PROCESS_CONTINUE_PROCESSING;
    } else
#endif
#ifndef OPENSSL_NO_SRP
    if (alg_k & SSL_kSRP) {
        if (!PACKET_get_net_2(pkt, &i)
                || !PACKET_get_bytes(pkt, &data, i)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, SSL_R_BAD_SRP_A_LENGTH);
            goto f_err;
        }
        if ((s->srp_ctx.A = BN_bin2bn(data, i, NULL)) == NULL) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        if (BN_ucmp(s->srp_ctx.A, s->srp_ctx.N) >= 0
            || BN_is_zero(s->srp_ctx.A)) {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                   SSL_R_BAD_SRP_PARAMETERS);
            goto f_err;
        }
        OPENSSL_free(s->session->srp_username);
        s->session->srp_username = BUF_strdup(s->srp_ctx.login);
        if (s->session->srp_username == NULL) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (!srp_generate_server_master_secret(s)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else
#endif                          /* OPENSSL_NO_SRP */
#ifndef OPENSSL_NO_GOST
    if (alg_k & SSL_kGOST) {
        EVP_PKEY_CTX *pkey_ctx;
        EVP_PKEY *client_pub_pkey = NULL, *pk = NULL;
        unsigned char premaster_secret[32], *start;
        size_t outlen = 32, inlen;
        unsigned long alg_a;
        int Ttag, Tclass;
        long Tlen;
        long sess_key_len;

        /* Get our certificate private key */
        alg_a = s->s3->tmp.new_cipher->algorithm_auth;
        if (alg_a & SSL_aGOST12) {
            /*
             * New GOST ciphersuites have SSL_aGOST01 bit too
             */
            pk = s->cert->pkeys[SSL_PKEY_GOST12_512].privatekey;
            if (pk == NULL) {
                pk = s->cert->pkeys[SSL_PKEY_GOST12_256].privatekey;
            }
            if (pk == NULL) {
                pk = s->cert->pkeys[SSL_PKEY_GOST01].privatekey;
            }
        } else if (alg_a & SSL_aGOST01) {
            pk = s->cert->pkeys[SSL_PKEY_GOST01].privatekey;
        }

        pkey_ctx = EVP_PKEY_CTX_new(pk, NULL);
        if (pkey_ctx == NULL) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }
        if (EVP_PKEY_decrypt_init(pkey_ctx) <= 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }
        /*
         * If client certificate is present and is of the same type, maybe
         * use it for key exchange.  Don't mind errors from
         * EVP_PKEY_derive_set_peer, because it is completely valid to use a
         * client certificate for authorization only.
         */
        client_pub_pkey = X509_get_pubkey(s->session->peer);
        if (client_pub_pkey) {
            if (EVP_PKEY_derive_set_peer(pkey_ctx, client_pub_pkey) <= 0)
                ERR_clear_error();
        }
        /* Decrypt session key */
        sess_key_len = PACKET_remaining(pkt);
        if (!PACKET_get_bytes(pkt, &data, sess_key_len)) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto gerr;
        }
        if (ASN1_get_object ((const unsigned char **)&data, &Tlen, &Ttag,
                             &Tclass, sess_key_len) != V_ASN1_CONSTRUCTED
            || Ttag != V_ASN1_SEQUENCE
            || Tclass != V_ASN1_UNIVERSAL) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                   SSL_R_DECRYPTION_FAILED);
            goto gerr;
        }
        start = data;
        inlen = Tlen;
        if (EVP_PKEY_decrypt
            (pkey_ctx, premaster_secret, &outlen, start, inlen) <= 0) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
                   SSL_R_DECRYPTION_FAILED);
            goto gerr;
        }
        /* Generate master secret */
        if (!ssl_generate_master_secret(s, premaster_secret,
                                        sizeof(premaster_secret), 0)) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto gerr;
        }
        /* Check if pubkey from client certificate was used */
        if (EVP_PKEY_CTX_ctrl
            (pkey_ctx, -1, -1, EVP_PKEY_CTRL_PEER_KEY, 2, NULL) > 0)
            s->statem.no_cert_verify = 1;

        EVP_PKEY_free(client_pub_pkey);
        EVP_PKEY_CTX_free(pkey_ctx);
        return MSG_PROCESS_CONTINUE_PROCESSING;
 gerr:
        EVP_PKEY_free(client_pub_pkey);
        EVP_PKEY_CTX_free(pkey_ctx);
        goto f_err;
    } else
#endif
    {
        al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE, SSL_R_UNKNOWN_CIPHER_TYPE);
        goto f_err;
    }

    return MSG_PROCESS_CONTINUE_PROCESSING;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_RSA) || !defined(OPENSSL_NO_EC) || defined(OPENSSL_NO_SRP)
 err:
#endif
#ifndef OPENSSL_NO_EC
    EVP_PKEY_free(clnt_pub_pkey);
    EC_POINT_free(clnt_ecpoint);
    EC_KEY_free(srvr_ecdh);
    BN_CTX_free(bn_ctx);
    OPENSSL_free(rsa_decrypt);
#endif
#ifndef OPENSSL_NO_PSK
    OPENSSL_clear_free(s->s3->tmp.psk, s->s3->tmp.psklen);
    s->s3->tmp.psk = NULL;
#endif
    ossl_statem_set_error(s);
    return MSG_PROCESS_ERROR;
}

WORK_STATE tls_post_process_client_key_exchange(SSL *s, WORK_STATE wst)
{
#ifndef OPENSSL_NO_SCTP
    if (wst == WORK_MORE_A) {
        if (SSL_IS_DTLS(s)) {
            unsigned char sctpauthkey[64];
            char labelbuffer[sizeof(DTLS1_SCTP_AUTH_LABEL)];
            /*
             * Add new shared key for SCTP-Auth, will be ignored if no SCTP
             * used.
             */
            memcpy(labelbuffer, DTLS1_SCTP_AUTH_LABEL,
                   sizeof(DTLS1_SCTP_AUTH_LABEL));

            if (SSL_export_keying_material(s, sctpauthkey,
                                       sizeof(sctpauthkey), labelbuffer,
                                       sizeof(labelbuffer), NULL, 0, 0) <= 0) {
                ossl_statem_set_error(s);
                return WORK_ERROR;;
            }

            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                     sizeof(sctpauthkey), sctpauthkey);
        }
        wst = WORK_MORE_B;
    }

    if ((wst == WORK_MORE_B)
            /* Is this SCTP? */
            && BIO_dgram_is_sctp(SSL_get_wbio(s))
            /* Are we renegotiating? */
            && s->renegotiate
            /* Are we going to skip the CertificateVerify? */
            && (s->session->peer == NULL || s->statem.no_cert_verify)
            && BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
        s->s3->in_read_app_data = 2;
        s->rwstate = SSL_READING;
        BIO_clear_retry_flags(SSL_get_rbio(s));
        BIO_set_retry_read(SSL_get_rbio(s));
        ossl_statem_set_sctp_read_sock(s, 1);
        return WORK_MORE_B;
    } else {
        ossl_statem_set_sctp_read_sock(s, 0);
    }
#endif

    if (s->statem.no_cert_verify) {
        /* No certificate verify so we no longer need the handshake_buffer */
        BIO_free(s->s3->handshake_buffer);
        s->s3->handshake_buffer = NULL;
        return WORK_FINISHED_CONTINUE;
    } else {
        if (!s->session->peer) {
            /* No peer certificate so we no longer need the handshake_buffer */
            BIO_free(s->s3->handshake_buffer);
            return WORK_FINISHED_CONTINUE;
        }
        if (!s->s3->handshake_buffer) {
            SSLerr(SSL_F_TLS_POST_PROCESS_CLIENT_KEY_EXCHANGE,
                   ERR_R_INTERNAL_ERROR);
            ossl_statem_set_error(s);
            return WORK_ERROR;
        }
        /*
         * For sigalgs freeze the handshake buffer. If we support
         * extms we've done this already so this is a no-op
         */
        if (!ssl3_digest_cached_records(s, 1)) {
            ossl_statem_set_error(s);
            return WORK_ERROR;
        }
    }

    return WORK_FINISHED_CONTINUE;
}

MSG_PROCESS_RETURN tls_process_cert_verify(SSL *s, PACKET *pkt)
{
    EVP_PKEY *pkey = NULL;
    unsigned char *sig, *data;
    int al, ret = MSG_PROCESS_ERROR;
    int type = 0, j;
    unsigned int len;
    X509 *peer;
    const EVP_MD *md = NULL;
    long hdatalen = 0;
    void *hdata;

    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);

    peer = s->session->peer;
    pkey = X509_get_pubkey(peer);
    type = X509_certificate_type(peer, pkey);

    if (!(type & EVP_PKT_SIGN)) {
        SSLerr(SSL_F_TLS_PROCESS_CERT_VERIFY,
               SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE);
        al = SSL_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }

    /* Check for broken implementations of GOST ciphersuites */
    /*
     * If key is GOST and n is exactly 64, it is bare signature without
     * length field (CryptoPro implementations at least till CSP 4.0)
     */
#ifndef OPENSSL_NO_GOST
    if (PACKET_remaining(pkt) == 64 && pkey->type == NID_id_GostR3410_2001) {
        len = 64;
    } else
#endif
    {
        if (SSL_USE_SIGALGS(s)) {
            int rv;

            if (!PACKET_get_bytes(pkt, &sig, 2)) {
                al = SSL_AD_DECODE_ERROR;
                goto f_err;
            }
            rv = tls12_check_peer_sigalg(&md, s, sig, pkey);
            if (rv == -1) {
                al = SSL_AD_INTERNAL_ERROR;
                goto f_err;
            } else if (rv == 0) {
                al = SSL_AD_DECODE_ERROR;
                goto f_err;
            }
#ifdef SSL_DEBUG
            fprintf(stderr, "USING TLSv1.2 HASH %s\n", EVP_MD_name(md));
#endif
        } else {
            /* Use default digest for this key type */
            int idx = ssl_cert_type(NULL, pkey);
            if (idx >= 0)
                md = s->s3->tmp.md[idx];
            if (md == NULL) {
                al = SSL_AD_INTERNAL_ERROR;
                goto f_err;
            }
        }

        if (!PACKET_get_net_2(pkt, &len)) {
            SSLerr(SSL_F_TLS_PROCESS_CERT_VERIFY, SSL_R_LENGTH_MISMATCH);
            al = SSL_AD_DECODE_ERROR;
            goto f_err;
        }
    }
    j = EVP_PKEY_size(pkey);
    if (((int)len > j) || ((int)PACKET_remaining(pkt) > j)
            || (PACKET_remaining(pkt) == 0)) {
        SSLerr(SSL_F_TLS_PROCESS_CERT_VERIFY, SSL_R_WRONG_SIGNATURE_SIZE);
        al = SSL_AD_DECODE_ERROR;
        goto f_err;
    }
    if (!PACKET_get_bytes(pkt, &data, len)) {
        SSLerr(SSL_F_TLS_PROCESS_CERT_VERIFY, SSL_R_LENGTH_MISMATCH);
        al = SSL_AD_DECODE_ERROR;
        goto f_err;
    }

    hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
    if (hdatalen <= 0) {
        SSLerr(SSL_F_TLS_PROCESS_CERT_VERIFY, ERR_R_INTERNAL_ERROR);
        al = SSL_AD_INTERNAL_ERROR;
        goto f_err;
    }
#ifdef SSL_DEBUG
    fprintf(stderr, "Using client verify alg %s\n", EVP_MD_name(md));
#endif
    if (!EVP_VerifyInit_ex(&mctx, md, NULL)
        || !EVP_VerifyUpdate(&mctx, hdata, hdatalen)) {
        SSLerr(SSL_F_TLS_PROCESS_CERT_VERIFY, ERR_R_EVP_LIB);
        al = SSL_AD_INTERNAL_ERROR;
        goto f_err;
    }

#ifndef OPENSSL_NO_GOST
    if (pkey->type == NID_id_GostR3410_2001
            || pkey->type == NID_id_GostR3410_2012_256
            || pkey->type == NID_id_GostR3410_2012_512) {
        BUF_reverse(data, NULL, len);
    }
#endif

    if (s->version == SSL3_VERSION
        && !EVP_MD_CTX_ctrl(&mctx, EVP_CTRL_SSL3_MASTER_SECRET,
                            s->session->master_key_length,
                            s->session->master_key)) {
        SSLerr(SSL_F_TLS_PROCESS_CERT_VERIFY, ERR_R_EVP_LIB);
        al = SSL_AD_INTERNAL_ERROR;
        goto f_err;
    }

    if (EVP_VerifyFinal(&mctx, data, len, pkey) <= 0) {
        al = SSL_AD_DECRYPT_ERROR;
        SSLerr(SSL_F_TLS_PROCESS_CERT_VERIFY, SSL_R_BAD_SIGNATURE);
        goto f_err;
    }

    ret = MSG_PROCESS_CONTINUE_PROCESSING;
    if (0) {
 f_err:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        ossl_statem_set_error(s);
    }
    BIO_free(s->s3->handshake_buffer);
    s->s3->handshake_buffer = NULL;
    EVP_MD_CTX_cleanup(&mctx);
    EVP_PKEY_free(pkey);
    return ret;
}

MSG_PROCESS_RETURN tls_process_client_certificate(SSL *s, PACKET *pkt)
{
    int i, al = SSL_AD_INTERNAL_ERROR, ret = MSG_PROCESS_ERROR;
    X509 *x = NULL;
    unsigned long l, llen;
    const unsigned char *certstart;
    unsigned char *certbytes;
    STACK_OF(X509) *sk = NULL;
    PACKET spkt;

    if ((sk = sk_X509_new_null()) == NULL) {
        SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        goto f_err;
    }

    if (!PACKET_get_net_3(pkt, &llen)
            || !PACKET_get_sub_packet(pkt, &spkt, llen)
            || PACKET_remaining(pkt) != 0) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }

    while (PACKET_remaining(&spkt) > 0) {
        if (!PACKET_get_net_3(&spkt, &l)
                || !PACKET_get_bytes(&spkt, &certbytes, l)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }

        certstart = certbytes;
        x = d2i_X509(NULL, (const unsigned char **)&certbytes, l);
        if (x == NULL) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE, ERR_R_ASN1_LIB);
            goto f_err;
        }
        if (certbytes != (certstart + l)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }
        if (!sk_X509_push(sk, x)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }
        x = NULL;
    }

    if (sk_X509_num(sk) <= 0) {
        /* TLS does not mind 0 certs returned */
        if (s->version == SSL3_VERSION) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE,
                   SSL_R_NO_CERTIFICATES_RETURNED);
            goto f_err;
        }
        /* Fail for TLS only if we required a certificate */
        else if ((s->verify_mode & SSL_VERIFY_PEER) &&
                 (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE,
                   SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
            al = SSL_AD_HANDSHAKE_FAILURE;
            goto f_err;
        }
        /* No client certificate so digest cached records */
        if (s->s3->handshake_buffer && !ssl3_digest_cached_records(s, 0)) {
            goto f_err;
        }
    } else {
        EVP_PKEY *pkey;
        i = ssl_verify_cert_chain(s, sk);
        if (i <= 0) {
            al = ssl_verify_alarm_type(s->verify_result);
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE,
                   SSL_R_CERTIFICATE_VERIFY_FAILED);
            goto f_err;
        }
        if (i > 1) {
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE, i);
            al = SSL_AD_HANDSHAKE_FAILURE;
            goto f_err;
        }
        pkey = X509_get_pubkey(sk_X509_value(sk, 0));
        if (pkey == NULL) {
            al = SSL3_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE,
                   SSL_R_UNKNOWN_CERTIFICATE_TYPE);
            goto f_err;
        }
        EVP_PKEY_free(pkey);
    }

    X509_free(s->session->peer);
    s->session->peer = sk_X509_shift(sk);
    s->session->verify_result = s->verify_result;

    sk_X509_pop_free(s->session->peer_chain, X509_free);
    s->session->peer_chain = sk;
    /*
     * Inconsistency alert: cert_chain does *not* include the peer's own
     * certificate, while we do include it in s3_clnt.c
     */
    sk = NULL;
    ret = MSG_PROCESS_CONTINUE_READING;
    goto done;

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    ossl_statem_set_error(s);
 done:
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);
    return ret;
}

int tls_construct_server_certificate(SSL *s)
{
    CERT_PKEY *cpk;

    cpk = ssl_get_server_send_pkey(s);
    if (cpk == NULL) {
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_CERTIFICATE, ERR_R_INTERNAL_ERROR);
        ossl_statem_set_error(s);
        return 0;
    }

    if (!ssl3_output_cert_chain(s, cpk)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_SERVER_CERTIFICATE, ERR_R_INTERNAL_ERROR);
        ossl_statem_set_error(s);
        return 0;
    }

    return 1;
}

int tls_construct_new_session_ticket(SSL *s)
{
    unsigned char *senc = NULL;
    EVP_CIPHER_CTX ctx;
    HMAC_CTX hctx;
    unsigned char *p, *macstart;
    const unsigned char *const_p;
    int len, slen_full, slen;
    SSL_SESSION *sess;
    unsigned int hlen;
    SSL_CTX *tctx = s->initial_ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char key_name[16];

    /* get session encoding length */
    slen_full = i2d_SSL_SESSION(s->session, NULL);
    /*
     * Some length values are 16 bits, so forget it if session is too
     * long
     */
    if (slen_full == 0 || slen_full > 0xFF00) {
        ossl_statem_set_error(s);
        return 0;
    }
    senc = OPENSSL_malloc(slen_full);
    if (senc == NULL) {
        ossl_statem_set_error(s);
        return 0;
    }

    EVP_CIPHER_CTX_init(&ctx);
    HMAC_CTX_init(&hctx);

    p = senc;
    if (!i2d_SSL_SESSION(s->session, &p))
        goto err;

    /*
     * create a fresh copy (not shared with other threads) to clean up
     */
    const_p = senc;
    sess = d2i_SSL_SESSION(NULL, &const_p, slen_full);
    if (sess == NULL)
        goto err;
    sess->session_id_length = 0; /* ID is irrelevant for the ticket */

    slen = i2d_SSL_SESSION(sess, NULL);
    if (slen == 0 || slen > slen_full) { /* shouldn't ever happen */
        SSL_SESSION_free(sess);
        goto err;
    }
    p = senc;
    if (!i2d_SSL_SESSION(sess, &p)) {
        SSL_SESSION_free(sess);
        goto err;
    }
    SSL_SESSION_free(sess);

    /*-
     * Grow buffer if need be: the length calculation is as
     * follows handshake_header_length +
     * 4 (ticket lifetime hint) + 2 (ticket length) +
     * 16 (key name) + max_iv_len (iv length) +
     * session_length + max_enc_block_size (max encrypted session
     * length) + max_md_size (HMAC).
     */
    if (!BUF_MEM_grow(s->init_buf,
                      SSL_HM_HEADER_LENGTH(s) + 22 + EVP_MAX_IV_LENGTH +
                      EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE + slen))
        goto err;

    p = ssl_handshake_start(s);
    /*
     * Initialize HMAC and cipher contexts. If callback present it does
     * all the work otherwise use generated values from parent ctx.
     */
    if (tctx->tlsext_ticket_key_cb) {
        if (tctx->tlsext_ticket_key_cb(s, key_name, iv, &ctx,
                                       &hctx, 1) < 0)
            goto err;
    } else {
        if (RAND_bytes(iv, 16) <= 0)
            goto err;
        if (!EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL,
                                tctx->tlsext_tick_aes_key, iv))
            goto err;
        if (!HMAC_Init_ex(&hctx, tctx->tlsext_tick_hmac_key, 16,
                          EVP_sha256(), NULL))
            goto err;
        memcpy(key_name, tctx->tlsext_tick_key_name, 16);
    }

    /*
     * Ticket lifetime hint (advisory only): We leave this unspecified
     * for resumed session (for simplicity), and guess that tickets for
     * new sessions will live as long as their sessions.
     */
    l2n(s->hit ? 0 : s->session->timeout, p);

    /* Skip ticket length for now */
    p += 2;
    /* Output key name */
    macstart = p;
    memcpy(p, key_name, 16);
    p += 16;
    /* output IV */
    memcpy(p, iv, EVP_CIPHER_CTX_iv_length(&ctx));
    p += EVP_CIPHER_CTX_iv_length(&ctx);
    /* Encrypt session data */
    if (!EVP_EncryptUpdate(&ctx, p, &len, senc, slen))
        goto err;
    p += len;
    if (!EVP_EncryptFinal(&ctx, p, &len))
        goto err;
    p += len;

    if (!HMAC_Update(&hctx, macstart, p - macstart))
        goto err;
    if (!HMAC_Final(&hctx, p, &hlen))
        goto err;

    EVP_CIPHER_CTX_cleanup(&ctx);
    HMAC_CTX_cleanup(&hctx);

    p += hlen;
    /* Now write out lengths: p points to end of data written */
    /* Total length */
    len = p - ssl_handshake_start(s);
    /* Skip ticket lifetime hint */
    p = ssl_handshake_start(s) + 4;
    s2n(len - 6, p);
    if (!ssl_set_handshake_header(s, SSL3_MT_NEWSESSION_TICKET, len))
        goto err;
    OPENSSL_free(senc);

    return 1;
 err:
    OPENSSL_free(senc);
    EVP_CIPHER_CTX_cleanup(&ctx);
    HMAC_CTX_cleanup(&hctx);
    ossl_statem_set_error(s);
    return 0;
}

int tls_construct_cert_status(SSL *s)
{
    unsigned char *p;
    /*-
     * Grow buffer if need be: the length calculation is as
     * follows 1 (message type) + 3 (message length) +
     * 1 (ocsp response type) + 3 (ocsp response length)
     * + (ocsp response)
     */
    if (!BUF_MEM_grow(s->init_buf, 8 + s->tlsext_ocsp_resplen)) {
        ossl_statem_set_error(s);
        return 0;
    }

    p = (unsigned char *)s->init_buf->data;

    /* do the header */
    *(p++) = SSL3_MT_CERTIFICATE_STATUS;
    /* message length */
    l2n3(s->tlsext_ocsp_resplen + 4, p);
    /* status type */
    *(p++) = s->tlsext_status_type;
    /* length of OCSP response */
    l2n3(s->tlsext_ocsp_resplen, p);
    /* actual response */
    memcpy(p, s->tlsext_ocsp_resp, s->tlsext_ocsp_resplen);
    /* number of bytes to write */
    s->init_num = 8 + s->tlsext_ocsp_resplen;
    s->init_off = 0;

    return 1;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * tls_process_next_proto reads a Next Protocol Negotiation handshake message.
 * It sets the next_proto member in s if found
 */
MSG_PROCESS_RETURN tls_process_next_proto(SSL *s, PACKET *pkt)
{
    PACKET next_proto, padding;
    size_t next_proto_len;

    /*-
     * The payload looks like:
     *   uint8 proto_len;
     *   uint8 proto[proto_len];
     *   uint8 padding_len;
     *   uint8 padding[padding_len];
     */
    if (!PACKET_get_length_prefixed_1(pkt, &next_proto)
        || !PACKET_get_length_prefixed_1(pkt, &padding)
        || PACKET_remaining(pkt) > 0) {
        SSLerr(SSL_F_TLS_PROCESS_NEXT_PROTO, SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    if (!PACKET_memdup(&next_proto, &s->next_proto_negotiated,
                       &next_proto_len)) {
        s->next_proto_negotiated_len = 0;
        goto err;
    }

    s->next_proto_negotiated_len = (unsigned char)next_proto_len;

    return MSG_PROCESS_CONTINUE_READING;
err:
    ossl_statem_set_error(s);
    return MSG_PROCESS_ERROR;
}
#endif

#define SSLV2_CIPHER_LEN    3

STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list(SSL *s,
                                               PACKET *cipher_suites,
                                               STACK_OF(SSL_CIPHER) **skp,
                                               int sslv2format, int *al
                                               )
{
    const SSL_CIPHER *c;
    STACK_OF(SSL_CIPHER) *sk;
    int n;
    /* 3 = SSLV2_CIPHER_LEN > TLS_CIPHER_LEN = 2. */
    unsigned char cipher[SSLV2_CIPHER_LEN];

    s->s3->send_connection_binding = 0;

    n = sslv2format ? SSLV2_CIPHER_LEN : TLS_CIPHER_LEN;

    if (PACKET_remaining(cipher_suites) == 0) {
        SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST, SSL_R_NO_CIPHERS_SPECIFIED);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return NULL;
    }

    if (PACKET_remaining(cipher_suites) % n != 0) {
        SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
               SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return NULL;
    }

    if ((skp == NULL) || (*skp == NULL)) {
        sk = sk_SSL_CIPHER_new_null(); /* change perhaps later */
        if(sk == NULL) {
            SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
            *al = SSL_AD_INTERNAL_ERROR;
            return NULL;
        }
    } else {
        sk = *skp;
        sk_SSL_CIPHER_zero(sk);
    }

    if (!PACKET_memdup(cipher_suites, &s->s3->tmp.ciphers_raw,
                       &s->s3->tmp.ciphers_rawlen)) {
        *al = SSL_AD_INTERNAL_ERROR;
        goto err;
    }

    while (PACKET_copy_bytes(cipher_suites, cipher, n)) {
        /*
         * SSLv3 ciphers wrapped in an SSLv2-compatible ClientHello have the
         * first byte set to zero, while true SSLv2 ciphers have a non-zero
         * first byte. We don't support any true SSLv2 ciphers, so skip them.
         */
        if (sslv2format && cipher[0] != '\0')
                continue;

        /* Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
        if ((cipher[n - 2] == ((SSL3_CK_SCSV >> 8) & 0xff)) &&
            (cipher[n - 1] == (SSL3_CK_SCSV & 0xff))) {
            /* SCSV fatal if renegotiating */
            if (s->renegotiate) {
                SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
                       SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING);
                *al = SSL_AD_HANDSHAKE_FAILURE;
                goto err;
            }
            s->s3->send_connection_binding = 1;
#ifdef OPENSSL_RI_DEBUG
            fprintf(stderr, "SCSV received by server\n");
#endif
            continue;
        }

        /* Check for TLS_FALLBACK_SCSV */
        if ((cipher[n - 2] == ((SSL3_CK_FALLBACK_SCSV >> 8) & 0xff)) &&
            (cipher[n - 1] == (SSL3_CK_FALLBACK_SCSV & 0xff))) {
            /*
             * The SCSV indicates that the client previously tried a higher
             * version. Fail if the current version is an unexpected
             * downgrade.
             */
            if (!SSL_ctrl(s, SSL_CTRL_CHECK_PROTO_VERSION, 0, NULL)) {
                SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
                       SSL_R_INAPPROPRIATE_FALLBACK);
                *al = SSL_AD_INAPPROPRIATE_FALLBACK;
                goto err;
            }
            continue;
        }

        /* For SSLv2-compat, ignore leading 0-byte. */
        c = ssl_get_cipher_by_char(s, sslv2format ? &cipher[1] : cipher);
        if (c != NULL) {
            if (!sk_SSL_CIPHER_push(sk, c)) {
                SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
                *al = SSL_AD_INTERNAL_ERROR;
                goto err;
            }
        }
    }
    if (PACKET_remaining(cipher_suites) > 0) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (skp != NULL)
        *skp = sk;
    return (sk);
 err:
    if ((skp == NULL) || (*skp == NULL))
        sk_SSL_CIPHER_free(sk);
    return NULL;
}
