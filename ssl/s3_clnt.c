/* ssl/s3_clnt.c */
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
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#include <openssl/bn.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

static int ssl_set_version(SSL *s);
static int ca_dn_cmp(const X509_NAME *const *a, const X509_NAME *const *b);
static int ssl3_check_change(SSL *s);
static int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk,
                                    unsigned char *p);


int ssl3_connect(SSL *s)
{
    BUF_MEM *buf = NULL;
    unsigned long Time = (unsigned long)time(NULL);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    int ret = -1;
    int new_state, state, skip = 0;

    RAND_add(&Time, sizeof(Time), 0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s)) {
        if (!SSL_clear(s))
            return -1;
    }

#ifndef OPENSSL_NO_HEARTBEATS
    /*
     * If we're awaiting a HeartbeatResponse, pretend we already got and
     * don't await it anymore, because Heartbeats don't make sense during
     * handshakes anyway.
     */
    if (s->tlsext_hb_pending) {
        s->tlsext_hb_pending = 0;
        s->tlsext_hb_seq++;
    }
#endif

    for (;;) {
        state = s->state;

        switch (s->state) {
        case SSL_ST_RENEGOTIATE:
            s->renegotiate = 1;
            s->state = SSL_ST_CONNECT;
            s->ctx->stats.sess_connect_renegotiate++;
            /* break */
        case SSL_ST_BEFORE:
        case SSL_ST_CONNECT:
        case SSL_ST_BEFORE | SSL_ST_CONNECT:
        case SSL_ST_OK | SSL_ST_CONNECT:

            s->server = 0;
            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_START, 1);

            if ((s->version >> 8) != SSL3_VERSION_MAJOR
                    && s->version != TLS_ANY_VERSION) {
                SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
                s->state = SSL_ST_ERR;
                ret = -1;
                goto end;
            }

            if (s->version != TLS_ANY_VERSION &&
                    !ssl_security(s, SSL_SECOP_VERSION, 0, s->version, NULL)) {
                SSLerr(SSL_F_SSL3_CONNECT, SSL_R_VERSION_TOO_LOW);
                return -1;
            }

            /* s->version=SSL3_VERSION; */
            s->type = SSL_ST_CONNECT;

            if (s->init_buf == NULL) {
                if ((buf = BUF_MEM_new()) == NULL) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                s->init_buf = buf;
                buf = NULL;
            }

            if (!ssl3_setup_buffers(s)) {
                ret = -1;
                goto end;
            }

            /* setup buffing BIO */
            if (!ssl_init_wbio_buffer(s, 0)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            /* don't push the buffering BIO quite yet */

            ssl3_init_finished_mac(s);

            s->state = SSL3_ST_CW_CLNT_HELLO_A;
            s->ctx->stats.sess_connect++;
            s->init_num = 0;
            /*
             * Should have been reset by ssl3_get_finished, too.
             */
            s->s3->change_cipher_spec = 0;
            break;

        case SSL3_ST_CW_CLNT_HELLO_A:
        case SSL3_ST_CW_CLNT_HELLO_B:

            s->shutdown = 0;
            ret = ssl3_client_hello(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_SRVR_HELLO_A;
            s->init_num = 0;

            /* turn on buffering for the next lot of output */
            if (s->bbio != s->wbio)
                s->wbio = BIO_push(s->bbio, s->wbio);

            break;

        case SSL3_ST_CR_SRVR_HELLO_A:
        case SSL3_ST_CR_SRVR_HELLO_B:
            ret = ssl3_get_server_hello(s);
            if (ret <= 0)
                goto end;

            if (s->hit) {
                s->state = SSL3_ST_CR_CHANGE_A;
                if (s->tlsext_ticket_expected) {
                    /* receive renewed session ticket */
                    s->state = SSL3_ST_CR_SESSION_TICKET_A;
                }
            } else {
                s->state = SSL3_ST_CR_CERT_A;
            }
            s->init_num = 0;
            break;
        case SSL3_ST_CR_CERT_A:
        case SSL3_ST_CR_CERT_B:
            /* Noop (ret = 0) for everything but EAP-FAST. */
            ret = ssl3_check_change(s);
            if (ret < 0)
                goto end;
            if (ret == 1) {
                s->hit = 1;
                s->state = SSL3_ST_CR_CHANGE_A;
                s->init_num = 0;
                break;
            }

            /* Check if it is anon DH/ECDH, SRP auth */
            /* or PSK */
            if (!(s->s3->tmp.new_cipher->algorithm_auth &
                    (SSL_aNULL | SSL_aSRP | SSL_aPSK))) {
                ret = ssl3_get_server_certificate(s);
                if (ret <= 0)
                    goto end;

                if (s->tlsext_status_expected)
                    s->state = SSL3_ST_CR_CERT_STATUS_A;
                else
                    s->state = SSL3_ST_CR_KEY_EXCH_A;
            } else {
                skip = 1;
                s->state = SSL3_ST_CR_KEY_EXCH_A;
            }

            s->init_num = 0;
            break;

        case SSL3_ST_CR_KEY_EXCH_A:
        case SSL3_ST_CR_KEY_EXCH_B:
            ret = ssl3_get_key_exchange(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_CERT_REQ_A;
            s->init_num = 0;

            /*
             * at this point we check that we have the required stuff from
             * the server
             */
            if (!ssl3_check_cert_and_algorithm(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }
            break;

        case SSL3_ST_CR_CERT_REQ_A:
        case SSL3_ST_CR_CERT_REQ_B:
            ret = ssl3_get_certificate_request(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_SRVR_DONE_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CR_SRVR_DONE_A:
        case SSL3_ST_CR_SRVR_DONE_B:
            ret = ssl3_get_server_done(s);
            if (ret <= 0)
                goto end;
#ifndef OPENSSL_NO_SRP
            if (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kSRP) {
                if ((ret = SRP_Calc_A_param(s)) <= 0) {
                    SSLerr(SSL_F_SSL3_CONNECT, SSL_R_SRP_A_CALC);
                    ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
                    s->state = SSL_ST_ERR;
                    goto end;
                }
            }
#endif
            if (s->s3->tmp.cert_req)
                s->state = SSL3_ST_CW_CERT_A;
            else
                s->state = SSL3_ST_CW_KEY_EXCH_A;
            s->init_num = 0;

            break;

        case SSL3_ST_CW_CERT_A:
        case SSL3_ST_CW_CERT_B:
        case SSL3_ST_CW_CERT_C:
        case SSL3_ST_CW_CERT_D:
            ret = ssl3_send_client_certificate(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_KEY_EXCH_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_KEY_EXCH_A:
        case SSL3_ST_CW_KEY_EXCH_B:
            ret = ssl3_send_client_key_exchange(s);
            if (ret <= 0)
                goto end;
            /*
             * EAY EAY EAY need to check for DH fix cert sent back
             */
            /*
             * For TLS, cert_req is set to 2, so a cert chain of nothing is
             * sent, but no verify packet is sent
             */
            /*
             * XXX: For now, we do not support client authentication in ECDH
             * cipher suites with ECDH (rather than ECDSA) certificates. We
             * need to skip the certificate verify message when client's
             * ECDH public key is sent inside the client certificate.
             */
            if (s->s3->tmp.cert_req == 1) {
                s->state = SSL3_ST_CW_CERT_VRFY_A;
            } else {
                s->state = SSL3_ST_CW_CHANGE_A;
            }
            if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
                s->state = SSL3_ST_CW_CHANGE_A;
            }

            s->init_num = 0;
            break;

        case SSL3_ST_CW_CERT_VRFY_A:
        case SSL3_ST_CW_CERT_VRFY_B:
            ret = ssl3_send_client_verify(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_CHANGE_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_CHANGE_A:
        case SSL3_ST_CW_CHANGE_B:
            ret = ssl3_send_change_cipher_spec(s,
                                               SSL3_ST_CW_CHANGE_A,
                                               SSL3_ST_CW_CHANGE_B);
            if (ret <= 0)
                goto end;

#if defined(OPENSSL_NO_NEXTPROTONEG)
            s->state = SSL3_ST_CW_FINISHED_A;
#else
            if (s->s3->next_proto_neg_seen)
                s->state = SSL3_ST_CW_NEXT_PROTO_A;
            else
                s->state = SSL3_ST_CW_FINISHED_A;
#endif
            s->init_num = 0;

            s->session->cipher = s->s3->tmp.new_cipher;
#ifdef OPENSSL_NO_COMP
            s->session->compress_meth = 0;
#else
            if (s->s3->tmp.new_compression == NULL)
                s->session->compress_meth = 0;
            else
                s->session->compress_meth = s->s3->tmp.new_compression->id;
#endif
            if (!s->method->ssl3_enc->setup_key_block(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            if (!s->method->ssl3_enc->change_cipher_state(s,
                                                          SSL3_CHANGE_CIPHER_CLIENT_WRITE))
            {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            break;

#if !defined(OPENSSL_NO_NEXTPROTONEG)
        case SSL3_ST_CW_NEXT_PROTO_A:
        case SSL3_ST_CW_NEXT_PROTO_B:
            ret = ssl3_send_next_proto(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_FINISHED_A;
            break;
#endif

        case SSL3_ST_CW_FINISHED_A:
        case SSL3_ST_CW_FINISHED_B:
            ret = ssl3_send_finished(s,
                                     SSL3_ST_CW_FINISHED_A,
                                     SSL3_ST_CW_FINISHED_B,
                                     s->method->
                                     ssl3_enc->client_finished_label,
                                     s->method->
                                     ssl3_enc->client_finished_label_len);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_FLUSH;

            if (s->hit) {
                s->s3->tmp.next_state = SSL_ST_OK;
            } else {
                /*
                 * Allow NewSessionTicket if ticket expected
                 */
                if (s->tlsext_ticket_expected)
                    s->s3->tmp.next_state = SSL3_ST_CR_SESSION_TICKET_A;
                else
                    s->s3->tmp.next_state = SSL3_ST_CR_CHANGE_A;
            }
            s->init_num = 0;
            break;

        case SSL3_ST_CR_SESSION_TICKET_A:
        case SSL3_ST_CR_SESSION_TICKET_B:
            ret = ssl3_get_new_session_ticket(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_CHANGE_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CR_CERT_STATUS_A:
        case SSL3_ST_CR_CERT_STATUS_B:
            ret = ssl3_get_cert_status(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_KEY_EXCH_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CR_CHANGE_A:
        case SSL3_ST_CR_CHANGE_B:
            ret = ssl3_get_change_cipher_spec(s, SSL3_ST_CR_CHANGE_A,
                                              SSL3_ST_CR_CHANGE_B);
            if (ret <= 0)
                goto end;

            s->state = SSL3_ST_CR_FINISHED_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CR_FINISHED_A:
        case SSL3_ST_CR_FINISHED_B:
            ret = ssl3_get_finished(s, SSL3_ST_CR_FINISHED_A,
                                    SSL3_ST_CR_FINISHED_B);
            if (ret <= 0)
                goto end;

            if (s->hit)
                s->state = SSL3_ST_CW_CHANGE_A;
            else
                s->state = SSL_ST_OK;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_FLUSH:
            s->rwstate = SSL_WRITING;
            if (BIO_flush(s->wbio) <= 0) {
                ret = -1;
                goto end;
            }
            s->rwstate = SSL_NOTHING;
            s->state = s->s3->tmp.next_state;
            break;

        case SSL_ST_OK:
            /* clean a few things up */
            ssl3_cleanup_key_block(s);
            BUF_MEM_free(s->init_buf);
            s->init_buf = NULL;

            /* remove the buffering */
            ssl_free_wbio_buffer(s);

            s->init_num = 0;
            s->renegotiate = 0;
            s->new_session = 0;

            ssl_update_cache(s, SSL_SESS_CACHE_CLIENT);
            if (s->hit)
                s->ctx->stats.sess_hit++;

            ret = 1;
            /* s->server=0; */
            s->handshake_func = ssl3_connect;
            s->ctx->stats.sess_connect_good++;

            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_DONE, 1);

            goto end;
            /* break; */

        case SSL_ST_ERR:
        default:
            SSLerr(SSL_F_SSL3_CONNECT, SSL_R_UNKNOWN_STATE);
            ret = -1;
            goto end;
            /* break; */
        }

        /* did we do anything */
        if (!s->s3->tmp.reuse_message && !skip) {
            if (s->debug) {
                if ((ret = BIO_flush(s->wbio)) <= 0)
                    goto end;
            }

            if ((cb != NULL) && (s->state != state)) {
                new_state = s->state;
                s->state = state;
                cb(s, SSL_CB_CONNECT_LOOP, 1);
                s->state = new_state;
            }
        }
        skip = 0;
    }
 end:
    s->in_handshake--;
    BUF_MEM_free(buf);
    if (cb != NULL)
        cb(s, SSL_CB_CONNECT_EXIT, ret);
    return (ret);
}

/*
 * Work out what version we should be using for the initial ClientHello if
 * the version is currently set to (D)TLS_ANY_VERSION.
 * Returns 1 on success
 * Returns 0 on error
 */
static int ssl_set_version(SSL *s)
{
    unsigned long mask, options = s->options;

    if (s->method->version == TLS_ANY_VERSION) {
        /*
         * SSL_OP_NO_X disables all protocols above X *if* there are
         * some protocols below X enabled. This is required in order
         * to maintain "version capability" vector contiguous. So
         * that if application wants to disable TLS1.0 in favour of
         * TLS1>=1, it would be insufficient to pass SSL_NO_TLSv1, the
         * answer is SSL_OP_NO_TLSv1|SSL_OP_NO_SSLv3.
         */
        mask = SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1
#if !defined(OPENSSL_NO_SSL3)
            | SSL_OP_NO_SSLv3
#endif
            ;
#if !defined(OPENSSL_NO_TLS1_2_CLIENT)
        if (options & SSL_OP_NO_TLSv1_2) {
            if ((options & mask) != mask) {
                s->version = TLS1_1_VERSION;
            } else {
                SSLerr(SSL_F_SSL_SET_VERSION, SSL_R_NO_PROTOCOLS_AVAILABLE);
                return 0;
            }
        } else {
            s->version = TLS1_2_VERSION;
        }
#else
        if ((options & mask) == mask) {
            SSLerr(SSL_F_SSL_SET_VERSION, SSL_R_NO_PROTOCOLS_AVAILABLE);
            return 0;
        }
        s->version = TLS1_1_VERSION;
#endif

        mask &= ~SSL_OP_NO_TLSv1_1;
        if ((options & SSL_OP_NO_TLSv1_1) && (options & mask) != mask)
            s->version = TLS1_VERSION;
        mask &= ~SSL_OP_NO_TLSv1;
#if !defined(OPENSSL_NO_SSL3)
        if ((options & SSL_OP_NO_TLSv1) && (options & mask) != mask)
            s->version = SSL3_VERSION;
#endif

        if (s->version != TLS1_2_VERSION && tls1_suiteb(s)) {
            SSLerr(SSL_F_SSL_SET_VERSION,
                   SSL_R_ONLY_TLS_1_2_ALLOWED_IN_SUITEB_MODE);
            return 0;
        }

        if (s->version == SSL3_VERSION && FIPS_mode()) {
            SSLerr(SSL_F_SSL_SET_VERSION, SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE);
            return 0;
        }

    } else if (s->method->version == DTLS_ANY_VERSION) {
        /* Determine which DTLS version to use */
        /* If DTLS 1.2 disabled correct the version number */
        if (options & SSL_OP_NO_DTLSv1_2) {
            if (tls1_suiteb(s)) {
                SSLerr(SSL_F_SSL_SET_VERSION,
                       SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
                return 0;
            }
            /*
             * Disabling all versions is silly: return an error.
             */
            if (options & SSL_OP_NO_DTLSv1) {
                SSLerr(SSL_F_SSL_SET_VERSION, SSL_R_WRONG_SSL_VERSION);
                return 0;
            }
            /*
             * Update method so we don't use any DTLS 1.2 features.
             */
            s->method = DTLSv1_client_method();
            s->version = DTLS1_VERSION;
        } else {
            /*
             * We only support one version: update method
             */
            if (options & SSL_OP_NO_DTLSv1)
                s->method = DTLSv1_2_client_method();
            s->version = DTLS1_2_VERSION;
        }
    }

    s->client_version = s->version;

    return 1;
}

int ssl3_client_hello(SSL *s)
{
    unsigned char *buf;
    unsigned char *p, *d;
    int i;
    unsigned long l;
    int al = 0;
#ifndef OPENSSL_NO_COMP
    int j;
    SSL_COMP *comp;
#endif

    buf = (unsigned char *)s->init_buf->data;
    if (s->state == SSL3_ST_CW_CLNT_HELLO_A) {
        SSL_SESSION *sess = s->session;

        /* Work out what SSL/TLS/DTLS version to use */
        if (ssl_set_version(s) == 0)
            goto err;

        if ((sess == NULL) || (sess->ssl_version != s->version) ||
            /*
             * In the case of EAP-FAST, we can have a pre-shared
             * "ticket" without a session ID.
             */
            (!sess->session_id_length && !sess->tlsext_tick) ||
            (sess->not_resumable)) {
            if (!ssl_get_new_session(s, 0))
                goto err;
        }
        /* else use the pre-loaded session */

        p = s->s3->client_random;

        /*
         * for DTLS if client_random is initialized, reuse it, we are
         * required to use same upon reply to HelloVerify
         */
        if (SSL_IS_DTLS(s)) {
            size_t idx;
            i = 1;
            for (idx = 0; idx < sizeof(s->s3->client_random); idx++) {
                if (p[idx]) {
                    i = 0;
                    break;
                }
            }
        } else
            i = 1;

        if (i && ssl_fill_hello_random(s, 0, p,
                                       sizeof(s->s3->client_random)) <= 0)
            goto err;

        /* Do the message type and length last */
        d = p = ssl_handshake_start(s);

        /*-
         * version indicates the negotiated version: for example from
         * an SSLv2/v3 compatible client hello). The client_version
         * field is the maximum version we permit and it is also
         * used in RSA encrypted premaster secrets. Some servers can
         * choke if we initially report a higher version then
         * renegotiate to a lower one in the premaster secret. This
         * didn't happen with TLS 1.0 as most servers supported it
         * but it can with TLS 1.1 or later if the server only supports
         * 1.0.
         *
         * Possible scenario with previous logic:
         *      1. Client hello indicates TLS 1.2
         *      2. Server hello says TLS 1.0
         *      3. RSA encrypted premaster secret uses 1.2.
         *      4. Handhaked proceeds using TLS 1.0.
         *      5. Server sends hello request to renegotiate.
         *      6. Client hello indicates TLS v1.0 as we now
         *         know that is maximum server supports.
         *      7. Server chokes on RSA encrypted premaster secret
         *         containing version 1.0.
         *
         * For interoperability it should be OK to always use the
         * maximum version we support in client hello and then rely
         * on the checking of version to ensure the servers isn't
         * being inconsistent: for example initially negotiating with
         * TLS 1.0 and renegotiating with TLS 1.2. We do this by using
         * client_version in client hello and not resetting it to
         * the negotiated version.
         */
        *(p++) = s->client_version >> 8;
        *(p++) = s->client_version & 0xff;

        /* Random stuff */
        memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
        p += SSL3_RANDOM_SIZE;

        /* Session ID */
        if (s->new_session)
            i = 0;
        else
            i = s->session->session_id_length;
        *(p++) = i;
        if (i != 0) {
            if (i > (int)sizeof(s->session->session_id)) {
                SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(p, s->session->session_id, i);
            p += i;
        }

        /* cookie stuff for DTLS */
        if (SSL_IS_DTLS(s)) {
            if (s->d1->cookie_len > sizeof(s->d1->cookie)) {
                SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            *(p++) = s->d1->cookie_len;
            memcpy(p, s->d1->cookie, s->d1->cookie_len);
            p += s->d1->cookie_len;
        }

        /* Ciphers supported */
        i = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), &(p[2]));
        if (i == 0) {
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, SSL_R_NO_CIPHERS_AVAILABLE);
            goto err;
        }
#ifdef OPENSSL_MAX_TLS1_2_CIPHER_LENGTH
        /*
         * Some servers hang if client hello > 256 bytes as hack workaround
         * chop number of supported ciphers to keep it well below this if we
         * use TLS v1.2
         */
        if (TLS1_get_version(s) >= TLS1_2_VERSION
            && i > OPENSSL_MAX_TLS1_2_CIPHER_LENGTH)
            i = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;
#endif
        s2n(i, p);
        p += i;

        /* COMPRESSION */
#ifdef OPENSSL_NO_COMP
        *(p++) = 1;
#else

        if (!ssl_allow_compression(s) || !s->ctx->comp_methods)
            j = 0;
        else
            j = sk_SSL_COMP_num(s->ctx->comp_methods);
        *(p++) = 1 + j;
        for (i = 0; i < j; i++) {
            comp = sk_SSL_COMP_value(s->ctx->comp_methods, i);
            *(p++) = comp->id;
        }
#endif
        *(p++) = 0;             /* Add the NULL method */

        /* TLS extensions */
        if (ssl_prepare_clienthello_tlsext(s) <= 0) {
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
            goto err;
        }
        if ((p =
             ssl_add_clienthello_tlsext(s, p, buf + SSL3_RT_MAX_PLAIN_LENGTH,
                                        &al)) == NULL) {
            ssl3_send_alert(s, SSL3_AL_FATAL, al);
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        l = p - d;
        if (!ssl_set_handshake_header(s, SSL3_MT_CLIENT_HELLO, l)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        s->state = SSL3_ST_CW_CLNT_HELLO_B;
    }

    /* SSL3_ST_CW_CLNT_HELLO_B */
    return ssl_do_write(s);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_server_hello(SSL *s)
{
    STACK_OF(SSL_CIPHER) *sk;
    const SSL_CIPHER *c;
    PACKET pkt, session_id;
    size_t session_id_len;
    unsigned char *cipherchars;
    int i, al = SSL_AD_INTERNAL_ERROR, ok;
    unsigned int compression;
    long n;
#ifndef OPENSSL_NO_COMP
    SSL_COMP *comp;
#endif
    /*
     * Hello verify request and/or server hello version may not match so set
     * first packet if we're negotiating version.
     */
    s->first_packet = 1;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SRVR_HELLO_A,
                                   SSL3_ST_CR_SRVR_HELLO_B, -1, 20000, &ok);

    if (!ok)
        return ((int)n);

    s->first_packet = 0;
    if (SSL_IS_DTLS(s)) {
        if (s->s3->tmp.message_type == DTLS1_MT_HELLO_VERIFY_REQUEST) {
            if (s->d1->send_cookie == 0) {
                s->s3->tmp.reuse_message = 1;
                return 1;
            } else {            /* already sent a cookie */

                al = SSL_AD_UNEXPECTED_MESSAGE;
                SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_BAD_MESSAGE_TYPE);
                goto f_err;
            }
        }
    }

    if (s->s3->tmp.message_type != SSL3_MT_SERVER_HELLO) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_BAD_MESSAGE_TYPE);
        goto f_err;
    }

    if (!PACKET_buf_init(&pkt, s->init_msg, n)) {
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
        goto f_err;
    }

    if (s->method->version == TLS_ANY_VERSION) {
        unsigned int sversion;

        if (!PACKET_get_net_2(&pkt, &sversion)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }

#if TLS_MAX_VERSION != TLS1_2_VERSION
#error Code needs updating for new TLS version
#endif
#ifndef OPENSSL_NO_SSL3
        if ((sversion == SSL3_VERSION) && !(s->options & SSL_OP_NO_SSLv3)) {
            if (FIPS_mode()) {
                SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
                       SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE);
                al = SSL_AD_PROTOCOL_VERSION;
                goto f_err;
            }
            s->method = SSLv3_client_method();
        } else
#endif
        if ((sversion == TLS1_VERSION) && !(s->options & SSL_OP_NO_TLSv1)) {
            s->method = TLSv1_client_method();
        } else if ((sversion == TLS1_1_VERSION) &&
                   !(s->options & SSL_OP_NO_TLSv1_1)) {
            s->method = TLSv1_1_client_method();
        } else if ((sversion == TLS1_2_VERSION) &&
                   !(s->options & SSL_OP_NO_TLSv1_2)) {
            s->method = TLSv1_2_client_method();
        } else {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_UNSUPPORTED_PROTOCOL);
            al = SSL_AD_PROTOCOL_VERSION;
            goto f_err;
        }
        s->session->ssl_version = s->version = s->method->version;

        if (!ssl_security(s, SSL_SECOP_VERSION, 0, s->version, NULL)) {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_VERSION_TOO_LOW);
            al = SSL_AD_PROTOCOL_VERSION;
            goto f_err;
        }
    } else if (s->method->version == DTLS_ANY_VERSION) {
        /* Work out correct protocol version to use */
        unsigned int hversion;
        int options;

        if (!PACKET_get_net_2(&pkt, &hversion)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }

        options = s->options;
        if (hversion == DTLS1_2_VERSION && !(options & SSL_OP_NO_DTLSv1_2))
            s->method = DTLSv1_2_client_method();
        else if (tls1_suiteb(s)) {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
                   SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
            s->version = hversion;
            al = SSL_AD_PROTOCOL_VERSION;
            goto f_err;
        } else if (hversion == DTLS1_VERSION && !(options & SSL_OP_NO_DTLSv1))
            s->method = DTLSv1_client_method();
        else {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_SSL_VERSION);
            s->version = hversion;
            al = SSL_AD_PROTOCOL_VERSION;
            goto f_err;
        }
        s->session->ssl_version = s->version = s->method->version;
    } else {
        unsigned char *vers;

        if (!PACKET_get_bytes(&pkt, &vers, 2)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }
        if ((vers[0] != (s->version >> 8))
                || (vers[1] != (s->version & 0xff))) {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_SSL_VERSION);
            s->version = (s->version & 0xff00) | vers[1];
            al = SSL_AD_PROTOCOL_VERSION;
            goto f_err;
        }
    }

    /* load the server hello data */
    /* load the server random */
    if (!PACKET_copy_bytes(&pkt, s->s3->server_random, SSL3_RANDOM_SIZE)) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }

    s->hit = 0;

    /* Get the session-id. */
    if (!PACKET_get_length_prefixed_1(&pkt, &session_id)) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    session_id_len = PACKET_remaining(&session_id);
    if (session_id_len > sizeof s->session->session_id
        || session_id_len > SSL3_SESSION_ID_SIZE) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_SSL3_SESSION_ID_TOO_LONG);
        goto f_err;
    }

    if (!PACKET_get_bytes(&pkt, &cipherchars, TLS_CIPHER_LEN)) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_LENGTH_MISMATCH);
        al = SSL_AD_DECODE_ERROR;
        goto f_err;
    }

    /*
     * Check if we can resume the session based on external pre-shared secret.
     * EAP-FAST (RFC 4851) supports two types of session resumption.
     * Resumption based on server-side state works with session IDs.
     * Resumption based on pre-shared Protected Access Credentials (PACs)
     * works by overriding the SessionTicket extension at the application
     * layer, and does not send a session ID. (We do not know whether EAP-FAST
     * servers would honour the session ID.) Therefore, the session ID alone
     * is not a reliable indicator of session resumption, so we first check if
     * we can resume, and later peek at the next handshake message to see if the
     * server wants to resume.
     */
    if (s->version >= TLS1_VERSION && s->tls_session_secret_cb &&
        s->session->tlsext_tick) {
        SSL_CIPHER *pref_cipher = NULL;
        s->session->master_key_length = sizeof(s->session->master_key);
        if (s->tls_session_secret_cb(s, s->session->master_key,
                                     &s->session->master_key_length,
                                     NULL, &pref_cipher,
                                     s->tls_session_secret_cb_arg)) {
            s->session->cipher = pref_cipher ?
                pref_cipher : ssl_get_cipher_by_char(s, cipherchars);
        } else {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }
    }

    if (session_id_len != 0 && session_id_len == s->session->session_id_length
        && memcmp(PACKET_data(&session_id), s->session->session_id,
                  session_id_len) == 0) {
        if (s->sid_ctx_length != s->session->sid_ctx_length
            || memcmp(s->session->sid_ctx, s->sid_ctx, s->sid_ctx_length)) {
            /* actually a client application bug */
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
                   SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
            goto f_err;
        }
        s->hit = 1;
    } else {
        /*
         * If we were trying for session-id reuse but the server
         * didn't echo the ID, make a new SSL_SESSION.
         * In the case of EAP-FAST and PAC, we do not send a session ID,
         * so the PAC-based session secret is always preserved. It'll be
         * overwritten if the server refuses resumption.
         */
        if (s->session->session_id_length > 0) {
            if (!ssl_get_new_session(s, 0)) {
                goto f_err;
            }
        }

        s->session->session_id_length = session_id_len;
        /* session_id_len could be 0 */
        memcpy(s->session->session_id, PACKET_data(&session_id),
               session_id_len);
    }

    c = ssl_get_cipher_by_char(s, cipherchars);
    if (c == NULL) {
        /* unknown cipher */
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_UNKNOWN_CIPHER_RETURNED);
        goto f_err;
    }
    /* Set version disabled mask now we know version */
    if (!SSL_USE_TLS1_2_CIPHERS(s))
        s->s3->tmp.mask_ssl = SSL_TLSV1_2;
    else
        s->s3->tmp.mask_ssl = 0;
    /*
     * If it is a disabled cipher we didn't send it in client hello, so
     * return an error.
     */
    if (ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_CHECK)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_CIPHER_RETURNED);
        goto f_err;
    }

    sk = ssl_get_ciphers_by_id(s);
    i = sk_SSL_CIPHER_find(sk, c);
    if (i < 0) {
        /* we did not say we would use this cipher */
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_CIPHER_RETURNED);
        goto f_err;
    }

    /*
     * Depending on the session caching (internal/external), the cipher
     * and/or cipher_id values may not be set. Make sure that cipher_id is
     * set and use it for comparison.
     */
    if (s->session->cipher)
        s->session->cipher_id = s->session->cipher->id;
    if (s->hit && (s->session->cipher_id != c->id)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED);
        goto f_err;
    }
    s->s3->tmp.new_cipher = c;
    /*
     * Don't digest cached records if no sigalgs: we may need them for client
     * authentication.
     */
    if (!SSL_USE_SIGALGS(s) && !ssl3_digest_cached_records(s, 0))
        goto f_err;
    /* lets get the compression algorithm */
    /* COMPRESSION */
    if (!PACKET_get_1(&pkt, &compression)) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_LENGTH_MISMATCH);
        al = SSL_AD_DECODE_ERROR;
        goto f_err;
    }
#ifdef OPENSSL_NO_COMP
    if (compression != 0) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        goto f_err;
    }
    /*
     * If compression is disabled we'd better not try to resume a session
     * using compression.
     */
    if (s->session->compress_meth != 0) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_INCONSISTENT_COMPRESSION);
        goto f_err;
    }
#else
    if (s->hit && compression != s->session->compress_meth) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED);
        goto f_err;
    }
    if (compression == 0)
        comp = NULL;
    else if (!ssl_allow_compression(s)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_COMPRESSION_DISABLED);
        goto f_err;
    } else {
        comp = ssl3_comp_find(s->ctx->comp_methods, compression);
    }

    if (compression != 0 && comp == NULL) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        goto f_err;
    } else {
        s->s3->tmp.new_compression = comp;
    }
#endif

    /* TLS extensions */
    if (!ssl_parse_serverhello_tlsext(s, &pkt)) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_PARSE_TLSEXT);
        goto err;
    }

    if (PACKET_remaining(&pkt) != 0) {
        /* wrong packet length */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_BAD_PACKET_LENGTH);
        goto f_err;
    }

    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_server_certificate(SSL *s)
{
    int al, i, ok, ret = -1, exp_idx;
    unsigned long n, cert_list_len, cert_len;
    X509 *x = NULL;
    unsigned char *certstart, *certbytes;
    STACK_OF(X509) *sk = NULL;
    EVP_PKEY *pkey = NULL;
    PACKET pkt;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_CERT_A,
                                   SSL3_ST_CR_CERT_B,
                                   -1, s->max_cert_list, &ok);

    if (!ok)
        return ((int)n);

    if (s->s3->tmp.message_type == SSL3_MT_SERVER_KEY_EXCHANGE) {
        s->s3->tmp.reuse_message = 1;
        return (1);
    }

    if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_BAD_MESSAGE_TYPE);
        goto f_err;
    }

    if (!PACKET_buf_init(&pkt, s->init_msg, n)) {
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_INTERNAL_ERROR);
        goto f_err;
    }

    if ((sk = sk_X509_new_null()) == NULL) {
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!PACKET_get_net_3(&pkt, &cert_list_len)
            || PACKET_remaining(&pkt) != cert_list_len) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    while (PACKET_remaining(&pkt)) {
        if (!PACKET_get_net_3(&pkt, &cert_len)
                || !PACKET_get_bytes(&pkt, &certbytes, cert_len)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }

        certstart = certbytes;
        x = d2i_X509(NULL, (const unsigned char **)&certbytes, cert_len);
        if (x == NULL) {
            al = SSL_AD_BAD_CERTIFICATE;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_ASN1_LIB);
            goto f_err;
        }
        if (certbytes != (certstart + cert_len)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }
        if (!sk_X509_push(sk, x)) {
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        x = NULL;
    }

    i = ssl_verify_cert_chain(s, sk);
    if (s->verify_mode != SSL_VERIFY_NONE && i <= 0) {
        al = ssl_verify_alarm_type(s->verify_result);
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_CERTIFICATE_VERIFY_FAILED);
        goto f_err;
    }
    ERR_clear_error();          /* but we keep s->verify_result */
    if (i > 1) {
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, i);
        al = SSL_AD_HANDSHAKE_FAILURE;
        goto f_err;
    }

    s->session->peer_chain = sk;
    /*
     * Inconsistency alert: cert_chain does include the peer's certificate,
     * which we don't include in s3_srvr.c
     */
    x = sk_X509_value(sk, 0);
    sk = NULL;
    /*
     * VRS 19990621: possible memory leak; sk=null ==> !sk_pop_free() @end
     */

    pkey = X509_get_pubkey(x);

    if (pkey == NULL || EVP_PKEY_missing_parameters(pkey)) {
        x = NULL;
        al = SSL3_AL_FATAL;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS);
        goto f_err;
    }

    i = ssl_cert_type(x, pkey);
    if (i < 0) {
        x = NULL;
        al = SSL3_AL_FATAL;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        goto f_err;
    }

    exp_idx = ssl_cipher_get_cert_index(s->s3->tmp.new_cipher);
    if (exp_idx >= 0 && i != exp_idx) {
        x = NULL;
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_WRONG_CERTIFICATE_TYPE);
        goto f_err;
    }
    s->session->peer_type = i;

    X509_free(s->session->peer);
    X509_up_ref(x);
    s->session->peer = x;
    s->session->verify_result = s->verify_result;

    x = NULL;
    ret = 1;
    goto done;

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    s->state = SSL_ST_ERR;
 done:
    EVP_PKEY_free(pkey);
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);
    return (ret);
}

int ssl3_get_key_exchange(SSL *s)
{
#ifndef OPENSSL_NO_RSA
    unsigned char *q, md_buf[EVP_MAX_MD_SIZE * 2];
#endif
    EVP_MD_CTX md_ctx;
    int al, j, verify_ret, ok;
    long n, alg_k, alg_a;
    EVP_PKEY *pkey = NULL;
    const EVP_MD *md = NULL;
#ifndef OPENSSL_NO_RSA
    RSA *rsa = NULL;
#endif
#ifndef OPENSSL_NO_DH
    DH *dh = NULL;
#endif
#ifndef OPENSSL_NO_EC
    EC_KEY *ecdh = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *srvr_ecpoint = NULL;
    int curve_nid = 0;
#endif
    PACKET pkt, save_param_start, signature;

    EVP_MD_CTX_init(&md_ctx);

    /*
     * use same message size as in ssl3_get_certificate_request() as
     * ServerKeyExchange message may be skipped
     */
    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_KEY_EXCH_A,
                                   SSL3_ST_CR_KEY_EXCH_B,
                                   -1, s->max_cert_list, &ok);
    if (!ok)
        return ((int)n);

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE) {
        /*
         * Can't skip server key exchange if this is an ephemeral
         * ciphersuite.
         */
        if (alg_k & (SSL_kDHE | SSL_kECDHE | SSL_kDHEPSK | SSL_kECDHEPSK)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
            al = SSL_AD_UNEXPECTED_MESSAGE;
            goto f_err;
        }

        s->s3->tmp.reuse_message = 1;
        return (1);
    }

    if (!PACKET_buf_init(&pkt, s->init_msg, n)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
    }
    save_param_start = pkt;

#ifndef OPENSSL_NO_RSA
    RSA_free(s->s3->peer_rsa_tmp);
    s->s3->peer_rsa_tmp = NULL;
#endif
#ifndef OPENSSL_NO_DH
    DH_free(s->s3->peer_dh_tmp);
    s->s3->peer_dh_tmp = NULL;
#endif
#ifndef OPENSSL_NO_EC
    EC_KEY_free(s->s3->peer_ecdh_tmp);
    s->s3->peer_ecdh_tmp = NULL;
#endif

    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    al = SSL_AD_DECODE_ERROR;

#ifndef OPENSSL_NO_PSK
    /* PSK ciphersuites are preceded by an identity hint */
    if (alg_k & SSL_PSK) {
        PACKET psk_identity_hint;
        if (!PACKET_get_length_prefixed_2(&pkt, &psk_identity_hint)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }

        /*
         * Store PSK identity hint for later use, hint is used in
         * ssl3_send_client_key_exchange.  Assume that the maximum length of
         * a PSK identity hint can be as long as the maximum length of a PSK
         * identity.
         */
        if (PACKET_remaining(&psk_identity_hint) > PSK_MAX_IDENTITY_LEN) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_DATA_LENGTH_TOO_LONG);
            goto f_err;
        }

        if (!PACKET_strndup(&psk_identity_hint,
                            &s->session->psk_identity_hint)) {
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }
    }

    /* Nothing else to do for plain PSK or RSAPSK */
    if (alg_k & (SSL_kPSK | SSL_kRSAPSK)) {
    } else
#endif                          /* !OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (alg_k & SSL_kSRP) {
        PACKET prime, generator, salt, server_pub;
        if (!PACKET_get_length_prefixed_2(&pkt, &prime)
            || !PACKET_get_length_prefixed_2(&pkt, &generator)
            || !PACKET_get_length_prefixed_1(&pkt, &salt)
            || !PACKET_get_length_prefixed_2(&pkt, &server_pub)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }

        if ((s->srp_ctx.N =
             BN_bin2bn(PACKET_data(&prime),
                       PACKET_remaining(&prime), NULL)) == NULL
            || (s->srp_ctx.g =
                BN_bin2bn(PACKET_data(&generator),
                          PACKET_remaining(&generator), NULL)) == NULL
            || (s->srp_ctx.s =
                BN_bin2bn(PACKET_data(&salt),
                          PACKET_remaining(&salt), NULL)) == NULL
            || (s->srp_ctx.B =
                BN_bin2bn(PACKET_data(&server_pub),
                          PACKET_remaining(&server_pub), NULL)) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }

        if (!srp_verify_server_param(s, &al)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_PARAMETERS);
            goto f_err;
        }

/* We must check if there is a certificate */
        if (alg_a & (SSL_aRSA|SSL_aDSS))
            pkey = X509_get_pubkey(s->session->peer);
    } else
#endif                          /* !OPENSSL_NO_SRP */
#ifndef OPENSSL_NO_RSA
    if (alg_k & SSL_kRSA) {
        PACKET mod, exp;
        /* Temporary RSA keys only allowed in export ciphersuites */
        if (!SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }

        if (!PACKET_get_length_prefixed_2(&pkt, &mod)
            || !PACKET_get_length_prefixed_2(&pkt, &exp)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }

        if ((rsa = RSA_new()) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if ((rsa->n = BN_bin2bn(PACKET_data(&mod), PACKET_remaining(&mod),
                                rsa->n)) == NULL
            || (rsa->e = BN_bin2bn(PACKET_data(&exp), PACKET_remaining(&exp),
                                   rsa->e)) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }

        /* this should be because we are using an export cipher */
        if (alg_a & SSL_aRSA)
            pkey = X509_get_pubkey(s->session->peer);
        else {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (EVP_PKEY_bits(pkey) <= SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }

        s->s3->peer_rsa_tmp = rsa;
        rsa = NULL;
    }
#else                           /* OPENSSL_NO_RSA */
    if (0) ;
#endif
#ifndef OPENSSL_NO_DH
    else if (alg_k & (SSL_kDHE | SSL_kDHEPSK)) {
        PACKET prime, generator, pub_key;

        if (!PACKET_get_length_prefixed_2(&pkt, &prime)
            || !PACKET_get_length_prefixed_2(&pkt, &generator)
            || !PACKET_get_length_prefixed_2(&pkt, &pub_key)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }

        if ((dh = DH_new()) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_DH_LIB);
            goto err;
        }

        if ((dh->p = BN_bin2bn(PACKET_data(&prime),
                               PACKET_remaining(&prime), NULL)) == NULL
            || (dh->g = BN_bin2bn(PACKET_data(&generator),
                                  PACKET_remaining(&generator), NULL)) == NULL
            || (dh->pub_key =
                BN_bin2bn(PACKET_data(&pub_key),
                          PACKET_remaining(&pub_key), NULL)) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }

        if (BN_is_zero(dh->p) || BN_is_zero(dh->g) || BN_is_zero(dh->pub_key)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_VALUE);
            goto f_err;
        }

        if (!ssl_security(s, SSL_SECOP_TMP_DH, DH_security_bits(dh), 0, dh)) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_DH_KEY_TOO_SMALL);
            goto f_err;
        }
        if (alg_a & (SSL_aRSA|SSL_aDSS))
            pkey = X509_get_pubkey(s->session->peer);
        /* else anonymous DH, so no certificate or pkey. */

        s->s3->peer_dh_tmp = dh;
        dh = NULL;
    }
#endif                          /* !OPENSSL_NO_DH */

#ifndef OPENSSL_NO_EC
    else if (alg_k & (SSL_kECDHE | SSL_kECDHEPSK)) {
        EC_GROUP *ngroup;
        const EC_GROUP *group;
        PACKET encoded_pt;
        unsigned char *ecparams;

        if ((ecdh = EC_KEY_new()) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /*
         * Extract elliptic curve parameters and the server's ephemeral ECDH
         * public key. For now we only support named (not generic) curves and
         * ECParameters in this case is just three bytes.
         */
        if (!PACKET_get_bytes(&pkt, &ecparams, 3)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        /*
         * Check curve is one of our preferences, if not server has sent an
         * invalid curve. ECParameters is 3 bytes.
         */
        if (!tls1_check_curve(s, ecparams, 3)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_WRONG_CURVE);
            goto f_err;
        }

        if ((curve_nid = tls1_ec_curve_id2nid(*(ecparams + 2))) == 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                   SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
            goto f_err;
        }

        ngroup = EC_GROUP_new_by_curve_name(curve_nid);
        if (ngroup == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_EC_LIB);
            goto err;
        }
        if (EC_KEY_set_group(ecdh, ngroup) == 0) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_EC_LIB);
            goto err;
        }
        EC_GROUP_free(ngroup);

        group = EC_KEY_get0_group(ecdh);

        if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
            (EC_GROUP_get_degree(group) > 163)) {
            al = SSL_AD_EXPORT_RESTRICTION;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                   SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER);
            goto f_err;
        }

        /* Next, get the encoded ECPoint */
        if (((srvr_ecpoint = EC_POINT_new(group)) == NULL) ||
            ((bn_ctx = BN_CTX_new()) == NULL)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (!PACKET_get_length_prefixed_1(&pkt, &encoded_pt)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }

        if (EC_POINT_oct2point(group, srvr_ecpoint, PACKET_data(&encoded_pt),
                               PACKET_remaining(&encoded_pt), bn_ctx) == 0) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_ECPOINT);
            goto f_err;
        }

        /*
         * The ECC/TLS specification does not mention the use of DSA to sign
         * ECParameters in the server key exchange message. We do support RSA
         * and ECDSA.
         */
        if (0) ;
# ifndef OPENSSL_NO_RSA
        else if (alg_a & SSL_aRSA)
            pkey = X509_get_pubkey(s->session->peer);
# endif
# ifndef OPENSSL_NO_EC
        else if (alg_a & SSL_aECDSA)
            pkey = X509_get_pubkey(s->session->peer);
# endif
        /* else anonymous ECDH, so no certificate or pkey. */
        EC_KEY_set_public_key(ecdh, srvr_ecpoint);
        s->s3->peer_ecdh_tmp = ecdh;
        ecdh = NULL;
        BN_CTX_free(bn_ctx);
        bn_ctx = NULL;
        EC_POINT_free(srvr_ecpoint);
        srvr_ecpoint = NULL;
    } else if (alg_k) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
        goto f_err;
    }
#endif                          /* !OPENSSL_NO_EC */

    /* if it was signed, check the signature */
    if (pkey != NULL) {
        PACKET params;
        /*
         * |pkt| now points to the beginning of the signature, so the difference
         * equals the length of the parameters.
         */
        if (!PACKET_get_sub_packet(&save_param_start, &params,
                                   PACKET_remaining(&save_param_start) -
                                   PACKET_remaining(&pkt))) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }

        if (SSL_USE_SIGALGS(s)) {
            unsigned char *sigalgs;
            int rv;
            if (!PACKET_get_bytes(&pkt, &sigalgs, 2)) {
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
                goto f_err;
            }
            rv = tls12_check_peer_sigalg(&md, s, sigalgs, pkey);
            if (rv == -1)
                goto err;
            else if (rv == 0) {
                goto f_err;
            }
#ifdef SSL_DEBUG
            fprintf(stderr, "USING TLSv1.2 HASH %s\n", EVP_MD_name(md));
#endif
        } else {
            md = EVP_sha1();
        }

        if (!PACKET_get_length_prefixed_2(&pkt, &signature)
            || PACKET_remaining(&pkt) != 0) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }
        j = EVP_PKEY_size(pkey);
        if (j < 0) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }

        /*
         * Check signature length
         */
        if (PACKET_remaining(&signature) > (size_t)j) {
            /* wrong packet length */
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_WRONG_SIGNATURE_LENGTH);
            goto f_err;
        }
#ifndef OPENSSL_NO_RSA
        if (pkey->type == EVP_PKEY_RSA && !SSL_USE_SIGALGS(s)) {
            int num;
            unsigned int size;

            j = 0;
            q = md_buf;
            for (num = 2; num > 0; num--) {
                EVP_MD_CTX_set_flags(&md_ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
                EVP_DigestInit_ex(&md_ctx, (num == 2)
                                  ? s->ctx->md5 : s->ctx->sha1, NULL);
                EVP_DigestUpdate(&md_ctx, &(s->s3->client_random[0]),
                                 SSL3_RANDOM_SIZE);
                EVP_DigestUpdate(&md_ctx, &(s->s3->server_random[0]),
                                 SSL3_RANDOM_SIZE);
                EVP_DigestUpdate(&md_ctx, PACKET_data(&params),
                                 PACKET_remaining(&params));
                EVP_DigestFinal_ex(&md_ctx, q, &size);
                q += size;
                j += size;
            }
            verify_ret =
                RSA_verify(NID_md5_sha1, md_buf, j, PACKET_data(&signature),
                           PACKET_remaining(&signature), pkey->pkey.rsa);
            if (verify_ret < 0) {
                al = SSL_AD_DECRYPT_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_RSA_DECRYPT);
                goto f_err;
            }
            if (verify_ret == 0) {
                /* bad signature */
                al = SSL_AD_DECRYPT_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SIGNATURE);
                goto f_err;
            }
        } else
#endif
        {
            EVP_VerifyInit_ex(&md_ctx, md, NULL);
            EVP_VerifyUpdate(&md_ctx, &(s->s3->client_random[0]),
                             SSL3_RANDOM_SIZE);
            EVP_VerifyUpdate(&md_ctx, &(s->s3->server_random[0]),
                             SSL3_RANDOM_SIZE);
            EVP_VerifyUpdate(&md_ctx, PACKET_data(&params),
                             PACKET_remaining(&params));
            if (EVP_VerifyFinal(&md_ctx, PACKET_data(&signature),
                                PACKET_remaining(&signature), pkey) <= 0) {
                /* bad signature */
                al = SSL_AD_DECRYPT_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SIGNATURE);
                goto f_err;
            }
        }
    } else {
        /* aNULL, aSRP or PSK do not need public keys */
        if (!(alg_a & (SSL_aNULL | SSL_aSRP)) && !(alg_k & SSL_PSK)) {
            /* Might be wrong key type, check it */
            if (ssl3_check_cert_and_algorithm(s))
                /* Otherwise this shouldn't happen */
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* still data left over */
        if (PACKET_remaining(&pkt) != 0) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_EXTRA_DATA_IN_MESSAGE);
            goto f_err;
        }
    }
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_cleanup(&md_ctx);
    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    EVP_PKEY_free(pkey);
#ifndef OPENSSL_NO_RSA
    RSA_free(rsa);
#endif
#ifndef OPENSSL_NO_DH
    DH_free(dh);
#endif
#ifndef OPENSSL_NO_EC
    BN_CTX_free(bn_ctx);
    EC_POINT_free(srvr_ecpoint);
    EC_KEY_free(ecdh);
#endif
    EVP_MD_CTX_cleanup(&md_ctx);
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_certificate_request(SSL *s)
{
    int ok, ret = 0;
    unsigned long n;
    unsigned int list_len, ctype_num, i, name_len;
    X509_NAME *xn = NULL;
    unsigned char *data;
    unsigned char *namestart, *namebytes;
    STACK_OF(X509_NAME) *ca_sk = NULL;
    PACKET pkt;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_CERT_REQ_A,
                                   SSL3_ST_CR_CERT_REQ_B,
                                   -1, s->max_cert_list, &ok);

    if (!ok)
        return ((int)n);

    s->s3->tmp.cert_req = 0;

    if (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE) {
        s->s3->tmp.reuse_message = 1;
        /*
         * If we get here we don't need any cached handshake records as we
         * wont be doing client auth.
         */
        if (!ssl3_digest_cached_records(s, 0))
            goto err;
        return (1);
    }

    if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_REQUEST) {
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_WRONG_MESSAGE_TYPE);
        goto err;
    }

    /* TLS does not like anon-DH with client cert */
    if (s->version > SSL3_VERSION) {
        if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER);
            goto err;
        }
    }

    if (!PACKET_buf_init(&pkt, s->init_msg, n)) {
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((ca_sk = sk_X509_NAME_new(ca_dn_cmp)) == NULL) {
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* get the certificate types */
    if (!PACKET_get_1(&pkt, &ctype_num)
            || !PACKET_get_bytes(&pkt, &data, ctype_num)) {
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_LENGTH_MISMATCH);
        goto err;
    }
    OPENSSL_free(s->cert->ctypes);
    s->cert->ctypes = NULL;
    if (ctype_num > SSL3_CT_NUMBER) {
        /* If we exceed static buffer copy all to cert structure */
        s->cert->ctypes = OPENSSL_malloc(ctype_num);
        if (s->cert->ctypes == NULL) {
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(s->cert->ctypes, data, ctype_num);
        s->cert->ctype_num = (size_t)ctype_num;
        ctype_num = SSL3_CT_NUMBER;
    }
    for (i = 0; i < ctype_num; i++)
        s->s3->tmp.ctype[i] = data[i];

    if (SSL_USE_SIGALGS(s)) {
        if (!PACKET_get_net_2(&pkt, &list_len)
                || !PACKET_get_bytes(&pkt, &data, list_len)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_LENGTH_MISMATCH);
            goto err;
        }

        /* Clear certificate digests and validity flags */
        for (i = 0; i < SSL_PKEY_NUM; i++) {
            s->s3->tmp.md[i] = NULL;
            s->s3->tmp.valid_flags[i] = 0;
        }
        if ((list_len & 1) || !tls1_save_sigalgs(s, data, list_len)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_SIGNATURE_ALGORITHMS_ERROR);
            goto err;
        }
        if (!tls1_process_sigalgs(s)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    /* get the CA RDNs */
    if (!PACKET_get_net_2(&pkt, &list_len)
            || PACKET_remaining(&pkt) != list_len) {
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    while (PACKET_remaining(&pkt)) {
        if (!PACKET_get_net_2(&pkt, &name_len)
                || !PACKET_get_bytes(&pkt, &namebytes, name_len)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_LENGTH_MISMATCH);
            goto err;
        }

        namestart = namebytes;

        if ((xn = d2i_X509_NAME(NULL, (const unsigned char **)&namebytes,
                                name_len)) == NULL) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_ASN1_LIB);
            goto err;
        }

        if (namebytes != (namestart + name_len)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_CA_DN_LENGTH_MISMATCH);
            goto err;
        }
        if (!sk_X509_NAME_push(ca_sk, xn)) {
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    /* we should setup a certificate to return.... */
    s->s3->tmp.cert_req = 1;
    s->s3->tmp.ctype_num = ctype_num;
    sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
    s->s3->tmp.ca_names = ca_sk;
    ca_sk = NULL;

    ret = 1;
    goto done;
 err:
    s->state = SSL_ST_ERR;
 done:
    sk_X509_NAME_pop_free(ca_sk, X509_NAME_free);
    return (ret);
}

static int ca_dn_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return (X509_NAME_cmp(*a, *b));
}

int ssl3_get_new_session_ticket(SSL *s)
{
    int ok, al, ret = 0;
    unsigned int ticklen;
    unsigned long ticket_lifetime_hint;
    long n;
    PACKET pkt;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SESSION_TICKET_A,
                                   SSL3_ST_CR_SESSION_TICKET_B,
                                   SSL3_MT_NEWSESSION_TICKET, 16384, &ok);

    if (!ok)
        return ((int)n);

    if (!PACKET_buf_init(&pkt, s->init_msg, n)) {
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, ERR_R_INTERNAL_ERROR);
        goto f_err;
    }

    if (!PACKET_get_net_4(&pkt, &ticket_lifetime_hint)
            || !PACKET_get_net_2(&pkt, &ticklen)
            || PACKET_remaining(&pkt) != ticklen) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }

    /* Server is allowed to change its mind and send an empty ticket. */
    if (ticklen == 0)
        return 1;

    if (s->session->session_id_length > 0) {
        int i = s->session_ctx->session_cache_mode;
        SSL_SESSION *new_sess;
        /*
         * We reused an existing session, so we need to replace it with a new
         * one
         */
        if (i & SSL_SESS_CACHE_CLIENT) {
            /*
             * Remove the old session from the cache
             */
            if (i & SSL_SESS_CACHE_NO_INTERNAL_STORE) {
                if (s->session_ctx->remove_session_cb != NULL)
                    s->session_ctx->remove_session_cb(s->session_ctx,
                                                      s->session);
            } else {
                /* We carry on if this fails */
                SSL_CTX_remove_session(s->session_ctx, s->session);
            }
        }

        if ((new_sess = ssl_session_dup(s->session, 0)) == 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }

        SSL_SESSION_free(s->session);
        s->session = new_sess;
    }

    OPENSSL_free(s->session->tlsext_tick);
    s->session->tlsext_ticklen = 0;

    s->session->tlsext_tick = OPENSSL_malloc(ticklen);
    if (!s->session->tlsext_tick) {
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!PACKET_copy_bytes(&pkt, s->session->tlsext_tick, ticklen)) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }

    s->session->tlsext_tick_lifetime_hint = ticket_lifetime_hint;
    s->session->tlsext_ticklen = ticklen;
    /*
     * There are two ways to detect a resumed ticket session. One is to set
     * an appropriate session ID and then the server must return a match in
     * ServerHello. This allows the normal client session ID matching to work
     * and we know much earlier that the ticket has been accepted. The
     * other way is to set zero length session ID when the ticket is
     * presented and rely on the handshake to determine session resumption.
     * We choose the former approach because this fits in with assumptions
     * elsewhere in OpenSSL. The session ID is set to the SHA256 (or SHA1 is
     * SHA256 is disabled) hash of the ticket.
     */
    EVP_Digest(s->session->tlsext_tick, ticklen,
               s->session->session_id, &s->session->session_id_length,
               EVP_sha256(), NULL);
    ret = 1;
    return (ret);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_cert_status(SSL *s)
{
    int ok, al;
    unsigned long resplen, n;
    unsigned int type;
    PACKET pkt;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_CERT_STATUS_A,
                                   SSL3_ST_CR_CERT_STATUS_B,
                                   SSL3_MT_CERTIFICATE_STATUS, 16384, &ok);

    if (!ok)
        return ((int)n);

    if (!PACKET_buf_init(&pkt, s->init_msg, n)) {
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_GET_CERT_STATUS, ERR_R_INTERNAL_ERROR);
        goto f_err;
    }
    if (!PACKET_get_1(&pkt, &type)
            || type != TLSEXT_STATUSTYPE_ocsp) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_UNSUPPORTED_STATUS_TYPE);
        goto f_err;
    }
    if (!PACKET_get_net_3(&pkt, &resplen)
            || PACKET_remaining(&pkt) != resplen) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    OPENSSL_free(s->tlsext_ocsp_resp);
    s->tlsext_ocsp_resp = OPENSSL_malloc(resplen);
    if (!s->tlsext_ocsp_resp) {
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_GET_CERT_STATUS, ERR_R_MALLOC_FAILURE);
        goto f_err;
    }
    if (!PACKET_copy_bytes(&pkt, s->tlsext_ocsp_resp, resplen)) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    s->tlsext_ocsp_resplen = resplen;
    if (s->ctx->tlsext_status_cb) {
        int ret;
        ret = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
        if (ret == 0) {
            al = SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_INVALID_STATUS_RESPONSE);
            goto f_err;
        }
        if (ret < 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }
    }
    return 1;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_server_done(SSL *s)
{
    int ok, ret = 0;
    long n;

    /* Second to last param should be very small, like 0 :-) */
    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SRVR_DONE_A,
                                   SSL3_ST_CR_SRVR_DONE_B,
                                   SSL3_MT_SERVER_DONE, 30, &ok);

    if (!ok)
        return ((int)n);
    if (n > 0) {
        /* should contain no data */
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
        SSLerr(SSL_F_SSL3_GET_SERVER_DONE, SSL_R_LENGTH_MISMATCH);
        s->state = SSL_ST_ERR;
        return -1;
    }
    ret = 1;
    return (ret);
}

int ssl3_send_client_key_exchange(SSL *s)
{
    unsigned char *p;
    int n;
#ifndef OPENSSL_NO_PSK
    size_t pskhdrlen = 0;
#endif
    unsigned long alg_k;
#ifndef OPENSSL_NO_RSA
    unsigned char *q;
    EVP_PKEY *pkey = NULL;
#endif
#ifndef OPENSSL_NO_EC
    EC_KEY *clnt_ecdh = NULL;
    const EC_POINT *srvr_ecpoint = NULL;
    EVP_PKEY *srvr_pub_pkey = NULL;
    unsigned char *encodedPoint = NULL;
    int encoded_pt_len = 0;
    BN_CTX *bn_ctx = NULL;
#endif
    unsigned char *pms = NULL;
    size_t pmslen = 0;
    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    if (s->state == SSL3_ST_CW_KEY_EXCH_A) {
        p = ssl_handshake_start(s);


#ifndef OPENSSL_NO_PSK
        if (alg_k & SSL_PSK) {
            int psk_err = 1;
            /*
             * The callback needs PSK_MAX_IDENTITY_LEN + 1 bytes to return a
             * \0-terminated identity. The last byte is for us for simulating
             * strnlen.
             */
            char identity[PSK_MAX_IDENTITY_LEN + 1];
            size_t identitylen;
            unsigned char psk[PSK_MAX_PSK_LEN];
            size_t psklen;

            if (s->psk_client_callback == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_PSK_NO_CLIENT_CB);
                goto err;
            }

            memset(identity, 0, sizeof(identity));

            psklen = s->psk_client_callback(s, s->session->psk_identity_hint,
                                            identity, sizeof(identity) - 1,
                                            psk, sizeof(psk));

            if (psklen > PSK_MAX_PSK_LEN) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto psk_err;
            } else if (psklen == 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_PSK_IDENTITY_NOT_FOUND);
                goto psk_err;
            }

            OPENSSL_free(s->s3->tmp.psk);
            s->s3->tmp.psk = BUF_memdup(psk, psklen);
            OPENSSL_cleanse(psk, psklen);

            if (s->s3->tmp.psk == NULL) {
                OPENSSL_cleanse(identity, sizeof(identity));
                goto memerr;
            }

            s->s3->tmp.psklen = psklen;

            identitylen = strlen(identity);
            if (identitylen > PSK_MAX_IDENTITY_LEN) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto psk_err;
            }
            OPENSSL_free(s->session->psk_identity);
            s->session->psk_identity = BUF_strdup(identity);
            if (s->session->psk_identity == NULL) {
                OPENSSL_cleanse(identity, sizeof(identity));
                goto memerr;
            }

            s2n(identitylen, p);
            memcpy(p, identity, identitylen);
            pskhdrlen = 2 + identitylen;
            p += identitylen;
            psk_err = 0;
 psk_err:
            OPENSSL_cleanse(identity, sizeof(identity));
            if (psk_err != 0) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                goto err;
            }
        }
        if (alg_k & SSL_kPSK) {
            n = 0;
        } else
#endif

        /* Fool emacs indentation */
        if (0) {
        }
#ifndef OPENSSL_NO_RSA
        else if (alg_k & (SSL_kRSA | SSL_kRSAPSK)) {
            RSA *rsa;
            pmslen = SSL_MAX_MASTER_KEY_LENGTH;
            pms = OPENSSL_malloc(pmslen);
            if (!pms)
                goto memerr;

            if (s->session->peer == NULL) {
                /*
                 * We should always have a server certificate with SSL_kRSA.
                 */
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if (s->s3->peer_rsa_tmp != NULL)
                rsa = s->s3->peer_rsa_tmp;
            else {
                pkey = X509_get_pubkey(s->session->peer);
                if ((pkey == NULL) || (pkey->type != EVP_PKEY_RSA)
                    || (pkey->pkey.rsa == NULL)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    EVP_PKEY_free(pkey);
                    goto err;
                }
                rsa = pkey->pkey.rsa;
                EVP_PKEY_free(pkey);
            }

            pms[0] = s->client_version >> 8;
            pms[1] = s->client_version & 0xff;
            if (RAND_bytes(pms + 2, pmslen - 2) <= 0)
                goto err;

            q = p;
            /* Fix buf for TLS and beyond */
            if (s->version > SSL3_VERSION)
                p += 2;
            n = RSA_public_encrypt(pmslen, pms, p, rsa, RSA_PKCS1_PADDING);
# ifdef PKCS1_CHECK
            if (s->options & SSL_OP_PKCS1_CHECK_1)
                p[1]++;
            if (s->options & SSL_OP_PKCS1_CHECK_2)
                tmp_buf[0] = 0x70;
# endif
            if (n <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_BAD_RSA_ENCRYPT);
                goto err;
            }

            /* Fix buf for TLS and beyond */
            if (s->version > SSL3_VERSION) {
                s2n(n, q);
                n += 2;
            }
        }
#endif
#ifndef OPENSSL_NO_DH
        else if (alg_k & (SSL_kDHE | SSL_kDHr | SSL_kDHd | SSL_kDHEPSK)) {
            DH *dh_srvr, *dh_clnt;
            if (s->s3->peer_dh_tmp != NULL)
                dh_srvr = s->s3->peer_dh_tmp;
            else {
                /* we get them from the cert */
                EVP_PKEY *spkey = NULL;
                dh_srvr = NULL;
                spkey = X509_get_pubkey(s->session->peer);
                if (spkey) {
                    dh_srvr = EVP_PKEY_get1_DH(spkey);
                    EVP_PKEY_free(spkey);
                }
                if (dh_srvr == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    goto err;
                }
            }
            if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
                /* Use client certificate key */
                EVP_PKEY *clkey = s->cert->key->privatekey;
                dh_clnt = NULL;
                if (clkey)
                    dh_clnt = EVP_PKEY_get1_DH(clkey);
                if (dh_clnt == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    goto err;
                }
            } else {
                /* generate a new random key */
                if ((dh_clnt = DHparams_dup(dh_srvr)) == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
                    goto err;
                }
                if (!DH_generate_key(dh_clnt)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
                    DH_free(dh_clnt);
                    goto err;
                }
            }

            pmslen = DH_size(dh_clnt);
            pms = OPENSSL_malloc(pmslen);
            if (!pms)
                goto memerr;

            /*
             * use the 'p' output buffer for the DH key, but make sure to
             * clear it out afterwards
             */

            n = DH_compute_key(pms, dh_srvr->pub_key, dh_clnt);
            if (s->s3->peer_dh_tmp == NULL)
                DH_free(dh_srvr);

            if (n <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
                DH_free(dh_clnt);
                goto err;
            }
            pmslen = n;

            if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY)
                n = 0;
            else {
                /* send off the data */
                n = BN_num_bytes(dh_clnt->pub_key);
                s2n(n, p);
                BN_bn2bin(dh_clnt->pub_key, p);
                n += 2;
            }

            DH_free(dh_clnt);
        }
#endif

#ifndef OPENSSL_NO_EC
        else if (alg_k & (SSL_kECDHE | SSL_kECDHr | SSL_kECDHe | SSL_kECDHEPSK)) {
            const EC_GROUP *srvr_group = NULL;
            EC_KEY *tkey;
            int ecdh_clnt_cert = 0;
            int field_size = 0;
            /*
             * Did we send out the client's ECDH share for use in premaster
             * computation as part of client certificate? If so, set
             * ecdh_clnt_cert to 1.
             */
            if ((alg_k & (SSL_kECDHr | SSL_kECDHe)) && (s->cert != NULL)) {
                /*-
                 * XXX: For now, we do not support client
                 * authentication using ECDH certificates.
                 * To add such support, one needs to add
                 * code that checks for appropriate
                 * conditions and sets ecdh_clnt_cert to 1.
                 * For example, the cert have an ECC
                 * key on the same curve as the server's
                 * and the key should be authorized for
                 * key agreement.
                 *
                 * One also needs to add code in ssl3_connect
                 * to skip sending the certificate verify
                 * message.
                 *
                 * if ((s->cert->key->privatekey != NULL) &&
                 *     (s->cert->key->privatekey->type ==
                 *      EVP_PKEY_EC) && ...)
                 * ecdh_clnt_cert = 1;
                 */
            }

            if (s->s3->peer_ecdh_tmp != NULL) {
                tkey = s->s3->peer_ecdh_tmp;
            } else {
                /* Get the Server Public Key from Cert */
                srvr_pub_pkey = X509_get_pubkey(s->session->peer);
                if ((srvr_pub_pkey == NULL)
                    || (srvr_pub_pkey->type != EVP_PKEY_EC)
                    || (srvr_pub_pkey->pkey.ec == NULL)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    goto err;
                }

                tkey = srvr_pub_pkey->pkey.ec;
            }

            srvr_group = EC_KEY_get0_group(tkey);
            srvr_ecpoint = EC_KEY_get0_public_key(tkey);

            if ((srvr_group == NULL) || (srvr_ecpoint == NULL)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if ((clnt_ecdh = EC_KEY_new()) == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }

            if (!EC_KEY_set_group(clnt_ecdh, srvr_group)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                goto err;
            }
            if (ecdh_clnt_cert) {
                /*
                 * Reuse key info from our certificate We only need our
                 * private key to perform the ECDH computation.
                 */
                const BIGNUM *priv_key;
                tkey = s->cert->key->privatekey->pkey.ec;
                priv_key = EC_KEY_get0_private_key(tkey);
                if (priv_key == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_MALLOC_FAILURE);
                    goto err;
                }
                if (!EC_KEY_set_private_key(clnt_ecdh, priv_key)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                    goto err;
                }
            } else {
                /* Generate a new ECDH key pair */
                if (!(EC_KEY_generate_key(clnt_ecdh))) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_ECDH_LIB);
                    goto err;
                }
            }

            /*
             * use the 'p' output buffer for the ECDH key, but make sure to
             * clear it out afterwards
             */

            field_size = EC_GROUP_get_degree(srvr_group);
            if (field_size <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
                goto err;
            }
            pmslen = (field_size + 7) / 8;
            pms = OPENSSL_malloc(pmslen);
            if (!pms)
                goto memerr;
            n = ECDH_compute_key(pms, pmslen, srvr_ecpoint, clnt_ecdh, NULL);
            if (n <= 0 || pmslen != (size_t)n) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
                goto err;
            }

            if (ecdh_clnt_cert) {
                /* Send empty client key exch message */
                n = 0;
            } else {
                /*
                 * First check the size of encoding and allocate memory
                 * accordingly.
                 */
                encoded_pt_len =
                    EC_POINT_point2oct(srvr_group,
                                       EC_KEY_get0_public_key(clnt_ecdh),
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       NULL, 0, NULL);

                encodedPoint = (unsigned char *)
                    OPENSSL_malloc(encoded_pt_len * sizeof(unsigned char));
                bn_ctx = BN_CTX_new();
                if ((encodedPoint == NULL) || (bn_ctx == NULL)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_MALLOC_FAILURE);
                    goto err;
                }

                /* Encode the public key */
                n = EC_POINT_point2oct(srvr_group,
                                       EC_KEY_get0_public_key(clnt_ecdh),
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       encodedPoint, encoded_pt_len, bn_ctx);

                *p = n;         /* length of encoded point */
                /* Encoded point will be copied here */
                p += 1;
                /* copy the point */
                memcpy(p, encodedPoint, n);
                /* increment n to account for length field */
                n += 1;
            }

            /* Free allocated memory */
            BN_CTX_free(bn_ctx);
            OPENSSL_free(encodedPoint);
            EC_KEY_free(clnt_ecdh);
            EVP_PKEY_free(srvr_pub_pkey);
        }
#endif                          /* !OPENSSL_NO_EC */
        else if (alg_k & SSL_kGOST) {
            /* GOST key exchange message creation */
            EVP_PKEY_CTX *pkey_ctx;
            X509 *peer_cert;
            size_t msglen;
            unsigned int md_len;
            unsigned char shared_ukm[32], tmp[256];
            EVP_MD_CTX *ukm_hash;
            EVP_PKEY *pub_key;

            pmslen = 32;
            pms = OPENSSL_malloc(pmslen);
            if (!pms)
                goto memerr;

            /*
             * Get server sertificate PKEY and create ctx from it
             */
            peer_cert = s->session->peer;
            if (!peer_cert) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER);
                goto err;
            }

            pkey_ctx = EVP_PKEY_CTX_new(pub_key =
                                        X509_get_pubkey(peer_cert), NULL);
            /*
             * If we have send a certificate, and certificate key
             *
             * * parameters match those of server certificate, use
             * certificate key for key exchange
             */

            /* Otherwise, generate ephemeral key pair */

            EVP_PKEY_encrypt_init(pkey_ctx);
            /* Generate session key */
            if (RAND_bytes(pms, pmslen) <= 0) {
                EVP_PKEY_CTX_free(pkey_ctx);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            };
            /*
             * If we have client certificate, use its secret as peer key
             */
            if (s->s3->tmp.cert_req && s->cert->key->privatekey) {
                if (EVP_PKEY_derive_set_peer
                    (pkey_ctx, s->cert->key->privatekey) <= 0) {
                    /*
                     * If there was an error - just ignore it. Ephemeral key
                     * * would be used
                     */
                    ERR_clear_error();
                }
            }
            /*
             * Compute shared IV and store it in algorithm-specific context
             * data
             */
            ukm_hash = EVP_MD_CTX_create();
            EVP_DigestInit(ukm_hash,
                           EVP_get_digestbynid(NID_id_GostR3411_94));
            EVP_DigestUpdate(ukm_hash, s->s3->client_random,
                             SSL3_RANDOM_SIZE);
            EVP_DigestUpdate(ukm_hash, s->s3->server_random,
                             SSL3_RANDOM_SIZE);
            EVP_DigestFinal_ex(ukm_hash, shared_ukm, &md_len);
            EVP_MD_CTX_destroy(ukm_hash);
            if (EVP_PKEY_CTX_ctrl
                (pkey_ctx, -1, EVP_PKEY_OP_ENCRYPT, EVP_PKEY_CTRL_SET_IV, 8,
                 shared_ukm) < 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_LIBRARY_BUG);
                goto err;
            }
            /* Make GOST keytransport blob message */
            /*
             * Encapsulate it into sequence
             */
            *(p++) = V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED;
            msglen = 255;
            if (EVP_PKEY_encrypt(pkey_ctx, tmp, &msglen, pms, pmslen) < 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_LIBRARY_BUG);
                goto err;
            }
            if (msglen >= 0x80) {
                *(p++) = 0x81;
                *(p++) = msglen & 0xff;
                n = msglen + 3;
            } else {
                *(p++) = msglen & 0xff;
                n = msglen + 2;
            }
            memcpy(p, tmp, msglen);
            /* Check if pubkey from client certificate was used */
            if (EVP_PKEY_CTX_ctrl
                (pkey_ctx, -1, -1, EVP_PKEY_CTRL_PEER_KEY, 2, NULL) > 0) {
                /* Set flag "skip certificate verify" */
                s->s3->flags |= TLS1_FLAGS_SKIP_CERT_VERIFY;
            }
            EVP_PKEY_CTX_free(pkey_ctx);
            EVP_PKEY_free(pub_key);

        }
#ifndef OPENSSL_NO_SRP
        else if (alg_k & SSL_kSRP) {
            if (s->srp_ctx.A != NULL) {
                /* send off the data */
                n = BN_num_bytes(s->srp_ctx.A);
                s2n(n, p);
                BN_bn2bin(s->srp_ctx.A, p);
                n += 2;
            } else {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            OPENSSL_free(s->session->srp_username);
            s->session->srp_username = BUF_strdup(s->srp_ctx.login);
            if (s->session->srp_username == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
#endif
        else {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
            SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

#ifndef OPENSSL_NO_PSK
        n += pskhdrlen;
#endif

        if (!ssl_set_handshake_header(s, SSL3_MT_CLIENT_KEY_EXCHANGE, n)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
            SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        s->state = SSL3_ST_CW_KEY_EXCH_B;
    }

    /* SSL3_ST_CW_KEY_EXCH_B */
    n = ssl_do_write(s);
#ifndef OPENSSL_NO_SRP
    /* Check for SRP */
    if (alg_k & SSL_kSRP) {
        /*
         * If everything written generate master key: no need to save PMS as
         * srp_generate_client_master_secret generates it internally.
         */
        if (n > 0) {
            if (!srp_generate_client_master_secret(s)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    } else
#endif
        /* If we haven't written everything save PMS */
    if (n <= 0) {
        s->s3->tmp.pms = pms;
        s->s3->tmp.pmslen = pmslen;
    } else {
        /* If we don't have a PMS restore */
        if (pms == NULL) {
            pms = s->s3->tmp.pms;
            pmslen = s->s3->tmp.pmslen;
        }
        if (pms == NULL && !(alg_k & SSL_kPSK)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
            SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (!ssl_generate_master_secret(s, pms, pmslen, 1)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
            SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    return n;
 memerr:
    ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
 err:
    OPENSSL_clear_free(pms, pmslen);
    s->s3->tmp.pms = NULL;
#ifndef OPENSSL_NO_EC
    BN_CTX_free(bn_ctx);
    OPENSSL_free(encodedPoint);
    EC_KEY_free(clnt_ecdh);
    EVP_PKEY_free(srvr_pub_pkey);
#endif
#ifndef OPENSSL_NO_PSK
    OPENSSL_clear_free(s->s3->tmp.psk, s->s3->tmp.psklen);
    s->s3->tmp.psk = NULL;
#endif
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_send_client_verify(SSL *s)
{
    unsigned char *p;
    unsigned char data[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX mctx;
    unsigned u = 0;
    unsigned long n;
    int j;

    EVP_MD_CTX_init(&mctx);

    if (s->state == SSL3_ST_CW_CERT_VRFY_A) {
        p = ssl_handshake_start(s);
        pkey = s->cert->key->privatekey;
/* Create context from key and test if sha1 is allowed as digest */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_sign_init(pctx);
        if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha1()) > 0) {
            if (!SSL_USE_SIGALGS(s))
                s->method->ssl3_enc->cert_verify_mac(s,
                                                     NID_sha1,
                                                     &(data
                                                       [MD5_DIGEST_LENGTH]));
        } else {
            ERR_clear_error();
        }
        /*
         * For TLS v1.2 send signature algorithm and signature using agreed
         * digest and cached handshake records.
         */
        if (SSL_USE_SIGALGS(s)) {
            long hdatalen = 0;
            void *hdata;
            const EVP_MD *md = s->s3->tmp.md[s->cert->key - s->cert->pkeys];
            hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
            if (hdatalen <= 0 || !tls12_get_sigandhash(p, pkey, md)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            p += 2;
#ifdef SSL_DEBUG
            fprintf(stderr, "Using TLS 1.2 with client alg %s\n",
                    EVP_MD_name(md));
#endif
            if (!EVP_SignInit_ex(&mctx, md, NULL)
                || !EVP_SignUpdate(&mctx, hdata, hdatalen)
                || !EVP_SignFinal(&mctx, p + 2, &u, pkey)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_EVP_LIB);
                goto err;
            }
            s2n(u, p);
            n = u + 4;
            /* Digest cached records and discard handshake buffer */
            if (!ssl3_digest_cached_records(s, 0))
                goto err;
        } else
#ifndef OPENSSL_NO_RSA
        if (pkey->type == EVP_PKEY_RSA) {
            s->method->ssl3_enc->cert_verify_mac(s, NID_md5, &(data[0]));
            if (RSA_sign(NID_md5_sha1, data,
                         MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
                         &(p[2]), &u, pkey->pkey.rsa) <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_RSA_LIB);
                goto err;
            }
            s2n(u, p);
            n = u + 2;
        } else
#endif
#ifndef OPENSSL_NO_DSA
        if (pkey->type == EVP_PKEY_DSA) {
            if (!DSA_sign(pkey->save_type,
                          &(data[MD5_DIGEST_LENGTH]),
                          SHA_DIGEST_LENGTH, &(p[2]),
                          (unsigned int *)&j, pkey->pkey.dsa)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_DSA_LIB);
                goto err;
            }
            s2n(j, p);
            n = j + 2;
        } else
#endif
#ifndef OPENSSL_NO_EC
        if (pkey->type == EVP_PKEY_EC) {
            if (!ECDSA_sign(pkey->save_type,
                            &(data[MD5_DIGEST_LENGTH]),
                            SHA_DIGEST_LENGTH, &(p[2]),
                            (unsigned int *)&j, pkey->pkey.ec)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_ECDSA_LIB);
                goto err;
            }
            s2n(j, p);
            n = j + 2;
        } else
#endif
        if (pkey->type == NID_id_GostR3410_2001) {
            unsigned char signbuf[64];
            int i;
            size_t sigsize = 64;
            s->method->ssl3_enc->cert_verify_mac(s,
                                                 NID_id_GostR3411_94, data);
            if (EVP_PKEY_sign(pctx, signbuf, &sigsize, data, 32) <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            for (i = 63, j = 0; i >= 0; j++, i--) {
                p[2 + j] = signbuf[i];
            }
            s2n(j, p);
            n = j + 2;
        } else {
            SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (!ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE_VERIFY, n)) {
            SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        s->state = SSL3_ST_CW_CERT_VRFY_B;
    }
    EVP_MD_CTX_cleanup(&mctx);
    EVP_PKEY_CTX_free(pctx);
    return ssl_do_write(s);
 err:
    EVP_MD_CTX_cleanup(&mctx);
    EVP_PKEY_CTX_free(pctx);
    s->state = SSL_ST_ERR;
    return (-1);
}

/*
 * Check a certificate can be used for client authentication. Currently check
 * cert exists, if we have a suitable digest for TLS 1.2 if static DH client
 * certificates can be used and optionally checks suitability for Suite B.
 */
static int ssl3_check_client_certificate(SSL *s)
{
    unsigned long alg_k;
    if (!s->cert || !s->cert->key->x509 || !s->cert->key->privatekey)
        return 0;
    /* If no suitable signature algorithm can't use certificate */
    if (SSL_USE_SIGALGS(s) && !s->s3->tmp.md[s->cert->key - s->cert->pkeys])
        return 0;
    /*
     * If strict mode check suitability of chain before using it. This also
     * adjusts suite B digest if necessary.
     */
    if (s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT &&
        !tls1_check_chain(s, NULL, NULL, NULL, -2))
        return 0;
    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    /* See if we can use client certificate for fixed DH */
    if (alg_k & (SSL_kDHr | SSL_kDHd)) {
        int i = s->session->peer_type;
        EVP_PKEY *clkey = NULL, *spkey = NULL;
        clkey = s->cert->key->privatekey;
        /* If client key not DH assume it can be used */
        if (EVP_PKEY_id(clkey) != EVP_PKEY_DH)
            return 1;
        if (i >= 0)
            spkey = X509_get_pubkey(s->session->peer);
        if (spkey) {
            /* Compare server and client parameters */
            i = EVP_PKEY_cmp_parameters(clkey, spkey);
            EVP_PKEY_free(spkey);
            if (i != 1)
                return 0;
        }
        s->s3->flags |= TLS1_FLAGS_SKIP_CERT_VERIFY;
    }
    return 1;
}

int ssl3_send_client_certificate(SSL *s)
{
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    int i;

    if (s->state == SSL3_ST_CW_CERT_A) {
        /* Let cert callback update client certificates if required */
        if (s->cert->cert_cb) {
            i = s->cert->cert_cb(s, s->cert->cert_cb_arg);
            if (i < 0) {
                s->rwstate = SSL_X509_LOOKUP;
                return -1;
            }
            if (i == 0) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
                s->state = SSL_ST_ERR;
                return 0;
            }
            s->rwstate = SSL_NOTHING;
        }
        if (ssl3_check_client_certificate(s))
            s->state = SSL3_ST_CW_CERT_C;
        else
            s->state = SSL3_ST_CW_CERT_B;
    }

    /* We need to get a client cert */
    if (s->state == SSL3_ST_CW_CERT_B) {
        /*
         * If we get an error, we need to ssl->rwstate=SSL_X509_LOOKUP;
         * return(-1); We then get retied later
         */
        i = ssl_do_client_cert_cb(s, &x509, &pkey);
        if (i < 0) {
            s->rwstate = SSL_X509_LOOKUP;
            return (-1);
        }
        s->rwstate = SSL_NOTHING;
        if ((i == 1) && (pkey != NULL) && (x509 != NULL)) {
            s->state = SSL3_ST_CW_CERT_B;
            if (!SSL_use_certificate(s, x509) || !SSL_use_PrivateKey(s, pkey))
                i = 0;
        } else if (i == 1) {
            i = 0;
            SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE,
                   SSL_R_BAD_DATA_RETURNED_BY_CALLBACK);
        }

        X509_free(x509);
        EVP_PKEY_free(pkey);
        if (i && !ssl3_check_client_certificate(s))
            i = 0;
        if (i == 0) {
            if (s->version == SSL3_VERSION) {
                s->s3->tmp.cert_req = 0;
                ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_NO_CERTIFICATE);
                return (1);
            } else {
                s->s3->tmp.cert_req = 2;
                if (!ssl3_digest_cached_records(s, 0)) {
                    ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
                    s->state = SSL_ST_ERR;
                    return 0;
                }
            }
        }

        /* Ok, we have a cert */
        s->state = SSL3_ST_CW_CERT_C;
    }

    if (s->state == SSL3_ST_CW_CERT_C) {
        s->state = SSL3_ST_CW_CERT_D;
        if (!ssl3_output_cert_chain(s,
                                    (s->s3->tmp.cert_req ==
                                     2) ? NULL : s->cert->key)) {
            SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE, ERR_R_INTERNAL_ERROR);
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return 0;
        }
    }
    /* SSL3_ST_CW_CERT_D */
    return ssl_do_write(s);
}

#define has_bits(i,m)   (((i)&(m)) == (m))

int ssl3_check_cert_and_algorithm(SSL *s)
{
    int i, idx;
    long alg_k, alg_a;
    EVP_PKEY *pkey = NULL;
    int pkey_bits;
#ifndef OPENSSL_NO_RSA
    RSA *rsa;
#endif
#ifndef OPENSSL_NO_DH
    DH *dh;
#endif
    int al = SSL_AD_HANDSHAKE_FAILURE;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    /* we don't have a certificate */
    if ((alg_a & SSL_aNULL) || (alg_k & SSL_kPSK))
        return (1);
#ifndef OPENSSL_NO_RSA
    rsa = s->s3->peer_rsa_tmp;
#endif
#ifndef OPENSSL_NO_DH
    dh = s->s3->peer_dh_tmp;
#endif

    /* This is the passed certificate */

    idx = s->session->peer_type;
#ifndef OPENSSL_NO_EC
    if (idx == SSL_PKEY_ECC) {
        if (ssl_check_srvr_ecc_cert_and_alg(s->session->peer, s) == 0) {
            /* check failed */
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, SSL_R_BAD_ECC_CERT);
            goto f_err;
        } else {
            return 1;
        }
    } else if (alg_a & SSL_aECDSA) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_ECDSA_SIGNING_CERT);
        goto f_err;
    } else if (alg_k & (SSL_kECDHr | SSL_kECDHe)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, SSL_R_MISSING_ECDH_CERT);
        goto f_err;
    }
#endif
    pkey = X509_get_pubkey(s->session->peer);
    pkey_bits = EVP_PKEY_bits(pkey);
    i = X509_certificate_type(s->session->peer, pkey);
    EVP_PKEY_free(pkey);

    /* Check that we have a certificate if we require one */
    if ((alg_a & SSL_aRSA) && !has_bits(i, EVP_PK_RSA | EVP_PKT_SIGN)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_RSA_SIGNING_CERT);
        goto f_err;
    }
#ifndef OPENSSL_NO_DSA
    else if ((alg_a & SSL_aDSS) && !has_bits(i, EVP_PK_DSA | EVP_PKT_SIGN)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_DSA_SIGNING_CERT);
        goto f_err;
    }
#endif
#ifndef OPENSSL_NO_RSA
    if (alg_k & (SSL_kRSA | SSL_kRSAPSK)) {
        if (!SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
            !has_bits(i, EVP_PK_RSA | EVP_PKT_ENC)) {
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                   SSL_R_MISSING_RSA_ENCRYPTING_CERT);
            goto f_err;
        } else if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)) {
            if (pkey_bits <= SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
                if (!has_bits(i, EVP_PK_RSA | EVP_PKT_ENC)) {
                    SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                           SSL_R_MISSING_RSA_ENCRYPTING_CERT);
                    goto f_err;
                }
                if (rsa != NULL) {
                    /* server key exchange is not allowed. */
                    al = SSL_AD_INTERNAL_ERROR;
                    SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, ERR_R_INTERNAL_ERROR);
                    goto f_err;
                }
            }
        }
    }
#endif
#ifndef OPENSSL_NO_DH
    if ((alg_k & SSL_kDHE) && (dh == NULL)) {
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, ERR_R_INTERNAL_ERROR);
        goto f_err;
    } else if ((alg_k & SSL_kDHr) && !SSL_USE_SIGALGS(s) &&
               !has_bits(i, EVP_PK_DH | EVP_PKS_RSA)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_DH_RSA_CERT);
        goto f_err;
    }
# ifndef OPENSSL_NO_DSA
    else if ((alg_k & SSL_kDHd) && !SSL_USE_SIGALGS(s) &&
             !has_bits(i, EVP_PK_DH | EVP_PKS_DSA)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_DH_DSA_CERT);
        goto f_err;
    }
# endif
#endif

    if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
        pkey_bits > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
#ifndef OPENSSL_NO_RSA
        if (alg_k & SSL_kRSA) {
            if (rsa == NULL) {
                SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                       SSL_R_MISSING_EXPORT_TMP_RSA_KEY);
                goto f_err;
            } else if (RSA_bits(rsa) >
                SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
                /* We have a temporary RSA key but it's too large. */
                al = SSL_AD_EXPORT_RESTRICTION;
                SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                       SSL_R_MISSING_EXPORT_TMP_RSA_KEY);
                goto f_err;
            }
        } else
#endif
#ifndef OPENSSL_NO_DH
        if (alg_k & SSL_kDHE) {
            if (DH_bits(dh) >
                SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
                /* We have a temporary DH key but it's too large. */
                al = SSL_AD_EXPORT_RESTRICTION;
                SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                       SSL_R_MISSING_EXPORT_TMP_DH_KEY);
                goto f_err;
            }
        } else if (alg_k & (SSL_kDHr | SSL_kDHd)) {
            /* The cert should have had an export DH key. */
            al = SSL_AD_EXPORT_RESTRICTION;
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                   SSL_R_MISSING_EXPORT_TMP_DH_KEY);
                goto f_err;
        } else
#endif
        {
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                   SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
            goto f_err;
        }
    }
    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    return (0);
}

/*
 * Normally, we can tell if the server is resuming the session from
 * the session ID. EAP-FAST (RFC 4851), however, relies on the next server
 * message after the ServerHello to determine if the server is resuming.
 * Therefore, we allow EAP-FAST to peek ahead.
 * ssl3_check_change returns 1 if we are resuming from an external
 * pre-shared secret, we have a "ticket" and the next server message
 * is CCS; and 0 otherwise. It returns -1 upon an error.
 */
static int ssl3_check_change(SSL *s)
{
    int ok = 0;

    if (s->version < TLS1_VERSION || !s->tls_session_secret_cb ||
        !s->session->tlsext_tick)
        return 0;

    /*
     * This function is called when we might get a Certificate message instead,
     * so permit appropriate message length.
     * We ignore the return value as we're only interested in the message type
     * and not its length.
     */
    s->method->ssl_get_message(s,
                               SSL3_ST_CR_CERT_A,
                               SSL3_ST_CR_CERT_B,
                               -1, s->max_cert_list, &ok);

    if (!ok)
        return -1;

    s->s3->tmp.reuse_message = 1;

    if (s->s3->tmp.message_type == SSL3_MT_CHANGE_CIPHER_SPEC)
        return 1;

    return 0;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
int ssl3_send_next_proto(SSL *s)
{
    unsigned int len, padding_len;
    unsigned char *d;

    if (s->state == SSL3_ST_CW_NEXT_PROTO_A) {
        len = s->next_proto_negotiated_len;
        padding_len = 32 - ((len + 2) % 32);
        d = (unsigned char *)s->init_buf->data;
        d[4] = len;
        memcpy(d + 5, s->next_proto_negotiated, len);
        d[5 + len] = padding_len;
        memset(d + 6 + len, 0, padding_len);
        *(d++) = SSL3_MT_NEXT_PROTO;
        l2n3(2 + len + padding_len, d);
        s->state = SSL3_ST_CW_NEXT_PROTO_B;
        s->init_num = 4 + 2 + len + padding_len;
        s->init_off = 0;
    }

    return ssl3_do_write(s, SSL3_RT_HANDSHAKE);
}
#endif

int ssl_do_client_cert_cb(SSL *s, X509 **px509, EVP_PKEY **ppkey)
{
    int i = 0;
#ifndef OPENSSL_NO_ENGINE
    if (s->ctx->client_cert_engine) {
        i = ENGINE_load_ssl_client_cert(s->ctx->client_cert_engine, s,
                                        SSL_get_client_CA_list(s),
                                        px509, ppkey, NULL, NULL, NULL);
        if (i != 0)
            return i;
    }
#endif
    if (s->ctx->client_cert_cb)
        i = s->ctx->client_cert_cb(s, px509, ppkey);
    return i;
}

int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk,
                             unsigned char *p)
{
    int i, j = 0;
    SSL_CIPHER *c;
    unsigned char *q;
    int empty_reneg_info_scsv = !s->renegotiate;
    /* Set disabled masks for this session */
    ssl_set_client_disabled(s);

    if (sk == NULL)
        return (0);
    q = p;

    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        c = sk_SSL_CIPHER_value(sk, i);
        /* Skip disabled ciphers */
        if (ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_SUPPORTED))
            continue;
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        if (c->id == SSL3_CK_SCSV) {
            if (!empty_reneg_info_scsv)
                continue;
            else
                empty_reneg_info_scsv = 0;
        }
#endif
        j = s->method->put_cipher_by_char(c, p);
        p += j;
    }
    /*
     * If p == q, no ciphers; caller indicates an error. Otherwise, add
     * applicable SCSVs.
     */
    if (p != q) {
        if (empty_reneg_info_scsv) {
            static SSL_CIPHER scsv = {
                0, NULL, SSL3_CK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            j = s->method->put_cipher_by_char(&scsv, p);
            p += j;
#ifdef OPENSSL_RI_DEBUG
            fprintf(stderr,
                    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV sent by client\n");
#endif
        }
        if (s->mode & SSL_MODE_SEND_FALLBACK_SCSV) {
            static SSL_CIPHER scsv = {
                0, NULL, SSL3_CK_FALLBACK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            j = s->method->put_cipher_by_char(&scsv, p);
            p += j;
        }
    }

    return (p - q);
}
