/* $OpenBSD: d1_clnt.c,v 1.27 2014/07/10 08:51:14 tedu Exp $ */
/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
 */
/* ====================================================================
 * Copyright (c) 1999-2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

static const SSL_METHOD *dtls1_get_client_method(int ver);
static int dtls1_get_hello_verify(SSL *s);

const SSL_METHOD DTLSv1_client_method_data = {
	.version = DTLS1_VERSION,
	.ssl_new = dtls1_new,
	.ssl_clear = dtls1_clear,
	.ssl_free = dtls1_free,
	.ssl_accept = ssl_undefined_function,
	.ssl_connect = dtls1_connect,
	.ssl_read = ssl3_read,
	.ssl_peek = ssl3_peek,
	.ssl_write = ssl3_write,
	.ssl_shutdown = dtls1_shutdown,
	.ssl_renegotiate = ssl3_renegotiate,
	.ssl_renegotiate_check = ssl3_renegotiate_check,
	.ssl_get_message = dtls1_get_message,
	.ssl_read_bytes = dtls1_read_bytes,
	.ssl_write_bytes = dtls1_write_app_data_bytes,
	.ssl_dispatch_alert = dtls1_dispatch_alert,
	.ssl_ctrl = dtls1_ctrl,
	.ssl_ctx_ctrl = ssl3_ctx_ctrl,
	.get_cipher_by_char = ssl3_get_cipher_by_char,
	.put_cipher_by_char = ssl3_put_cipher_by_char,
	.ssl_pending = ssl3_pending,
	.num_ciphers = ssl3_num_ciphers,
	.get_cipher = dtls1_get_cipher,
	.get_ssl_method = dtls1_get_client_method,
	.get_timeout = dtls1_default_timeout,
	.ssl3_enc = &DTLSv1_enc_data,
	.ssl_version = ssl_undefined_void_function,
	.ssl_callback_ctrl = ssl3_callback_ctrl,
	.ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *
DTLSv1_client_method(void)
{
	return &DTLSv1_client_method_data;
}

static const SSL_METHOD *
dtls1_get_client_method(int ver)
{
	if (ver == DTLS1_VERSION || ver == DTLS1_BAD_VER)
		return (DTLSv1_client_method());
	return (NULL);
}

int
dtls1_connect(SSL *s)
{
	BUF_MEM *buf = NULL;
	void (*cb)(const SSL *ssl, int type, int val) = NULL;
	int ret = -1;
	int new_state, state, skip = 0;
#ifndef OPENSSL_NO_SCTP
	unsigned char sctpauthkey[64];
	char labelbuffer[sizeof(DTLS1_SCTP_AUTH_LABEL)];
#endif

	ERR_clear_error();
	errno = 0;

	if (s->info_callback != NULL)
		cb = s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb = s->ctx->info_callback;

	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s))
		SSL_clear(s);

#ifndef OPENSSL_NO_SCTP
	/* Notify SCTP BIO socket to enter handshake
	 * mode and prevent stream identifier other
	 * than 0. Will be ignored if no SCTP is used.
	 */
	BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
	    s->in_handshake, NULL);
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
		case SSL_ST_BEFORE|SSL_ST_CONNECT:
		case SSL_ST_OK|SSL_ST_CONNECT:

			s->server = 0;
			if (cb != NULL)
				cb(s, SSL_CB_HANDSHAKE_START, 1);

			if ((s->version & 0xff00 ) != (DTLS1_VERSION & 0xff00) &&
			    (s->version & 0xff00 ) != (DTLS1_BAD_VER & 0xff00)) {
				SSLerr(SSL_F_DTLS1_CONNECT,
				    ERR_R_INTERNAL_ERROR);
				ret = -1;
				goto end;
			}

			/* s->version=SSL3_VERSION; */
			s->type = SSL_ST_CONNECT;

			if (s->init_buf == NULL) {
				if ((buf = BUF_MEM_new()) == NULL) {
					ret = -1;
					goto end;
				}
				if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
					ret = -1;
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
				goto end;
			}

			/* don't push the buffering BIO quite yet */

			s->state = SSL3_ST_CW_CLNT_HELLO_A;
			s->ctx->stats.sess_connect++;
			s->init_num = 0;
			/* mark client_random uninitialized */
			memset(s->s3->client_random, 0,
			    sizeof(s->s3->client_random));
			s->d1->send_cookie = 0;
			s->hit = 0;
			break;

#ifndef OPENSSL_NO_SCTP
		case DTLS1_SCTP_ST_CR_READ_SOCK:

			if (BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
				s->s3->in_read_app_data = 2;
				s->rwstate = SSL_READING;
				BIO_clear_retry_flags(SSL_get_rbio(s));
				BIO_set_retry_read(SSL_get_rbio(s));
				ret = -1;
				goto end;
			}

			s->state = s->s3->tmp.next_state;
			break;

		case DTLS1_SCTP_ST_CW_WRITE_SOCK:
			/* read app data until dry event */

			ret = BIO_dgram_sctp_wait_for_dry(SSL_get_wbio(s));
			if (ret < 0)
				goto end;

			if (ret == 0) {
				s->s3->in_read_app_data = 2;
				s->rwstate = SSL_READING;
				BIO_clear_retry_flags(SSL_get_rbio(s));
				BIO_set_retry_read(SSL_get_rbio(s));
				ret = -1;
				goto end;
			}

			s->state = s->d1->next_state;
			break;
#endif

		case SSL3_ST_CW_CLNT_HELLO_A:
		case SSL3_ST_CW_CLNT_HELLO_B:

			s->shutdown = 0;

			/* every DTLS ClientHello resets Finished MAC */
			ssl3_init_finished_mac(s);

			dtls1_start_timer(s);
			ret = dtls1_client_hello(s);
			if (ret <= 0)
				goto end;

			if (s->d1->send_cookie) {
				s->state = SSL3_ST_CW_FLUSH;
				s->s3->tmp.next_state = SSL3_ST_CR_SRVR_HELLO_A;
			} else
				s->state = SSL3_ST_CR_SRVR_HELLO_A;

			s->init_num = 0;

#ifndef OPENSSL_NO_SCTP
			/* Disable buffering for SCTP */
			if (!BIO_dgram_is_sctp(SSL_get_wbio(s))) {
#endif
				/* turn on buffering for the next lot of output */
				if (s->bbio != s->wbio)
					s->wbio = BIO_push(s->bbio, s->wbio);
#ifndef OPENSSL_NO_SCTP
			}
#endif
			break;

		case SSL3_ST_CR_SRVR_HELLO_A:
		case SSL3_ST_CR_SRVR_HELLO_B:
			ret = ssl3_get_server_hello(s);
			if (ret <= 0)
				goto end;
			else {
				if (s->hit) {
#ifndef OPENSSL_NO_SCTP
					/* Add new shared key for SCTP-Auth,
					 * will be ignored if no SCTP used.
					 */
					snprintf((char*) labelbuffer, sizeof(DTLS1_SCTP_AUTH_LABEL),
					    DTLS1_SCTP_AUTH_LABEL);

					SSL_export_keying_material(s, sctpauthkey,
					    sizeof(sctpauthkey), labelbuffer,
					    sizeof(labelbuffer), NULL, 0, 0);

					BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
					    sizeof(sctpauthkey), sctpauthkey);
#endif

					s->state = SSL3_ST_CR_FINISHED_A;
				} else
					s->state = DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A;
			}
			s->init_num = 0;
			break;

		case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A:
		case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B:

			ret = dtls1_get_hello_verify(s);
			if (ret <= 0)
				goto end;
			dtls1_stop_timer(s);
			if ( s->d1->send_cookie) /* start again, with a cookie */
				s->state = SSL3_ST_CW_CLNT_HELLO_A;
			else
				s->state = SSL3_ST_CR_CERT_A;
			s->init_num = 0;
			break;

		case SSL3_ST_CR_CERT_A:
		case SSL3_ST_CR_CERT_B:
			ret = ssl3_check_finished(s);
			if (ret <= 0)
				goto end;
			if (ret == 2) {
				s->hit = 1;
				if (s->tlsext_ticket_expected)
					s->state = SSL3_ST_CR_SESSION_TICKET_A;
				else
					s->state = SSL3_ST_CR_FINISHED_A;
				s->init_num = 0;
				break;
			}
			/* Check if it is anon DH or PSK */
			if (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) &&
			    !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
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

			/* at this point we check that we have the
			 * required stuff from the server */
			if (!ssl3_check_cert_and_algorithm(s)) {
				ret = -1;
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
			dtls1_stop_timer(s);
			if (s->s3->tmp.cert_req)
				s->s3->tmp.next_state = SSL3_ST_CW_CERT_A;
			else
				s->s3->tmp.next_state = SSL3_ST_CW_KEY_EXCH_A;
			s->init_num = 0;

#ifndef OPENSSL_NO_SCTP
			if (BIO_dgram_is_sctp(SSL_get_wbio(s)) &&
			    state == SSL_ST_RENEGOTIATE)
				s->state = DTLS1_SCTP_ST_CR_READ_SOCK;
			else
#endif
				s->state = s->s3->tmp.next_state;
			break;

		case SSL3_ST_CW_CERT_A:
		case SSL3_ST_CW_CERT_B:
		case SSL3_ST_CW_CERT_C:
		case SSL3_ST_CW_CERT_D:
			dtls1_start_timer(s);
			ret = dtls1_send_client_certificate(s);
			if (ret <= 0)
				goto end;
			s->state = SSL3_ST_CW_KEY_EXCH_A;
			s->init_num = 0;
			break;

		case SSL3_ST_CW_KEY_EXCH_A:
		case SSL3_ST_CW_KEY_EXCH_B:
			dtls1_start_timer(s);
			ret = dtls1_send_client_key_exchange(s);
			if (ret <= 0)
				goto end;

#ifndef OPENSSL_NO_SCTP
			/* Add new shared key for SCTP-Auth,
			 * will be ignored if no SCTP used.
			 */
			snprintf((char*)labelbuffer,
			    sizeof(DTLS1_SCTP_AUTH_LABEL),
			    DTLS1_SCTP_AUTH_LABEL);

			SSL_export_keying_material(s, sctpauthkey,
			    sizeof(sctpauthkey), labelbuffer,
			    sizeof(labelbuffer), NULL, 0, 0);

			BIO_ctrl(SSL_get_wbio(s),
			    BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
			    sizeof(sctpauthkey), sctpauthkey);
#endif

			/* EAY EAY EAY need to check for DH fix cert
			 * sent back */
			/* For TLS, cert_req is set to 2, so a cert chain
			 * of nothing is sent, but no verify packet is sent */
			if (s->s3->tmp.cert_req == 1) {
				s->state = SSL3_ST_CW_CERT_VRFY_A;
			} else {
#ifndef OPENSSL_NO_SCTP
				if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
					s->d1->next_state = SSL3_ST_CW_CHANGE_A;
					s->state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
				} else
#endif
					s->state = SSL3_ST_CW_CHANGE_A;
				s->s3->change_cipher_spec = 0;
			}

			s->init_num = 0;
			break;

		case SSL3_ST_CW_CERT_VRFY_A:
		case SSL3_ST_CW_CERT_VRFY_B:
			dtls1_start_timer(s);
			ret = dtls1_send_client_verify(s);
			if (ret <= 0)
				goto end;
#ifndef OPENSSL_NO_SCTP
			if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
				s->d1->next_state = SSL3_ST_CW_CHANGE_A;
				s->state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
			} else
#endif
				s->state = SSL3_ST_CW_CHANGE_A;
			s->init_num = 0;
			s->s3->change_cipher_spec = 0;
			break;

		case SSL3_ST_CW_CHANGE_A:
		case SSL3_ST_CW_CHANGE_B:
			if (!s->hit)
				dtls1_start_timer(s);
			ret = dtls1_send_change_cipher_spec(s,
			    SSL3_ST_CW_CHANGE_A, SSL3_ST_CW_CHANGE_B);
			if (ret <= 0)
				goto end;

			s->state = SSL3_ST_CW_FINISHED_A;
			s->init_num = 0;

			s->session->cipher = s->s3->tmp.new_cipher;
			if (!s->method->ssl3_enc->setup_key_block(s)) {
				ret = -1;
				goto end;
			}

			if (!s->method->ssl3_enc->change_cipher_state(s,
			    SSL3_CHANGE_CIPHER_CLIENT_WRITE)) {
				ret = -1;
				goto end;
			}

#ifndef OPENSSL_NO_SCTP
			if (s->hit) {
				/* Change to new shared key of SCTP-Auth,
				 * will be ignored if no SCTP used.
				 */
				BIO_ctrl(SSL_get_wbio(s),
				    BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY, 0, NULL);
			}
#endif

			dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
			break;

		case SSL3_ST_CW_FINISHED_A:
		case SSL3_ST_CW_FINISHED_B:
			if (!s->hit)
				dtls1_start_timer(s);
			ret = dtls1_send_finished(s,
			    SSL3_ST_CW_FINISHED_A, SSL3_ST_CW_FINISHED_B,
			    s->method->ssl3_enc->client_finished_label,
			    s->method->ssl3_enc->client_finished_label_len);
			if (ret <= 0)
				goto end;
			s->state = SSL3_ST_CW_FLUSH;

			/* clear flags */
			s->s3->flags&= ~SSL3_FLAGS_POP_BUFFER;
			if (s->hit) {
				s->s3->tmp.next_state = SSL_ST_OK;
#ifndef OPENSSL_NO_SCTP
				if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
					s->d1->next_state = s->s3->tmp.next_state;
					s->s3->tmp.next_state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
				}
#endif
				if (s->s3->flags & SSL3_FLAGS_DELAY_CLIENT_FINISHED) {
					s->state = SSL_ST_OK;
#ifndef OPENSSL_NO_SCTP
					if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
						s->d1->next_state = SSL_ST_OK;
						s->state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
					}
#endif
					s->s3->flags |= SSL3_FLAGS_POP_BUFFER;
					s->s3->delay_buf_pop_ret = 0;
				}
			} else {
#ifndef OPENSSL_NO_SCTP
				/* Change to new shared key of SCTP-Auth,
				 * will be ignored if no SCTP used.
				 */
				BIO_ctrl(SSL_get_wbio(s),
				    BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY, 0, NULL);
#endif

				/* Allow NewSessionTicket if ticket expected */
				if (s->tlsext_ticket_expected)
					s->s3->tmp.next_state =
					    SSL3_ST_CR_SESSION_TICKET_A;
				else
					s->s3->tmp.next_state =
					    SSL3_ST_CR_FINISHED_A;
			}
			s->init_num = 0;
			break;

		case SSL3_ST_CR_SESSION_TICKET_A:
		case SSL3_ST_CR_SESSION_TICKET_B:
			ret = ssl3_get_new_session_ticket(s);
			if (ret <= 0)
				goto end;
			s->state = SSL3_ST_CR_FINISHED_A;
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

		case SSL3_ST_CR_FINISHED_A:
		case SSL3_ST_CR_FINISHED_B:
			s->d1->change_cipher_spec_ok = 1;
			ret = ssl3_get_finished(s, SSL3_ST_CR_FINISHED_A,
			    SSL3_ST_CR_FINISHED_B);
			if (ret <= 0)
				goto end;
			dtls1_stop_timer(s);

			if (s->hit)
				s->state = SSL3_ST_CW_CHANGE_A;
			else
				s->state = SSL_ST_OK;

#ifndef OPENSSL_NO_SCTP
			if (BIO_dgram_is_sctp(SSL_get_wbio(s)) &&
			    state == SSL_ST_RENEGOTIATE) {
				s->d1->next_state = s->state;
				s->state = DTLS1_SCTP_ST_CW_WRITE_SOCK;
			}
#endif

			s->init_num = 0;
			break;

		case SSL3_ST_CW_FLUSH:
			s->rwstate = SSL_WRITING;
			if (BIO_flush(s->wbio) <= 0) {
				/* If the write error was fatal, stop trying */
				if (!BIO_should_retry(s->wbio)) {
					s->rwstate = SSL_NOTHING;
					s->state = s->s3->tmp.next_state;
				}

				ret = -1;
				goto end;
			}
			s->rwstate = SSL_NOTHING;
			s->state = s->s3->tmp.next_state;
			break;

		case SSL_ST_OK:
			/* clean a few things up */
			ssl3_cleanup_key_block(s);

			/* If we are not 'joining' the last two packets,
			 * remove the buffering now */
			if (!(s->s3->flags & SSL3_FLAGS_POP_BUFFER))
				ssl_free_wbio_buffer(s);
			/* else do it later in ssl3_write */

			s->init_num = 0;
			s->renegotiate = 0;
			s->new_session = 0;

			ssl_update_cache(s, SSL_SESS_CACHE_CLIENT);
			if (s->hit)
				s->ctx->stats.sess_hit++;

			ret = 1;
			/* s->server=0; */
			s->handshake_func = dtls1_connect;
			s->ctx->stats.sess_connect_good++;

			if (cb != NULL)
				cb(s, SSL_CB_HANDSHAKE_DONE, 1);

			/* done with handshaking */
			s->d1->handshake_read_seq = 0;
			s->d1->next_handshake_write_seq = 0;
			goto end;
			/* break; */

		default:
			SSLerr(SSL_F_DTLS1_CONNECT, SSL_R_UNKNOWN_STATE);
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

#ifndef OPENSSL_NO_SCTP
	/* Notify SCTP BIO socket to leave handshake
	 * mode and allow stream identifier other
	 * than 0. Will be ignored if no SCTP is used.
	 */
	BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
	    s->in_handshake, NULL);
#endif

	if (buf != NULL)
		BUF_MEM_free(buf);
	if (cb != NULL)
		cb(s, SSL_CB_CONNECT_EXIT, ret);
	return (ret);
}

int
dtls1_client_hello(SSL *s)
{
	unsigned char *buf;
	unsigned char *p, *d;
	unsigned int i;
	unsigned long l;

	buf = (unsigned char *)s->init_buf->data;
	if (s->state == SSL3_ST_CW_CLNT_HELLO_A) {
		SSL_SESSION *sess = s->session;
		if ((s->session == NULL) ||
		    (s->session->ssl_version != s->version) ||
		    (!sess->session_id_length && !sess->tlsext_tick) ||
		    (s->session->not_resumable)) {
			if (!ssl_get_new_session(s, 0))
				goto err;
		}
		/* else use the pre-loaded session */

		p = s->s3->client_random;

		/* if client_random is initialized, reuse it, we are
		 * required to use same upon reply to HelloVerify */
		for (i = 0; p[i]=='\0' && i < sizeof(s->s3->client_random); i++)
			;
		if (i == sizeof(s->s3->client_random))
			RAND_pseudo_bytes(p, sizeof(s->s3->client_random));

		/* Do the message type and length last */
		d = p = &(buf[DTLS1_HM_HEADER_LENGTH]);

		*(p++) = s->version >> 8;
		*(p++) = s->version&0xff;
		s->client_version = s->version;

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
			if (i > sizeof s->session->session_id) {
				SSLerr(SSL_F_DTLS1_CLIENT_HELLO,
				    ERR_R_INTERNAL_ERROR);
				goto err;
			}
			memcpy(p, s->session->session_id, i);
			p += i;
		}

		/* cookie stuff */
		if (s->d1->cookie_len > sizeof(s->d1->cookie)) {
			SSLerr(SSL_F_DTLS1_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
			goto err;
		}
		*(p++) = s->d1->cookie_len;
		memcpy(p, s->d1->cookie, s->d1->cookie_len);
		p += s->d1->cookie_len;

		/* Ciphers supported */
		i = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), &(p[2]), 0);
		if (i == 0) {
			SSLerr(SSL_F_DTLS1_CLIENT_HELLO,
			    SSL_R_NO_CIPHERS_AVAILABLE);
			goto err;
		}
		s2n(i, p);
		p += i;

		/* add in (no) COMPRESSION */
		*(p++) = 1;
		*(p++) = 0; /* Add the NULL method */

		if ((p = ssl_add_clienthello_tlsext(s, p,
		    buf + SSL3_RT_MAX_PLAIN_LENGTH)) == NULL) {
			SSLerr(SSL_F_DTLS1_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
			goto err;
		}

		l = (p - d);
		d = buf;

		d = dtls1_set_message_header(s, d, SSL3_MT_CLIENT_HELLO,
		    l, 0, l);

		s->state = SSL3_ST_CW_CLNT_HELLO_B;
		/* number of bytes to write */
		s->init_num = p - buf;
		s->init_off = 0;

		/* buffer the message to handle re-xmits */
		dtls1_buffer_message(s, 0);
	}

	/* SSL3_ST_CW_CLNT_HELLO_B */
	return (dtls1_do_write(s, SSL3_RT_HANDSHAKE));
err:
	return (-1);
}

static int
dtls1_get_hello_verify(SSL *s)
{
	int n, al, ok = 0;
	unsigned char *data;
	unsigned int cookie_len;

	n = s->method->ssl_get_message(s, DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A,
	    DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B, -1, s->max_cert_list, &ok);

	if (!ok)
		return ((int)n);

	if (s->s3->tmp.message_type != DTLS1_MT_HELLO_VERIFY_REQUEST) {
		s->d1->send_cookie = 0;
		s->s3->tmp.reuse_message = 1;
		return (1);
	}

	data = (unsigned char *)s->init_msg;

	if ((data[0] != (s->version >> 8)) || (data[1] != (s->version&0xff))) {
		SSLerr(SSL_F_DTLS1_GET_HELLO_VERIFY, SSL_R_WRONG_SSL_VERSION);
		s->version = (s->version & 0xff00) | data[1];
		al = SSL_AD_PROTOCOL_VERSION;
		goto f_err;
	}
	data += 2;

	cookie_len = *(data++);
	if (cookie_len > sizeof(s->d1->cookie)) {
		al = SSL_AD_ILLEGAL_PARAMETER;
		goto f_err;
	}

	memcpy(s->d1->cookie, data, cookie_len);
	s->d1->cookie_len = cookie_len;

	s->d1->send_cookie = 1;
	return 1;

f_err:
	ssl3_send_alert(s, SSL3_AL_FATAL, al);
	return -1;
}

int
dtls1_send_client_key_exchange(SSL *s)
{
	unsigned char *p, *d;
	int n;
	unsigned long alg_k;
	unsigned char *q;
	EVP_PKEY *pkey = NULL;
	EC_KEY *clnt_ecdh = NULL;
	const EC_POINT *srvr_ecpoint = NULL;
	EVP_PKEY *srvr_pub_pkey = NULL;
	unsigned char *encodedPoint = NULL;
	int encoded_pt_len = 0;
	BN_CTX * bn_ctx = NULL;

	if (s->state == SSL3_ST_CW_KEY_EXCH_A) {
		d = (unsigned char *)s->init_buf->data;
		p = &(d[DTLS1_HM_HEADER_LENGTH]);

		alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

		if (alg_k & SSL_kRSA) {
			RSA *rsa;
			unsigned char tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];

			if (s->session->sess_cert->peer_rsa_tmp != NULL)
				rsa = s->session->sess_cert->peer_rsa_tmp;
			else {
				pkey = X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
				if ((pkey == NULL) ||
				    (pkey->type != EVP_PKEY_RSA) ||
				    (pkey->pkey.rsa == NULL)) {
					SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_INTERNAL_ERROR);
					goto err;
				}
				rsa = pkey->pkey.rsa;
				EVP_PKEY_free(pkey);
			}

			tmp_buf[0] = s->client_version >> 8;
			tmp_buf[1] = s->client_version&0xff;
			if (RAND_bytes(&(tmp_buf[2]), sizeof tmp_buf - 2) <= 0)
				goto err;

			s->session->master_key_length = sizeof tmp_buf;

			q = p;
			/* Fix buf for TLS and [incidentally] DTLS */
			if (s->version > SSL3_VERSION)
				p += 2;
			n = RSA_public_encrypt(sizeof tmp_buf,
			    tmp_buf, p, rsa, RSA_PKCS1_PADDING);
			if (n <= 0) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    SSL_R_BAD_RSA_ENCRYPT);
				goto err;
			}

			/* Fix buf for TLS and [incidentally] DTLS */
			if (s->version > SSL3_VERSION) {
				s2n(n, q);
				n += 2;
			}

			s->session->master_key_length =
			    s->method->ssl3_enc->generate_master_secret(s,
			    s->session->master_key,
			    tmp_buf, sizeof tmp_buf);
			OPENSSL_cleanse(tmp_buf, sizeof tmp_buf);
		} else if (alg_k & (SSL_kEDH|SSL_kDHr|SSL_kDHd)) {
			DH *dh_srvr, *dh_clnt;

			if (s->session->sess_cert->peer_dh_tmp != NULL)
				dh_srvr = s->session->sess_cert->peer_dh_tmp;
			else {
				/* we get them from the cert */
				ssl3_send_alert(s, SSL3_AL_FATAL,
				    SSL_AD_HANDSHAKE_FAILURE);
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    SSL_R_UNABLE_TO_FIND_DH_PARAMETERS);
				goto err;
			}

			/* generate a new random key */
			if ((dh_clnt = DHparams_dup(dh_srvr)) == NULL) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_DH_LIB);
				goto err;
			}
			if (!DH_generate_key(dh_clnt)) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_DH_LIB);
				goto err;
			}

			/* use the 'p' output buffer for the DH key, but
			 * make sure to clear it out afterwards */

			n = DH_compute_key(p, dh_srvr->pub_key, dh_clnt);

			if (n <= 0) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_DH_LIB);
				goto err;
			}

			/* generate master key from the result */
			s->session->master_key_length =
			    s->method->ssl3_enc->generate_master_secret(
				s, s->session->master_key, p, n);
			/* clean up */
			memset(p, 0, n);

			/* send off the data */
			n = BN_num_bytes(dh_clnt->pub_key);
			s2n(n, p);
			BN_bn2bin(dh_clnt->pub_key, p);
			n += 2;

			DH_free(dh_clnt);

			/* perhaps clean things up a bit EAY EAY EAY EAY*/
		} else if (alg_k & (SSL_kEECDH|SSL_kECDHr|SSL_kECDHe)) {
			const EC_GROUP *srvr_group = NULL;
			EC_KEY *tkey;
			int ecdh_clnt_cert = 0;
			int field_size = 0;

			/* Did we send out the client's
			 * ECDH share for use in premaster
			 * computation as part of client certificate?
			 * If so, set ecdh_clnt_cert to 1.
			 */
			if ((alg_k & (SSL_kECDHr|SSL_kECDHe)) &&
			    (s->cert != NULL)) {
				/* XXX: For now, we do not support client
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

			if (s->session->sess_cert->peer_ecdh_tmp != NULL) {
				tkey = s->session->sess_cert->peer_ecdh_tmp;
			} else {
				/* Get the Server Public Key from Cert */
				srvr_pub_pkey = X509_get_pubkey(s->session-> \
				    sess_cert->peer_pkeys[SSL_PKEY_ECC].x509);
				if ((srvr_pub_pkey == NULL) ||
				    (srvr_pub_pkey->type != EVP_PKEY_EC) ||
				    (srvr_pub_pkey->pkey.ec == NULL)) {
					SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_INTERNAL_ERROR);
					goto err;
				}

				tkey = srvr_pub_pkey->pkey.ec;
			}

			srvr_group = EC_KEY_get0_group(tkey);
			srvr_ecpoint = EC_KEY_get0_public_key(tkey);

			if ((srvr_group == NULL) || (srvr_ecpoint == NULL)) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_INTERNAL_ERROR);
				goto err;
			}

			if ((clnt_ecdh = EC_KEY_new()) == NULL) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_MALLOC_FAILURE);
				goto err;
			}

			if (!EC_KEY_set_group(clnt_ecdh, srvr_group)) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_EC_LIB);
				goto err;
			}
			if (ecdh_clnt_cert) {
				/* Reuse key info from our certificate
				 * We only need our private key to perform
				 * the ECDH computation.
				 */
				const BIGNUM *priv_key;
				tkey = s->cert->key->privatekey->pkey.ec;
				priv_key = EC_KEY_get0_private_key(tkey);
				if (priv_key == NULL) {
					SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_MALLOC_FAILURE);
					goto err;
				}
				if (!EC_KEY_set_private_key(clnt_ecdh, priv_key)) {
					SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_EC_LIB);
					goto err;
				}
			} else {
				/* Generate a new ECDH key pair */
				if (!(EC_KEY_generate_key(clnt_ecdh))) {
					SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_ECDH_LIB);
					goto err;
				}
			}

			/* use the 'p' output buffer for the ECDH key, but
			 * make sure to clear it out afterwards
			 */

			field_size = EC_GROUP_get_degree(srvr_group);
			if (field_size <= 0) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_ECDH_LIB);
				goto err;
			}
			n = ECDH_compute_key(p, (field_size + 7)/8, srvr_ecpoint, clnt_ecdh, NULL);
			if (n <= 0) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_ECDH_LIB);
				goto err;
			}

			/* generate master key from the result */
			s->session->master_key_length =
			    s->method->ssl3_enc->generate_master_secret(
				s, s->session->master_key, p, n);
			memset(p, 0, n); /* clean up */

			if (ecdh_clnt_cert) {
				/* Send empty client key exch message */
				n = 0;
			} else {
				/* First check the size of encoding and
				 * allocate memory accordingly.
				 */
				encoded_pt_len = EC_POINT_point2oct(srvr_group,
				    EC_KEY_get0_public_key(clnt_ecdh),
				    POINT_CONVERSION_UNCOMPRESSED,
				    NULL, 0, NULL);

				encodedPoint = malloc(encoded_pt_len);

				bn_ctx = BN_CTX_new();
				if ((encodedPoint == NULL) ||
				    (bn_ctx == NULL)) {
					SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_MALLOC_FAILURE);
					goto err;
				}

				/* Encode the public key */
				n = EC_POINT_point2oct(srvr_group,
				    EC_KEY_get0_public_key(clnt_ecdh),
				    POINT_CONVERSION_UNCOMPRESSED,
				    encodedPoint, encoded_pt_len, bn_ctx);

				*p = n; /* length of encoded point */
				/* Encoded point will be copied here */
				p += 1;

				/* copy the point */
				memcpy((unsigned char *)p, encodedPoint, n);
				/* increment n to account for length field */
				n += 1;

			}

			/* Free allocated memory */
			BN_CTX_free(bn_ctx);
			free(encodedPoint);
			EC_KEY_free(clnt_ecdh);
			EVP_PKEY_free(srvr_pub_pkey);
		}

		else {
			ssl3_send_alert(s, SSL3_AL_FATAL,
			    SSL_AD_HANDSHAKE_FAILURE);
			SSLerr(SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}

		d = dtls1_set_message_header(s, d,
		    SSL3_MT_CLIENT_KEY_EXCHANGE, n, 0, n);
		/*
		 *(d++)=SSL3_MT_CLIENT_KEY_EXCHANGE;
		 l2n3(n,d);
		 l2n(s->d1->handshake_write_seq,d);
		 s->d1->handshake_write_seq++;
		*/

		s->state = SSL3_ST_CW_KEY_EXCH_B;
		/* number of bytes to write */
		s->init_num = n + DTLS1_HM_HEADER_LENGTH;
		s->init_off = 0;

		/* buffer the message to handle re-xmits */
		dtls1_buffer_message(s, 0);
	}

	/* SSL3_ST_CW_KEY_EXCH_B */
	return (dtls1_do_write(s, SSL3_RT_HANDSHAKE));

err:
	BN_CTX_free(bn_ctx);
	free(encodedPoint);
	EC_KEY_free(clnt_ecdh);
	EVP_PKEY_free(srvr_pub_pkey);
	return (-1);
}

int
dtls1_send_client_verify(SSL *s)
{
	unsigned char *p, *d;
	unsigned char data[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
	EVP_PKEY *pkey;
	unsigned u = 0;
	unsigned long n;
	int j;

	if (s->state == SSL3_ST_CW_CERT_VRFY_A) {
		d = (unsigned char *)s->init_buf->data;
		p = &(d[DTLS1_HM_HEADER_LENGTH]);
		pkey = s->cert->key->privatekey;

		s->method->ssl3_enc->cert_verify_mac(s, NID_sha1,
		    &(data[MD5_DIGEST_LENGTH]));

		if (pkey->type == EVP_PKEY_RSA) {
			s->method->ssl3_enc->cert_verify_mac(s,
			    NID_md5, &(data[0]));
			if (RSA_sign(NID_md5_sha1, data,
			    MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
			    &(p[2]), &u, pkey->pkey.rsa) <= 0 ) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_VERIFY,
				    ERR_R_RSA_LIB);
				goto err;
			}
			s2n(u, p);
			n = u + 2;
		} else if (pkey->type == EVP_PKEY_DSA) {
			if (!DSA_sign(pkey->save_type,
			    &(data[MD5_DIGEST_LENGTH]),
			    SHA_DIGEST_LENGTH, &(p[2]),
			    (unsigned int *)&j, pkey->pkey.dsa)) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_VERIFY,
				    ERR_R_DSA_LIB);
				goto err;
			}
			s2n(j, p);
			n = j + 2;
		} else if (pkey->type == EVP_PKEY_EC) {
			if (!ECDSA_sign(pkey->save_type,
			    &(data[MD5_DIGEST_LENGTH]),
			    SHA_DIGEST_LENGTH, &(p[2]),
			    (unsigned int *)&j, pkey->pkey.ec)) {
				SSLerr(SSL_F_DTLS1_SEND_CLIENT_VERIFY,
				    ERR_R_ECDSA_LIB);
				goto err;
			}
			s2n(j, p);
			n = j + 2;
		} else {
			SSLerr(SSL_F_DTLS1_SEND_CLIENT_VERIFY,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}

		d = dtls1_set_message_header(s, d,
		    SSL3_MT_CERTIFICATE_VERIFY, n, 0, n);

		s->init_num = (int)n + DTLS1_HM_HEADER_LENGTH;
		s->init_off = 0;

		/* buffer the message to handle re-xmits */
		dtls1_buffer_message(s, 0);

		s->state = SSL3_ST_CW_CERT_VRFY_B;
	}

	/* s->state = SSL3_ST_CW_CERT_VRFY_B */
	return (dtls1_do_write(s, SSL3_RT_HANDSHAKE));
err:
	return (-1);
}

int
dtls1_send_client_certificate(SSL *s)
{
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	int i;
	unsigned long l;

	if (s->state ==	SSL3_ST_CW_CERT_A) {
		if ((s->cert == NULL) || (s->cert->key->x509 == NULL) ||
		    (s->cert->key->privatekey == NULL))
			s->state = SSL3_ST_CW_CERT_B;
		else
			s->state = SSL3_ST_CW_CERT_C;
	}

	/* We need to get a client cert */
	if (s->state == SSL3_ST_CW_CERT_B) {
		/* If we get an error, we need to
		 * ssl->rwstate=SSL_X509_LOOKUP; return(-1);
		 * We then get retied later */
		i = 0;
		i = ssl_do_client_cert_cb(s, &x509, &pkey);
		if (i < 0) {
			s->rwstate = SSL_X509_LOOKUP;
			return (-1);
		}
		s->rwstate = SSL_NOTHING;
		if ((i == 1) && (pkey != NULL) && (x509 != NULL)) {
			s->state = SSL3_ST_CW_CERT_B;
			if (!SSL_use_certificate(s, x509) ||
			    !SSL_use_PrivateKey(s, pkey))
				i = 0;
		} else if (i == 1) {
			i = 0;
			SSLerr(SSL_F_DTLS1_SEND_CLIENT_CERTIFICATE,
			    SSL_R_BAD_DATA_RETURNED_BY_CALLBACK);
		}

		if (x509 != NULL)
			X509_free(x509);
		EVP_PKEY_free(pkey);
		if (i == 0) {
			if (s->version == SSL3_VERSION) {
				s->s3->tmp.cert_req = 0;
				ssl3_send_alert(s, SSL3_AL_WARNING,
				    SSL_AD_NO_CERTIFICATE);
				return (1);
			} else {
				s->s3->tmp.cert_req = 2;
			}
		}

		/* Ok, we have a cert */
		s->state = SSL3_ST_CW_CERT_C;
	}

	if (s->state == SSL3_ST_CW_CERT_C) {
		s->state = SSL3_ST_CW_CERT_D;
		l = dtls1_output_cert_chain(s,
		    (s->s3->tmp.cert_req == 2) ? NULL : s->cert->key->x509);
		s->init_num = (int)l;
		s->init_off = 0;

		/* set header called by dtls1_output_cert_chain() */

		/* buffer the message to handle re-xmits */
		dtls1_buffer_message(s, 0);
	}

	/* SSL3_ST_CW_CERT_D */
	return (dtls1_do_write(s, SSL3_RT_HANDSHAKE));
}
