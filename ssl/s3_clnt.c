/* $OpenBSD: s3_clnt.c,v 1.76 2014/07/11 13:21:15 miod Exp $ */
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
#include <openssl/dh.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

static const SSL_METHOD *ssl3_get_client_method(int ver);
static int ca_dn_cmp(const X509_NAME * const *a, const X509_NAME * const *b);

const SSL_METHOD SSLv3_client_method_data = {
	.version = SSL3_VERSION,
	.ssl_new = ssl3_new,
	.ssl_clear = ssl3_clear,
	.ssl_free = ssl3_free,
	.ssl_accept = ssl_undefined_function,
	.ssl_connect = ssl3_connect,
	.ssl_read = ssl3_read,
	.ssl_peek = ssl3_peek,
	.ssl_write = ssl3_write,
	.ssl_shutdown = ssl3_shutdown,
	.ssl_renegotiate = ssl3_renegotiate,
	.ssl_renegotiate_check = ssl3_renegotiate_check,
	.ssl_get_message = ssl3_get_message,
	.ssl_read_bytes = ssl3_read_bytes,
	.ssl_write_bytes = ssl3_write_bytes,
	.ssl_dispatch_alert = ssl3_dispatch_alert,
	.ssl_ctrl = ssl3_ctrl,
	.ssl_ctx_ctrl = ssl3_ctx_ctrl,
	.get_cipher_by_char = ssl3_get_cipher_by_char,
	.put_cipher_by_char = ssl3_put_cipher_by_char,
	.ssl_pending = ssl3_pending,
	.num_ciphers = ssl3_num_ciphers,
	.get_cipher = ssl3_get_cipher,
	.get_ssl_method = ssl3_get_client_method,
	.get_timeout = ssl3_default_timeout,
	.ssl3_enc = &SSLv3_enc_data,
	.ssl_version = ssl_undefined_void_function,
	.ssl_callback_ctrl = ssl3_callback_ctrl,
	.ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *
SSLv3_client_method(void)
{
	return &SSLv3_client_method_data;
}

static const SSL_METHOD *
ssl3_get_client_method(int ver)
{
	if (ver == SSL3_VERSION)
		return (SSLv3_client_method());
	return (NULL);
}

int
ssl3_connect(SSL *s)
{
	BUF_MEM	*buf = NULL;
	void   (*cb)(const SSL *ssl, int type, int val) = NULL;
	int	 ret = -1;
	int	 new_state, state, skip = 0;

	ERR_clear_error();
	errno = 0;

	if (s->info_callback != NULL)
		cb = s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb = s->ctx->info_callback;

	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s))
		SSL_clear(s);

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

			if ((s->version & 0xff00 ) != 0x0300) {
				SSLerr(SSL_F_SSL3_CONNECT,
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
				if (!BUF_MEM_grow(buf,
				    SSL3_RT_MAX_PLAIN_LENGTH)) {
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

			ssl3_init_finished_mac(s);

			s->state = SSL3_ST_CW_CLNT_HELLO_A;
			s->ctx->stats.sess_connect++;
			s->init_num = 0;
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
				s->state = SSL3_ST_CR_FINISHED_A;
				if (s->tlsext_ticket_expected) {
					/* receive renewed session ticket */
					s->state = SSL3_ST_CR_SESSION_TICKET_A;
				}
			} else
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
			/* Check if it is anon DH/ECDH or PSK */
			if (!(s->s3->tmp.new_cipher->algorithm_auth &
			    SSL_aNULL) &&
			    !(s->s3->tmp.new_cipher->algorithm_mkey &
			    SSL_kPSK)) {
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
			 * At this point we check that we have the
			 * required stuff from the server.
			 */
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
			 * EAY EAY EAY need to check for DH fix cert
			 * sent back
			 */
			/*
			 * For TLS, cert_req is set to 2, so a cert chain
			 * of nothing is sent, but no verify packet is sent
			 */
			/*
			 * XXX: For now, we do not support client
			 * authentication in ECDH cipher suites with
			 * ECDH (rather than ECDSA) certificates.
			 * We need to skip the certificate verify
			 * message when client's ECDH public key is sent
			 * inside the client certificate.
			 */
			if (s->s3->tmp.cert_req == 1) {
				s->state = SSL3_ST_CW_CERT_VRFY_A;
			} else {
				s->state = SSL3_ST_CW_CHANGE_A;
				s->s3->change_cipher_spec = 0;
			}
			if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
				s->state = SSL3_ST_CW_CHANGE_A;
				s->s3->change_cipher_spec = 0;
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
			s->s3->change_cipher_spec = 0;
			break;

		case SSL3_ST_CW_CHANGE_A:
		case SSL3_ST_CW_CHANGE_B:
			ret = ssl3_send_change_cipher_spec(s,
			SSL3_ST_CW_CHANGE_A, SSL3_ST_CW_CHANGE_B);
			if (ret <= 0)
				goto end;

#ifdef OPENSSL_NO_NEXTPROTONEG
			s->state = SSL3_ST_CW_FINISHED_A;
#else
			if (s->s3->next_proto_neg_seen)
				s->state = SSL3_ST_CW_NEXT_PROTO_A;
			else
				s->state = SSL3_ST_CW_FINISHED_A;
#endif
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

			break;

#ifndef OPENSSL_NO_NEXTPROTONEG
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
			ret = ssl3_send_finished(s, SSL3_ST_CW_FINISHED_A,
			    SSL3_ST_CW_FINISHED_B,
			    s->method->ssl3_enc->client_finished_label,
			    s->method->ssl3_enc->client_finished_label_len);
			if (ret <= 0)
				goto end;
			s->s3->flags |= SSL3_FLAGS_CCS_OK;
			s->state = SSL3_ST_CW_FLUSH;

			/* clear flags */
			s->s3->flags &= ~SSL3_FLAGS_POP_BUFFER;
			if (s->hit) {
				s->s3->tmp.next_state = SSL_ST_OK;
				if (s->s3->flags &
				    SSL3_FLAGS_DELAY_CLIENT_FINISHED) {
					s->state = SSL_ST_OK;
					s->s3->flags|=SSL3_FLAGS_POP_BUFFER;
					s->s3->delay_buf_pop_ret = 0;
				}
			} else {
				/* Allow NewSessionTicket if ticket expected */
				if (s->tlsext_ticket_expected)
					s->s3->tmp.next_state =
					    SSL3_ST_CR_SESSION_TICKET_A;
				else

				s->s3->tmp.next_state = SSL3_ST_CR_FINISHED_A;
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
			s->s3->flags |= SSL3_FLAGS_CCS_OK;
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

			if (s->init_buf != NULL) {
				BUF_MEM_free(s->init_buf);
				s->init_buf = NULL;
			}

			/*
			 * If we are not 'joining' the last two packets,
			 * remove the buffering now
			 */
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
			s->handshake_func = ssl3_connect;
			s->ctx->stats.sess_connect_good++;

			if (cb != NULL)
				cb(s, SSL_CB_HANDSHAKE_DONE, 1);

			goto end;
			/* break; */

		default:
			SSLerr(SSL_F_SSL3_CONNECT,
			    SSL_R_UNKNOWN_STATE);
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
	if (buf != NULL)
		BUF_MEM_free(buf);
	if (cb != NULL)
		cb(s, SSL_CB_CONNECT_EXIT, ret);
	return (ret);
}


int
ssl3_client_hello(SSL *s)
{
	unsigned char	*buf;
	unsigned char	*p, *d;
	int		 i;
	unsigned long	 l;

	buf = (unsigned char *)s->init_buf->data;
	if (s->state == SSL3_ST_CW_CLNT_HELLO_A) {
		SSL_SESSION *sess = s->session;
		if ((sess == NULL) ||
		    (sess->ssl_version != s->version) ||
		    (!sess->session_id_length && !sess->tlsext_tick) ||
		    (sess->not_resumable)) {
			if (!ssl_get_new_session(s, 0))
				goto err;
		}
		/* else use the pre-loaded session */

		p = s->s3->client_random;
		RAND_pseudo_bytes(p, SSL3_RANDOM_SIZE);

		/* Do the message type and length last */
		d = p = &(buf[4]);

		/*
		 * Version indicates the negotiated version: for example from
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
		 * 	1. Client hello indicates TLS 1.2
		 * 	2. Server hello says TLS 1.0
		 *	3. RSA encrypted premaster secret uses 1.2.
		 * 	4. Handhaked proceeds using TLS 1.0.
		 *	5. Server sends hello request to renegotiate.
		 *	6. Client hello indicates TLS v1.0 as we now
		 *	   know that is maximum server supports.
		 *	7. Server chokes on RSA encrypted premaster secret
		 *	   containing version 1.0.
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
				SSLerr(SSL_F_SSL3_CLIENT_HELLO,
				    ERR_R_INTERNAL_ERROR);
				goto err;
			}
			memcpy(p, s->session->session_id, i);
			p += i;
		}

		/* Ciphers supported */
		i = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), &(p[2]), 0);
		if (i == 0) {
			SSLerr(SSL_F_SSL3_CLIENT_HELLO,
			    SSL_R_NO_CIPHERS_AVAILABLE);
			goto err;
		}
#ifdef OPENSSL_MAX_TLS1_2_CIPHER_LENGTH
			/*
			 * Some servers hang if client hello > 256 bytes
			 * as hack workaround chop number of supported ciphers
			 * to keep it well below this if we use TLS v1.2
			 */
		if (TLS1_get_version(s) >= TLS1_2_VERSION &&
		    i > OPENSSL_MAX_TLS1_2_CIPHER_LENGTH)
			i = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;
#endif
		s2n(i, p);
		p += i;

		/* add in (no) COMPRESSION */
		*(p++) = 1;
		*(p++) = 0; /* Add the NULL method */

		/* TLS extensions*/
		if (ssl_prepare_clienthello_tlsext(s) <= 0) {
			SSLerr(SSL_F_SSL3_CLIENT_HELLO,
			    SSL_R_CLIENTHELLO_TLSEXT);
			goto err;
		}
		if ((p = ssl_add_clienthello_tlsext(s, p,
		    buf + SSL3_RT_MAX_PLAIN_LENGTH)) == NULL) {
			SSLerr(SSL_F_SSL3_CLIENT_HELLO,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}

		l = (p - d);
		d = buf;
		*(d++) = SSL3_MT_CLIENT_HELLO;
		l2n3(l, d);

		s->state = SSL3_ST_CW_CLNT_HELLO_B;
		/* number of bytes to write */
		s->init_num = p - buf;
		s->init_off = 0;
	}

	/* SSL3_ST_CW_CLNT_HELLO_B */
	return (ssl3_do_write(s, SSL3_RT_HANDSHAKE));
err:
	return (-1);
}

int
ssl3_get_server_hello(SSL *s)
{
	STACK_OF(SSL_CIPHER)	*sk;
	const SSL_CIPHER	*c;
	unsigned char		*p, *d;
	int			 i, al, ok;
	unsigned int		 j;
	long			 n;

	n = s->method->ssl_get_message(s, SSL3_ST_CR_SRVR_HELLO_A,
	    SSL3_ST_CR_SRVR_HELLO_B, -1, 20000, /* ?? */ &ok);

	if (!ok)
		return ((int)n);

	if (SSL_IS_DTLS(s)) {
		if (s->s3->tmp.message_type == DTLS1_MT_HELLO_VERIFY_REQUEST) {
			if (s->d1->send_cookie == 0) {
				s->s3->tmp.reuse_message = 1;
				return (1);
			} else {
				/* Already sent a cookie. */
				al = SSL_AD_UNEXPECTED_MESSAGE;
				SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
				    SSL_R_BAD_MESSAGE_TYPE);
				goto f_err;
			}
		}
	}

	if (s->s3->tmp.message_type != SSL3_MT_SERVER_HELLO) {
		al = SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
		    SSL_R_BAD_MESSAGE_TYPE);
		goto f_err;
	}

	d = p = (unsigned char *)s->init_msg;

	if ((p[0] != (s->version >> 8)) || (p[1] != (s->version & 0xff))) {
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_SSL_VERSION);
		s->version = (s->version&0xff00) | p[1];
		al = SSL_AD_PROTOCOL_VERSION;
		goto f_err;
	}
	p += 2;

	/* load the server hello data */
	/* load the server random */
	memcpy(s->s3->server_random, p, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;

	/* get the session-id */
	j= *(p++);

	if ((j > sizeof s->session->session_id) ||
	    (j > SSL3_SESSION_ID_SIZE)) {
		al = SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
		    SSL_R_SSL3_SESSION_ID_TOO_LONG);
		goto f_err;
	}

	/*
	 * Check if we want to resume the session based on external
	 * pre-shared secret
	 */
	if (s->version >= TLS1_VERSION && s->tls_session_secret_cb) {
		SSL_CIPHER *pref_cipher = NULL;
		s->session->master_key_length = sizeof(s->session->master_key);
		if (s->tls_session_secret_cb(s, s->session->master_key,
		    &s->session->master_key_length, NULL, &pref_cipher,
		    s->tls_session_secret_cb_arg)) {
			s->session->cipher = pref_cipher ?
			    pref_cipher : ssl_get_cipher_by_char(s, p + j);
			s->s3->flags |= SSL3_FLAGS_CCS_OK;
		}
	}

	if (j != 0 && j == s->session->session_id_length &&
	    timingsafe_memcmp(p, s->session->session_id, j) == 0) {
		if (s->sid_ctx_length != s->session->sid_ctx_length ||
		    timingsafe_memcmp(s->session->sid_ctx,
		    s->sid_ctx, s->sid_ctx_length) != 0) {
			/* actually a client application bug */
			al = SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
			    SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
			goto f_err;
		}
		s->s3->flags |= SSL3_FLAGS_CCS_OK;
		s->hit = 1;
	} else {
		/* a miss or crap from the other end */

		/* If we were trying for session-id reuse, make a new
		 * SSL_SESSION so we don't stuff up other people */
		s->hit = 0;
		if (s->session->session_id_length > 0) {
			if (!ssl_get_new_session(s, 0)) {
				al = SSL_AD_INTERNAL_ERROR;
				goto f_err;
			}
		}
		s->session->session_id_length = j;
		memcpy(s->session->session_id,p,j); /* j could be 0 */
	}
	p += j;
	c = ssl_get_cipher_by_char(s, p);
	if (c == NULL) {
		/* unknown cipher */
		al = SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
		    SSL_R_UNKNOWN_CIPHER_RETURNED);
		goto f_err;
	}
	/* TLS v1.2 only ciphersuites require v1.2 or later */
	if ((c->algorithm_ssl & SSL_TLSV1_2) &&
	    (TLS1_get_version(s) < TLS1_2_VERSION)) {
		al = SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
		    SSL_R_WRONG_CIPHER_RETURNED);
		goto f_err;
	}
	p += ssl_put_cipher_by_char(s, NULL, NULL);

	sk = ssl_get_ciphers_by_id(s);
	i = sk_SSL_CIPHER_find(sk, c);
	if (i < 0) {
		/* we did not say we would use this cipher */
		al = SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
		    SSL_R_WRONG_CIPHER_RETURNED);
		goto f_err;
	}

	/*
	 * Depending on the session caching (internal/external), the cipher
	 * and/or cipher_id values may not be set. Make sure that
	 * cipher_id is set and use it for comparison.
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
	 * Don't digest cached records if no sigalgs: we may need them for
	 * client authentication.
	 */
	if (!SSL_USE_SIGALGS(s) && !ssl3_digest_cached_records(s)) {
		al = SSL_AD_INTERNAL_ERROR;
		goto f_err;
	}
	/* lets get the compression algorithm */
	/* COMPRESSION */
	if (*(p++) != 0) {
		al = SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
		    SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
		goto f_err;
	}

	/* TLS extensions*/
	if (s->version >= SSL3_VERSION) {
		if (!ssl_parse_serverhello_tlsext(s, &p, d, n, &al)) {
			/* 'al' set by ssl_parse_serverhello_tlsext */
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
			    SSL_R_PARSE_TLSEXT);
			goto f_err;

		}
		if (ssl_check_serverhello_tlsext(s) <= 0) {
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
			    SSL_R_SERVERHELLO_TLSEXT);
			goto err;
		}
	}

	if (p != (d + n)) {
		/* wrong packet length */
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
		    SSL_R_BAD_PACKET_LENGTH);
		goto f_err;
	}

	return (1);
f_err:
	ssl3_send_alert(s, SSL3_AL_FATAL, al);
err:
	return (-1);
}

int
ssl3_get_server_certificate(SSL *s)
{
	int			 al, i, ok, ret = -1;
	unsigned long		 n, nc, llen, l;
	X509			*x = NULL;
	const unsigned char	*q, *p;
	unsigned char		*d;
	STACK_OF(X509)		*sk = NULL;
	SESS_CERT		*sc;
	EVP_PKEY		*pkey = NULL;

	/* VRS: 0=> will allow null cert if auth == KRB5 */
	int			 need_cert = 1;

	n = s->method->ssl_get_message(s, SSL3_ST_CR_CERT_A,
	    SSL3_ST_CR_CERT_B, -1, s->max_cert_list, &ok);

	if (!ok)
		return ((int)n);

	if ((s->s3->tmp.message_type == SSL3_MT_SERVER_KEY_EXCHANGE) ||
	    ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5) &&
	    (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE))) {
		s->s3->tmp.reuse_message = 1;
		return (1);
	}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
		al = SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
		    SSL_R_BAD_MESSAGE_TYPE);
		goto f_err;
	}
	p = d = (unsigned char *)s->init_msg;

	if ((sk = sk_X509_new_null()) == NULL) {
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
		    ERR_R_MALLOC_FAILURE);
		goto err;
	}

	n2l3(p, llen);
	if (llen + 3 != n) {
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
		    SSL_R_LENGTH_MISMATCH);
		goto f_err;
	}
	for (nc = 0; nc < llen; ) {
		n2l3(p, l);
		if ((l + nc + 3) > llen) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
			    SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
		}

		q = p;
		x = d2i_X509(NULL, &q, l);
		if (x == NULL) {
			al = SSL_AD_BAD_CERTIFICATE;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
			    ERR_R_ASN1_LIB);
			goto f_err;
		}
		if (q != (p + l)) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
			    SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
		}
		if (!sk_X509_push(sk, x)) {
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}
		x = NULL;
		nc += l + 3;
		p = q;
	}

	i = ssl_verify_cert_chain(s, sk);
	if ((s->verify_mode != SSL_VERIFY_NONE) && (i <= 0)) {
		al = ssl_verify_alarm_type(s->verify_result);
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
		    SSL_R_CERTIFICATE_VERIFY_FAILED);
		goto f_err;

	}
	ERR_clear_error(); /* but we keep s->verify_result */

	sc = ssl_sess_cert_new();
	if (sc == NULL)
		goto err;
	if (s->session->sess_cert)
		ssl_sess_cert_free(s->session->sess_cert);
	s->session->sess_cert = sc;

	sc->cert_chain = sk;
	/*
	 * Inconsistency alert: cert_chain does include the peer's
	 * certificate, which we don't include in s3_srvr.c
	 */
	x = sk_X509_value(sk, 0);
	sk = NULL;
	/* VRS 19990621: possible memory leak; sk=null ==> !sk_pop_free() @end*/

	pkey = X509_get_pubkey(x);

	/* VRS: allow null cert if auth == KRB5 */
	need_cert = ((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5) &&
	    (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5))
	    ? 0 : 1;


	if (need_cert && ((pkey == NULL) ||
	    EVP_PKEY_missing_parameters(pkey))) {
		x = NULL;
		al = SSL3_AL_FATAL;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
		SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS);
		goto f_err;
	}

	i = ssl_cert_type(x, pkey);
	if (need_cert && i < 0) {
		x = NULL;
		al = SSL3_AL_FATAL;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
		SSL_R_UNKNOWN_CERTIFICATE_TYPE);
		goto f_err;
	}

	if (need_cert) {
		sc->peer_cert_type = i;
		CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
		/*
		 * Why would the following ever happen?
		 * We just created sc a couple of lines ago.
		 */
		if (sc->peer_pkeys[i].x509 != NULL)
			X509_free(sc->peer_pkeys[i].x509);
		sc->peer_pkeys[i].x509 = x;
		sc->peer_key = &(sc->peer_pkeys[i]);

		if (s->session->peer != NULL)
			X509_free(s->session->peer);
		CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
		s->session->peer = x;
	} else {
		sc->peer_cert_type = i;
		sc->peer_key = NULL;

		if (s->session->peer != NULL)
			X509_free(s->session->peer);
		s->session->peer = NULL;
	}
	s->session->verify_result = s->verify_result;

	x = NULL;
	ret = 1;

	if (0) {
f_err:
		ssl3_send_alert(s, SSL3_AL_FATAL, al);
	}
err:
	EVP_PKEY_free(pkey);
	X509_free(x);
	sk_X509_pop_free(sk, X509_free);
	return (ret);
}

int
ssl3_get_key_exchange(SSL *s)
{
	unsigned char	*q, md_buf[EVP_MAX_MD_SIZE*2];
	EVP_MD_CTX	 md_ctx;
	unsigned char	*param, *p;
	int		 al, i, j, param_len, ok;
	long		 n, alg_k, alg_a;
	EVP_PKEY	*pkey = NULL;
	const		 EVP_MD *md = NULL;
	RSA		*rsa = NULL;
	DH		*dh = NULL;
	EC_KEY		*ecdh = NULL;
	BN_CTX		*bn_ctx = NULL;
	EC_POINT	*srvr_ecpoint = NULL;
	int		 curve_nid = 0;
	int		 encoded_pt_len = 0;

	/*
	 * Use same message size as in ssl3_get_certificate_request()
	 * as ServerKeyExchange message may be skipped.
	 */
	n = s->method->ssl_get_message(s, SSL3_ST_CR_KEY_EXCH_A,
	    SSL3_ST_CR_KEY_EXCH_B, -1, s->max_cert_list, &ok);
	if (!ok)
		return ((int)n);

	if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE) {
		s->s3->tmp.reuse_message = 1;
		return (1);
	}

	param = p = (unsigned char *)s->init_msg;
	if (s->session->sess_cert != NULL) {
		RSA_free(s->session->sess_cert->peer_rsa_tmp);
		s->session->sess_cert->peer_rsa_tmp = NULL;

		DH_free(s->session->sess_cert->peer_dh_tmp);
		s->session->sess_cert->peer_dh_tmp = NULL;

		EC_KEY_free(s->session->sess_cert->peer_ecdh_tmp);
		s->session->sess_cert->peer_ecdh_tmp = NULL;
	} else {
		s->session->sess_cert = ssl_sess_cert_new();
		if (s->session->sess_cert == NULL)
			goto err; 
	}

	param_len = 0;
	alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	alg_a = s->s3->tmp.new_cipher->algorithm_auth;
	EVP_MD_CTX_init(&md_ctx);

	if (alg_k & SSL_kRSA) {
		if ((rsa = RSA_new()) == NULL) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}
		n2s(p, i);
		param_len = i + 2;
		if (param_len > n) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    SSL_R_BAD_RSA_MODULUS_LENGTH);
			goto f_err;
		}
		if (!(rsa->n = BN_bin2bn(p, i, rsa->n))) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_BN_LIB);
			goto err;
		}
		p += i;

		n2s(p, i);
		param_len += i + 2;
		if (param_len > n) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    SSL_R_BAD_RSA_E_LENGTH);
			goto f_err;
		}
		if (!(rsa->e = BN_bin2bn(p, i, rsa->e))) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_BN_LIB);
			goto err;
		}
		p += i;
		n -= param_len;

		/*
		 * This should be because we are using an
		 * export cipher
		 */
		if (alg_a & SSL_aRSA)
			pkey = X509_get_pubkey(
			    s->session->sess_cert->peer_pkeys[
			    SSL_PKEY_RSA_ENC].x509);
		else {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}
		s->session->sess_cert->peer_rsa_tmp = rsa;
		rsa = NULL;
	} else if (alg_k & SSL_kEDH) {
		if ((dh = DH_new()) == NULL) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_DH_LIB);
			goto err;
		}
		n2s(p, i);
		param_len = i + 2;
		if (param_len > n) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    SSL_R_BAD_DH_P_LENGTH);
			goto f_err;
		}
		if (!(dh->p = BN_bin2bn(p, i, NULL))) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_BN_LIB);
			goto err;
		}
		p += i;

		n2s(p, i);
		param_len += i + 2;
		if (param_len > n) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    SSL_R_BAD_DH_G_LENGTH);
			goto f_err;
		}
		if (!(dh->g = BN_bin2bn(p, i, NULL))) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_BN_LIB);
			goto err;
		}
		p += i;

		n2s(p, i);
		param_len += i + 2;
		if (param_len > n) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    SSL_R_BAD_DH_PUB_KEY_LENGTH);
			goto f_err;
		}
		if (!(dh->pub_key = BN_bin2bn(p, i, NULL))) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_BN_LIB);
			goto err;
		}
		p += i;
		n -= param_len;

		if (alg_a & SSL_aRSA)
			pkey = X509_get_pubkey(
			    s->session->sess_cert->peer_pkeys[
			    SSL_PKEY_RSA_ENC].x509);
		else if (alg_a & SSL_aDSS)
			pkey = X509_get_pubkey(
			    s->session->sess_cert->peer_pkeys[
			    SSL_PKEY_DSA_SIGN].x509);
		/* else anonymous DH, so no certificate or pkey. */

		s->session->sess_cert->peer_dh_tmp = dh;
		dh = NULL;
	} else if ((alg_k & SSL_kDHr) || (alg_k & SSL_kDHd)) {
		al = SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
		    SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER);
		goto f_err;
	} else if (alg_k & SSL_kEECDH) {
		EC_GROUP *ngroup;
		const EC_GROUP *group;

		if ((ecdh = EC_KEY_new()) == NULL) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}

		/*
		 * Extract elliptic curve parameters and the
		 * server's ephemeral ECDH public key.
		 * Keep accumulating lengths of various components in
		 * param_len and make sure it never exceeds n.
		 */

		/*
		 * XXX: For now we only support named (not generic) curves
		 * and the ECParameters in this case is just three bytes.
		 */
		param_len = 3;
		if ((param_len > n) || (*p != NAMED_CURVE_TYPE) ||
		    ((curve_nid = tls1_ec_curve_id2nid(*(p + 2))) == 0)) {
			al = SSL_AD_INTERNAL_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
			goto f_err;
		}

		ngroup = EC_GROUP_new_by_curve_name(curve_nid);
		if (ngroup == NULL) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_EC_LIB);
			goto err;
		}
		if (EC_KEY_set_group(ecdh, ngroup) == 0) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_EC_LIB);
			goto err;
		}
		EC_GROUP_free(ngroup);

		group = EC_KEY_get0_group(ecdh);

		p += 3;

		/* Next, get the encoded ECPoint */
		if (((srvr_ecpoint = EC_POINT_new(group)) == NULL) ||
		    ((bn_ctx = BN_CTX_new()) == NULL)) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}

		encoded_pt_len = *p;
		/* length of encoded point */
		p += 1;
		param_len += (1 + encoded_pt_len);
		if ((param_len > n) || (EC_POINT_oct2point(group, srvr_ecpoint,
		    p, encoded_pt_len, bn_ctx) == 0)) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    SSL_R_BAD_ECPOINT);
			goto f_err;
		}

		n -= param_len;
		p += encoded_pt_len;

		/*
		 * The ECC/TLS specification does not mention the use
		 * of DSA to sign ECParameters in the server key
		 * exchange message. We do support RSA and ECDSA.
		 */
		if (alg_a & SSL_aRSA)
			pkey = X509_get_pubkey(
			    s->session->sess_cert->peer_pkeys[
			    SSL_PKEY_RSA_ENC].x509);
		else if (alg_a & SSL_aECDSA)
			pkey = X509_get_pubkey(
			    s->session->sess_cert->peer_pkeys[
			    SSL_PKEY_ECC].x509);
		/* Else anonymous ECDH, so no certificate or pkey. */
		EC_KEY_set_public_key(ecdh, srvr_ecpoint);
		s->session->sess_cert->peer_ecdh_tmp = ecdh;
		ecdh = NULL;
		BN_CTX_free(bn_ctx);
		bn_ctx = NULL;
		EC_POINT_free(srvr_ecpoint);
		srvr_ecpoint = NULL;
	} else if (alg_k) {
		al = SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
		    SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
	}

	/* p points to the next byte, there are 'n' bytes left */

	/* if it was signed, check the signature */
	if (pkey != NULL) {
		if (SSL_USE_SIGALGS(s)) {
			int sigalg = tls12_get_sigid(pkey);
			/* Should never happen */
			if (sigalg == -1) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				    ERR_R_INTERNAL_ERROR);
				goto err;
			}
			/*
			 * Check key type is consistent
			 * with signature
			 */
			if (sigalg != (int)p[1]) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				    SSL_R_WRONG_SIGNATURE_TYPE);
				al = SSL_AD_DECODE_ERROR;
				goto f_err;
			}
			md = tls12_get_hash(p[0]);
			if (md == NULL) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				    SSL_R_UNKNOWN_DIGEST);
				al = SSL_AD_DECODE_ERROR;
				goto f_err;
			}
			p += 2;
			n -= 2;
		} else
			md = EVP_sha1();

		n2s(p, i);
		n -= 2;
		j = EVP_PKEY_size(pkey);

		if ((i != n) || (n > j) || (n <= 0)) {
			/* wrong packet length */
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    SSL_R_WRONG_SIGNATURE_LENGTH);
			goto f_err;
		}

		if (pkey->type == EVP_PKEY_RSA && !SSL_USE_SIGALGS(s)) {
			int num;

			j = 0;
			q = md_buf;
			for (num = 2; num > 0; num--) {
				EVP_DigestInit_ex(&md_ctx,
				    (num == 2) ?  s->ctx->md5 : s->ctx->sha1,
				    NULL);
				EVP_DigestUpdate(&md_ctx,
				    &(s->s3->client_random[0]),
				    SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx,
				    &(s->s3->server_random[0]),
				    SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx, param, param_len);
				EVP_DigestFinal_ex(&md_ctx, q,
				    (unsigned int *)&i);
				q += i;
				j += i;
			}
			i = RSA_verify(NID_md5_sha1, md_buf, j,
			    p, n, pkey->pkey.rsa);
			if (i < 0) {
				al = SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				    SSL_R_BAD_RSA_DECRYPT);
				goto f_err;
			}
			if (i == 0) {
				/* bad signature */
				al = SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				    SSL_R_BAD_SIGNATURE);
				goto f_err;
			}
		} else {
			EVP_VerifyInit_ex(&md_ctx, md, NULL);
			EVP_VerifyUpdate(&md_ctx, &(s->s3->client_random[0]),
			    SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx, &(s->s3->server_random[0]),
			    SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx, param, param_len);
			if (EVP_VerifyFinal(&md_ctx, p,(int)n, pkey) <= 0) {
				/* bad signature */
				al = SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				    SSL_R_BAD_SIGNATURE);
				goto f_err;
			}
		}
	} else {
		/* aNULL or kPSK do not need public keys */
		if (!(alg_a & SSL_aNULL) && !(alg_k & SSL_kPSK)) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}
		/* still data left over */
		if (n != 0) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
			    SSL_R_EXTRA_DATA_IN_MESSAGE);
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
	RSA_free(rsa);
	DH_free(dh);
	BN_CTX_free(bn_ctx);
	EC_POINT_free(srvr_ecpoint);
	EC_KEY_free(ecdh);
	EVP_MD_CTX_cleanup(&md_ctx);
	return (-1);
}

int
ssl3_get_certificate_request(SSL *s)
{
	int			 ok, ret = 0;
	unsigned long		 n, nc, l;
	unsigned int		 llen, ctype_num, i;
	X509_NAME		*xn = NULL;
	const unsigned char	*p, *q;
	unsigned char		*d;
	STACK_OF(X509_NAME)	*ca_sk = NULL;

	n = s->method->ssl_get_message(s, SSL3_ST_CR_CERT_REQ_A,
	    SSL3_ST_CR_CERT_REQ_B, -1, s->max_cert_list, &ok);

	if (!ok)
		return ((int)n);

	s->s3->tmp.cert_req = 0;

	if (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE) {
		s->s3->tmp.reuse_message = 1;
		/*
		 * If we get here we don't need any cached handshake records
		 * as we wont be doing client auth.
		 */
		if (s->s3->handshake_buffer) {
			if (!ssl3_digest_cached_records(s))
				goto err;
		}
		return (1);
	}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_REQUEST) {
		ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
		SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
		    SSL_R_WRONG_MESSAGE_TYPE);
		goto err;
	}

	/* TLS does not like anon-DH with client cert */
	if (s->version > SSL3_VERSION) {
		if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) {
			ssl3_send_alert(s, SSL3_AL_FATAL,
			    SSL_AD_UNEXPECTED_MESSAGE);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
			    SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER);
			goto err;
		}
	}

	p = d = (unsigned char *)s->init_msg;

	if ((ca_sk = sk_X509_NAME_new(ca_dn_cmp)) == NULL) {
		SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
		    ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* get the certificate types */
	ctype_num= *(p++);
	if (ctype_num > SSL3_CT_NUMBER)
		ctype_num = SSL3_CT_NUMBER;
	for (i = 0; i < ctype_num; i++)
		s->s3->tmp.ctype[i] = p[i];
	p += ctype_num;
	if (SSL_USE_SIGALGS(s)) {
		n2s(p, llen);
		/* Check we have enough room for signature algorithms and
		 * following length value.
		 */
		if ((unsigned long)(p - d + llen + 2) > n) {
			ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
			    SSL_R_DATA_LENGTH_TOO_LONG);
			goto err;
		}
		if ((llen & 1) || !tls1_process_sigalgs(s, p, llen)) {
			ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
			    SSL_R_SIGNATURE_ALGORITHMS_ERROR);
			goto err;
		}
		p += llen;
	}

	/* get the CA RDNs */
	n2s(p, llen);

	if ((unsigned long)(p - d + llen) != n) {
		ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
		SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
		    SSL_R_LENGTH_MISMATCH);
		goto err;
	}

	for (nc = 0; nc < llen; ) {
		n2s(p, l);
		if ((l + nc + 2) > llen) {
			if ((s->options & SSL_OP_NETSCAPE_CA_DN_BUG))
				goto cont; /* netscape bugs */
			ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
			    SSL_R_CA_DN_TOO_LONG);
			goto err;
		}

		q = p;

		if ((xn = d2i_X509_NAME(NULL, &q, l)) == NULL) {
			/* If netscape tolerance is on, ignore errors */
			if (s->options & SSL_OP_NETSCAPE_CA_DN_BUG)
				goto cont;
			else {
				ssl3_send_alert(s, SSL3_AL_FATAL,
				    SSL_AD_DECODE_ERROR);
				SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
				    ERR_R_ASN1_LIB);
				goto err;
			}
		}

		if (q != (p + l)) {
			ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
			    SSL_R_CA_DN_LENGTH_MISMATCH);
			goto err;
		}
		if (!sk_X509_NAME_push(ca_sk, xn)) {
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}

		p += l;
		nc += l + 2;
	}

	if (0) {
cont:
		ERR_clear_error();
	}

	/* we should setup a certificate to return.... */
	s->s3->tmp.cert_req = 1;
	s->s3->tmp.ctype_num = ctype_num;
	if (s->s3->tmp.ca_names != NULL)
		sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
	s->s3->tmp.ca_names = ca_sk;
	ca_sk = NULL;

	ret = 1;
err:
	if (ca_sk != NULL)
		sk_X509_NAME_pop_free(ca_sk, X509_NAME_free);
	return (ret);
}

static int
ca_dn_cmp(const X509_NAME * const *a, const X509_NAME * const *b)
{
	return (X509_NAME_cmp(*a, *b));
}

int
ssl3_get_new_session_ticket(SSL *s)
{
	int			 ok, al, ret = 0, ticklen;
	long			 n;
	const unsigned char	*p;
	unsigned char		*d;

	n = s->method->ssl_get_message(s, SSL3_ST_CR_SESSION_TICKET_A,
	    SSL3_ST_CR_SESSION_TICKET_B, -1, 16384, &ok);
	if (!ok)
		return ((int)n);

	if (s->s3->tmp.message_type == SSL3_MT_FINISHED) {
		s->s3->tmp.reuse_message = 1;
		return (1);
	}
	if (s->s3->tmp.message_type != SSL3_MT_NEWSESSION_TICKET) {
		al = SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET,
		    SSL_R_BAD_MESSAGE_TYPE);
		goto f_err;
	}
	if (n < 6) {
		/* need at least ticket_lifetime_hint + ticket length */
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET,
		    SSL_R_LENGTH_MISMATCH);
		goto f_err;
	}

	p = d = (unsigned char *)s->init_msg;
	n2l(p, s->session->tlsext_tick_lifetime_hint);
	n2s(p, ticklen);
	/* ticket_lifetime_hint + ticket_length + ticket */
	if (ticklen + 6 != n) {
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET,
		    SSL_R_LENGTH_MISMATCH);
		goto f_err;
	}
	free(s->session->tlsext_tick);
	s->session->tlsext_ticklen = 0;
	s->session->tlsext_tick = malloc(ticklen);
	if (!s->session->tlsext_tick) {
		SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET,
		    ERR_R_MALLOC_FAILURE);
		goto err;
	}
	memcpy(s->session->tlsext_tick, p, ticklen);
	s->session->tlsext_ticklen = ticklen;
	/*
	 * There are two ways to detect a resumed ticket sesion.
	 * One is to set an appropriate session ID and then the server
	 * must return a match in ServerHello. This allows the normal
	 * client session ID matching to work and we know much
	 * earlier that the ticket has been accepted.
	 *
	 * The other way is to set zero length session ID when the
	 * ticket is presented and rely on the handshake to determine
	 * session resumption.
	 *
	 * We choose the former approach because this fits in with
	 * assumptions elsewhere in OpenSSL. The session ID is set
	 * to the SHA256 (or SHA1 is SHA256 is disabled) hash of the
	 * ticket.
	 */
	EVP_Digest(p, ticklen, s->session->session_id,
	    &s->session->session_id_length, EVP_sha256(), NULL);
	ret = 1;
	return (ret);
f_err:
	ssl3_send_alert(s, SSL3_AL_FATAL, al);
err:
	return (-1);
}

int
ssl3_get_cert_status(SSL *s)
{
	int			 ok, al;
	unsigned long		 resplen, n;
	const unsigned char	*p;

	n = s->method->ssl_get_message(s, SSL3_ST_CR_CERT_STATUS_A,
	    SSL3_ST_CR_CERT_STATUS_B, SSL3_MT_CERTIFICATE_STATUS,
	    16384, &ok);

	if (!ok)
		return ((int)n);
	if (n < 4) {
		/* need at least status type + length */
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS,
		    SSL_R_LENGTH_MISMATCH);
		goto f_err;
	}
	p = (unsigned char *)s->init_msg;
	if (*p++ != TLSEXT_STATUSTYPE_ocsp) {
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS,
		    SSL_R_UNSUPPORTED_STATUS_TYPE);
		goto f_err;
	}
	n2l3(p, resplen);
	if (resplen + 4 != n) {
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS,
		    SSL_R_LENGTH_MISMATCH);
		goto f_err;
	}
	free(s->tlsext_ocsp_resp);
	s->tlsext_ocsp_resp = BUF_memdup(p, resplen);
	if (!s->tlsext_ocsp_resp) {
		al = SSL_AD_INTERNAL_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS,
		    ERR_R_MALLOC_FAILURE);
		goto f_err;
	}
	s->tlsext_ocsp_resplen = resplen;
	if (s->ctx->tlsext_status_cb) {
		int ret;
		ret = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
		if (ret == 0) {
			al = SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
			SSLerr(SSL_F_SSL3_GET_CERT_STATUS,
			    SSL_R_INVALID_STATUS_RESPONSE);
			goto f_err;
		}
		if (ret < 0) {
			al = SSL_AD_INTERNAL_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_STATUS,
			    ERR_R_MALLOC_FAILURE);
			goto f_err;
		}
	}
	return (1);
f_err:
	ssl3_send_alert(s, SSL3_AL_FATAL, al);
	return (-1);
}

int
ssl3_get_server_done(SSL *s)
{
	int	ok, ret = 0;
	long	n;

	n = s->method->ssl_get_message(s, SSL3_ST_CR_SRVR_DONE_A,
	    SSL3_ST_CR_SRVR_DONE_B, SSL3_MT_SERVER_DONE,
	    30, /* should be very small, like 0 :-) */ &ok);

	if (!ok)
		return ((int)n);
	if (n > 0) {
		/* should contain no data */
		ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
		SSLerr(SSL_F_SSL3_GET_SERVER_DONE, SSL_R_LENGTH_MISMATCH);
		return (-1);
	}
	ret = 1;
	return (ret);
}


int
ssl3_send_client_key_exchange(SSL *s)
{
	unsigned char	*p, *d;
	int		 n;
	unsigned long	 alg_k;
	unsigned char	*q;
	EVP_PKEY	*pkey = NULL;
	EC_KEY		*clnt_ecdh = NULL;
	const EC_POINT	*srvr_ecpoint = NULL;
	EVP_PKEY	*srvr_pub_pkey = NULL;
	unsigned char	*encodedPoint = NULL;
	int		 encoded_pt_len = 0;
	BN_CTX		*bn_ctx = NULL;

	if (s->state == SSL3_ST_CW_KEY_EXCH_A) {
		d = (unsigned char *)s->init_buf->data;
		p = &(d[4]);

		alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

		if (alg_k & SSL_kRSA) {
			RSA *rsa;
			unsigned char tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];

			if (s->session->sess_cert->peer_rsa_tmp != NULL)
				rsa = s->session->sess_cert->peer_rsa_tmp;
			else {
				pkey = X509_get_pubkey(
				    s->session->sess_cert->peer_pkeys[
				    SSL_PKEY_RSA_ENC].x509);
				if ((pkey == NULL) ||
				    (pkey->type != EVP_PKEY_RSA) ||
				    (pkey->pkey.rsa == NULL)) {
					SSLerr(
					    SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_INTERNAL_ERROR);
					goto err;
				}
				rsa = pkey->pkey.rsa;
				EVP_PKEY_free(pkey);
			}

			tmp_buf[0] = s->client_version >> 8;
			tmp_buf[1] = s->client_version & 0xff;
			if (RAND_bytes(&(tmp_buf[2]), sizeof tmp_buf - 2) <= 0)
				goto err;

			s->session->master_key_length = sizeof tmp_buf;

			q = p;
			/* Fix buf for TLS and beyond */
			if (s->version > SSL3_VERSION)
				p += 2;
			n = RSA_public_encrypt(sizeof tmp_buf,
			tmp_buf, p, rsa, RSA_PKCS1_PADDING);
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

			s->session->master_key_length =
			    s->method->ssl3_enc->generate_master_secret(
			    s, s->session->master_key, tmp_buf, sizeof tmp_buf);
			OPENSSL_cleanse(tmp_buf, sizeof tmp_buf);
		} else if (alg_k & (SSL_kEDH|SSL_kDHr|SSL_kDHd)) {
			DH *dh_srvr, *dh_clnt;

			if (s->session->sess_cert == NULL) {
				ssl3_send_alert(s, SSL3_AL_FATAL,
				    SSL_AD_UNEXPECTED_MESSAGE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    SSL_R_UNEXPECTED_MESSAGE);
				goto err;
			}

			if (s->session->sess_cert->peer_dh_tmp != NULL)
				dh_srvr = s->session->sess_cert->peer_dh_tmp;
			else {
				/* We get them from the cert. */
				ssl3_send_alert(s, SSL3_AL_FATAL,
				    SSL_AD_HANDSHAKE_FAILURE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    SSL_R_UNABLE_TO_FIND_DH_PARAMETERS);
				goto err;
			}

			/* Generate a new random key. */
			if ((dh_clnt = DHparams_dup(dh_srvr)) == NULL) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_DH_LIB);
				goto err;
			}
			if (!DH_generate_key(dh_clnt)) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_DH_LIB);
				DH_free(dh_clnt);
				goto err;
			}

			/*
			 * Use the 'p' output buffer for the DH key, but
			 * make sure to clear it out afterwards.
			 */
			n = DH_compute_key(p, dh_srvr->pub_key, dh_clnt);

			if (n <= 0) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_DH_LIB);
				DH_free(dh_clnt);
				goto err;
			}

			/* Generate master key from the result. */
			s->session->master_key_length =
			s->method->ssl3_enc->generate_master_secret(s,
			s->session->master_key, p, n);
			/* Clean up. */
			memset(p, 0, n);

			/* Send off the data. */
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

			if (s->session->sess_cert == NULL) {
				ssl3_send_alert(s, SSL3_AL_FATAL,
				    SSL_AD_UNEXPECTED_MESSAGE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    SSL_R_UNEXPECTED_MESSAGE);
				goto err;
			}

			/*
			 * Did we send out the client's ECDH share for use
			 * in premaster computation as part of client
			 * certificate? If so, set ecdh_clnt_cert to 1.
			 */
			if ((alg_k & (SSL_kECDHr|SSL_kECDHe)) &&
			    (s->cert != NULL)) {
				/*
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

			if (s->session->sess_cert->peer_ecdh_tmp != NULL) {
				tkey = s->session->sess_cert->peer_ecdh_tmp;
			} else {
				/* Get the Server Public Key from Cert */
				srvr_pub_pkey = X509_get_pubkey(s->session-> \
				    sess_cert->peer_pkeys[SSL_PKEY_ECC].x509);
				if ((srvr_pub_pkey == NULL) ||
				    (srvr_pub_pkey->type != EVP_PKEY_EC) ||
				    (srvr_pub_pkey->pkey.ec == NULL)) {
					SSLerr(
					    SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
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
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_EC_LIB);
				goto err;
			}
			if (ecdh_clnt_cert) {
				/*
				 * Reuse key info from our certificate
				 * We only need our private key to perform
				 * the ECDH computation.
				 */
				const BIGNUM *priv_key;
				tkey = s->cert->key->privatekey->pkey.ec;
				priv_key = EC_KEY_get0_private_key(tkey);
				if (priv_key == NULL) {
					SSLerr(
					    SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_MALLOC_FAILURE);
					goto err;
				}
				if (!EC_KEY_set_private_key(clnt_ecdh,
				    priv_key)) {
					SSLerr(
					    SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_EC_LIB);
					goto err;
				}
			} else {
				/* Generate a new ECDH key pair */
				if (!(EC_KEY_generate_key(clnt_ecdh))) {
					SSLerr(
					    SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_ECDH_LIB);
					goto err;
				}
			}

			/*
			 * Use the 'p' output buffer for the ECDH key, but
			 * make sure to clear it out afterwards.
			 */
			field_size = EC_GROUP_get_degree(srvr_group);
			if (field_size <= 0) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_ECDH_LIB);
				goto err;
			}
			n = ECDH_compute_key(p, (field_size + 7)/8,
			    srvr_ecpoint, clnt_ecdh, NULL);
			if (n <= 0) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_ECDH_LIB);
				goto err;
			}

			/* generate master key from the result */
			s->session->master_key_length = s->method->ssl3_enc \
			    -> generate_master_secret(s,
			    s->session->master_key, p, n);

			memset(p, 0, n); /* clean up */

			if (ecdh_clnt_cert) {
				/* Send empty client key exch message. */
				n = 0;
			} else {
				/*
				 * First check the size of encoding and
				 * allocate memory accordingly.
				 */
				encoded_pt_len = EC_POINT_point2oct(
				    srvr_group,
				    EC_KEY_get0_public_key(clnt_ecdh),
				    POINT_CONVERSION_UNCOMPRESSED,
				    NULL, 0, NULL);

				encodedPoint = malloc(encoded_pt_len);

				bn_ctx = BN_CTX_new();
				if ((encodedPoint == NULL) ||
				    (bn_ctx == NULL)) {
					SSLerr(
					    SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
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
		} else if (alg_k & SSL_kGOST) {
			/* GOST key exchange message creation */
			EVP_PKEY_CTX *pkey_ctx;
			X509 *peer_cert;

			size_t msglen;
			unsigned int md_len;
			int keytype;
			unsigned char premaster_secret[32], shared_ukm[32],
			    tmp[256];
			EVP_MD_CTX *ukm_hash;
			EVP_PKEY *pub_key;

			/* Get server sertificate PKEY and create ctx from it */
			peer_cert = s->session->sess_cert->peer_pkeys[(
			    keytype = SSL_PKEY_GOST01)].x509;
			if (!peer_cert)
				peer_cert = s->session->sess_cert->peer_pkeys[
				    (keytype = SSL_PKEY_GOST94)].x509;
			if (!peer_cert) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER);
				goto err;
			}

			pkey_ctx = EVP_PKEY_CTX_new(
			    pub_key = X509_get_pubkey(peer_cert),
			    NULL);
			/*
			 * If we have send a certificate, and certificate key
			 * parameters match those of server certificate, use
			 * certificate key for key exchange.
			 * Otherwise, generate ephemeral key pair.
			 */

			EVP_PKEY_encrypt_init(pkey_ctx);
			/* Generate session key. */
			RAND_bytes(premaster_secret, 32);
			/*
			 * If we have client certificate, use its secret
			 * as peer key.
			 */
			if (s->s3->tmp.cert_req && s->cert->key->privatekey) {
				if (EVP_PKEY_derive_set_peer(pkey_ctx,
				    s->cert->key->privatekey) <=0) {
					/*
					 * If there was an error -
					 * just ignore it. Ephemeral key
					 * would be used
					 */
					ERR_clear_error();
				}
			}
			/*
			 * Compute shared IV and store it in algorithm-specific
			 * context data
			 */
			ukm_hash = EVP_MD_CTX_create();
			if (ukm_hash == NULL) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_MALLOC_FAILURE);
				goto err;
			}
			EVP_DigestInit(ukm_hash,
			    EVP_get_digestbynid(NID_id_GostR3411_94));
			EVP_DigestUpdate(ukm_hash,
			    s->s3->client_random, SSL3_RANDOM_SIZE);
			EVP_DigestUpdate(ukm_hash,
			    s->s3->server_random, SSL3_RANDOM_SIZE);
			EVP_DigestFinal_ex(ukm_hash, shared_ukm, &md_len);
			EVP_MD_CTX_destroy(ukm_hash);
			if (EVP_PKEY_CTX_ctrl(pkey_ctx, -1, EVP_PKEY_OP_ENCRYPT,
			    EVP_PKEY_CTRL_SET_IV, 8, shared_ukm) < 0) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    SSL_R_LIBRARY_BUG);
				goto err;
			}
			/*
			 * Make GOST keytransport blob message,
			 * encapsulate it into sequence.
			 */
			*(p++) = V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED;
			msglen = 255;
			if (EVP_PKEY_encrypt(pkey_ctx, tmp, &msglen,
			    premaster_secret, 32) < 0) {
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
			/* Check if pubkey from client certificate was used. */
			if (EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1,
			    EVP_PKEY_CTRL_PEER_KEY, 2, NULL) > 0) {
				/* Set flag "skip certificate verify". */
				s->s3->flags |= TLS1_FLAGS_SKIP_CERT_VERIFY;
			}
			EVP_PKEY_CTX_free(pkey_ctx);
			s->session->master_key_length =
			    s->method->ssl3_enc->generate_master_secret(s,
			    s->session->master_key, premaster_secret, 32);
			EVP_PKEY_free(pub_key);

		}
		else {
			ssl3_send_alert(s, SSL3_AL_FATAL,
			SSL_AD_HANDSHAKE_FAILURE);
			SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
			ERR_R_INTERNAL_ERROR);
			goto err;
		}

		*(d++) = SSL3_MT_CLIENT_KEY_EXCHANGE;
		l2n3(n, d);

		s->state = SSL3_ST_CW_KEY_EXCH_B;
		/* number of bytes to write */
		s->init_num = n + 4;
		s->init_off = 0;
	}

	/* SSL3_ST_CW_KEY_EXCH_B */
	return (ssl3_do_write(s, SSL3_RT_HANDSHAKE));

err:
	BN_CTX_free(bn_ctx);
	free(encodedPoint);
	EC_KEY_free(clnt_ecdh);
	EVP_PKEY_free(srvr_pub_pkey);
	return (-1);
}

int
ssl3_send_client_verify(SSL *s)
{
	unsigned char	*p, *d;
	unsigned char	 data[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
	EVP_PKEY	*pkey;
	EVP_PKEY_CTX	*pctx = NULL;
	EVP_MD_CTX	 mctx;
	unsigned	 u = 0;
	unsigned long	 n;
	int		 j;

	EVP_MD_CTX_init(&mctx);

	if (s->state == SSL3_ST_CW_CERT_VRFY_A) {
		d = (unsigned char *)s->init_buf->data;
		p = &(d[4]);
		pkey = s->cert->key->privatekey;
		/*
		 * Create context from key and test if sha1 is allowed as
		 * digest.
		 */
		pctx = EVP_PKEY_CTX_new(pkey, NULL);
		EVP_PKEY_sign_init(pctx);
		if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha1()) > 0) {
			if (!SSL_USE_SIGALGS(s))
				s->method->ssl3_enc->cert_verify_mac(s,
				    NID_sha1, &(data[MD5_DIGEST_LENGTH]));
		} else {
			ERR_clear_error();
		}
		/*
		 * For TLS v1.2 send signature algorithm and signature
		 * using agreed digest and cached handshake records.
		 */
		if (SSL_USE_SIGALGS(s)) {
			long hdatalen = 0;
			void *hdata;
			const EVP_MD *md = s->cert->key->digest;
			hdatalen = BIO_get_mem_data(s->s3->handshake_buffer,
			    &hdata);
			if (hdatalen <= 0 ||
			    !tls12_get_sigandhash(p, pkey, md)) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,
				    ERR_R_INTERNAL_ERROR);
				goto err;
			}
			p += 2;
			if (!EVP_SignInit_ex(&mctx, md, NULL) ||
			    !EVP_SignUpdate(&mctx, hdata, hdatalen) ||
			    !EVP_SignFinal(&mctx, p + 2, &u, pkey)) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,
				    ERR_R_EVP_LIB);
				goto err;
			}
			s2n(u, p);
			n = u + 4;
			if (!ssl3_digest_cached_records(s))
				goto err;
		} else if (pkey->type == EVP_PKEY_RSA) {
			s->method->ssl3_enc->cert_verify_mac(
			    s, NID_md5, &(data[0]));
			if (RSA_sign(NID_md5_sha1, data,
			    MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, &(p[2]),
			    &u, pkey->pkey.rsa) <= 0 ) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,
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
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,
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
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,
				    ERR_R_ECDSA_LIB);
				goto err;
			}
			s2n(j, p);
			n = j + 2;
		} else if (pkey->type == NID_id_GostR3410_94 ||
		    pkey->type == NID_id_GostR3410_2001) {
			unsigned char signbuf[64];
			int i;
			size_t sigsize = 64;
			s->method->ssl3_enc->cert_verify_mac(s,
			    NID_id_GostR3411_94, data);
			if (EVP_PKEY_sign(pctx, signbuf, &sigsize, data, 32)
			    <= 0) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,
				    ERR_R_INTERNAL_ERROR);
				goto err;
			}
			for (i = 63, j = 0; i >= 0; j++, i--) {
				p[2 + j] = signbuf[i];
			}
			s2n(j, p);
			n = j + 2;
		} else {
			SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}
		*(d++) = SSL3_MT_CERTIFICATE_VERIFY;
		l2n3(n, d);

		s->state = SSL3_ST_CW_CERT_VRFY_B;
		s->init_num = (int)n + 4;
		s->init_off = 0;
	}
	EVP_MD_CTX_cleanup(&mctx);
	EVP_PKEY_CTX_free(pctx);
	return (ssl3_do_write(s, SSL3_RT_HANDSHAKE));
err:
	EVP_MD_CTX_cleanup(&mctx);
	EVP_PKEY_CTX_free(pctx);
	return (-1);
}

int
ssl3_send_client_certificate(SSL *s)
{
	X509		*x509 = NULL;
	EVP_PKEY	*pkey = NULL;
	int		 i;
	unsigned long	 l;

	if (s->state ==	SSL3_ST_CW_CERT_A) {
		if ((s->cert == NULL) || (s->cert->key->x509 == NULL) ||
		    (s->cert->key->privatekey == NULL))
			s->state = SSL3_ST_CW_CERT_B;
		else
			s->state = SSL3_ST_CW_CERT_C;
	}

	/* We need to get a client cert */
	if (s->state == SSL3_ST_CW_CERT_B) {
		/*
		 * If we get an error, we need to
		 * ssl->rwstate=SSL_X509_LOOKUP; return(-1);
		 * We then get retied later
		 */
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
			SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE,
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
		l = ssl3_output_cert_chain(s,
		    (s->s3->tmp.cert_req == 2) ? NULL : s->cert->key->x509);
		s->init_num = (int)l;
		s->init_off = 0;
	}
	/* SSL3_ST_CW_CERT_D */
	return (ssl3_do_write(s, SSL3_RT_HANDSHAKE));
}

#define has_bits(i,m)	(((i)&(m)) == (m))

int
ssl3_check_cert_and_algorithm(SSL *s)
{
	int		 i, idx;
	long		 alg_k, alg_a;
	EVP_PKEY	*pkey = NULL;
	SESS_CERT	*sc;
	RSA		*rsa;
	DH		*dh;

	alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	alg_a = s->s3->tmp.new_cipher->algorithm_auth;

	/* We don't have a certificate. */
	if ((alg_a & (SSL_aDH|SSL_aNULL|SSL_aKRB5)) || (alg_k & SSL_kPSK))
		return (1);

	sc = s->session->sess_cert;
	if (sc == NULL) {
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
		    ERR_R_INTERNAL_ERROR);
		goto err;
	}

	rsa = s->session->sess_cert->peer_rsa_tmp;
	dh = s->session->sess_cert->peer_dh_tmp;

	/* This is the passed certificate. */

	idx = sc->peer_cert_type;
	if (idx == SSL_PKEY_ECC) {
		if (ssl_check_srvr_ecc_cert_and_alg(sc->peer_pkeys[idx].x509,
		    s) == 0) {
			/* check failed */
			SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
			    SSL_R_BAD_ECC_CERT);
			goto f_err;
		} else {
			return (1);
		}
	}
	pkey = X509_get_pubkey(sc->peer_pkeys[idx].x509);
	i = X509_certificate_type(sc->peer_pkeys[idx].x509, pkey);
	EVP_PKEY_free(pkey);

	/* Check that we have a certificate if we require one */
	if ((alg_a & SSL_aRSA) && !has_bits(i, EVP_PK_RSA|EVP_PKT_SIGN)) {
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
		    SSL_R_MISSING_RSA_SIGNING_CERT);
		goto f_err;
	} else if ((alg_a & SSL_aDSS) &&
	    !has_bits(i, EVP_PK_DSA|EVP_PKT_SIGN)) {
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
		    SSL_R_MISSING_DSA_SIGNING_CERT);
		goto f_err;
	}
	if ((alg_k & SSL_kRSA) &&
	    !(has_bits(i, EVP_PK_RSA|EVP_PKT_ENC) || (rsa != NULL))) {
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
		    SSL_R_MISSING_RSA_ENCRYPTING_CERT);
		goto f_err;
	}
	if ((alg_k & SSL_kEDH) &&
	    !(has_bits(i, EVP_PK_DH|EVP_PKT_EXCH) || (dh != NULL))) {
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
		    SSL_R_MISSING_DH_KEY);
		goto f_err;
	} else if ((alg_k & SSL_kDHr) && !has_bits(i, EVP_PK_DH|EVP_PKS_RSA)) {
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
		    SSL_R_MISSING_DH_RSA_CERT);
		goto f_err;
	} else if ((alg_k & SSL_kDHd) && !has_bits(i, EVP_PK_DH|EVP_PKS_DSA)) {
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
		    SSL_R_MISSING_DH_DSA_CERT);
		goto f_err;
	}

	return (1);
f_err:
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
err:
	return (0);
}

#ifndef OPENSSL_NO_NEXTPROTONEG
int
ssl3_send_next_proto(SSL *s)
{
	unsigned int	 len, padding_len;
	unsigned char	*d;

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

	return (ssl3_do_write(s, SSL3_RT_HANDSHAKE));
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

/*
 * Check to see if handshake is full or resumed. Usually this is just a
 * case of checking to see if a cache hit has occurred. In the case of
 * session tickets we have to check the next message to be sure.
 */

int
ssl3_check_finished(SSL *s)
{
	int	ok;
	long	n;

	/* If we have no ticket it cannot be a resumed session. */
	if (!s->session->tlsext_tick)
		return (1);
	/* this function is called when we really expect a Certificate
	 * message, so permit appropriate message length */
	n = s->method->ssl_get_message(s, SSL3_ST_CR_CERT_A,
	    SSL3_ST_CR_CERT_B, -1, s->max_cert_list, &ok);
	if (!ok)
		return ((int)n);
	s->s3->tmp.reuse_message = 1;
	if ((s->s3->tmp.message_type == SSL3_MT_FINISHED) ||
	    (s->s3->tmp.message_type == SSL3_MT_NEWSESSION_TICKET))
		return (2);

	return (1);
}

int
ssl_do_client_cert_cb(SSL *s, X509 **px509, EVP_PKEY **ppkey)
{
	int	i = 0;

#ifndef OPENSSL_NO_ENGINE
	if (s->ctx->client_cert_engine) {
		i = ENGINE_load_ssl_client_cert(s->ctx->client_cert_engine, s,
		SSL_get_client_CA_list(s),
		px509, ppkey, NULL, NULL, NULL);
		if (i != 0)
			return (i);
	}
#endif
	if (s->ctx->client_cert_cb)
		i = s->ctx->client_cert_cb(s, px509, ppkey);
	return (i);
}
