/* ssl/s3_srvr.c */
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

#define REUSE_CIPHER_BUG
#define NETSCAPE_HANG_BUG


#include <stdio.h>
#include "ssl_locl.h"
#include "kssl_lcl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/krb5_asn.h>
#include <openssl/md5.h>
#include "cryptlib.h"

static SSL_METHOD *ssl3_get_server_method(int ver);
static int ssl3_get_client_hello(SSL *s);
static int ssl3_check_client_hello(SSL *s);
static int ssl3_send_server_hello(SSL *s);
static int ssl3_send_server_key_exchange(SSL *s);
static int ssl3_send_certificate_request(SSL *s);
static int ssl3_send_server_done(SSL *s);
static int ssl3_get_client_key_exchange(SSL *s);
static int ssl3_get_client_certificate(SSL *s);
static int ssl3_get_cert_verify(SSL *s);
static int ssl3_send_hello_request(SSL *s);

static SSL_METHOD *ssl3_get_server_method(int ver)
	{
	if (ver == SSL3_VERSION)
		return(SSLv3_server_method());
	else
		return(NULL);
	}

SSL_METHOD *SSLv3_server_method(void)
	{
	static int init=1;
	static SSL_METHOD SSLv3_server_data;

	if (init)
		{
		memcpy((char *)&SSLv3_server_data,(char *)sslv3_base_method(),
			sizeof(SSL_METHOD));
		SSLv3_server_data.ssl_accept=ssl3_accept;
		SSLv3_server_data.get_ssl_method=ssl3_get_server_method;
		init=0;
		}
	return(&SSLv3_server_data);
	}

int ssl3_accept(SSL *s)
	{
	BUF_MEM *buf;
	unsigned long l,Time=time(NULL);
	void (*cb)(const SSL *ssl,int type,int val)=NULL;
	long num1;
	int ret= -1;
	int new_state,state,skip=0;

	RAND_add(&Time,sizeof(Time),0);
	ERR_clear_error();
	clear_sys_error();

	if (s->info_callback != NULL)
		cb=s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb=s->ctx->info_callback;

	/* init things to blank */
	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s);

	if (s->cert == NULL)
		{
		SSLerr(SSL_F_SSL3_ACCEPT,SSL_R_NO_CERTIFICATE_SET);
		return(-1);
		}

	for (;;)
		{
		state=s->state;

		switch (s->state)
			{
		case SSL_ST_RENEGOTIATE:
			s->new_session=1;
			/* s->state=SSL_ST_ACCEPT; */

		case SSL_ST_BEFORE:
		case SSL_ST_ACCEPT:
		case SSL_ST_BEFORE|SSL_ST_ACCEPT:
		case SSL_ST_OK|SSL_ST_ACCEPT:

			s->server=1;
			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

			if ((s->version>>8) != 3)
				{
				SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
				return -1;
				}
			s->type=SSL_ST_ACCEPT;

			if (s->init_buf == NULL)
				{
				if ((buf=BUF_MEM_new()) == NULL)
					{
					ret= -1;
					goto end;
					}
				if (!BUF_MEM_grow(buf,SSL3_RT_MAX_PLAIN_LENGTH))
					{
					ret= -1;
					goto end;
					}
				s->init_buf=buf;
				}

			if (!ssl3_setup_buffers(s))
				{
				ret= -1;
				goto end;
				}

			s->init_num=0;

			if (s->state != SSL_ST_RENEGOTIATE)
				{
				/* Ok, we now need to push on a buffering BIO so that
				 * the output is sent in a way that TCP likes :-)
				 */
				if (!ssl_init_wbio_buffer(s,1)) { ret= -1; goto end; }
				
				ssl3_init_finished_mac(s);
				s->state=SSL3_ST_SR_CLNT_HELLO_A;
				s->ctx->stats.sess_accept++;
				}
			else
				{
				/* s->state == SSL_ST_RENEGOTIATE,
				 * we will just send a HelloRequest */
				s->ctx->stats.sess_accept_renegotiate++;
				s->state=SSL3_ST_SW_HELLO_REQ_A;
				}
			break;

		case SSL3_ST_SW_HELLO_REQ_A:
		case SSL3_ST_SW_HELLO_REQ_B:

			s->shutdown=0;
			ret=ssl3_send_hello_request(s);
			if (ret <= 0) goto end;
			s->s3->tmp.next_state=SSL3_ST_SW_HELLO_REQ_C;
			s->state=SSL3_ST_SW_FLUSH;
			s->init_num=0;

			ssl3_init_finished_mac(s);
			break;

		case SSL3_ST_SW_HELLO_REQ_C:
			s->state=SSL_ST_OK;
			break;

		case SSL3_ST_SR_CLNT_HELLO_A:
		case SSL3_ST_SR_CLNT_HELLO_B:
		case SSL3_ST_SR_CLNT_HELLO_C:

			s->shutdown=0;
			ret=ssl3_get_client_hello(s);
			if (ret <= 0) goto end;
			s->new_session = 2;
			s->state=SSL3_ST_SW_SRVR_HELLO_A;
			s->init_num=0;
			break;

		case SSL3_ST_SW_SRVR_HELLO_A:
		case SSL3_ST_SW_SRVR_HELLO_B:
			ret=ssl3_send_server_hello(s);
			if (ret <= 0) goto end;

			if (s->hit)
				s->state=SSL3_ST_SW_CHANGE_A;
			else
				s->state=SSL3_ST_SW_CERT_A;
			s->init_num=0;
			break;

		case SSL3_ST_SW_CERT_A:
		case SSL3_ST_SW_CERT_B:
			/* Check if it is anon DH */
			if (!(s->s3->tmp.new_cipher->algorithms & SSL_aNULL))
				{
				ret=ssl3_send_server_certificate(s);
				if (ret <= 0) goto end;
				}
			else
				skip=1;
			s->state=SSL3_ST_SW_KEY_EXCH_A;
			s->init_num=0;
			break;

		case SSL3_ST_SW_KEY_EXCH_A:
		case SSL3_ST_SW_KEY_EXCH_B:
			l=s->s3->tmp.new_cipher->algorithms;

			/* clear this, it may get reset by
			 * send_server_key_exchange */
			if ((s->options & SSL_OP_EPHEMERAL_RSA)
#ifndef OPENSSL_NO_KRB5
				&& !(l & SSL_KRB5)
#endif /* OPENSSL_NO_KRB5 */
				)
				/* option SSL_OP_EPHEMERAL_RSA sends temporary RSA key
				 * even when forbidden by protocol specs
				 * (handshake may fail as clients are not required to
				 * be able to handle this) */
				s->s3->tmp.use_rsa_tmp=1;
			else
				s->s3->tmp.use_rsa_tmp=0;

			/* only send if a DH key exchange, fortezza or
			 * RSA but we have a sign only certificate */
			if (s->s3->tmp.use_rsa_tmp
			    || (l & (SSL_DH|SSL_kFZA))
			    || ((l & SSL_kRSA)
				&& (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL
				    || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)
					&& EVP_PKEY_size(s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey)*8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)
					)
				    )
				)
			    )
				{
				ret=ssl3_send_server_key_exchange(s);
				if (ret <= 0) goto end;
				}
			else
				skip=1;

			s->state=SSL3_ST_SW_CERT_REQ_A;
			s->init_num=0;
			break;

		case SSL3_ST_SW_CERT_REQ_A:
		case SSL3_ST_SW_CERT_REQ_B:
			if (/* don't request cert unless asked for it: */
				!(s->verify_mode & SSL_VERIFY_PEER) ||
				/* if SSL_VERIFY_CLIENT_ONCE is set,
				 * don't request cert during re-negotiation: */
				((s->session->peer != NULL) &&
				 (s->verify_mode & SSL_VERIFY_CLIENT_ONCE)) ||
				/* never request cert in anonymous ciphersuites
				 * (see section "Certificate request" in SSL 3 drafts
				 * and in RFC 2246): */
				((s->s3->tmp.new_cipher->algorithms & SSL_aNULL) &&
				 /* ... except when the application insists on verification
				  * (against the specs, but s3_clnt.c accepts this for SSL 3) */
				 !(s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) ||
                                 /* never request cert in Kerberos ciphersuites */
                                (s->s3->tmp.new_cipher->algorithms & SSL_aKRB5))
				{
				/* no cert request */
				skip=1;
				s->s3->tmp.cert_request=0;
				s->state=SSL3_ST_SW_SRVR_DONE_A;
				}
			else
				{
				s->s3->tmp.cert_request=1;
				ret=ssl3_send_certificate_request(s);
				if (ret <= 0) goto end;
#ifndef NETSCAPE_HANG_BUG
				s->state=SSL3_ST_SW_SRVR_DONE_A;
#else
				s->state=SSL3_ST_SW_FLUSH;
				s->s3->tmp.next_state=SSL3_ST_SR_CERT_A;
#endif
				s->init_num=0;
				}
			break;

		case SSL3_ST_SW_SRVR_DONE_A:
		case SSL3_ST_SW_SRVR_DONE_B:
			ret=ssl3_send_server_done(s);
			if (ret <= 0) goto end;
			s->s3->tmp.next_state=SSL3_ST_SR_CERT_A;
			s->state=SSL3_ST_SW_FLUSH;
			s->init_num=0;
			break;
		
		case SSL3_ST_SW_FLUSH:
			/* number of bytes to be flushed */
			num1=BIO_ctrl(s->wbio,BIO_CTRL_INFO,0,NULL);
			if (num1 > 0)
				{
				s->rwstate=SSL_WRITING;
				num1=BIO_flush(s->wbio);
				if (num1 <= 0) { ret= -1; goto end; }
				s->rwstate=SSL_NOTHING;
				}

			s->state=s->s3->tmp.next_state;
			break;

		case SSL3_ST_SR_CERT_A:
		case SSL3_ST_SR_CERT_B:
			/* Check for second client hello (MS SGC) */
			ret = ssl3_check_client_hello(s);
			if (ret <= 0)
				goto end;
			if (ret == 2)
				s->state = SSL3_ST_SR_CLNT_HELLO_C;
			else {
				/* could be sent for a DH cert, even if we
				 * have not asked for it :-) */
				ret=ssl3_get_client_certificate(s);
				if (ret <= 0) goto end;
				s->init_num=0;
				s->state=SSL3_ST_SR_KEY_EXCH_A;
			}
			break;

		case SSL3_ST_SR_KEY_EXCH_A:
		case SSL3_ST_SR_KEY_EXCH_B:
			ret=ssl3_get_client_key_exchange(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_SR_CERT_VRFY_A;
			s->init_num=0;

			/* We need to get hashes here so if there is
			 * a client cert, it can be verified */ 
			s->method->ssl3_enc->cert_verify_mac(s,
				&(s->s3->finish_dgst1),
				&(s->s3->tmp.cert_verify_md[0]));
			s->method->ssl3_enc->cert_verify_mac(s,
				&(s->s3->finish_dgst2),
				&(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]));

			break;

		case SSL3_ST_SR_CERT_VRFY_A:
		case SSL3_ST_SR_CERT_VRFY_B:

			/* we should decide if we expected this one */
			ret=ssl3_get_cert_verify(s);
			if (ret <= 0) goto end;

			s->state=SSL3_ST_SR_FINISHED_A;
			s->init_num=0;
			break;

		case SSL3_ST_SR_FINISHED_A:
		case SSL3_ST_SR_FINISHED_B:
			ret=ssl3_get_finished(s,SSL3_ST_SR_FINISHED_A,
				SSL3_ST_SR_FINISHED_B);
			if (ret <= 0) goto end;
			if (s->hit)
				s->state=SSL_ST_OK;
			else
				s->state=SSL3_ST_SW_CHANGE_A;
			s->init_num=0;
			break;

		case SSL3_ST_SW_CHANGE_A:
		case SSL3_ST_SW_CHANGE_B:

			s->session->cipher=s->s3->tmp.new_cipher;
			if (!s->method->ssl3_enc->setup_key_block(s))
				{ ret= -1; goto end; }

			ret=ssl3_send_change_cipher_spec(s,
				SSL3_ST_SW_CHANGE_A,SSL3_ST_SW_CHANGE_B);

			if (ret <= 0) goto end;
			s->state=SSL3_ST_SW_FINISHED_A;
			s->init_num=0;

			if (!s->method->ssl3_enc->change_cipher_state(s,
				SSL3_CHANGE_CIPHER_SERVER_WRITE))
				{
				ret= -1;
				goto end;
				}

			break;

		case SSL3_ST_SW_FINISHED_A:
		case SSL3_ST_SW_FINISHED_B:
			ret=ssl3_send_finished(s,
				SSL3_ST_SW_FINISHED_A,SSL3_ST_SW_FINISHED_B,
				s->method->ssl3_enc->server_finished_label,
				s->method->ssl3_enc->server_finished_label_len);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_SW_FLUSH;
			if (s->hit)
				s->s3->tmp.next_state=SSL3_ST_SR_FINISHED_A;
			else
				s->s3->tmp.next_state=SSL_ST_OK;
			s->init_num=0;
			break;

		case SSL_ST_OK:
			/* clean a few things up */
			ssl3_cleanup_key_block(s);

			BUF_MEM_free(s->init_buf);
			s->init_buf=NULL;

			/* remove buffering on output */
			ssl_free_wbio_buffer(s);

			s->init_num=0;

			if (s->new_session == 2) /* skipped if we just sent a HelloRequest */
				{
				/* actually not necessarily a 'new' session unless
				 * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set */
				
				s->new_session=0;
				
				ssl_update_cache(s,SSL_SESS_CACHE_SERVER);
				
				s->ctx->stats.sess_accept_good++;
				/* s->server=1; */
				s->handshake_func=ssl3_accept;

				if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_DONE,1);
				}
			
			ret = 1;
			goto end;
			/* break; */

		default:
			SSLerr(SSL_F_SSL3_ACCEPT,SSL_R_UNKNOWN_STATE);
			ret= -1;
			goto end;
			/* break; */
			}
		
		if (!s->s3->tmp.reuse_message && !skip)
			{
			if (s->debug)
				{
				if ((ret=BIO_flush(s->wbio)) <= 0)
					goto end;
				}


			if ((cb != NULL) && (s->state != state))
				{
				new_state=s->state;
				s->state=state;
				cb(s,SSL_CB_ACCEPT_LOOP,1);
				s->state=new_state;
				}
			}
		skip=0;
		}
end:
	/* BIO_flush(s->wbio); */

	s->in_handshake--;
	if (cb != NULL)
		cb(s,SSL_CB_ACCEPT_EXIT,ret);
	return(ret);
	}

static int ssl3_send_hello_request(SSL *s)
	{
	unsigned char *p;

	if (s->state == SSL3_ST_SW_HELLO_REQ_A)
		{
		p=(unsigned char *)s->init_buf->data;
		*(p++)=SSL3_MT_HELLO_REQUEST;
		*(p++)=0;
		*(p++)=0;
		*(p++)=0;

		s->state=SSL3_ST_SW_HELLO_REQ_B;
		/* number of bytes to write */
		s->init_num=4;
		s->init_off=0;
		}

	/* SSL3_ST_SW_HELLO_REQ_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
	}

static int ssl3_check_client_hello(SSL *s)
	{
	int ok;
	long n;

	/* this function is called when we really expect a Certificate message,
	 * so permit appropriate message length */
	n=ssl3_get_message(s,
		SSL3_ST_SR_CERT_A,
		SSL3_ST_SR_CERT_B,
		-1,
		s->max_cert_list,
		&ok);
	if (!ok) return((int)n);
	s->s3->tmp.reuse_message = 1;
	if (s->s3->tmp.message_type == SSL3_MT_CLIENT_HELLO)
		{
		/* Throw away what we have done so far in the current handshake,
		 * which will now be aborted. (A full SSL_clear would be too much.)
		 * I hope that tmp.dh is the only thing that may need to be cleared
		 * when a handshake is not completed ... */
#ifndef OPENSSL_NO_DH
		if (s->s3->tmp.dh != NULL)
			{
			DH_free(s->s3->tmp.dh);
			s->s3->tmp.dh = NULL;
			}
#endif
		return 2;
		}
	return 1;
}

static int ssl3_get_client_hello(SSL *s)
	{
	int i,j,ok,al,ret= -1;
	long n;
	unsigned long id;
	unsigned char *p,*d,*q;
	SSL_CIPHER *c;
	SSL_COMP *comp=NULL;
	STACK_OF(SSL_CIPHER) *ciphers=NULL;

	/* We do this so that we will respond with our native type.
	 * If we are TLSv1 and we get SSLv3, we will respond with TLSv1,
	 * This down switching should be handled by a different method.
	 * If we are SSLv3, we will respond with SSLv3, even if prompted with
	 * TLSv1.
	 */
	if (s->state == SSL3_ST_SR_CLNT_HELLO_A)
		{
		s->first_packet=1;
		s->state=SSL3_ST_SR_CLNT_HELLO_B;
		}
	n=ssl3_get_message(s,
		SSL3_ST_SR_CLNT_HELLO_B,
		SSL3_ST_SR_CLNT_HELLO_C,
		SSL3_MT_CLIENT_HELLO,
		SSL3_RT_MAX_PLAIN_LENGTH,
		&ok);

	if (!ok) return((int)n);
	d=p=(unsigned char *)s->init_msg;

	/* use version from inside client hello, not from record header
	 * (may differ: see RFC 2246, Appendix E, second paragraph) */
	s->client_version=(((int)p[0])<<8)|(int)p[1];
	p+=2;

	if (s->client_version < s->version)
		{
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_WRONG_VERSION_NUMBER);
		if ((s->client_version>>8) == SSL3_VERSION_MAJOR) 
			{
			/* similar to ssl3_get_record, send alert using remote version number */
			s->version = s->client_version;
			}
		al = SSL_AD_PROTOCOL_VERSION;
		goto f_err;
		}

	/* load the client random */
	memcpy(s->s3->client_random,p,SSL3_RANDOM_SIZE);
	p+=SSL3_RANDOM_SIZE;

	/* get the session-id */
	j= *(p++);

	s->hit=0;
	/* Versions before 0.9.7 always allow session reuse during renegotiation
	 * (i.e. when s->new_session is true), option
	 * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is new with 0.9.7.
	 * Maybe this optional behaviour should always have been the default,
	 * but we cannot safely change the default behaviour (or new applications
	 * might be written that become totally unsecure when compiled with
	 * an earlier library version)
	 */
	if (j == 0 || (s->new_session && (s->options & SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION)))
		{
		if (!ssl_get_new_session(s,1))
			goto err;
		}
	else
		{
		i=ssl_get_prev_session(s,p,j);
		if (i == 1)
			{ /* previous session */
			s->hit=1;
			}
		else if (i == -1)
			goto err;
		else /* i == 0 */
			{
			if (!ssl_get_new_session(s,1))
				goto err;
			}
		}

	p+=j;
	n2s(p,i);
	if ((i == 0) && (j != 0))
		{
		/* we need a cipher if we are not resuming a session */
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,SSL_R_NO_CIPHERS_SPECIFIED);
		goto f_err;
		}
	if ((p+i) >= (d+n))
		{
		/* not enough data */
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,SSL_R_LENGTH_MISMATCH);
		goto f_err;
		}
	if ((i > 0) && (ssl_bytes_to_cipher_list(s,p,i,&(ciphers))
		== NULL))
		{
		goto err;
		}
	p+=i;

	/* If it is a hit, check that the cipher is in the list */
	if ((s->hit) && (i > 0))
		{
		j=0;
		id=s->session->cipher->id;

#ifdef CIPHER_DEBUG
		printf("client sent %d ciphers\n",sk_num(ciphers));
#endif
		for (i=0; i<sk_SSL_CIPHER_num(ciphers); i++)
			{
			c=sk_SSL_CIPHER_value(ciphers,i);
#ifdef CIPHER_DEBUG
			printf("client [%2d of %2d]:%s\n",
				i,sk_num(ciphers),SSL_CIPHER_get_name(c));
#endif
			if (c->id == id)
				{
				j=1;
				break;
				}
			}
		if (j == 0)
			{
			if ((s->options & SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG) && (sk_SSL_CIPHER_num(ciphers) == 1))
				{
				/* Very bad for multi-threading.... */
				s->session->cipher=sk_SSL_CIPHER_value(ciphers,
								       0);
				}
			else
				{
				/* we need to have the cipher in the cipher
				 * list if we are asked to reuse it */
				al=SSL_AD_ILLEGAL_PARAMETER;
				SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,SSL_R_REQUIRED_CIPHER_MISSING);
				goto f_err;
				}
			}
		}

	/* compression */
	i= *(p++);
	if ((p+i) > (d+n))
		{
		/* not enough data */
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,SSL_R_LENGTH_MISMATCH);
		goto f_err;
		}
	q=p;
	for (j=0; j<i; j++)
		{
		if (p[j] == 0) break;
		}

	p+=i;
	if (j >= i)
		{
		/* no compress */
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,SSL_R_NO_COMPRESSION_SPECIFIED);
		goto f_err;
		}

	/* Worst case, we will use the NULL compression, but if we have other
	 * options, we will now look for them.  We have i-1 compression
	 * algorithms from the client, starting at q. */
	s->s3->tmp.new_compression=NULL;
	if (s->ctx->comp_methods != NULL)
		{ /* See if we have a match */
		int m,nn,o,v,done=0;

		nn=sk_SSL_COMP_num(s->ctx->comp_methods);
		for (m=0; m<nn; m++)
			{
			comp=sk_SSL_COMP_value(s->ctx->comp_methods,m);
			v=comp->id;
			for (o=0; o<i; o++)
				{
				if (v == q[o])
					{
					done=1;
					break;
					}
				}
			if (done) break;
			}
		if (done)
			s->s3->tmp.new_compression=comp;
		else
			comp=NULL;
		}

	/* TLS does not mind if there is extra stuff */
	if (s->version == SSL3_VERSION)
		{
		if (p < (d+n))
			{
			/* wrong number of bytes,
			 * there could be more to follow */
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,SSL_R_LENGTH_MISMATCH);
			goto f_err;
			}
		}

	/* Given s->session->ciphers and SSL_get_ciphers, we must
	 * pick a cipher */

	if (!s->hit)
		{
		s->session->compress_meth=(comp == NULL)?0:comp->id;
		if (s->session->ciphers != NULL)
			sk_SSL_CIPHER_free(s->session->ciphers);
		s->session->ciphers=ciphers;
		if (ciphers == NULL)
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,SSL_R_NO_CIPHERS_PASSED);
			goto f_err;
			}
		ciphers=NULL;
		c=ssl3_choose_cipher(s,s->session->ciphers,
				     SSL_get_ciphers(s));

		if (c == NULL)
			{
			al=SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,SSL_R_NO_SHARED_CIPHER);
			goto f_err;
			}
		s->s3->tmp.new_cipher=c;
		}
	else
		{
		/* Session-id reuse */
#ifdef REUSE_CIPHER_BUG
		STACK_OF(SSL_CIPHER) *sk;
		SSL_CIPHER *nc=NULL;
		SSL_CIPHER *ec=NULL;

		if (s->options & SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG)
			{
			sk=s->session->ciphers;
			for (i=0; i<sk_SSL_CIPHER_num(sk); i++)
				{
				c=sk_SSL_CIPHER_value(sk,i);
				if (c->algorithms & SSL_eNULL)
					nc=c;
				if (SSL_C_IS_EXPORT(c))
					ec=c;
				}
			if (nc != NULL)
				s->s3->tmp.new_cipher=nc;
			else if (ec != NULL)
				s->s3->tmp.new_cipher=ec;
			else
				s->s3->tmp.new_cipher=s->session->cipher;
			}
		else
#endif
		s->s3->tmp.new_cipher=s->session->cipher;
		}
	
	/* we now have the following setup. 
	 * client_random
	 * cipher_list 		- our prefered list of ciphers
	 * ciphers 		- the clients prefered list of ciphers
	 * compression		- basically ignored right now
	 * ssl version is set	- sslv3
	 * s->session		- The ssl session has been setup.
	 * s->hit		- session reuse flag
	 * s->tmp.new_cipher	- the new cipher to use.
	 */

	ret=1;
	if (0)
		{
f_err:
		ssl3_send_alert(s,SSL3_AL_FATAL,al);
		}
err:
	if (ciphers != NULL) sk_SSL_CIPHER_free(ciphers);
	return(ret);
	}

static int ssl3_send_server_hello(SSL *s)
	{
	unsigned char *buf;
	unsigned char *p,*d;
	int i,sl;
	unsigned long l,Time;

	if (s->state == SSL3_ST_SW_SRVR_HELLO_A)
		{
		buf=(unsigned char *)s->init_buf->data;
		p=s->s3->server_random;
		Time=time(NULL);			/* Time */
		l2n(Time,p);
		RAND_pseudo_bytes(p,SSL3_RANDOM_SIZE-sizeof(Time));
		/* Do the message type and length last */
		d=p= &(buf[4]);

		*(p++)=s->version>>8;
		*(p++)=s->version&0xff;

		/* Random stuff */
		memcpy(p,s->s3->server_random,SSL3_RANDOM_SIZE);
		p+=SSL3_RANDOM_SIZE;

		/* now in theory we have 3 options to sending back the
		 * session id.  If it is a re-use, we send back the
		 * old session-id, if it is a new session, we send
		 * back the new session-id or we send back a 0 length
		 * session-id if we want it to be single use.
		 * Currently I will not implement the '0' length session-id
		 * 12-Jan-98 - I'll now support the '0' length stuff.
		 */
		if (!(s->ctx->session_cache_mode & SSL_SESS_CACHE_SERVER))
			s->session->session_id_length=0;

		sl=s->session->session_id_length;
		if (sl > sizeof s->session->session_id)
			{
			SSLerr(SSL_F_SSL3_SEND_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
			return -1;
			}
		*(p++)=sl;
		memcpy(p,s->session->session_id,sl);
		p+=sl;

		/* put the cipher */
		i=ssl3_put_cipher_by_char(s->s3->tmp.new_cipher,p);
		p+=i;

		/* put the compression method */
		if (s->s3->tmp.new_compression == NULL)
			*(p++)=0;
		else
			*(p++)=s->s3->tmp.new_compression->id;

		/* do the header */
		l=(p-d);
		d=buf;
		*(d++)=SSL3_MT_SERVER_HELLO;
		l2n3(l,d);

		s->state=SSL3_ST_CW_CLNT_HELLO_B;
		/* number of bytes to write */
		s->init_num=p-buf;
		s->init_off=0;
		}

	/* SSL3_ST_CW_CLNT_HELLO_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
	}

static int ssl3_send_server_done(SSL *s)
	{
	unsigned char *p;

	if (s->state == SSL3_ST_SW_SRVR_DONE_A)
		{
		p=(unsigned char *)s->init_buf->data;

		/* do the header */
		*(p++)=SSL3_MT_SERVER_DONE;
		*(p++)=0;
		*(p++)=0;
		*(p++)=0;

		s->state=SSL3_ST_SW_SRVR_DONE_B;
		/* number of bytes to write */
		s->init_num=4;
		s->init_off=0;
		}

	/* SSL3_ST_CW_CLNT_HELLO_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
	}

static int ssl3_send_server_key_exchange(SSL *s)
	{
#ifndef OPENSSL_NO_RSA
	unsigned char *q;
	int j,num;
	RSA *rsa;
	unsigned char md_buf[MD5_DIGEST_LENGTH+SHA_DIGEST_LENGTH];
	unsigned int u;
#endif
#ifndef OPENSSL_NO_DH
	DH *dh=NULL,*dhp;
#endif
	EVP_PKEY *pkey;
	unsigned char *p,*d;
	int al,i;
	unsigned long type;
	int n;
	CERT *cert;
	BIGNUM *r[4];
	int nr[4],kn;
	BUF_MEM *buf;
	EVP_MD_CTX md_ctx;

	EVP_MD_CTX_init(&md_ctx);
	if (s->state == SSL3_ST_SW_KEY_EXCH_A)
		{
		type=s->s3->tmp.new_cipher->algorithms & SSL_MKEY_MASK;
		cert=s->cert;

		buf=s->init_buf;

		r[0]=r[1]=r[2]=r[3]=NULL;
		n=0;
#ifndef OPENSSL_NO_RSA
		if (type & SSL_kRSA)
			{
			rsa=cert->rsa_tmp;
			if ((rsa == NULL) && (s->cert->rsa_tmp_cb != NULL))
				{
				rsa=s->cert->rsa_tmp_cb(s,
				      SSL_C_IS_EXPORT(s->s3->tmp.new_cipher),
				      SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher));
				if(rsa == NULL)
				{
					al=SSL_AD_HANDSHAKE_FAILURE;
					SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,SSL_R_ERROR_GENERATING_TMP_RSA_KEY);
					goto f_err;
				}
				RSA_up_ref(rsa);
				cert->rsa_tmp=rsa;
				}
			if (rsa == NULL)
				{
				al=SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,SSL_R_MISSING_TMP_RSA_KEY);
				goto f_err;
				}
			r[0]=rsa->n;
			r[1]=rsa->e;
			s->s3->tmp.use_rsa_tmp=1;
			}
		else
#endif
#ifndef OPENSSL_NO_DH
			if (type & SSL_kEDH)
			{
			dhp=cert->dh_tmp;
			if ((dhp == NULL) && (s->cert->dh_tmp_cb != NULL))
				dhp=s->cert->dh_tmp_cb(s,
				      SSL_C_IS_EXPORT(s->s3->tmp.new_cipher),
				      SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher));
			if (dhp == NULL)
				{
				al=SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,SSL_R_MISSING_TMP_DH_KEY);
				goto f_err;
				}

			if (s->s3->tmp.dh != NULL)
				{
				DH_free(dh);
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto err;
				}

			if ((dh=DHparams_dup(dhp)) == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,ERR_R_DH_LIB);
				goto err;
				}

			s->s3->tmp.dh=dh;
			if ((dhp->pub_key == NULL ||
			     dhp->priv_key == NULL ||
			     (s->options & SSL_OP_SINGLE_DH_USE)))
				{
				if(!DH_generate_key(dh))
				    {
				    SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
					   ERR_R_DH_LIB);
				    goto err;
				    }
				}
			else
				{
				dh->pub_key=BN_dup(dhp->pub_key);
				dh->priv_key=BN_dup(dhp->priv_key);
				if ((dh->pub_key == NULL) ||
					(dh->priv_key == NULL))
					{
					SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,ERR_R_DH_LIB);
					goto err;
					}
				}
			r[0]=dh->p;
			r[1]=dh->g;
			r[2]=dh->pub_key;
			}
		else 
#endif
			{
			al=SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
			goto f_err;
			}
		for (i=0; r[i] != NULL; i++)
			{
			nr[i]=BN_num_bytes(r[i]);
			n+=2+nr[i];
			}

		if (!(s->s3->tmp.new_cipher->algorithms & SSL_aNULL))
			{
			if ((pkey=ssl_get_sign_pkey(s,s->s3->tmp.new_cipher))
				== NULL)
				{
				al=SSL_AD_DECODE_ERROR;
				goto f_err;
				}
			kn=EVP_PKEY_size(pkey);
			}
		else
			{
			pkey=NULL;
			kn=0;
			}

		if (!BUF_MEM_grow(buf,n+4+kn))
			{
			SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,ERR_LIB_BUF);
			goto err;
			}
		d=(unsigned char *)s->init_buf->data;
		p= &(d[4]);

		for (i=0; r[i] != NULL; i++)
			{
			s2n(nr[i],p);
			BN_bn2bin(r[i],p);
			p+=nr[i];
			}

		/* not anonymous */
		if (pkey != NULL)
			{
			/* n is the length of the params, they start at &(d[4])
			 * and p points to the space at the end. */
#ifndef OPENSSL_NO_RSA
			if (pkey->type == EVP_PKEY_RSA)
				{
				q=md_buf;
				j=0;
				for (num=2; num > 0; num--)
					{
					EVP_DigestInit_ex(&md_ctx,(num == 2)
						?s->ctx->md5:s->ctx->sha1, NULL);
					EVP_DigestUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
					EVP_DigestUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
					EVP_DigestUpdate(&md_ctx,&(d[4]),n);
					EVP_DigestFinal_ex(&md_ctx,q,
						(unsigned int *)&i);
					q+=i;
					j+=i;
					}
				if (RSA_sign(NID_md5_sha1, md_buf, j,
					&(p[2]), &u, pkey->pkey.rsa) <= 0)
					{
					SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,ERR_LIB_RSA);
					goto err;
					}
				s2n(u,p);
				n+=u+2;
				}
			else
#endif
#if !defined(OPENSSL_NO_DSA)
				if (pkey->type == EVP_PKEY_DSA)
				{
				/* lets do DSS */
				EVP_SignInit_ex(&md_ctx,EVP_dss1(), NULL);
				EVP_SignUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
				EVP_SignUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
				EVP_SignUpdate(&md_ctx,&(d[4]),n);
				if (!EVP_SignFinal(&md_ctx,&(p[2]),
					(unsigned int *)&i,pkey))
					{
					SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,ERR_LIB_DSA);
					goto err;
					}
				s2n(i,p);
				n+=i+2;
				}
			else
#endif
				{
				/* Is this error check actually needed? */
				al=SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,SSL_R_UNKNOWN_PKEY_TYPE);
				goto f_err;
				}
			}

		*(d++)=SSL3_MT_SERVER_KEY_EXCHANGE;
		l2n3(n,d);

		/* we should now have things packed up, so lets send
		 * it off */
		s->init_num=n+4;
		s->init_off=0;
		}

	s->state = SSL3_ST_SW_KEY_EXCH_B;
	EVP_MD_CTX_cleanup(&md_ctx);
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	EVP_MD_CTX_cleanup(&md_ctx);
	return(-1);
	}

static int ssl3_send_certificate_request(SSL *s)
	{
	unsigned char *p,*d;
	int i,j,nl,off,n;
	STACK_OF(X509_NAME) *sk=NULL;
	X509_NAME *name;
	BUF_MEM *buf;

	if (s->state == SSL3_ST_SW_CERT_REQ_A)
		{
		buf=s->init_buf;

		d=p=(unsigned char *)&(buf->data[4]);

		/* get the list of acceptable cert types */
		p++;
		n=ssl3_get_req_cert_type(s,p);
		d[0]=n;
		p+=n;
		n++;

		off=n;
		p+=2;
		n+=2;

		sk=SSL_get_client_CA_list(s);
		nl=0;
		if (sk != NULL)
			{
			for (i=0; i<sk_X509_NAME_num(sk); i++)
				{
				name=sk_X509_NAME_value(sk,i);
				j=i2d_X509_NAME(name,NULL);
				if (!BUF_MEM_grow(buf,4+n+j+2))
					{
					SSLerr(SSL_F_SSL3_SEND_CERTIFICATE_REQUEST,ERR_R_BUF_LIB);
					goto err;
					}
				p=(unsigned char *)&(buf->data[4+n]);
				if (!(s->options & SSL_OP_NETSCAPE_CA_DN_BUG))
					{
					s2n(j,p);
					i2d_X509_NAME(name,&p);
					n+=2+j;
					nl+=2+j;
					}
				else
					{
					d=p;
					i2d_X509_NAME(name,&p);
					j-=2; s2n(j,d); j+=2;
					n+=j;
					nl+=j;
					}
				}
			}
		/* else no CA names */
		p=(unsigned char *)&(buf->data[4+off]);
		s2n(nl,p);

		d=(unsigned char *)buf->data;
		*(d++)=SSL3_MT_CERTIFICATE_REQUEST;
		l2n3(n,d);

		/* we should now have things packed up, so lets send
		 * it off */

		s->init_num=n+4;
		s->init_off=0;
#ifdef NETSCAPE_HANG_BUG
		p=(unsigned char *)s->init_buf->data + s->init_num;

		/* do the header */
		*(p++)=SSL3_MT_SERVER_DONE;
		*(p++)=0;
		*(p++)=0;
		*(p++)=0;
		s->init_num += 4;
#endif

		}

	/* SSL3_ST_SW_CERT_REQ_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
err:
	return(-1);
	}

static int ssl3_get_client_key_exchange(SSL *s)
	{
	int i,al,ok;
	long n;
	unsigned long l;
	unsigned char *p;
#ifndef OPENSSL_NO_RSA
	RSA *rsa=NULL;
	EVP_PKEY *pkey=NULL;
#endif
#ifndef OPENSSL_NO_DH
	BIGNUM *pub=NULL;
	DH *dh_srvr;
#endif
#ifndef OPENSSL_NO_KRB5
        KSSL_ERR kssl_err;
#endif /* OPENSSL_NO_KRB5 */

	n=ssl3_get_message(s,
		SSL3_ST_SR_KEY_EXCH_A,
		SSL3_ST_SR_KEY_EXCH_B,
		SSL3_MT_CLIENT_KEY_EXCHANGE,
		2048, /* ??? */
		&ok);

	if (!ok) return((int)n);
	p=(unsigned char *)s->init_msg;

	l=s->s3->tmp.new_cipher->algorithms;

#ifndef OPENSSL_NO_RSA
	if (l & SSL_kRSA)
		{
		/* FIX THIS UP EAY EAY EAY EAY */
		if (s->s3->tmp.use_rsa_tmp)
			{
			if ((s->cert != NULL) && (s->cert->rsa_tmp != NULL))
				rsa=s->cert->rsa_tmp;
			/* Don't do a callback because rsa_tmp should
			 * be sent already */
			if (rsa == NULL)
				{
				al=SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,SSL_R_MISSING_TMP_RSA_PKEY);
				goto f_err;

				}
			}
		else
			{
			pkey=s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey;
			if (	(pkey == NULL) ||
				(pkey->type != EVP_PKEY_RSA) ||
				(pkey->pkey.rsa == NULL))
				{
				al=SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,SSL_R_MISSING_RSA_CERTIFICATE);
				goto f_err;
				}
			rsa=pkey->pkey.rsa;
			}

		/* TLS */
		if (s->version > SSL3_VERSION)
			{
			n2s(p,i);
			if (n != i+2)
				{
				if (!(s->options & SSL_OP_TLS_D5_BUG))
					{
					SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG);
					goto err;
					}
				else
					p-=2;
				}
			else
				n=i;
			}

		i=RSA_private_decrypt((int)n,p,p,rsa,RSA_PKCS1_PADDING);

		al = -1;
		
		if (i != SSL_MAX_MASTER_KEY_LENGTH)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,SSL_R_BAD_RSA_DECRYPT);
			}

		if ((al == -1) && !((p[0] == (s->client_version>>8)) && (p[1] == (s->client_version & 0xff))))
			{
			/* The premaster secret must contain the same version number as the
			 * ClientHello to detect version rollback attacks (strangely, the
			 * protocol does not offer such protection for DH ciphersuites).
			 * However, buggy clients exist that send the negotiated protocol
			 * version instead if the server does not support the requested
			 * protocol version.
			 * If SSL_OP_TLS_ROLLBACK_BUG is set, tolerate such clients. */
			if (!((s->options & SSL_OP_TLS_ROLLBACK_BUG) &&
				(p[0] == (s->version>>8)) && (p[1] == (s->version & 0xff))))
				{
				al=SSL_AD_DECODE_ERROR;
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,SSL_R_BAD_PROTOCOL_VERSION_NUMBER);
				goto f_err;
				}
			}

		if (al != -1)
			{
#if 0
			goto f_err;
#else
			/* Some decryption failure -- use random value instead as countermeasure
			 * against Bleichenbacher's attack on PKCS #1 v1.5 RSA padding
			 * (see RFC 2246, section 7.4.7.1).
			 * But note that due to length and protocol version checking, the
			 * attack is impractical anyway (see section 5 in D. Bleichenbacher:
			 * "Chosen Ciphertext Attacks Against Protocols Based on the RSA
			 * Encryption Standard PKCS #1", CRYPTO '98, LNCS 1462, pp. 1-12).
			 */
			ERR_clear_error();
			i = SSL_MAX_MASTER_KEY_LENGTH;
			p[0] = s->client_version >> 8;
			p[1] = s->client_version & 0xff;
			RAND_pseudo_bytes(p+2, i-2); /* should be RAND_bytes, but we cannot work around a failure */
#endif
			}
	
		s->session->master_key_length=
			s->method->ssl3_enc->generate_master_secret(s,
				s->session->master_key,
				p,i);
		memset(p,0,i);
		}
	else
#endif
#ifndef OPENSSL_NO_DH
		if (l & (SSL_kEDH|SSL_kDHr|SSL_kDHd))
		{
		n2s(p,i);
		if (n != i+2)
			{
			if (!(s->options & SSL_OP_SSLEAY_080_CLIENT_DH_BUG))
				{
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG);
				goto err;
				}
			else
				{
				p-=2;
				i=(int)n;
				}
			}

		if (n == 0L) /* the parameters are in the cert */
			{
			al=SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,SSL_R_UNABLE_TO_DECODE_DH_CERTS);
			goto f_err;
			}
		else
			{
			if (s->s3->tmp.dh == NULL)
				{
				al=SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,SSL_R_MISSING_TMP_DH_KEY);
				goto f_err;
				}
			else
				dh_srvr=s->s3->tmp.dh;
			}

		pub=BN_bin2bn(p,i,NULL);
		if (pub == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,SSL_R_BN_LIB);
			goto err;
			}

		i=DH_compute_key(p,pub,dh_srvr);

		if (i <= 0)
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
			goto err;
			}

		DH_free(s->s3->tmp.dh);
		s->s3->tmp.dh=NULL;

		BN_clear_free(pub);
		pub=NULL;
		s->session->master_key_length=
			s->method->ssl3_enc->generate_master_secret(s,
				s->session->master_key,p,i);
		memset(p,0,i);
		}
	else
#endif
#ifndef OPENSSL_NO_KRB5
        if (l & SSL_kKRB5)
                {
                krb5_error_code		krb5rc;
		krb5_data		enc_ticket;
		krb5_data		authenticator;
		krb5_data		enc_pms;
                KSSL_CTX		*kssl_ctx = s->kssl_ctx;
		EVP_CIPHER_CTX		ciph_ctx;
		EVP_CIPHER		*enc = NULL;
		unsigned char		iv[EVP_MAX_IV_LENGTH];
		unsigned char		pms[SSL_MAX_MASTER_KEY_LENGTH
                                               + EVP_MAX_BLOCK_LENGTH];
		int                     padl, outl;
		krb5_timestamp		authtime = 0;
		krb5_ticket_times	ttimes;

		EVP_CIPHER_CTX_init(&ciph_ctx);

                if (!kssl_ctx)  kssl_ctx = kssl_ctx_new();

		n2s(p,i);
		enc_ticket.length = i;
		enc_ticket.data = (char *)p;
		p+=enc_ticket.length;

		n2s(p,i);
		authenticator.length = i;
		authenticator.data = (char *)p;
		p+=authenticator.length;

		n2s(p,i);
		enc_pms.length = i;
		enc_pms.data = (char *)p;
		p+=enc_pms.length;

		/* Note that the length is checked again below,
		** after decryption
		*/
		if(enc_pms.length > sizeof pms)
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
			       SSL_R_DATA_LENGTH_TOO_LONG);
			goto err;
			}

		if (n != enc_ticket.length + authenticator.length +
						enc_pms.length + 6)
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
				SSL_R_DATA_LENGTH_TOO_LONG);
			goto err;
			}

                if ((krb5rc = kssl_sget_tkt(kssl_ctx, &enc_ticket, &ttimes,
					&kssl_err)) != 0)
                        {
#ifdef KSSL_DEBUG
                        printf("kssl_sget_tkt rtn %d [%d]\n",
                                krb5rc, kssl_err.reason);
                        if (kssl_err.text)
                                printf("kssl_err text= %s\n", kssl_err.text);
#endif	/* KSSL_DEBUG */
                        SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                                kssl_err.reason);
                        goto err;
                        }

		/*  Note: no authenticator is not considered an error,
		**  but will return authtime == 0.
		*/
		if ((krb5rc = kssl_check_authent(kssl_ctx, &authenticator,
					&authtime, &kssl_err)) != 0)
			{
#ifdef KSSL_DEBUG
                        printf("kssl_check_authent rtn %d [%d]\n",
                                krb5rc, kssl_err.reason);
                        if (kssl_err.text)
                                printf("kssl_err text= %s\n", kssl_err.text);
#endif	/* KSSL_DEBUG */
                        SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                                kssl_err.reason);
                        goto err;
			}

		if ((krb5rc = kssl_validate_times(authtime, &ttimes)) != 0)
			{
			SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, krb5rc);
                        goto err;
			}

#ifdef KSSL_DEBUG
                kssl_ctx_show(kssl_ctx);
#endif	/* KSSL_DEBUG */

		enc = kssl_map_enc(kssl_ctx->enctype);
                if (enc == NULL)
                    goto err;

		memset(iv, 0, EVP_MAX_IV_LENGTH);	/* per RFC 1510 */

		if (!EVP_DecryptInit_ex(&ciph_ctx,enc,NULL,kssl_ctx->key,iv))
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
				SSL_R_DECRYPTION_FAILED);
			goto err;
			}
		if (!EVP_DecryptUpdate(&ciph_ctx, pms,&outl,
					(unsigned char *)enc_pms.data, enc_pms.length))
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
				SSL_R_DECRYPTION_FAILED);
			goto err;
			}
		if (outl > SSL_MAX_MASTER_KEY_LENGTH)
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
				SSL_R_DATA_LENGTH_TOO_LONG);
			goto err;
			}
		if (!EVP_DecryptFinal_ex(&ciph_ctx,&(pms[outl]),&padl))
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
				SSL_R_DECRYPTION_FAILED);
			goto err;
			}
		outl += padl;
		if (outl > SSL_MAX_MASTER_KEY_LENGTH)
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
				SSL_R_DATA_LENGTH_TOO_LONG);
			goto err;
			}
		EVP_CIPHER_CTX_cleanup(&ciph_ctx);

                s->session->master_key_length=
                        s->method->ssl3_enc->generate_master_secret(s,
                                s->session->master_key, pms, outl);

                if (kssl_ctx->client_princ)
                        {
                        int len = strlen(kssl_ctx->client_princ);
                        if ( len < SSL_MAX_KRB5_PRINCIPAL_LENGTH ) 
                                {
                                s->session->krb5_client_princ_len = len;
                                memcpy(s->session->krb5_client_princ,kssl_ctx->client_princ,len);
                                }
                        }


                /*  Was doing kssl_ctx_free() here,
		**  but it caused problems for apache.
                **  kssl_ctx = kssl_ctx_free(kssl_ctx);
                **  if (s->kssl_ctx)  s->kssl_ctx = NULL;
                */
                }
	else
#endif	/* OPENSSL_NO_KRB5 */
		{
		al=SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
				SSL_R_UNKNOWN_CIPHER_TYPE);
		goto f_err;
		}

	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_RSA)
err:
#endif
	return(-1);
	}

static int ssl3_get_cert_verify(SSL *s)
	{
	EVP_PKEY *pkey=NULL;
	unsigned char *p;
	int al,ok,ret=0;
	long n;
	int type=0,i,j;
	X509 *peer;

	n=ssl3_get_message(s,
		SSL3_ST_SR_CERT_VRFY_A,
		SSL3_ST_SR_CERT_VRFY_B,
		-1,
		512, /* 512? */
		&ok);

	if (!ok) return((int)n);

	if (s->session->peer != NULL)
		{
		peer=s->session->peer;
		pkey=X509_get_pubkey(peer);
		type=X509_certificate_type(peer,pkey);
		}
	else
		{
		peer=NULL;
		pkey=NULL;
		}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_VERIFY)
		{
		s->s3->tmp.reuse_message=1;
		if ((peer != NULL) && (type | EVP_PKT_SIGN))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_MISSING_VERIFY_MESSAGE);
			goto f_err;
			}
		ret=1;
		goto end;
		}

	if (peer == NULL)
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_NO_CLIENT_CERT_RECEIVED);
		al=SSL_AD_UNEXPECTED_MESSAGE;
		goto f_err;
		}

	if (!(type & EVP_PKT_SIGN))
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE);
		al=SSL_AD_ILLEGAL_PARAMETER;
		goto f_err;
		}

	if (s->s3->change_cipher_spec)
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_CCS_RECEIVED_EARLY);
		al=SSL_AD_UNEXPECTED_MESSAGE;
		goto f_err;
		}

	/* we now have a signature that we need to verify */
	p=(unsigned char *)s->init_msg;
	n2s(p,i);
	n-=2;
	if (i > n)
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_LENGTH_MISMATCH);
		al=SSL_AD_DECODE_ERROR;
		goto f_err;
		}

	j=EVP_PKEY_size(pkey);
	if ((i > j) || (n > j) || (n <= 0))
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_WRONG_SIGNATURE_SIZE);
		al=SSL_AD_DECODE_ERROR;
		goto f_err;
		}

#ifndef OPENSSL_NO_RSA 
	if (pkey->type == EVP_PKEY_RSA)
		{
		i=RSA_verify(NID_md5_sha1, s->s3->tmp.cert_verify_md,
			MD5_DIGEST_LENGTH+SHA_DIGEST_LENGTH, p, i, 
							pkey->pkey.rsa);
		if (i < 0)
			{
			al=SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_BAD_RSA_DECRYPT);
			goto f_err;
			}
		if (i == 0)
			{
			al=SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_BAD_RSA_SIGNATURE);
			goto f_err;
			}
		}
	else
#endif
#ifndef OPENSSL_NO_DSA
		if (pkey->type == EVP_PKEY_DSA)
		{
		j=DSA_verify(pkey->save_type,
			&(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]),
			SHA_DIGEST_LENGTH,p,i,pkey->pkey.dsa);
		if (j <= 0)
			{
			/* bad signature */
			al=SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_BAD_DSA_SIGNATURE);
			goto f_err;
			}
		}
	else
#endif
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,ERR_R_INTERNAL_ERROR);
		al=SSL_AD_UNSUPPORTED_CERTIFICATE;
		goto f_err;
		}


	ret=1;
	if (0)
		{
f_err:
		ssl3_send_alert(s,SSL3_AL_FATAL,al);
		}
end:
	EVP_PKEY_free(pkey);
	return(ret);
	}

static int ssl3_get_client_certificate(SSL *s)
	{
	int i,ok,al,ret= -1;
	X509 *x=NULL;
	unsigned long l,nc,llen,n;
	unsigned char *p,*d,*q;
	STACK_OF(X509) *sk=NULL;

	n=ssl3_get_message(s,
		SSL3_ST_SR_CERT_A,
		SSL3_ST_SR_CERT_B,
		-1,
		s->max_cert_list,
		&ok);

	if (!ok) return((int)n);

	if	(s->s3->tmp.message_type == SSL3_MT_CLIENT_KEY_EXCHANGE)
		{
		if (	(s->verify_mode & SSL_VERIFY_PEER) &&
			(s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
			al=SSL_AD_HANDSHAKE_FAILURE;
			goto f_err;
			}
		/* If tls asked for a client cert, the client must return a 0 list */
		if ((s->version > SSL3_VERSION) && s->s3->tmp.cert_request)
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST);
			al=SSL_AD_UNEXPECTED_MESSAGE;
			goto f_err;
			}
		s->s3->tmp.reuse_message=1;
		return(1);
		}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,SSL_R_WRONG_MESSAGE_TYPE);
		goto f_err;
		}
	d=p=(unsigned char *)s->init_msg;

	if ((sk=sk_X509_new_null()) == NULL)
		{
		SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	n2l3(p,llen);
	if (llen+3 != n)
		{
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,SSL_R_LENGTH_MISMATCH);
		goto f_err;
		}
	for (nc=0; nc<llen; )
		{
		n2l3(p,l);
		if ((l+nc+3) > llen)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
			}

		q=p;
		x=d2i_X509(NULL,&p,l);
		if (x == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,ERR_R_ASN1_LIB);
			goto err;
			}
		if (p != (q+l))
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
			}
		if (!sk_X509_push(sk,x))
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		x=NULL;
		nc+=l+3;
		}

	if (sk_X509_num(sk) <= 0)
		{
		/* TLS does not mind 0 certs returned */
		if (s->version == SSL3_VERSION)
			{
			al=SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,SSL_R_NO_CERTIFICATES_RETURNED);
			goto f_err;
			}
		/* Fail for TLS only if we required a certificate */
		else if ((s->verify_mode & SSL_VERIFY_PEER) &&
			 (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
			al=SSL_AD_HANDSHAKE_FAILURE;
			goto f_err;
			}
		}
	else
		{
		i=ssl_verify_cert_chain(s,sk);
		if (!i)
			{
			al=ssl_verify_alarm_type(s->verify_result);
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,SSL_R_NO_CERTIFICATE_RETURNED);
			goto f_err;
			}
		}

	if (s->session->peer != NULL) /* This should not be needed */
		X509_free(s->session->peer);
	s->session->peer=sk_X509_shift(sk);
	s->session->verify_result = s->verify_result;

	/* With the current implementation, sess_cert will always be NULL
	 * when we arrive here. */
	if (s->session->sess_cert == NULL)
		{
		s->session->sess_cert = ssl_sess_cert_new();
		if (s->session->sess_cert == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
			goto err;
			}
		}
	if (s->session->sess_cert->cert_chain != NULL)
		sk_X509_pop_free(s->session->sess_cert->cert_chain, X509_free);
	s->session->sess_cert->cert_chain=sk;
	/* Inconsistency alert: cert_chain does *not* include the
	 * peer's own certificate, while we do include it in s3_clnt.c */

	sk=NULL;

	ret=1;
	if (0)
		{
f_err:
		ssl3_send_alert(s,SSL3_AL_FATAL,al);
		}
err:
	if (x != NULL) X509_free(x);
	if (sk != NULL) sk_X509_pop_free(sk,X509_free);
	return(ret);
	}

int ssl3_send_server_certificate(SSL *s)
	{
	unsigned long l;
	X509 *x;

	if (s->state == SSL3_ST_SW_CERT_A)
		{
		x=ssl_get_server_send_cert(s);
		if (x == NULL &&
                        /* VRS: allow null cert if auth == KRB5 */
                        (s->s3->tmp.new_cipher->algorithms
                                & (SSL_MKEY_MASK|SSL_AUTH_MASK))
                        != (SSL_aKRB5|SSL_kKRB5))
			{
			SSLerr(SSL_F_SSL3_SEND_SERVER_CERTIFICATE,ERR_R_INTERNAL_ERROR);
			return(0);
			}

		l=ssl3_output_cert_chain(s,x);
		s->state=SSL3_ST_SW_CERT_B;
		s->init_num=(int)l;
		s->init_off=0;
		}

	/* SSL3_ST_SW_CERT_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
	}
