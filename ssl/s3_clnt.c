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

#include <stdio.h>
#include "buffer.h"
#include "rand.h"
#include "objects.h"
#include "evp.h"
#include "ssl_locl.h"

#define BREAK break
/* SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,ERR_R_MALLOC_FAILURE);
 * SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_MALLOC_FAILURE);
 * SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,ERR_R_MALLOC_FAILURE);
 * SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
 * SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,ERR_R_MALLOC_FAILURE);
 * SSLerr(SSL_F_SSL3_GET_SERVER_DONE,ERR_R_MALLOC_FAILURE);
SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_SSL3_SESSION_ID_TOO_SHORT);
 */

#ifndef NOPROTO
static int ssl3_client_hello(SSL *s);
static int ssl3_get_server_hello(SSL *s);
static int ssl3_get_certificate_request(SSL *s);
static int ca_dn_cmp(X509_NAME **a,X509_NAME **b);
static int ssl3_get_server_done(SSL *s);
static int ssl3_send_client_verify(SSL *s);
static int ssl3_send_client_certificate(SSL *s);
static int ssl3_send_client_key_exchange(SSL *s);
static int ssl3_get_key_exchange(SSL *s);
static int ssl3_get_server_certificate(SSL *s);
static int ssl3_check_cert_and_algorithm(SSL *s);
#else
static int ssl3_client_hello();
static int ssl3_get_server_hello();
static int ssl3_get_certificate_request();
static int ca_dn_cmp();
static int ssl3_get_server_done();
static int ssl3_send_client_verify();
static int ssl3_send_client_certificate();
static int ssl3_send_client_key_exchange();
static int ssl3_get_key_exchange();
static int ssl3_get_server_certificate();
static int ssl3_check_cert_and_algorithm();
#endif

static SSL_METHOD *ssl3_get_client_method(ver)
int ver;
	{
	if (ver == SSL3_VERSION)
		return(SSLv3_client_method());
	else
		return(NULL);
	}

SSL_METHOD *SSLv3_client_method()
	{
	static int init=1;
	static SSL_METHOD SSLv3_client_data;

	if (init)
		{
		init=0;
		memcpy((char *)&SSLv3_client_data,(char *)sslv3_base_method(),
			sizeof(SSL_METHOD));
		SSLv3_client_data.ssl_connect=ssl3_connect;
		SSLv3_client_data.get_ssl_method=ssl3_get_client_method;
		}
	return(&SSLv3_client_data);
	}

int ssl3_connect(s)
SSL *s;
	{
	BUF_MEM *buf;
	unsigned long Time=time(NULL),l;
	long num1;
	void (*cb)()=NULL;
	int ret= -1;
	BIO *under;
	int new_state,state,skip=0;;

	RAND_seed((unsigned char *)&Time,sizeof(Time));
	ERR_clear_error();
	clear_sys_error();

	if (s->info_callback != NULL)
		cb=s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb=s->ctx->info_callback;
	
	if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s); 
	s->in_handshake++;

	for (;;)
		{
		state=s->state;

		switch(s->state)
			{
		case SSL_ST_RENEGOTIATE:
			s->new_session=1;
			s->state=SSL_ST_CONNECT;
			s->ctx->sess_connect_renegotiate++;
			/* break */
		case SSL_ST_BEFORE:
		case SSL_ST_CONNECT:
		case SSL_ST_BEFORE|SSL_ST_CONNECT:
		case SSL_ST_OK|SSL_ST_CONNECT:

			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

			if ((s->version & 0xff00 ) != 0x0300)
				abort();
			/* s->version=SSL3_VERSION; */
			s->type=SSL_ST_CONNECT;

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

			if (!ssl3_setup_buffers(s)) { ret= -1; goto end; }

			/* setup buffing BIO */
			if (!ssl_init_wbio_buffer(s,0)) { ret= -1; goto end; }

			/* don't push the buffering BIO quite yet */

			ssl3_init_finished_mac(s);

			s->state=SSL3_ST_CW_CLNT_HELLO_A;
			s->ctx->sess_connect++;
			s->init_num=0;
			break;

		case SSL3_ST_CW_CLNT_HELLO_A:
		case SSL3_ST_CW_CLNT_HELLO_B:

			s->shutdown=0;
			ret=ssl3_client_hello(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CR_SRVR_HELLO_A;
			s->init_num=0;

			/* turn on buffering for the next lot of output */
			if (s->bbio != s->wbio)
				s->wbio=BIO_push(s->bbio,s->wbio);

			break;

		case SSL3_ST_CR_SRVR_HELLO_A:
		case SSL3_ST_CR_SRVR_HELLO_B:
			ret=ssl3_get_server_hello(s);
			if (ret <= 0) goto end;
			if (s->hit)
				s->state=SSL3_ST_CR_FINISHED_A;
			else
				s->state=SSL3_ST_CR_CERT_A;
			s->init_num=0;
			break;

		case SSL3_ST_CR_CERT_A:
		case SSL3_ST_CR_CERT_B:
			/* Check if it is anon DH */
			if (!(s->s3->tmp.new_cipher->algorithms & SSL_aNULL))
				{
				ret=ssl3_get_server_certificate(s);
				if (ret <= 0) goto end;
				}
			else
				skip=1;
			s->state=SSL3_ST_CR_KEY_EXCH_A;
			s->init_num=0;
			break;

		case SSL3_ST_CR_KEY_EXCH_A:
		case SSL3_ST_CR_KEY_EXCH_B:
			ret=ssl3_get_key_exchange(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CR_CERT_REQ_A;
			s->init_num=0;

			/* at this point we check that we have the
			 * required stuff from the server */
			if (!ssl3_check_cert_and_algorithm(s))
				{
				ret= -1;
				goto end;
				}
			break;

		case SSL3_ST_CR_CERT_REQ_A:
		case SSL3_ST_CR_CERT_REQ_B:
			ret=ssl3_get_certificate_request(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CR_SRVR_DONE_A;
			s->init_num=0;
			break;

		case SSL3_ST_CR_SRVR_DONE_A:
		case SSL3_ST_CR_SRVR_DONE_B:
			ret=ssl3_get_server_done(s);
			if (ret <= 0) goto end;
			if (s->s3->tmp.cert_req)
				s->state=SSL3_ST_CW_CERT_A;
			else
				s->state=SSL3_ST_CW_KEY_EXCH_A;
			s->init_num=0;

			break;

		case SSL3_ST_CW_CERT_A:
		case SSL3_ST_CW_CERT_B:
		case SSL3_ST_CW_CERT_C:
			ret=ssl3_send_client_certificate(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CW_KEY_EXCH_A;
			s->init_num=0;
			break;

		case SSL3_ST_CW_KEY_EXCH_A:
		case SSL3_ST_CW_KEY_EXCH_B:
			ret=ssl3_send_client_key_exchange(s);
			if (ret <= 0) goto end;
			l=s->s3->tmp.new_cipher->algorithms;
			/* EAY EAY EAY need to check for DH fix cert
			 * sent back */
			/* For TLS, cert_req is set to 2, so a cert chain
			 * of nothing is sent, but no verify packet is sent */
			if (s->s3->tmp.cert_req == 1)
				{
				s->state=SSL3_ST_CW_CERT_VRFY_A;
				}
			else
				{
				s->state=SSL3_ST_CW_CHANGE_A;
				s->s3->change_cipher_spec=0;
				}

			s->init_num=0;
			break;

		case SSL3_ST_CW_CERT_VRFY_A:
		case SSL3_ST_CW_CERT_VRFY_B:
			ret=ssl3_send_client_verify(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CW_CHANGE_A;
			s->init_num=0;
			s->s3->change_cipher_spec=0;
			break;

		case SSL3_ST_CW_CHANGE_A:
		case SSL3_ST_CW_CHANGE_B:
			ret=ssl3_send_change_cipher_spec(s,
				SSL3_ST_CW_CHANGE_A,SSL3_ST_CW_CHANGE_B);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CW_FINISHED_A;
			s->init_num=0;

			s->session->cipher=s->s3->tmp.new_cipher;
			if (!s->method->ssl3_enc->setup_key_block(s))
				{
				ret= -1;
				goto end;
				}

			if (!s->method->ssl3_enc->change_cipher_state(s,
				SSL3_CHANGE_CIPHER_CLIENT_WRITE))
				{
				ret= -1;
				goto end;
				}

			break;

		case SSL3_ST_CW_FINISHED_A:
		case SSL3_ST_CW_FINISHED_B:
			ret=ssl3_send_finished(s,
				SSL3_ST_CW_FINISHED_A,SSL3_ST_CW_FINISHED_B,
				s->method->ssl3_enc->client_finished,
				s->method->ssl3_enc->client_finished_len);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CW_FLUSH;

			/* clear flags */
			s->s3->flags&= ~SSL3_FLAGS_POP_BUFFER;
			if (s->hit)
				{
				s->s3->tmp.next_state=SSL_ST_OK;
				if (s->s3->flags & SSL3_FLAGS_DELAY_CLIENT_FINISHED)
					{
					s->state=SSL_ST_OK;
					s->s3->flags|=SSL3_FLAGS_POP_BUFFER;
					s->s3->delay_buf_pop_ret=0;
					}
				}
			else
				{
				s->s3->tmp.next_state=SSL3_ST_CR_FINISHED_A;
				}
			s->init_num=0;
			break;

		case SSL3_ST_CR_FINISHED_A:
		case SSL3_ST_CR_FINISHED_B:

			ret=ssl3_get_finished(s,SSL3_ST_CR_FINISHED_A,
				SSL3_ST_CR_FINISHED_B);
			if (ret <= 0) goto end;

			if (s->hit)
				s->state=SSL3_ST_CW_CHANGE_A;
			else
				s->state=SSL_ST_OK;
			s->init_num=0;
			break;

		case SSL3_ST_CW_FLUSH:
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

		case SSL_ST_OK:
			/* clean a few things up */
			ssl3_cleanup_key_block(s);

			BUF_MEM_free(s->init_buf);
			s->init_buf=NULL;

			if (!(s->s3->flags & SSL3_FLAGS_POP_BUFFER))
				{
				/* remove buffering */
				under=BIO_pop(s->wbio);
				if (under != NULL)
					s->wbio=under;
				else
					abort(); /* ok */

				BIO_free(s->bbio);
				s->bbio=NULL;
				}
			/* else do it later */

			s->init_num=0;
			s->new_session=0;

			ssl_update_cache(s,SSL_SESS_CACHE_CLIENT);
			if (s->hit) s->ctx->sess_hit++;

			ret=1;
			/* s->server=0; */
			s->handshake_func=ssl3_connect;
			s->ctx->sess_connect_good++;

			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_DONE,1);

			goto end;
			break;
			
		default:
			SSLerr(SSL_F_SSL3_CONNECT,SSL_R_UNKNOWN_STATE);
			ret= -1;
			goto end;
			/* break; */
			}

		/* did we do anything */
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
				cb(s,SSL_CB_CONNECT_LOOP,1);
				s->state=new_state;
				}
			}
		skip=0;
		}
end:
	if (cb != NULL)
		cb(s,SSL_CB_CONNECT_EXIT,ret);
	s->in_handshake--;
	return(ret);
	}


static int ssl3_client_hello(s)
SSL *s;
	{
	unsigned char *buf;
	unsigned char *p,*d;
	int i;
	unsigned long Time,l;

	buf=(unsigned char *)s->init_buf->data;
	if (s->state == SSL3_ST_CW_CLNT_HELLO_A)
		{
		if ((s->session == NULL) ||
			(s->session->ssl_version != s->version))
			{
			if (!ssl_get_new_session(s,0))
				goto err;
			}
		/* else use the pre-loaded session */

		p=s->s3->client_random;
		Time=time(NULL);			/* Time */
		l2n(Time,p);
		RAND_bytes(&(p[4]),SSL3_RANDOM_SIZE-sizeof(Time));

		/* Do the message type and length last */
		d=p= &(buf[4]);

		*(p++)=s->version>>8;
		*(p++)=s->version&0xff;

		/* Random stuff */
		memcpy(p,s->s3->client_random,SSL3_RANDOM_SIZE);
		p+=SSL3_RANDOM_SIZE;

		/* Session ID */
		if (s->new_session)
			i=0;
		else
			i=s->session->session_id_length;
		*(p++)=i;
		if (i != 0)
			{
			memcpy(p,s->session->session_id,i);
			p+=i;
			}
		
		/* Ciphers supported */
		i=ssl_cipher_list_to_bytes(s,SSL_get_ciphers(s),&(p[2]));
		if (i == 0)
			{
			SSLerr(SSL_F_SSL3_CLIENT_HELLO,SSL_R_NO_CIPHERS_AVAILABLE);
			goto err;
			}
		s2n(i,p);
		p+=i;

		/* hardwire in the NULL compression algorithm. */
		*(p++)=1;
		*(p++)=0;
		
		l=(p-d);
		d=buf;
		*(d++)=SSL3_MT_CLIENT_HELLO;
		l2n3(l,d);

		s->state=SSL3_ST_CW_CLNT_HELLO_B;
		/* number of bytes to write */
		s->init_num=p-buf;
		s->init_off=0;
		}

	/* SSL3_ST_CW_CLNT_HELLO_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
err:
	return(-1);
	}

static int ssl3_get_server_hello(s)
SSL *s;
	{
	STACK *sk;
	SSL_CIPHER *c;
	unsigned char *p,*d;
	int i,al,ok;
	unsigned int j;
	long n;

	n=ssl3_get_message(s,
		SSL3_ST_CR_SRVR_HELLO_A,
		SSL3_ST_CR_SRVR_HELLO_B,
		SSL3_MT_SERVER_HELLO,
		300, /* ?? */
		&ok);

	if (!ok) return((int)n);
	d=p=(unsigned char *)s->init_buf->data;

	if ((p[0] != (s->version>>8)) || (p[1] != (s->version&0xff)))
		{
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_SSL_VERSION);
		s->version=(s->version&0xff00)|p[1];
		al=SSL_AD_PROTOCOL_VERSION;
		goto f_err;
		}
	p+=2;

	/* load the server hello data */
	/* load the server random */
	memcpy(s->s3->server_random,p,SSL3_RANDOM_SIZE);
	p+=SSL3_RANDOM_SIZE;

	/* get the session-id */
	j= *(p++);

	if ((j != 0) && (j != SSL3_SESSION_ID_SIZE))
		{
		/* SSLref returns 16 :-( */
		if (j < SSL2_SSL_SESSION_ID_LENGTH)
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_SSL3_SESSION_ID_TOO_SHORT);
			goto f_err;
			}
		}
	if ((j != 0) && (j == s->session->session_id_length) &&
		(memcmp(p,s->session->session_id,j) == 0))
		s->hit=1;
	else	/* a miss or crap from the other end */
		{
		/* If we were trying for session-id reuse, make a new
		 * SSL_SESSION so we don't stuff up other people */
		s->hit=0;
		if (s->session->session_id_length > 0)
			{
			if (!ssl_get_new_session(s,0))
				{
				al=SSL_AD_INTERNAL_ERROR;
				goto f_err;
				}
			}
		s->session->session_id_length=j;
		memcpy(s->session->session_id,p,j); /* j could be 0 */
		}
	p+=j;
	c=ssl_get_cipher_by_char(s,p);
	if (c == NULL)
		{
		/* unknown cipher */
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_UNKNOWN_CIPHER_RETURNED);
		goto f_err;
		}
	p+=ssl_put_cipher_by_char(s,NULL,NULL);

	sk=ssl_get_ciphers_by_id(s);
	i=sk_find(sk,(char *)c);
	if (i < 0)
		{
		/* we did not say we would use this cipher */
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_CIPHER_RETURNED);
		goto f_err;
		}

	if (s->hit && (s->session->cipher != c))
		{
		if (!(s->options &
			SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG))
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED);
			goto f_err;
			}
		}
	s->s3->tmp.new_cipher=c;

	/* lets get the compression algorithm */
	j= *(p++);
	if (j != 0)
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
		goto f_err;
		}

	if (p != (d+n))
		{
		/* wrong packet length */
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_BAD_PACKET_LENGTH);
		goto err;
		}

	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	return(-1);
	}

static int ssl3_get_server_certificate(s)
SSL *s;
	{
	int al,i,ok,ret= -1;
	unsigned long n,nc,llen,l;
	X509 *x=NULL;
	unsigned char *p,*d,*q;
	STACK *sk=NULL;
	CERT *c;
	EVP_PKEY *pkey=NULL;

	n=ssl3_get_message(s,
		SSL3_ST_CR_CERT_A,
		SSL3_ST_CR_CERT_B,
		-1,
#if defined(MSDOS) && !defined(WIN32)
		1024*30, /* 30k max cert list :-) */
#else
		1024*100, /* 100k max cert list :-) */
#endif
		&ok);

	if (!ok) return((int)n);

	if (s->s3->tmp.message_type == SSL3_MT_SERVER_KEY_EXCHANGE)
		{
		s->s3->tmp.reuse_message=1;
		return(1);
		}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_BAD_MESSAGE_TYPE);
		goto f_err;
		}
	d=p=(unsigned char *)s->init_buf->data;

	if ((sk=sk_new_null()) == NULL)
		{
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	n2l3(p,llen);
	if (llen+3 != n)
		{
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_LENGTH_MISMATCH);
		goto f_err;
		}
	for (nc=0; nc<llen; )
		{
		n2l3(p,l);
		if ((l+nc+3) > llen)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
			}

		q=p;
		x=d2i_X509(NULL,&q,l);
		if (x == NULL)
			{
			al=SSL_AD_BAD_CERTIFICATE;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_ASN1_LIB);
			goto f_err;
			}
		if (q != (p+l))
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
			}
		if (!sk_push(sk,(char *)x))
			{
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		x=NULL;
		nc+=l+3;
		p=q;
		}

	i=ssl_verify_cert_chain(s,sk);
        if ((s->verify_mode != SSL_VERIFY_NONE) && (!i))
		{
		al=ssl_verify_alarm_type(s->verify_result);
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_CERTIFICATE_VERIFY_FAILED);
		goto f_err; 
		}

	c=ssl_cert_new();
	if (c == NULL) goto err;

	if (s->session->cert) ssl_cert_free(s->session->cert);
	s->session->cert=c;

	c->cert_chain=sk;
	x=(X509 *)sk_value(sk,0);
	sk=NULL;

	pkey=X509_get_pubkey(x);

	if (EVP_PKEY_missing_parameters(pkey))
		{
		x=NULL;
		al=SSL3_AL_FATAL;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS);
		goto f_err;
		}

	i=ssl_cert_type(x,pkey);
	if (i < 0)
		{
		x=NULL;
		al=SSL3_AL_FATAL;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_UNKNOWN_CERTIFICATE_TYPE);
		goto f_err;
		}

	c->cert_type=i;
	CRYPTO_add(&x->references,1,CRYPTO_LOCK_X509);
	if (c->pkeys[i].x509 != NULL)
		X509_free(c->pkeys[i].x509);
	c->pkeys[i].x509=x;
	c->key= &(c->pkeys[i]);

	if ((s->session != NULL) && (s->session->peer != NULL)) 
		X509_free(s->session->peer);
	CRYPTO_add(&x->references,1,CRYPTO_LOCK_X509);
	s->session->peer=x;

	x=NULL;
	ret=1;

	if (0)
		{
f_err:
		ssl3_send_alert(s,SSL3_AL_FATAL,al);
		}
err:
	if (x != NULL) X509_free(x);
	if (sk != NULL) sk_pop_free(sk,X509_free);
	return(ret);
	}

static int ssl3_get_key_exchange(s)
SSL *s;
	{
#ifndef NO_RSA
	unsigned char *q,md_buf[EVP_MAX_MD_SIZE*2];
#endif
	EVP_MD_CTX md_ctx;
	unsigned char *param,*p;
	int al,i,j,param_len,ok;
	long n,alg;
	EVP_PKEY *pkey=NULL;
	RSA *rsa=NULL;
#ifndef NO_DH
	DH *dh=NULL;
#endif

	n=ssl3_get_message(s,
		SSL3_ST_CR_KEY_EXCH_A,
		SSL3_ST_CR_KEY_EXCH_B,
		-1,
		1024*8, /* ?? */
		&ok);

	if (!ok) return((int)n);

	if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE)
		{
		s->s3->tmp.reuse_message=1;
		return(1);
		}

	param=p=(unsigned char *)s->init_buf->data;

	if (s->session->cert != NULL)
		{
#ifndef NO_RSA
		if (s->session->cert->rsa_tmp != NULL)
			{
			RSA_free(s->session->cert->rsa_tmp);
			s->session->cert->rsa_tmp=NULL;
			}
#endif
#ifndef NO_DH
		if (s->session->cert->dh_tmp)
			{
			DH_free(s->session->cert->dh_tmp);
			s->session->cert->dh_tmp=NULL;
			}
#endif
		}
	else
		{
		s->session->cert=ssl_cert_new();
		}

	param_len=0;
	alg=s->s3->tmp.new_cipher->algorithms;

#ifndef NO_RSA
	if (alg & SSL_kRSA)
		{
		if ((rsa=RSA_new()) == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		n2s(p,i);
		param_len=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_MODULUS_LENGTH);
			goto f_err;
			}
		if (!(rsa->n=BN_bin2bn(p,i,rsa->n)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		n2s(p,i);
		param_len+=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_E_LENGTH);
			goto f_err;
			}
		if (!(rsa->e=BN_bin2bn(p,i,rsa->e)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;
		n-=param_len;

/*		s->session->cert->rsa_tmp=rsa;*/
		/* this should be because we are using an export cipher */
		if (alg & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->cert->pkeys[SSL_PKEY_RSA_ENC].x509);
		else
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_INTERNAL_ERROR);
			goto err;
			}
		s->session->cert->rsa_tmp=rsa;
		}
	else
#endif
#ifndef NO_DH
		if (alg & SSL_kEDH)
		{
		if ((dh=DH_new()) == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_DH_LIB);
			goto err;
			}
		n2s(p,i);
		param_len=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_P_LENGTH);
			goto f_err;
			}
		if (!(dh->p=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		n2s(p,i);
		param_len+=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_G_LENGTH);
			goto f_err;
			}
		if (!(dh->g=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		n2s(p,i);
		param_len+=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_PUB_KEY_LENGTH);
			goto f_err;
			}
		if (!(dh->pub_key=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;
		n-=param_len;

#ifndef NO_RSA
		if (alg & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->cert->pkeys[SSL_PKEY_RSA_ENC].x509);
		else
#endif
#ifndef NO_DSA
		if (alg & SSL_aDSS)
			pkey=X509_get_pubkey(s->session->cert->pkeys[SSL_PKEY_DSA_SIGN].x509);
#endif
		/* else anonymous DH, so no certificate or pkey. */

		s->session->cert->dh_tmp=dh;
		}
	else if ((alg & SSL_kDHr) || (alg & SSL_kDHd))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER);
		goto f_err;
		}
#endif

	/* p points to the next byte, there are 'n' bytes left */


	/* if it was signed, check the signature */
	if (pkey != NULL)
		{
		n2s(p,i);
		n-=2;
		j=EVP_PKEY_size(pkey);

		if ((i != n) || (n > j) || (n <= 0))
			{
			/* wrong packet length */
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_WRONG_SIGNATURE_LENGTH);
			goto err;
			}

#ifndef NO_RSA
		if (pkey->type == EVP_PKEY_RSA)
			{
			int num;

			j=0;
			q=md_buf;
			for (num=2; num > 0; num--)
				{
				EVP_DigestInit(&md_ctx,(num == 2)
					?s->ctx->md5:s->ctx->sha1);
				EVP_DigestUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx,param,param_len);
				EVP_DigestFinal(&md_ctx,q,(unsigned int *)&i);
				q+=i;
				j+=i;
				}
			i=RSA_public_decrypt((int)n,p,p,pkey->pkey.rsa,
				RSA_PKCS1_PADDING);
			if (i <= 0)
				{
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_DECRYPT);
				goto f_err;
				}
			if ((j != i) || (memcmp(p,md_buf,i) != 0))
				{
				/* bad signature */
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SIGNATURE);
				goto f_err;
				}
			}
		else
#endif
#ifndef NO_DSA
			if (pkey->type == EVP_PKEY_DSA)
			{
			/* lets do DSS */
			EVP_VerifyInit(&md_ctx,EVP_dss1());
			EVP_VerifyUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx,param,param_len);
			if (!EVP_VerifyFinal(&md_ctx,p,(int)n,pkey))
				{
				/* bad signature */
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SIGNATURE);
				goto f_err;
				}
			}
		else
#endif
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_INTERNAL_ERROR);
			goto err;
			}
		}
	else
		{
		/* still data left over */
		if (!(alg & SSL_aNULL))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_INTERNAL_ERROR);
			goto err;
			}
		if (n != 0)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_EXTRA_DATA_IN_MESSAGE);
			goto f_err;
			}
		}

	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	return(-1);
	}

static int ssl3_get_certificate_request(s)
SSL *s;
	{
	int ok,ret=0;
	unsigned long n,nc,l;
	unsigned int llen,ctype_num,i;
	X509_NAME *xn=NULL;
	unsigned char *p,*d,*q;
	STACK *ca_sk=NULL;

	n=ssl3_get_message(s,
		SSL3_ST_CR_CERT_REQ_A,
		SSL3_ST_CR_CERT_REQ_B,
		-1,
#if defined(MSDOS) && !defined(WIN32)
		1024*30,  /* 30k max cert list :-) */
#else
		1024*100, /* 100k max cert list :-) */
#endif
		&ok);

	if (!ok) return((int)n);

	s->s3->tmp.cert_req=0;

	if (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE)
		{
		s->s3->tmp.reuse_message=1;
		return(1);
		}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_REQUEST)
		{
		ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
		SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_WRONG_MESSAGE_TYPE);
		goto err;
		}

	/* TLS does not like anon-DH with client cert */
	if (s->version > SSL3_VERSION)
		{
		l=s->s3->tmp.new_cipher->algorithms;
		if (l & SSL_aNULL)
			{
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER);
			goto err;
			}
		}

	d=p=(unsigned char *)s->init_buf->data;

	if ((ca_sk=sk_new(ca_dn_cmp)) == NULL)
		{
		SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	/* get the certificate types */
	ctype_num= *(p++);
	if (ctype_num > SSL3_CT_NUMBER)
		ctype_num=SSL3_CT_NUMBER;
	for (i=0; i<ctype_num; i++)
		s->s3->tmp.ctype[i]= p[i];
	p+=ctype_num;

	/* get the CA RDNs */
	n2s(p,llen);
	if ((llen+ctype_num+2+1) != n)
		{
		ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
		SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_LENGTH_MISMATCH);
		goto err;
		}

	for (nc=0; nc<llen; )
		{
		n2s(p,l);
		if ((l+nc+2) > llen)
			{
			if ((s->options & SSL_OP_NETSCAPE_CA_DN_BUG))
				goto cont; /* netscape bugs */
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_CA_DN_TOO_LONG);
			goto err;
			}

		q=p;

		if ((xn=d2i_X509_NAME(NULL,&q,l)) == NULL)
			{
			/* If netscape tollerance is on, ignore errors */
			if (s->options & SSL_OP_NETSCAPE_CA_DN_BUG)
				goto cont;
			else
				{
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
				SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,ERR_R_ASN1_LIB);
				goto err;
				}
			}

		if (q != (p+l))
			{
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_CA_DN_LENGTH_MISMATCH);
			goto err;
			}
		if (!sk_push(ca_sk,(char *)xn))
			{
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,ERR_R_MALLOC_FAILURE);
			goto err;
			}

		p+=l;
		nc+=l+2;
		}

	if (0)
		{
cont:
		ERR_clear_error();
		}

	/* we should setup a certficate to return.... */
	s->s3->tmp.cert_req=1;
	s->s3->tmp.ctype_num=ctype_num;
	if (s->s3->tmp.ca_names != NULL)
		sk_pop_free(s->s3->tmp.ca_names,X509_NAME_free);
	s->s3->tmp.ca_names=ca_sk;
	ca_sk=NULL;

	ret=1;
err:
	if (ca_sk != NULL) sk_pop_free(ca_sk,X509_NAME_free);
	return(ret);
	}

static int ca_dn_cmp(a,b)
X509_NAME **a,**b;
	{
	return(X509_NAME_cmp(*a,*b));
	}

static int ssl3_get_server_done(s)
SSL *s;
	{
	int ok,ret=0;
	long n;

	n=ssl3_get_message(s,
		SSL3_ST_CR_SRVR_DONE_A,
		SSL3_ST_CR_SRVR_DONE_B,
		SSL3_MT_SERVER_DONE,
		30, /* should be very small, like 0 :-) */
		&ok);

	if (!ok) return((int)n);
	if (n > 0)
		{
		/* should contain no data */
		ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
		SSLerr(SSL_F_SSL3_GET_SERVER_DONE,SSL_R_LENGTH_MISMATCH);
		}
	ret=1;
	return(ret);
	}

static int ssl3_send_client_key_exchange(s)
SSL *s;
	{
	unsigned char *p,*q,*d;
	int n;
	unsigned long l;
	EVP_PKEY *pkey=NULL;

	if (s->state == SSL3_ST_CW_KEY_EXCH_A)
		{
		d=(unsigned char *)s->init_buf->data;
		p= &(d[4]);

		l=s->s3->tmp.new_cipher->algorithms;

#ifndef NO_RSA
		if (l & SSL_kRSA)
			{
			RSA *rsa;
			unsigned char tmp_buf[48];

			if (s->session->cert->rsa_tmp != NULL)
				rsa=s->session->cert->rsa_tmp;
			else
				{
				pkey=X509_get_pubkey(s->session->cert->pkeys[SSL_PKEY_RSA_ENC].x509);
				if ((pkey == NULL) ||
					(pkey->type != EVP_PKEY_RSA) ||
					(pkey->pkey.rsa == NULL))
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_INTERNAL_ERROR);
					goto err;
					}
				rsa=pkey->pkey.rsa;
				}
				
			tmp_buf[0]=s->version>>8;
			tmp_buf[1]=s->version&0xff;
			RAND_bytes(&(tmp_buf[2]),SSL_MAX_MASTER_KEY_LENGTH-2);

			s->session->master_key_length=SSL_MAX_MASTER_KEY_LENGTH;

			q=p;
			/* Fix buf for TLS and beyond */
			if (s->version > SSL3_VERSION)
				p+=2;
			n=RSA_public_encrypt(SSL_MAX_MASTER_KEY_LENGTH,
				tmp_buf,p,rsa,RSA_PKCS1_PADDING);
			if (n <= 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_BAD_RSA_ENCRYPT);
				goto err;
				}

			/* Fix buf for TLS and beyond */
			if (s->version > SSL3_VERSION)
				{
				s2n(n,q);
				n+=2;
				}

			s->session->master_key_length=
				s->method->ssl3_enc->generate_master_secret(s,
					s->session->master_key,
					tmp_buf,48);
			memset(tmp_buf,0,48);
			}
		else
#endif
#ifndef NO_DH
		if (l & (SSL_kEDH|SSL_kDHr|SSL_kDHd))
			{
			DH *dh_srvr,*dh_clnt;

			if (s->session->cert->dh_tmp != NULL)
				dh_srvr=s->session->cert->dh_tmp;
			else
				{
				/* we get them from the cert */
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_HANDSHAKE_FAILURE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNABLE_TO_FIND_DH_PARAMETERS);
				goto err;
				}
			
			/* generate a new random key */
			if ((dh_clnt=DHparams_dup(dh_srvr)) == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
				goto err;
				}
			if (!DH_generate_key(dh_clnt))
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
				goto err;
				}

			/* use the 'p' output buffer for the DH key, but
			 * make sure to clear it out afterwards */

			n=DH_compute_key(p,dh_srvr->pub_key,dh_clnt);

			if (n <= 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
				goto err;
				}

			/* generate master key from the result */
			s->session->master_key_length=
				s->method->ssl3_enc->generate_master_secret(s,
					s->session->master_key,p,n);
			/* clean up */
			memset(p,0,n);

			/* send off the data */
			n=BN_num_bytes(dh_clnt->pub_key);
			s2n(n,p);
			BN_bn2bin(dh_clnt->pub_key,p);
			n+=2;

			DH_free(dh_clnt);

			/* perhaps clean things up a bit EAY EAY EAY EAY*/
			}
		else
#endif
			{
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_HANDSHAKE_FAILURE);
			SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_INTERNAL_ERROR);
			goto err;
			}
		
		*(d++)=SSL3_MT_CLIENT_KEY_EXCHANGE;
		l2n3(n,d);

		s->state=SSL3_ST_CW_KEY_EXCH_B;
		/* number of bytes to write */
		s->init_num=n+4;
		s->init_off=0;
		}

	/* SSL3_ST_CW_KEY_EXCH_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
err:
	return(-1);
	}

static int ssl3_send_client_verify(s)
SSL *s;
	{
	unsigned char *p,*d;
	unsigned char data[MD5_DIGEST_LENGTH+SHA_DIGEST_LENGTH];
	EVP_PKEY *pkey;
	int i=0;
	unsigned long n;
#ifndef NO_DSA
	int j;
#endif

	if (s->state == SSL3_ST_CW_CERT_VRFY_A)
		{
		d=(unsigned char *)s->init_buf->data;
		p= &(d[4]);
		pkey=s->cert->key->privatekey;

		s->method->ssl3_enc->cert_verify_mac(s,&(s->s3->finish_dgst2),
			&(data[MD5_DIGEST_LENGTH]));

#ifndef NO_RSA
		if (pkey->type == EVP_PKEY_RSA)
			{
			s->method->ssl3_enc->cert_verify_mac(s,
				&(s->s3->finish_dgst1),&(data[0]));
			i=RSA_private_encrypt(
				MD5_DIGEST_LENGTH+SHA_DIGEST_LENGTH,
				data,&(p[2]),pkey->pkey.rsa,
				RSA_PKCS1_PADDING);
			if (i <= 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,ERR_R_RSA_LIB);
				goto err;
				}
			s2n(i,p);
			n=i+2;
			}
		else
#endif
#ifndef NO_DSA
			if (pkey->type == EVP_PKEY_DSA)
			{
			if (!DSA_sign(pkey->save_type,
				&(data[MD5_DIGEST_LENGTH]),
				SHA_DIGEST_LENGTH,&(p[2]),
				(unsigned int *)&j,pkey->pkey.dsa))
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,ERR_R_DSA_LIB);
				goto err;
				}
			s2n(j,p);
			n=j+2;
			}
		else
#endif
			{
			SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,SSL_R_INTERNAL_ERROR);
			goto err;
			}
		*(d++)=SSL3_MT_CERTIFICATE_VERIFY;
		l2n3(n,d);

		s->init_num=(int)n+4;
		s->init_off=0;
		}
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
err:
	return(-1);
	}

static int ssl3_send_client_certificate(s)
SSL *s;
	{
	X509 *x509=NULL;
	EVP_PKEY *pkey=NULL;
	int i;
	unsigned long l;

	if (s->state ==	SSL3_ST_CW_CERT_A)
		{
		if ((s->cert == NULL) ||
			(s->cert->key->x509 == NULL) ||
			(s->cert->key->privatekey == NULL))
			s->state=SSL3_ST_CW_CERT_B;
		else
			s->state=SSL3_ST_CW_CERT_C;
		}

	/* We need to get a client cert */
	if (s->state == SSL3_ST_CW_CERT_B)
		{
		/* If we get an error, we need to
		 * ssl->rwstate=SSL_X509_LOOKUP; return(-1);
		 * We then get retied later */
		i=0;
		if (s->ctx->client_cert_cb != NULL)
			i=s->ctx->client_cert_cb(s,&(x509),&(pkey));
		if (i < 0)
			{
			s->rwstate=SSL_X509_LOOKUP;
			return(-1);
			}
		s->rwstate=SSL_NOTHING;
		if ((i == 1) && (pkey != NULL) && (x509 != NULL))
			{
			s->state=SSL3_ST_CW_CERT_B;
			if (	!SSL_use_certificate(s,x509) ||
				!SSL_use_PrivateKey(s,pkey))
				i=0;
			}
		else if (i == 1)
			{
			i=0;
			SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE,SSL_R_BAD_DATA_RETURNED_BY_CALLBACK);
			}

		if (x509 != NULL) X509_free(x509);
		if (pkey != NULL) EVP_PKEY_free(pkey);
		if (i == 0)
			{
			if (s->version == SSL3_VERSION)
				{
				s->s3->tmp.cert_req=0;
				ssl3_send_alert(s,SSL3_AL_WARNING,SSL_AD_NO_CERTIFICATE);
				return(1);
				}
			else
				{
				s->s3->tmp.cert_req=2;
				}
			}

		/* Ok, we have a cert */
		s->state=SSL3_ST_CW_CERT_C;
		}

	if (s->state == SSL3_ST_CW_CERT_C)
		{
		s->state=SSL3_ST_CW_CERT_D;
		l=ssl3_output_cert_chain(s,
			(s->s3->tmp.cert_req == 2)?NULL:s->cert->key->x509);
		s->init_num=(int)l;
		s->init_off=0;
		}
	/* SSL3_ST_CW_CERT_D */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
	}

#define has_bits(i,m)	(((i)&(m)) == (m))

static int ssl3_check_cert_and_algorithm(s)
SSL *s;
	{
	int i,idx;
	long algs;
	EVP_PKEY *pkey=NULL;
	CERT *c;
	RSA *rsa;
	DH *dh;

	c=s->session->cert;

	if (c == NULL)
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_INTERNAL_ERROR);
		goto err;
		}

	algs=s->s3->tmp.new_cipher->algorithms;

	/* we don't have a certificate */
	if (algs & (SSL_aDH|SSL_aNULL))
		return(1);

	rsa=s->session->cert->rsa_tmp;
	dh=s->session->cert->dh_tmp;

	/* This is the passed certificate */

	idx=c->cert_type;
	pkey=X509_get_pubkey(c->pkeys[idx].x509);
	i=X509_certificate_type(c->pkeys[idx].x509,pkey);

	
	/* Check that we have a certificate if we require one */
	if ((algs & SSL_aRSA) && !has_bits(i,EVP_PK_RSA|EVP_PKT_SIGN))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_RSA_SIGNING_CERT);
		goto f_err;
		}
#ifndef NO_DSA
	else if ((algs & SSL_aDSS) && !has_bits(i,EVP_PK_DSA|EVP_PKT_SIGN))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_DSA_SIGNING_CERT);
		goto f_err;
		}
#endif

	if ((algs & SSL_kRSA) &&
		!(has_bits(i,EVP_PK_RSA|EVP_PKT_ENC) || (rsa != NULL)))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_RSA_ENCRYPTING_CERT);
		goto f_err;
		}
#ifndef NO_DH
	else if ((algs & SSL_kEDH) &&
		!(has_bits(i,EVP_PK_DH|EVP_PKT_EXCH) || (dh != NULL)))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_DH_KEY);
		goto f_err;
		}
	else if ((algs & SSL_kDHr) && !has_bits(i,EVP_PK_DH|EVP_PKS_RSA))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_DH_RSA_CERT);
		goto f_err;
		}
#ifndef NO_DSA
	else if ((algs & SSL_kDHd) && !has_bits(i,EVP_PK_DH|EVP_PKS_DSA))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_DH_DSA_CERT);
		goto f_err;
		}
#endif
#endif

	if ((algs & SSL_EXP) && !has_bits(i,EVP_PKT_EXP))
		{
#ifndef NO_RSA
		if (algs & SSL_kRSA)
			{
			if ((rsa == NULL) || (RSA_size(rsa) > 512))
				{
				SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_EXPORT_TMP_RSA_KEY);
				goto f_err;
				}
			}
		else
#endif
#ifndef NO_DH
			if (algs & (SSL_kEDH|SSL_kDHr|SSL_kDHd))
			{
			if ((dh == NULL) || (DH_size(dh) > 512))
				{
				SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_EXPORT_TMP_DH_KEY);
				goto f_err;
				}
			}
		else
#endif
			{
			SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
			goto f_err;
			}
		}
	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_HANDSHAKE_FAILURE);
err:
	return(0);
	}

