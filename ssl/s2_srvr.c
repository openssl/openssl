/* ssl/s2_srvr.c */
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
#include "bio.h"
#include "rand.h"
#include "objects.h"
#include "ssl_locl.h"
#include "evp.h"

#ifndef NOPROTO
static int get_client_master_key(SSL *s);
static int get_client_hello(SSL *s);
static int server_hello(SSL *s); 
static int get_client_finished(SSL *s);
static int server_verify(SSL *s);
static int server_finish(SSL *s);
static int request_certificate(SSL *s);
static int ssl_rsa_private_decrypt(CERT *c, int len, unsigned char *from,
	unsigned char *to,int padding);
#else
static int get_client_master_key();
static int get_client_hello();
static int server_hello(); 
static int get_client_finished();
static int server_verify();
static int server_finish();
static int request_certificate();
static int ssl_rsa_private_decrypt();
#endif

#define BREAK	break

static SSL_METHOD *ssl2_get_server_method(ver)
int ver;
	{
	if (ver == SSL2_VERSION)
		return(SSLv2_server_method());
	else
		return(NULL);
	}

SSL_METHOD *SSLv2_server_method()
	{
	static int init=1;
	static SSL_METHOD SSLv2_server_data;

	if (init)
		{
		init=0;
		memcpy((char *)&SSLv2_server_data,(char *)sslv2_base_method(),
			sizeof(SSL_METHOD));
		SSLv2_server_data.ssl_accept=ssl2_accept;
		SSLv2_server_data.get_ssl_method=ssl2_get_server_method;
		}
	return(&SSLv2_server_data);
	}

int ssl2_accept(s)
SSL *s;
	{
	unsigned long l=time(NULL);
	BUF_MEM *buf=NULL;
	int ret= -1;
	long num1;
	void (*cb)()=NULL;
	int new_state,state;

	RAND_seed((unsigned char *)&l,sizeof(l));
	ERR_clear_error();
	clear_sys_error();

	if (s->info_callback != NULL)
		cb=s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb=s->ctx->info_callback;

	/* init things to blank */
	if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s);
	s->in_handshake++;

	if (((s->session == NULL) || (s->session->cert == NULL)) &&
		(s->cert == NULL))
		{
		SSLerr(SSL_F_SSL2_ACCEPT,SSL_R_NO_CERTIFICATE_SET);
		return(-1);
		}

	clear_sys_error();
	for (;;)
		{
		state=s->state;

		switch (s->state)
			{
		case SSL_ST_BEFORE:
		case SSL_ST_ACCEPT:
		case SSL_ST_BEFORE|SSL_ST_ACCEPT:
		case SSL_ST_OK|SSL_ST_ACCEPT:

			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

			s->version=SSL2_VERSION;
			s->type=SSL_ST_ACCEPT;

			buf=s->init_buf;
			if ((buf == NULL) && ((buf=BUF_MEM_new()) == NULL))
				{ ret= -1; goto end; }
			if (!BUF_MEM_grow(buf,(int)
				SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER))
				{ ret= -1; goto end; }
			s->init_buf=buf;
			s->init_num=0;
			s->ctx->sess_accept++;
			s->handshake_func=ssl2_accept;
			s->state=SSL2_ST_GET_CLIENT_HELLO_A;
			BREAK;

		case SSL2_ST_GET_CLIENT_HELLO_A:
		case SSL2_ST_GET_CLIENT_HELLO_B:
		case SSL2_ST_GET_CLIENT_HELLO_C:
			s->shutdown=0;
			ret=get_client_hello(s);
			if (ret <= 0) goto end;
			s->init_num=0;
			s->state=SSL2_ST_SEND_SERVER_HELLO_A;
			BREAK;

		case SSL2_ST_SEND_SERVER_HELLO_A:
		case SSL2_ST_SEND_SERVER_HELLO_B:
			ret=server_hello(s);
			if (ret <= 0) goto end;
			s->init_num=0;
			if (!s->hit)
				{
				s->state=SSL2_ST_GET_CLIENT_MASTER_KEY_A;
				BREAK;
				}
			else
				{
				s->state=SSL2_ST_SERVER_START_ENCRYPTION;
				BREAK;
				}
		case SSL2_ST_GET_CLIENT_MASTER_KEY_A:
		case SSL2_ST_GET_CLIENT_MASTER_KEY_B:
			ret=get_client_master_key(s);
			if (ret <= 0) goto end;
			s->init_num=0;
			s->state=SSL2_ST_SERVER_START_ENCRYPTION;
			BREAK;

		case SSL2_ST_SERVER_START_ENCRYPTION:
			/* Ok we how have sent all the stuff needed to
			 * start encrypting, the next packet back will
			 * be encrypted. */
			if (!ssl2_enc_init(s,0))
				{ ret= -1; goto end; }
			s->s2->clear_text=0;
			s->state=SSL2_ST_SEND_SERVER_VERIFY_A;
			BREAK;

		case SSL2_ST_SEND_SERVER_VERIFY_A:
		case SSL2_ST_SEND_SERVER_VERIFY_B:
			ret=server_verify(s);
			if (ret <= 0) goto end;
			s->init_num=0;
			if (s->hit)
				{
				/* If we are in here, we have been
				 * buffering the output, so we need to
				 * flush it and remove buffering from
				 * future traffic */
				s->state=SSL2_ST_SEND_SERVER_VERIFY_C;
				BREAK;
				}
			else
				{
				s->state=SSL2_ST_GET_CLIENT_FINISHED_A;
				break;
				}

 		case SSL2_ST_SEND_SERVER_VERIFY_C:
 			/* get the number of bytes to write */
 			num1=BIO_ctrl(s->wbio,BIO_CTRL_INFO,0,NULL);
 			if (num1 != 0)
 				{
				s->rwstate=SSL_WRITING;
 				num1=BIO_flush(s->wbio);
 				if (num1 <= 0) { ret= -1; goto end; }
				s->rwstate=SSL_NOTHING;
				}

 			/* flushed and now remove buffering */
 			s->wbio=BIO_pop(s->wbio);

 			s->state=SSL2_ST_GET_CLIENT_FINISHED_A;
  			BREAK;

		case SSL2_ST_GET_CLIENT_FINISHED_A:
		case SSL2_ST_GET_CLIENT_FINISHED_B:
			ret=get_client_finished(s);
			if (ret <= 0)
				goto end;
			s->init_num=0;
			s->state=SSL2_ST_SEND_REQUEST_CERTIFICATE_A;
			BREAK;

		case SSL2_ST_SEND_REQUEST_CERTIFICATE_A:
		case SSL2_ST_SEND_REQUEST_CERTIFICATE_B:
		case SSL2_ST_SEND_REQUEST_CERTIFICATE_C:
		case SSL2_ST_SEND_REQUEST_CERTIFICATE_D:
			/* don't do a 'request certificate' if we
			 * don't want to, or we already have one, and
			 * we only want to do it once. */
			if (!(s->verify_mode & SSL_VERIFY_PEER) ||
				((s->session->peer != NULL) &&
				(s->verify_mode & SSL_VERIFY_CLIENT_ONCE)))
				{
				s->state=SSL2_ST_SEND_SERVER_FINISHED_A;
				break;
				}
			else
				{
				ret=request_certificate(s);
				if (ret <= 0) goto end;
				s->init_num=0;
				s->state=SSL2_ST_SEND_SERVER_FINISHED_A;
				}
			BREAK;

		case SSL2_ST_SEND_SERVER_FINISHED_A:
		case SSL2_ST_SEND_SERVER_FINISHED_B:
			ret=server_finish(s);
			if (ret <= 0) goto end;
			s->init_num=0;
			s->state=SSL_ST_OK;
			break;

		case SSL_ST_OK:
			BUF_MEM_free(s->init_buf);
			s->init_buf=NULL;
			s->init_num=0;
		/*	ERR_clear_error();*/

			ssl_update_cache(s,SSL_SESS_CACHE_SERVER);

			s->ctx->sess_accept_good++;
			/* s->server=1; */
			ret=1;

			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_DONE,1);

			goto end;
			/* BREAK; */

		default:
			SSLerr(SSL_F_SSL2_ACCEPT,SSL_R_UNKNOWN_STATE);
			ret= -1;
			goto end;
			/* BREAK; */
			}
		
		if ((cb != NULL) && (s->state != state))
			{
			new_state=s->state;
			s->state=state;
			cb(s,SSL_CB_ACCEPT_LOOP,1);
			s->state=new_state;
			}
		}
end:
	s->in_handshake--;
	if (cb != NULL)
		cb(s,SSL_CB_ACCEPT_EXIT,ret);
	return(ret);
	}

static int get_client_master_key(s)
SSL *s;
	{
	int export,i,n,keya,error=0,ek;
	unsigned char *p;
	SSL_CIPHER *cp;
	EVP_CIPHER *c;
	EVP_MD *md;

	p=(unsigned char *)s->init_buf->data;
	if (s->state == SSL2_ST_GET_CLIENT_MASTER_KEY_A)
		{
		i=ssl2_read(s,(char *)&(p[s->init_num]),10-s->init_num);

		if (i < (10-s->init_num))
			return(ssl2_part_read(s,SSL_F_GET_CLIENT_MASTER_KEY,i));
		if (*(p++) != SSL2_MT_CLIENT_MASTER_KEY)
			{
			if (p[-1] != SSL2_MT_ERROR)
				{
				ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
				SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,SSL_R_READ_WRONG_PACKET_TYPE);
				}
			else
				SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,
					SSL_R_PEER_ERROR);
			return(-1);
			}

		cp=ssl2_get_cipher_by_char(p);
		if (cp == NULL)
			{
			ssl2_return_error(s,SSL2_PE_NO_CIPHER);
			SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,
				SSL_R_NO_CIPHER_MATCH);
			return(-1);
			}
		s->session->cipher= cp;

		p+=3;
		n2s(p,i); s->s2->tmp.clear=i;
		n2s(p,i); s->s2->tmp.enc=i;
		n2s(p,i); s->session->key_arg_length=i;
		s->state=SSL2_ST_GET_CLIENT_MASTER_KEY_B;
		s->init_num=0;
		}

	/* SSL2_ST_GET_CLIENT_MASTER_KEY_B */
	p=(unsigned char *)s->init_buf->data;
	keya=s->session->key_arg_length;
	n=s->s2->tmp.clear+s->s2->tmp.enc+keya - s->init_num;
	i=ssl2_read(s,(char *)&(p[s->init_num]),n);
	if (i != n) return(ssl2_part_read(s,SSL_F_GET_CLIENT_MASTER_KEY,i));

	memcpy(s->session->key_arg,&(p[s->s2->tmp.clear+s->s2->tmp.enc]),
		(unsigned int)keya);

	if (s->session->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL)
		{
		ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
		SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,SSL_R_NO_PRIVATEKEY);
		return(-1);
		}
	i=ssl_rsa_private_decrypt(s->cert,s->s2->tmp.enc,
		&(p[s->s2->tmp.clear]),&(p[s->s2->tmp.clear]),
		(s->s2->ssl2_rollback)?RSA_SSLV23_PADDING:RSA_PKCS1_PADDING);

	export=(s->session->cipher->algorithms & SSL_EXP)?1:0;
	
	if (!ssl_cipher_get_evp(s->session->cipher,&c,&md))
		{
		ssl2_return_error(s,SSL2_PE_NO_CIPHER);
		SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS);
		return(0);
		}

	if (s->session->cipher->algorithm2 & SSL2_CF_8_BYTE_ENC)
		{
		export=1;
		ek=8;
		}
	else
		ek=5;

	/* bad decrypt */
#if 1
	/* If a bad decrypt, continue with protocol but with a
	 * dud master secret */
	if ((i < 0) ||
		((!export && (i != EVP_CIPHER_key_length(c)))
		|| ( export && ((i != ek) || (s->s2->tmp.clear+i !=
			EVP_CIPHER_key_length(c))))))
		{
		if (export)
			i=ek;
		else
			i=EVP_CIPHER_key_length(c);
		RAND_bytes(p,i);
		}
#else
	if (i < 0)
		{
		error=1;
		SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,SSL_R_BAD_RSA_DECRYPT);
		}
	/* incorrect number of key bytes for non export cipher */
	else if ((!export && (i != EVP_CIPHER_key_length(c)))
		|| ( export && ((i != ek) || (s->s2->tmp.clear+i !=
			EVP_CIPHER_key_length(c)))))
		{
		error=1;
		SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,SSL_R_WRONG_NUMBER_OF_KEY_BITS);
		}
	if (error)
		{
		ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
		return(-1);
		}
#endif

	if (export) i+=s->s2->tmp.clear;
	s->session->master_key_length=i;
	memcpy(s->session->master_key,p,(unsigned int)i);
	return(1);
	}

static int get_client_hello(s)
SSL *s;
	{
	int i,n;
	unsigned char *p;
	STACK *cs; /* a stack of SSL_CIPHERS */
	STACK *cl; /* the ones we want to use */
	int z;

	/* This is a bit of a hack to check for the correct packet
	 * type the first time round. */
	if (s->state == SSL2_ST_GET_CLIENT_HELLO_A)
		{
		s->first_packet=1;
		s->state=SSL2_ST_GET_CLIENT_HELLO_B;
		}

	p=(unsigned char *)s->init_buf->data;
	if (s->state == SSL2_ST_GET_CLIENT_HELLO_B)
		{
		i=ssl2_read(s,(char *)&(p[s->init_num]),9-s->init_num);
		if (i < (9-s->init_num)) 
			return(ssl2_part_read(s,SSL_F_GET_CLIENT_HELLO,i));
	
		if (*(p++) != SSL2_MT_CLIENT_HELLO)
			{
			if (p[-1] != SSL2_MT_ERROR)
				{
				ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
				SSLerr(SSL_F_GET_CLIENT_HELLO,SSL_R_READ_WRONG_PACKET_TYPE);
				}
			else
				SSLerr(SSL_F_GET_CLIENT_HELLO,SSL_R_PEER_ERROR);
			return(-1);
			}
		n2s(p,i);
		if (i < s->version) s->version=i;
		n2s(p,i); s->s2->tmp.cipher_spec_length=i;
		n2s(p,i); s->s2->tmp.session_id_length=i;
		n2s(p,i); s->s2->challenge_length=i;
		if (	(i < SSL2_MIN_CHALLENGE_LENGTH) ||
			(i > SSL2_MAX_CHALLENGE_LENGTH))
			{
			SSLerr(SSL_F_GET_CLIENT_HELLO,SSL_R_INVALID_CHALLENGE_LENGTH);
			return(-1);
			}
		s->state=SSL2_ST_GET_CLIENT_HELLO_C;
		s->init_num=0;
		}

	/* SSL2_ST_GET_CLIENT_HELLO_C */
	p=(unsigned char *)s->init_buf->data;
	n=s->s2->tmp.cipher_spec_length+s->s2->challenge_length+
		s->s2->tmp.session_id_length-s->init_num;
	i=ssl2_read(s,(char *)&(p[s->init_num]),n);
	if (i != n) return(ssl2_part_read(s,SSL_F_GET_CLIENT_HELLO,i));

	/* get session-id before cipher stuff so we can get out session
	 * structure if it is cached */
	/* session-id */
	if ((s->s2->tmp.session_id_length != 0) && 
		(s->s2->tmp.session_id_length != SSL2_SSL_SESSION_ID_LENGTH))
		{
		ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
		SSLerr(SSL_F_GET_CLIENT_HELLO,SSL_R_BAD_SSL_SESSION_ID_LENGTH);
		return(-1);
		}

	if (s->s2->tmp.session_id_length == 0)
		{
		if (!ssl_get_new_session(s,1))
			{
			ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
			return(-1);
			}
		}
	else
		{
		i=ssl_get_prev_session(s,&(p[s->s2->tmp.cipher_spec_length]),
			s->s2->tmp.session_id_length);
		if (i == 1)
			{ /* previous session */
			s->hit=1;
			}
		else if (i == -1)
			{
			ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
			return(-1);
			}
		else
			{
			if (s->cert == NULL)
				{
				ssl2_return_error(s,SSL2_PE_NO_CERTIFICATE);
				SSLerr(SSL_F_GET_CLIENT_HELLO,SSL_R_NO_CERTIFICATE_SET);
				return(-1);
				}

			if (!ssl_get_new_session(s,1))
				{
				ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
				return(-1);
				}
			}
		}

	if (!s->hit)
		{
		cs=ssl_bytes_to_cipher_list(s,p,s->s2->tmp.cipher_spec_length,
			&s->session->ciphers);
		if (cs == NULL) goto mem_err;

		cl=ssl_get_ciphers_by_id(s);

		for (z=0; z<sk_num(cs); z++)
			{
			if (sk_find(cl,sk_value(cs,z)) < 0)
				{
				sk_delete(cs,z);
				z--;
				}
			}

		/* s->session->ciphers should now have a list of
		 * ciphers that are on both the client and server.
		 * This list is ordered by the order the client sent
		 * the ciphers.
		 */
		}
	p+=s->s2->tmp.cipher_spec_length;
	/* done cipher selection */

	/* session id extracted already */
	p+=s->s2->tmp.session_id_length;

	/* challenge */
	memcpy(s->s2->challenge,p,(unsigned int)s->s2->challenge_length);
	return(1);
mem_err:
	SSLerr(SSL_F_GET_CLIENT_HELLO,ERR_R_MALLOC_FAILURE);
	return(0);
	}

static int server_hello(s)
SSL *s;
	{
	unsigned char *p,*d;
	int n,hit;
	STACK *sk;

	p=(unsigned char *)s->init_buf->data;
	if (s->state == SSL2_ST_SEND_SERVER_HELLO_A)
		{
		d=p+11;
		*(p++)=SSL2_MT_SERVER_HELLO;		/* type */
		hit=s->hit;
		*(p++)=(unsigned char)hit;
		if (!hit)
			{			/* else add cert to session */
			CRYPTO_add(&s->cert->references,1,CRYPTO_LOCK_SSL_CERT);
			if (s->session->cert != NULL)
				ssl_cert_free(s->session->cert);
			s->session->cert=s->cert;		
			}
		else	/* We have a session id-cache hit, if the
			 * session-id has no certificate listed against
			 * the 'cert' structure, grab the 'old' one
			 * listed against the SSL connection */
			{
			if (s->session->cert == NULL)
				{
				CRYPTO_add(&s->cert->references,1,
					CRYPTO_LOCK_SSL_CERT);
				s->session->cert=s->cert;
				}
			}

		if (s->session->cert == NULL)
			{
			ssl2_return_error(s,SSL2_PE_NO_CERTIFICATE);
			SSLerr(SSL_F_SERVER_HELLO,SSL_R_NO_CERTIFICATE_SPECIFIED);
			return(-1);
			}

		if (hit)
			{
			*(p++)=0;		/* no certificate type */
			s2n(s->version,p);	/* version */
			s2n(0,p);		/* cert len */
			s2n(0,p);		/* ciphers len */
			}
		else
			{
			/* EAY EAY */
			/* put certificate type */
			*(p++)=SSL2_CT_X509_CERTIFICATE;
			s2n(s->version,p);	/* version */
			n=i2d_X509(s->cert->pkeys[SSL_PKEY_RSA_ENC].x509,NULL);
			s2n(n,p);		/* certificate length */
			i2d_X509(s->cert->pkeys[SSL_PKEY_RSA_ENC].x509,&d);
			n=0;
			
			/* lets send out the ciphers we like in the
			 * prefered order */
			sk= s->session->ciphers;
			n=ssl_cipher_list_to_bytes(s,s->session->ciphers,d);
			d+=n;
			s2n(n,p);		/* add cipher length */
			}

		/* make and send conn_id */
		s2n(SSL2_CONNECTION_ID_LENGTH,p);	/* add conn_id length */
		s->s2->conn_id_length=SSL2_CONNECTION_ID_LENGTH;
		RAND_bytes(s->s2->conn_id,(int)s->s2->conn_id_length);
		memcpy(d,s->s2->conn_id,SSL2_CONNECTION_ID_LENGTH);
		d+=SSL2_CONNECTION_ID_LENGTH;

		s->state=SSL2_ST_SEND_SERVER_HELLO_B;
		s->init_num=d-(unsigned char *)s->init_buf->data;
		s->init_off=0;
		}
	/* SSL2_ST_SEND_SERVER_HELLO_B */
 	/* If we are using TCP/IP, the performace is bad if we do 2
 	 * writes without a read between them.  This occurs when
 	 * Session-id reuse is used, so I will put in a buffering module
 	 */
 	if (s->hit)
 		{
		if (!ssl_init_wbio_buffer(s,1)) return(-1);
 		}
 
	return(ssl2_do_write(s));
	}

static int get_client_finished(s)
SSL *s;
	{
	unsigned char *p;
	int i;

	p=(unsigned char *)s->init_buf->data;
	if (s->state == SSL2_ST_GET_CLIENT_FINISHED_A)
		{
		i=ssl2_read(s,(char *)&(p[s->init_num]),1-s->init_num);
		if (i < 1-s->init_num)
			return(ssl2_part_read(s,SSL_F_GET_CLIENT_FINISHED,i));

		if (*p != SSL2_MT_CLIENT_FINISHED)
			{
			if (*p != SSL2_MT_ERROR)
				{
				ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
				SSLerr(SSL_F_GET_CLIENT_FINISHED,SSL_R_READ_WRONG_PACKET_TYPE);
				}
			else
				SSLerr(SSL_F_GET_CLIENT_FINISHED,SSL_R_PEER_ERROR);
			return(-1);
			}
		s->init_num=0;
		s->state=SSL2_ST_GET_CLIENT_FINISHED_B;
		}

	/* SSL2_ST_GET_CLIENT_FINISHED_B */
	i=ssl2_read(s,(char *)&(p[s->init_num]),s->s2->conn_id_length-s->init_num);
	if (i < (int)s->s2->conn_id_length-s->init_num)
		{
		return(ssl2_part_read(s,SSL_F_GET_CLIENT_FINISHED,i));
		}
	if (memcmp(p,s->s2->conn_id,(unsigned int)s->s2->conn_id_length) != 0)
		{
		ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
		SSLerr(SSL_F_GET_CLIENT_FINISHED,SSL_R_CONNECTION_ID_IS_DIFFERENT);
		return(-1);
		}
	return(1);
	}

static int server_verify(s)
SSL *s;
	{
	unsigned char *p;

	if (s->state == SSL2_ST_SEND_SERVER_VERIFY_A)
		{
		p=(unsigned char *)s->init_buf->data;
		*(p++)=SSL2_MT_SERVER_VERIFY;
		memcpy(p,s->s2->challenge,(unsigned int)s->s2->challenge_length);
		/* p+=s->s2->challenge_length; */

		s->state=SSL2_ST_SEND_SERVER_VERIFY_B;
		s->init_num=s->s2->challenge_length+1;
		s->init_off=0;
		}
	return(ssl2_do_write(s));
	}

static int server_finish(s)
SSL *s;
	{
	unsigned char *p;

	if (s->state == SSL2_ST_SEND_SERVER_FINISHED_A)
		{
		p=(unsigned char *)s->init_buf->data;
		*(p++)=SSL2_MT_SERVER_FINISHED;

		memcpy(p,s->session->session_id,
			(unsigned int)s->session->session_id_length);
		/* p+=s->session->session_id_length; */

		s->state=SSL2_ST_SEND_SERVER_FINISHED_B;
		s->init_num=s->session->session_id_length+1;
		s->init_off=0;
		}

	/* SSL2_ST_SEND_SERVER_FINISHED_B */
	return(ssl2_do_write(s));
	}

/* send the request and check the response */
static int request_certificate(s)
SSL *s;
	{
	unsigned char *p,*p2,*buf2;
	unsigned char *ccd;
	int i,j,ctype,ret= -1;
	X509 *x509=NULL;
	STACK *sk=NULL;

	ccd=s->s2->tmp.ccl;
	if (s->state == SSL2_ST_SEND_REQUEST_CERTIFICATE_A)
		{
		p=(unsigned char *)s->init_buf->data;
		*(p++)=SSL2_MT_REQUEST_CERTIFICATE;
		*(p++)=SSL2_AT_MD5_WITH_RSA_ENCRYPTION;
		RAND_bytes(ccd,SSL2_MIN_CERT_CHALLENGE_LENGTH);
		memcpy(p,ccd,SSL2_MIN_CERT_CHALLENGE_LENGTH);

		s->state=SSL2_ST_SEND_REQUEST_CERTIFICATE_B;
		s->init_num=SSL2_MIN_CERT_CHALLENGE_LENGTH+2;
		s->init_off=0;
		}

	if (s->state == SSL2_ST_SEND_REQUEST_CERTIFICATE_B)
		{
		i=ssl2_do_write(s);
		if (i <= 0)
			{
			ret=i;
			goto end;
			}

		s->init_num=0;
		s->state=SSL2_ST_SEND_REQUEST_CERTIFICATE_C;
		}

	if (s->state == SSL2_ST_SEND_REQUEST_CERTIFICATE_C)
		{
		p=(unsigned char *)s->init_buf->data;
		i=ssl2_read(s,(char *)&(p[s->init_num]),6-s->init_num);
		if (i < 3)
			{
			ret=ssl2_part_read(s,SSL_F_REQUEST_CERTIFICATE,i);
			goto end;
			}

		if ((*p == SSL2_MT_ERROR) && (i >= 3))
			{
			n2s(p,i);
			if (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
				{
				ssl2_return_error(s,SSL2_PE_BAD_CERTIFICATE);
				SSLerr(SSL_F_REQUEST_CERTIFICATE,SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
				goto end;
				}
			ret=1;
			goto end;
			}
		if ((*(p++) != SSL2_MT_CLIENT_CERTIFICATE) || (i < 6))
			{
			ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
			SSLerr(SSL_F_REQUEST_CERTIFICATE,SSL_R_SHORT_READ);
			goto end;
			}
		/* ok we have a response */
		/* certificate type, there is only one right now. */
		ctype= *(p++);
		if (ctype != SSL2_AT_MD5_WITH_RSA_ENCRYPTION)
			{
			ssl2_return_error(s,SSL2_PE_UNSUPPORTED_CERTIFICATE_TYPE);
			SSLerr(SSL_F_REQUEST_CERTIFICATE,SSL_R_BAD_RESPONSE_ARGUMENT);
			goto end;
			}
		n2s(p,i); s->s2->tmp.clen=i;
		n2s(p,i); s->s2->tmp.rlen=i;
		s->state=SSL2_ST_SEND_REQUEST_CERTIFICATE_D;
		s->init_num=0;
		}

	/* SSL2_ST_SEND_REQUEST_CERTIFICATE_D */
	p=(unsigned char *)s->init_buf->data;
	j=s->s2->tmp.clen+s->s2->tmp.rlen-s->init_num;
	i=ssl2_read(s,(char *)&(p[s->init_num]),j);
	if (i < j) 
		{
		ret=ssl2_part_read(s,SSL_F_REQUEST_CERTIFICATE,i);
		goto end;
		}

	x509=(X509 *)d2i_X509(NULL,&p,(long)s->s2->tmp.clen);
	if (x509 == NULL)
		{
		SSLerr(SSL_F_REQUEST_CERTIFICATE,ERR_R_X509_LIB);
		goto msg_end;
		}

	if (((sk=sk_new_null()) == NULL) || (!sk_push(sk,(char *)x509)))
		{
		SSLerr(SSL_F_REQUEST_CERTIFICATE,ERR_R_MALLOC_FAILURE);
		goto msg_end;
		}

	i=ssl_verify_cert_chain(s,sk);

	if (i)	/* we like the packet, now check the chksum */
		{
		EVP_MD_CTX ctx;
		EVP_PKEY *pkey=NULL;

		EVP_VerifyInit(&ctx,s->ctx->rsa_md5);
		EVP_VerifyUpdate(&ctx,s->s2->key_material,
			(unsigned int)s->s2->key_material_length);
		EVP_VerifyUpdate(&ctx,ccd,SSL2_MIN_CERT_CHALLENGE_LENGTH);

		i=i2d_X509(s->session->cert->pkeys[SSL_PKEY_RSA_ENC].x509,NULL);
		buf2=(unsigned char *)Malloc((unsigned int)i);
		if (buf2 == NULL)
			{
			SSLerr(SSL_F_REQUEST_CERTIFICATE,ERR_R_MALLOC_FAILURE);
			goto msg_end;
			}
		p2=buf2;
		i=i2d_X509(s->session->cert->pkeys[SSL_PKEY_RSA_ENC].x509,&p2);
		EVP_VerifyUpdate(&ctx,buf2,(unsigned int)i);
		Free(buf2);

		pkey=X509_get_pubkey(x509);
		if (pkey == NULL) goto end;
		i=EVP_VerifyFinal(&ctx,p,s->s2->tmp.rlen,pkey);
		memset(&ctx,0,sizeof(ctx));

		if (i) 
			{
			if (s->session->peer != NULL)
				X509_free(s->session->peer);
			s->session->peer=x509;
			CRYPTO_add(&x509->references,1,CRYPTO_LOCK_X509);
			ret=1;
			goto end;
			}
		else
			{
			SSLerr(SSL_F_REQUEST_CERTIFICATE,SSL_R_BAD_CHECKSUM);
			goto msg_end;
			}
		}
	else
		{
msg_end:
		ssl2_return_error(s,SSL2_PE_BAD_CERTIFICATE);
		}
end:
	if (sk != NULL) sk_free(sk);
	if (x509 != NULL) X509_free(x509);
	return(ret);
	}

static int ssl_rsa_private_decrypt(c, len, from, to,padding)
CERT *c;
int len;
unsigned char *from;
unsigned char *to;
int padding;
	{
	RSA *rsa;
	int i;

	if ((c == NULL) || (c->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL))
		{
		SSLerr(SSL_F_SSL_RSA_PRIVATE_DECRYPT,SSL_R_NO_PRIVATEKEY);
		return(-1);
		}
	if (c->pkeys[SSL_PKEY_RSA_ENC].privatekey->type != EVP_PKEY_RSA)
		{
		SSLerr(SSL_F_SSL_RSA_PRIVATE_DECRYPT,SSL_R_PUBLIC_KEY_IS_NOT_RSA);
		return(-1);
		}
	rsa=c->pkeys[SSL_PKEY_RSA_ENC].privatekey->pkey.rsa;

	/* we have the public key */
	i=RSA_private_decrypt(len,from,to,rsa,padding);
	if (i < 0)
		SSLerr(SSL_F_SSL_RSA_PRIVATE_DECRYPT,ERR_R_RSA_LIB);
	return(i);
	}

