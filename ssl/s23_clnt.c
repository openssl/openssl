/* ssl/s23_clnt.c */
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

#ifndef NOPROTO
static int ssl23_client_hello(SSL *s);
static int ssl23_get_server_hello(SSL *s);
#else
static int ssl23_client_hello();
static int ssl23_get_server_hello();
#endif

static SSL_METHOD *ssl23_get_client_method(ver)
int ver;
	{
	if (ver == SSL2_VERSION)
		return(SSLv2_client_method());
	else if (ver == SSL3_VERSION)
		return(SSLv3_client_method());
	else if (ver == TLS1_VERSION)
		return(TLSv1_client_method());
	else
		return(NULL);
	}

SSL_METHOD *SSLv23_client_method()
	{
	static int init=1;
	static SSL_METHOD SSLv23_client_data;

	if (init)
		{
		init=0;
		memcpy((char *)&SSLv23_client_data,
			(char *)sslv23_base_method(),sizeof(SSL_METHOD));
		SSLv23_client_data.ssl_connect=ssl23_connect;
		SSLv23_client_data.get_ssl_method=ssl23_get_client_method;
		}
	return(&SSLv23_client_data);
	}

int ssl23_connect(s)
SSL *s;
	{
	BUF_MEM *buf;
	unsigned long Time=time(NULL);
	void (*cb)()=NULL;
	int ret= -1;
	int new_state,state;

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
		case SSL_ST_BEFORE:
		case SSL_ST_CONNECT:
		case SSL_ST_BEFORE|SSL_ST_CONNECT:
		case SSL_ST_OK|SSL_ST_CONNECT:

			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

			/* s->version=TLS1_VERSION; */
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

			ssl3_init_finished_mac(s);

			s->state=SSL23_ST_CW_CLNT_HELLO_A;
			s->ctx->sess_connect++;
			s->init_num=0;
			break;

		case SSL23_ST_CW_CLNT_HELLO_A:
		case SSL23_ST_CW_CLNT_HELLO_B:

			s->shutdown=0;
			ret=ssl23_client_hello(s);
			if (ret <= 0) goto end;
			s->state=SSL23_ST_CR_SRVR_HELLO_A;
			s->init_num=0;

			break;

		case SSL23_ST_CR_SRVR_HELLO_A:
		case SSL23_ST_CR_SRVR_HELLO_B:
			ret=ssl23_get_server_hello(s);
			if (ret >= 0) cb=NULL;
			goto end;
			break;

		default:
			SSLerr(SSL_F_SSL23_CONNECT,SSL_R_UNKNOWN_STATE);
			ret= -1;
			goto end;
			/* break; */
			}

		if (s->debug) BIO_flush(s->wbio);

		if ((cb != NULL) && (s->state != state))
			{
			new_state=s->state;
			s->state=state;
			cb(s,SSL_CB_CONNECT_LOOP,1);
			s->state=new_state;
			}
		}
end:
	s->in_handshake--;
	if (cb != NULL)
		cb(s,SSL_CB_CONNECT_EXIT,ret);
	return(ret);
	}


static int ssl23_client_hello(s)
SSL *s;
	{
	unsigned char *buf;
	unsigned char *p,*d;
	int i,ch_len;

	buf=(unsigned char *)s->init_buf->data;
	if (s->state == SSL23_ST_CW_CLNT_HELLO_A)
		{
#if 0
		/* don't reuse session-id's */
		if (!ssl_get_new_session(s,0))
			{
			return(-1);
			}
#endif

		p=s->s3->client_random;
		RAND_bytes(p,SSL3_RANDOM_SIZE);

		/* Do the message type and length last */
		d= &(buf[2]);
		p=d+9;

		*(d++)=SSL2_MT_CLIENT_HELLO;
		if (!(s->options & SSL_OP_NO_TLSv1))
			{
			*(d++)=TLS1_VERSION_MAJOR;
			*(d++)=TLS1_VERSION_MINOR;
			}
		else if (!(s->options & SSL_OP_NO_SSLv3))
			{
			*(d++)=SSL3_VERSION_MAJOR;
			*(d++)=SSL3_VERSION_MINOR;
			}
		else if (!(s->options & SSL_OP_NO_SSLv2))
			{
			*(d++)=SSL2_VERSION_MAJOR;
			*(d++)=SSL2_VERSION_MINOR;
			}
		else
			{
			SSLerr(SSL_F_SSL23_CLIENT_HELLO,SSL_R_NO_PROTOCOLS_AVAILABLE);
			return(-1);
			}

		/* Ciphers supported */
		i=ssl_cipher_list_to_bytes(s,SSL_get_ciphers(s),p);
		if (i == 0)
			{
			/* no ciphers */
			SSLerr(SSL_F_SSL23_CLIENT_HELLO,SSL_R_NO_CIPHERS_AVAILABLE);
			return(-1);
			}
		s2n(i,d);
		p+=i;

		/* put in the session-id, zero since there is no
		 * reuse. */
#if 0
		s->session->session_id_length=0;
#endif
		s2n(0,d);

		if (s->options & SSL_OP_NETSCAPE_CHALLENGE_BUG)
			ch_len=SSL2_CHALLENGE_LENGTH;
		else
			ch_len=SSL2_MAX_CHALLENGE_LENGTH;

		/* write out sslv2 challenge */
		if (SSL3_RANDOM_SIZE < ch_len)
			i=SSL3_RANDOM_SIZE;
		else
			i=ch_len;
		s2n(i,d);
		memset(&(s->s3->client_random[0]),0,SSL3_RANDOM_SIZE);
		RAND_bytes(&(s->s3->client_random[SSL3_RANDOM_SIZE-i]),i);
		memcpy(p,&(s->s3->client_random[SSL3_RANDOM_SIZE-i]),i);
		p+=i;

		i= p- &(buf[2]);
		buf[0]=((i>>8)&0xff)|0x80;
		buf[1]=(i&0xff);

		s->state=SSL23_ST_CW_CLNT_HELLO_B;
		/* number of bytes to write */
		s->init_num=i+2;
		s->init_off=0;

		ssl3_finish_mac(s,&(buf[2]),i);
		}

	/* SSL3_ST_CW_CLNT_HELLO_B */
	return(ssl23_write_bytes(s));
	}

static int ssl23_get_server_hello(s)
SSL *s;
	{
	char buf[8];
	unsigned char *p;
	int i,ch_len;
	int n;

	n=ssl23_read_bytes(s,7);

	if (n != 7) return(n);
	p=s->packet;

	memcpy(buf,p,n);

	if ((p[0] & 0x80) && (p[2] == SSL2_MT_SERVER_HELLO) &&
		(p[5] == 0x00) && (p[6] == 0x02))
		{
		/* we are talking sslv2 */
		/* we need to clean up the SSLv3 setup and put in the
		 * sslv2 stuff. */

		if (s->options & SSL_OP_NO_SSLv2)
			{
			SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_PROTOCOL);
			goto err;
			}
		if (s->s2 == NULL)
			{
			if (!ssl2_new(s))
				goto err;
			}
		else
			ssl2_clear(s);

		if (s->options & SSL_OP_NETSCAPE_CHALLENGE_BUG)
			ch_len=SSL2_CHALLENGE_LENGTH;
		else
			ch_len=SSL2_MAX_CHALLENGE_LENGTH;

		/* write out sslv2 challenge */
		i=(SSL3_RANDOM_SIZE < ch_len)
			?SSL3_RANDOM_SIZE:ch_len;
		s->s2->challenge_length=i;
		memcpy(s->s2->challenge,
			&(s->s3->client_random[SSL3_RANDOM_SIZE-i]),i);

		if (s->s3 != NULL) ssl3_free(s);

		if (!BUF_MEM_grow(s->init_buf,
			SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER))
			{
			SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,ERR_R_BUF_LIB);
			goto err;
			}

		s->state=SSL2_ST_GET_SERVER_HELLO_A;
		s->s2->ssl2_rollback=1;

		/* setup the 5 bytes we have read so we get them from
		 * the sslv2 buffer */
		s->rstate=SSL_ST_READ_HEADER;
		s->packet_length=n;
		s->packet= &(s->s2->rbuf[0]);
		memcpy(s->packet,buf,n);
		s->s2->rbuf_left=n;
		s->s2->rbuf_offs=0;

		/* we have already written one */
		s->s2->write_sequence=1;

		s->method=SSLv2_client_method();
		s->handshake_func=s->method->ssl_connect;
		}
	else if ((p[0] == SSL3_RT_HANDSHAKE) &&
		 (p[1] == SSL3_VERSION_MAJOR) &&
		 ((p[2] == SSL3_VERSION_MINOR) ||
		  (p[2] == TLS1_VERSION_MINOR)) &&
		 (p[5] == SSL3_MT_SERVER_HELLO))
		{
		/* we have sslv3 or tls1 */

		if (!ssl_init_wbio_buffer(s,1)) goto err;

		/* we are in this state */
		s->state=SSL3_ST_CR_SRVR_HELLO_A;

		/* put the 5 bytes we have read into the input buffer
		 * for SSLv3 */
		s->rstate=SSL_ST_READ_HEADER;
		s->packet_length=n;
		s->packet= &(s->s3->rbuf.buf[0]);
		memcpy(s->packet,buf,n);
		s->s3->rbuf.left=n;
		s->s3->rbuf.offset=0;

		if ((p[2] == SSL3_VERSION_MINOR) &&
			!(s->options & SSL_OP_NO_SSLv3))
			{
			s->version=SSL3_VERSION;
			s->method=SSLv3_client_method();
			}
		else if ((p[2] == TLS1_VERSION_MINOR) &&
			!(s->options & SSL_OP_NO_TLSv1))
			{
			s->version=TLS1_VERSION;
			s->method=TLSv1_client_method();
			}
		else
			{
			SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_PROTOCOL);
			goto err;
			}
			
		s->handshake_func=s->method->ssl_connect;
		}
	else if ((p[0] == SSL3_RT_ALERT) &&
		 (p[1] == SSL3_VERSION_MAJOR) &&
		 ((p[2] == SSL3_VERSION_MINOR) ||
		  (p[2] == TLS1_VERSION_MINOR)) &&
		 (p[3] == 0) &&
		 (p[4] == 2))
		{
		void (*cb)()=NULL;
		int j;

		/* An alert */
		if (s->info_callback != NULL)
			cb=s->info_callback;
		else if (s->ctx->info_callback != NULL)
			cb=s->ctx->info_callback;
 
		i=p[5];
		if (cb != NULL)
			{
			j=(i<<8)|p[6];
			cb(s,SSL_CB_READ_ALERT,j);
			}

		s->rwstate=SSL_NOTHING;
		SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,1000+p[6]);
		goto err;
		}
	else
		{
		SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,SSL_R_UNKNOWN_PROTOCOL);
		goto err;
		}
	s->init_num=0;

	/* Since, if we are sending a ssl23 client hello, we are not
	 * reusing a session-id */
	if (!ssl_get_new_session(s,0))
		goto err;

	s->first_packet=1;
	return(SSL_connect(s));
err:
	return(-1);
	}

