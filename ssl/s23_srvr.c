/* ssl/s23_srvr.c */
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
int ssl23_get_client_hello(SSL *s);
#else
int ssl23_get_client_hello();
#endif

static SSL_METHOD *ssl23_get_server_method(ver)
int ver;
	{
	if (ver == SSL2_VERSION)
		return(SSLv2_server_method());
	else if (ver == SSL3_VERSION)
		return(SSLv3_server_method());
	else if (ver == TLS1_VERSION)
		return(TLSv1_server_method());
	else
		return(NULL);
	}

SSL_METHOD *SSLv23_server_method()
	{
	static int init=1;
	static SSL_METHOD SSLv23_server_data;

	if (init)
		{
		init=0;
		memcpy((char *)&SSLv23_server_data,
			(char *)sslv23_base_method(),sizeof(SSL_METHOD));
		SSLv23_server_data.ssl_accept=ssl23_accept;
		SSLv23_server_data.get_ssl_method=ssl23_get_server_method;
		}
	return(&SSLv23_server_data);
	}

int ssl23_accept(s)
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
		case SSL_ST_ACCEPT:
		case SSL_ST_BEFORE|SSL_ST_ACCEPT:
		case SSL_ST_OK|SSL_ST_ACCEPT:

			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

			/* s->version=SSL3_VERSION; */
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

			ssl3_init_finished_mac(s);

			s->state=SSL23_ST_SR_CLNT_HELLO_A;
			s->ctx->sess_accept++;
			s->init_num=0;
			break;

		case SSL23_ST_SR_CLNT_HELLO_A:
		case SSL23_ST_SR_CLNT_HELLO_B:

			s->shutdown=0;
			ret=ssl23_get_client_hello(s);
			if (ret >= 0) cb=NULL;
			goto end;
			break;

		default:
			SSLerr(SSL_F_SSL23_ACCEPT,SSL_R_UNKNOWN_STATE);
			ret= -1;
			goto end;
			/* break; */
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
	if (cb != NULL)
		cb(s,SSL_CB_ACCEPT_EXIT,ret);
	s->in_handshake--;
	return(ret);
	}


int ssl23_get_client_hello(s)
SSL *s;
	{
	char buf_space[8];
	char *buf= &(buf_space[0]);
	unsigned char *p,*d,*dd;
	unsigned int i;
	unsigned int csl,sil,cl;
	int n=0,j,tls1=0;
	int type=0,use_sslv2_strong=0;

	/* read the initial header */
	if (s->state ==	SSL23_ST_SR_CLNT_HELLO_A)
		{
		if (!ssl3_setup_buffers(s)) goto err;

		n=ssl23_read_bytes(s,7);
		if (n != 7) return(n);

		p=s->packet;

		memcpy(buf,p,n);

		if ((p[0] & 0x80) && (p[2] == SSL2_MT_CLIENT_HELLO))
			{
			/* SSLv2 header */
			if ((p[3] == 0x00) && (p[4] == 0x02))
				{
				/* SSLv2 */
				if (!(s->options & SSL_OP_NO_SSLv2))
					type=1;
				}
			else if (p[3] == SSL3_VERSION_MAJOR)
				{
				/* SSLv3/TLSv1 */
				if (p[4] >= TLS1_VERSION_MINOR)
					{
					if (!(s->options & SSL_OP_NO_TLSv1))
						{
						tls1=1;
						s->state=SSL23_ST_SR_CLNT_HELLO_B;
						}
					else if (!(s->options & SSL_OP_NO_SSLv3))
						{
						s->state=SSL23_ST_SR_CLNT_HELLO_B;
						}
					}
				else if (!(s->options & SSL_OP_NO_SSLv3))
					s->state=SSL23_ST_SR_CLNT_HELLO_B;

				if (s->options & SSL_OP_NON_EXPORT_FIRST)
					{
					STACK *sk;
					SSL_CIPHER *c;
					int ne2,ne3;

					j=((p[0]&0x7f)<<8)|p[1];
					if (j > (1024*4))
						{
						SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO,SSL_R_RECORD_TOO_LARGE);
						goto err;
						}

					n=ssl23_read_bytes(s,j+2);
					if (n <= 0) return(n);
					p=s->packet;

					if ((buf=Malloc(n)) == NULL)
						{
						SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO,ERR_R_MALLOC_FAILURE);
						goto err;
						}
					memcpy(buf,p,n);

					p+=5;
					n2s(p,csl);
					p+=4;

					sk=ssl_bytes_to_cipher_list(
						s,p,csl,NULL);
					if (sk != NULL)
						{
						ne2=ne3=0;
						for (j=0; j<sk_num(sk); j++)
							{
							c=(SSL_CIPHER *)sk_value(sk,j);
							if (!(c->algorithms & SSL_EXP))
								{
								if ((c->id>>24L) == 2L)
									ne2=1;
								else
									ne3=1;
								}
							}
						if (ne2 && !ne3)
							{
							type=1;
							use_sslv2_strong=1;
							goto next_bit;
							}
						}
					}
				}
			}
		else if ((p[0] == SSL3_RT_HANDSHAKE) &&
			 (p[1] == SSL3_VERSION_MAJOR) &&
			 (p[5] == SSL3_MT_CLIENT_HELLO))
			{
			/* true SSLv3 or tls1 */
			if (p[2] >= TLS1_VERSION_MINOR)
				{
				if (!(s->options & SSL_OP_NO_TLSv1))
					{
					type=3;
					tls1=1;
					}
				else if (!(s->options & SSL_OP_NO_SSLv3))
					type=3;
				}
			else if (!(s->options & SSL_OP_NO_SSLv3))
				type=3;
			}
		else if ((strncmp("GET ", p,4) == 0) ||
			 (strncmp("POST ",p,5) == 0) ||
			 (strncmp("HEAD ",p,5) == 0) ||
			 (strncmp("PUT ", p,4) == 0))
			{
			SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO,SSL_R_HTTP_REQUEST);
			goto err;
			}
		else if (strncmp("CONNECT",p,7) == 0)
			{
			SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO,SSL_R_HTTPS_PROXY_REQUEST);
			goto err;
			}
		}

next_bit:
	if (s->state == SSL23_ST_SR_CLNT_HELLO_B)
		{
		/* we have a SSLv3/TLSv1 in a SSLv2 header */
		type=2;
		p=s->packet;
		n=((p[0]&0x7f)<<8)|p[1];
		if (n > (1024*4))
			{
			SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO,SSL_R_RECORD_TOO_LARGE);
			goto err;
			}

		j=ssl23_read_bytes(s,n+2);
		if (j <= 0) return(j);

		ssl3_finish_mac(s,&(s->packet[2]),s->packet_length-2);

		p=s->packet;
		p+=5;
		n2s(p,csl);
		n2s(p,sil);
		n2s(p,cl);
		d=(unsigned char *)s->init_buf->data;
		if ((csl+sil+cl+11) != s->packet_length)
			{
			SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO,SSL_R_RECORD_LENGTH_MISMATCH);
			goto err;
			}

		*(d++)=SSL3_VERSION_MAJOR;
		if (tls1)
			*(d++)=TLS1_VERSION_MINOR;
		else
			*(d++)=SSL3_VERSION_MINOR;

		/* lets populate the random area */
		/* get the chalenge_length */
		i=(cl > SSL3_RANDOM_SIZE)?SSL3_RANDOM_SIZE:cl;
		memset(d,0,SSL3_RANDOM_SIZE);
		memcpy(&(d[SSL3_RANDOM_SIZE-i]),&(p[csl+sil]),i);
		d+=SSL3_RANDOM_SIZE;

		/* no session-id reuse */
		*(d++)=0;

		/* ciphers */
		j=0;
		dd=d;
		d+=2;
		for (i=0; i<csl; i+=3)
			{
			if (p[i] != 0) continue;
			*(d++)=p[i+1];
			*(d++)=p[i+2];
			j+=2;
			}
		s2n(j,dd);

		/* compression */
		*(d++)=1;
		*(d++)=0;
		
		i=(d-(unsigned char *)s->init_buf->data);

		/* get the data reused from the init_buf */
		s->s3->tmp.reuse_message=1;
		s->s3->tmp.message_type=SSL3_MT_CLIENT_HELLO;
		s->s3->tmp.message_size=i;
		}

	if (type == 1)
		{
		/* we are talking sslv2 */
		/* we need to clean up the SSLv3/TLSv1 setup and put in the
		 * sslv2 stuff. */

		if (s->s2 == NULL)
			{
			if (!ssl2_new(s))
				goto err;
			}
		else
			ssl2_clear(s);

		if (s->s3 != NULL) ssl3_free(s);

		if (!BUF_MEM_grow(s->init_buf,
			SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER))
			{
			goto err;
			}

		s->state=SSL2_ST_GET_CLIENT_HELLO_A;
		if ((s->options & SSL_OP_MSIE_SSLV2_RSA_PADDING) ||
			use_sslv2_strong)
			s->s2->ssl2_rollback=0;
		else
			s->s2->ssl2_rollback=1;

		/* setup the 5 bytes we have read so we get them from
		 * the sslv2 buffer */
		s->rstate=SSL_ST_READ_HEADER;
		s->packet_length=n;
		s->packet= &(s->s2->rbuf[0]);
		memcpy(s->packet,buf,n);
		s->s2->rbuf_left=n;
		s->s2->rbuf_offs=0;

		s->method=SSLv2_server_method();
		s->handshake_func=s->method->ssl_accept;
		}

	if ((type == 2) || (type == 3))
		{
		/* we have SSLv3/TLSv1 */

		if (!ssl_init_wbio_buffer(s,1)) goto err;

		/* we are in this state */
		s->state=SSL3_ST_SR_CLNT_HELLO_A;

		if (type == 3)
			{
			/* put the 'n' bytes we have read into the input buffer
			 * for SSLv3 */
			s->rstate=SSL_ST_READ_HEADER;
			s->packet_length=n;
			s->packet= &(s->s3->rbuf.buf[0]);
			memcpy(s->packet,buf,n);
			s->s3->rbuf.left=n;
			s->s3->rbuf.offset=0;
			}
		else
			{
			s->packet_length=0;
			s->s3->rbuf.left=0;
			s->s3->rbuf.offset=0;
			}

		if (tls1)
			{
			s->version=TLS1_VERSION;
			s->method=TLSv1_server_method();
			}
		else
			{
			s->version=SSL3_VERSION;
			s->method=SSLv3_server_method();
			}
		s->handshake_func=s->method->ssl_accept;
		}
	
	if ((type < 1) || (type > 3))
		{
		/* bad, very bad */
		SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO,SSL_R_UNKNOWN_PROTOCOL);
		goto err;
		}
	s->init_num=0;

	if (buf != buf_space) Free(buf);
	s->first_packet=1;
	return(SSL_accept(s));
err:
	if (buf != buf_space) Free(buf);
	return(-1);
	}

