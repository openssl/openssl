/* ssl/s23_lib.c */
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
#include "objects.h"
#include "ssl_locl.h"

#ifndef NOPROTO
static int ssl23_num_ciphers(void );
static SSL_CIPHER *ssl23_get_cipher(unsigned int u);
static int ssl23_read(SSL *s, char *buf, int len);
static int ssl23_write(SSL *s, char *buf, int len);
static long ssl23_default_timeout(void );
static int ssl23_put_cipher_by_char(SSL_CIPHER *c, unsigned char *p);
static SSL_CIPHER *ssl23_get_cipher_by_char(unsigned char *p);
#else
static int ssl23_num_ciphers();
static SSL_CIPHER *ssl23_get_cipher();
static int ssl23_read();
static int ssl23_write();
static long ssl23_default_timeout();
static int ssl23_put_cipher_by_char();
static SSL_CIPHER *ssl23_get_cipher_by_char();
#endif

char *SSL23_version_str="SSLv2/3 compatablity part of SSLeay 0.7.0 30-Jan-1997";

static SSL_METHOD SSLv23_data= {
	TLS1_VERSION,
	tls1_new,
	tls1_clear,
	tls1_free,
	ssl_undefined_function,
	ssl_undefined_function,
	ssl23_read,
	ssl_undefined_function,
	ssl23_write,
	ssl_undefined_function,
	ssl_undefined_function,
	ssl3_ctrl,
	ssl3_ctx_ctrl,
	ssl23_get_cipher_by_char,
	ssl23_put_cipher_by_char,
	ssl_undefined_function,
	ssl23_num_ciphers,
	ssl23_get_cipher,
	ssl_bad_method,
	ssl23_default_timeout,
	&ssl3_undef_enc_method,
	};

static long ssl23_default_timeout()
	{
	return(300);
	}

SSL_METHOD *sslv23_base_method()
	{
	return(&SSLv23_data);
	}

static int ssl23_num_ciphers()
	{
	return(ssl3_num_ciphers()+ssl2_num_ciphers());
	}

static SSL_CIPHER *ssl23_get_cipher(u)
unsigned int u;
	{
	unsigned int uu=ssl3_num_ciphers();

	if (u < uu)
		return(ssl3_get_cipher(u));
	else
		return(ssl2_get_cipher(u-uu));
	}

/* This function needs to check if the ciphers required are actually
 * available */
static SSL_CIPHER *ssl23_get_cipher_by_char(p)
unsigned char *p;
	{
	SSL_CIPHER c,*cp;
	unsigned long id;
	int n;

	n=ssl3_num_ciphers();
	id=0x03000000|((unsigned long)p[0]<<16L)|
		((unsigned long)p[1]<<8L)|(unsigned long)p[2];
	c.id=id;
	cp=ssl3_get_cipher_by_char(p);
	if (cp == NULL)
		cp=ssl2_get_cipher_by_char(p);
	return(cp);
	}

static int ssl23_put_cipher_by_char(c,p)
SSL_CIPHER *c;
unsigned char *p;
	{
	long l;

	/* We can write SSLv2 and SSLv3 ciphers */
	if (p != NULL)
		{
		l=c->id;
		p[0]=((unsigned char)(l>>16L))&0xFF;
		p[1]=((unsigned char)(l>> 8L))&0xFF;
		p[2]=((unsigned char)(l     ))&0xFF;
		}
	return(3);
	}

static int ssl23_read(s,buf,len)
SSL *s;
char *buf;
int len;
	{
	int n;

#if 0
	if (s->shutdown & SSL_RECEIVED_SHUTDOWN)
		{
		s->rwstate=SSL_NOTHING;
		return(0);
		}
#endif
	clear_sys_error();
	if (SSL_in_init(s) && (!s->in_handshake))
		{
		n=s->handshake_func(s);
		if (n < 0) return(n);
		if (n == 0)
			{
			SSLerr(SSL_F_SSL23_READ,SSL_R_SSL_HANDSHAKE_FAILURE);
			return(-1);
			}
		return(SSL_read(s,buf,len));
		}
	else
		{
		ssl_undefined_function(s);
		return(-1);
		}
	}

static int ssl23_write(s,buf,len)
SSL *s;
char *buf;
int len;
	{
	int n;

#if 0
	if (s->shutdown & SSL_SENT_SHUTDOWN)
		{
		s->rwstate=SSL_NOTHING;
		return(0);
		}
#endif
	clear_sys_error();
	if (SSL_in_init(s) && (!s->in_handshake))
		{
		n=s->handshake_func(s);
		if (n < 0) return(n);
		if (n == 0)
			{
			SSLerr(SSL_F_SSL23_WRITE,SSL_R_SSL_HANDSHAKE_FAILURE);
			return(-1);
			}
		return(SSL_write(s,buf,len));
		}
	else
		{
		ssl_undefined_function(s);
		return(-1);
		}
	}
