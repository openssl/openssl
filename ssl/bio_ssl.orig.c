/* ssl/bio_ssl.c */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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
#include <string.h>
#include <errno.h>
#include "bio.h"
#include "err.h"
#include "ssl.h"

#ifndef NOPROTO
static int ssl_write(BIO *h,char *buf,int num);
static int ssl_read(BIO *h,char *buf,int size);
static int ssl_puts(BIO *h,char *str);
static long ssl_ctrl(BIO *h,int cmd,long arg1,char *arg2);
static int ssl_new(BIO *h);
static int ssl_free(BIO *data);
#else
static int ssl_write();
static int ssl_read();
static int ssl_puts();
static long ssl_ctrl();
static int ssl_new();
static int ssl_free();
#endif

static BIO_METHOD methods_sslp=
	{
	BIO_TYPE_SSL,"ssl",
	ssl_write,
	ssl_read,
	ssl_puts,
	NULL, /* ssl_gets, */
	ssl_ctrl,
	ssl_new,
	ssl_free,
	};

BIO_METHOD *BIO_f_ssl()
	{
	return(&methods_sslp);
	}

static int ssl_new(bi)
BIO *bi;
	{
	bi->init=0;
	bi->ptr=NULL;	/* The SSL structure */
	bi->flags=0;
	return(1);
	}

static int ssl_free(a)
BIO *a;
	{
	if (a == NULL) return(0);
	if (a->ptr != NULL) SSL_shutdown((SSL *)a->ptr);
	if (a->shutdown)
		{
		if (a->init) SSL_free((SSL *)a->ptr);
		a->init=0;
		a->flags=0;
		a->ptr=NULL;
		}
	return(1);
	}
	
static int ssl_read(b,out,outl)
BIO *b;
char *out;
int outl;
	{
	int ret=1,dr,dw;
	int inflags,outflags;
	SSL *ssl;
	int retry_reason=0;

	if (out == NULL) return(0);
	ssl=(SSL *)b->ptr;

	inflags=outflags=b->flags;

	dr=inflags&BIO_FLAGS_PROTOCOL_DELAYED_READ;
	dw=inflags&BIO_FLAGS_PROTOCOL_DELAYED_WRITE;

	outflags&= ~(BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY|
		BIO_FLAGS_PROTOCOL_DELAYED_WRITE|
		BIO_FLAGS_PROTOCOL_DELAYED_READ);

	if (!SSL_is_init_finished(ssl))
		{
		ret=SSL_do_handshake(ssl);
#if 0
		if (ret > 0)
			{
			outflags=(BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY|
				BIO_FLAGS_PROTOCOL_DELAYED_READ|dw);
			ret= -1;
			goto end;
			}
#endif
		}
	if (ret > 0)
		ret=SSL_read(ssl,out,outl);

	switch (SSL_get_error(ssl,ret))
		{
	case SSL_ERROR_NONE:
		if (ret <= 0) break;
		if (dw)
			outflags|=(BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY);
		break;
	case SSL_ERROR_WANT_READ:
		outflags=(BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY|
			BIO_FLAGS_PROTOCOL_DELAYED_READ|dw);
		break;
	case SSL_ERROR_WANT_WRITE:
		outflags=(BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY|
			BIO_FLAGS_PROTOCOL_DELAYED_READ|dw);
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		outflags=(BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY|
			BIO_FLAGS_PROTOCOL_DELAYED_READ|dw);
		retry_reason=BIO_RR_SSL_X509_LOOKUP;
		break;
	case SSL_ERROR_WANT_CONNECT:
		outflags=(BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY|
			BIO_FLAGS_PROTOCOL_DELAYED_READ|dw);
		retry_reason=BIO_RR_CONNECT;
		break;
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
	case SSL_ERROR_ZERO_RETURN:
	default:
		break;
		}

	b->retry_reason=retry_reason;
	b->flags=outflags;
	return(ret);
	}

static int ssl_write(b,out,outl)
BIO *b;
char *out;
int outl;
	{
	int ret,dr,dw;
	int inflags,outflags,retry_reason=0;
	SSL *ssl;

	if (out == NULL) return(0);
	ssl=(SSL *)b->ptr;

	inflags=outflags=b->flags;

	dr=inflags&BIO_FLAGS_PROTOCOL_DELAYED_READ;
	dw=inflags&BIO_FLAGS_PROTOCOL_DELAYED_WRITE;

	outflags&= ~(BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY|
		BIO_FLAGS_PROTOCOL_DELAYED_WRITE|
		BIO_FLAGS_PROTOCOL_DELAYED_READ);

	ret=SSL_do_handshake(ssl);
	if (ret > 0)
		ret=SSL_write(ssl,out,outl);

	switch (SSL_get_error(ssl,ret))
		{
	case SSL_ERROR_NONE:
		if (ret <= 0) break;
		if (dr)
			outflags|=(BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY);
		break;
	case SSL_ERROR_WANT_WRITE:
		outflags=(BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY|
			BIO_FLAGS_PROTOCOL_DELAYED_WRITE|dr);
		break;
	case SSL_ERROR_WANT_READ:
		outflags=(BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY|
			BIO_FLAGS_PROTOCOL_DELAYED_WRITE|dr);
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		outflags=(BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY|
			BIO_FLAGS_PROTOCOL_DELAYED_WRITE|dr);
		retry_reason=BIO_RR_SSL_X509_LOOKUP;
		break;
	case SSL_ERROR_WANT_CONNECT:
		outflags=(BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY|
			BIO_FLAGS_PROTOCOL_DELAYED_READ|dw);
		retry_reason=BIO_RR_CONNECT;
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
	default:
		break;
		}

	b->retry_reason=retry_reason;
	b->flags=outflags;
	return(ret);
	}

static long ssl_ctrl(b,cmd,num,ptr)
BIO *b;
int cmd;
long num;
char *ptr;
	{
	SSL **sslp,*ssl;
	BIO *dbio,*bio;
	long ret=1;

	ssl=(SSL *)b->ptr;
	switch (cmd)
		{
	case BIO_CTRL_RESET:
		SSL_shutdown(ssl);

		if (ssl->handshake_func == ssl->method->ssl_connect)
			SSL_set_connect_state(ssl);
		else if (ssl->handshake_func == ssl->method->ssl_accept)
			SSL_set_accept_state(ssl);

		SSL_clear(ssl);

		if (b->next_bio != NULL)
			ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		else if (ssl->rbio != NULL)
			ret=BIO_ctrl(ssl->rbio,cmd,num,ptr);
		else
			ret=1;
		break;
	case BIO_CTRL_EOF:
	case BIO_CTRL_INFO:
		ret=0;
		break;
	case BIO_C_SSL_MODE:
		if (num) /* client mode */
			SSL_set_connect_state(ssl);
		else
			SSL_set_accept_state(ssl);
		break;
	case BIO_C_SET_SSL:
		ssl_free(b);
		b->shutdown=(int)num;
		b->ptr=ptr;
		ssl=(SSL *)ptr;
		bio=SSL_get_rbio(ssl);
		if (bio != NULL)
			{
			if (b->next_bio != NULL)
				BIO_push(bio,b->next_bio);
			b->next_bio=bio;
			}
		b->init=1;
		break;
	case BIO_C_GET_SSL:
		if (ptr != NULL)
			{
			sslp=(SSL **)ptr;
			*sslp=ssl;
			}
		break;
	case BIO_CTRL_GET_CLOSE:
		ret=b->shutdown;
		break;
	case BIO_CTRL_SET_CLOSE:
		b->shutdown=(int)num;
		break;
	case BIO_CTRL_WPENDING:
		ret=BIO_ctrl(ssl->wbio,cmd,num,ptr);
		break;
	case BIO_CTRL_PENDING:
		ret=SSL_pending(ssl);
		if (ret == 0)
			ret=BIO_pending(ssl->rbio);
		break;
	case BIO_CTRL_FLUSH:
		BIO_clear_retry_flags(b);
		ret=BIO_ctrl(ssl->wbio,cmd,num,ptr);
		BIO_copy_next_retry(b);
		break;
	case BIO_CTRL_PUSH:
		if (b->next_bio != NULL)
			{
			SSL_set_bio(ssl,b->next_bio,b->next_bio);
			b->next_bio->references++;
			}
		break;
	case BIO_CTRL_POP:
		/* ugly bit of a hack */
		if (ssl->rbio != ssl->wbio) /* we are in trouble :-( */
			{
			BIO_free_all(ssl->wbio);
			}
		ssl->wbio=NULL;
		ssl->rbio=NULL;
		break;
	case BIO_C_DO_STATE_MACHINE:
		BIO_clear_retry_flags(b);

		b->retry_reason=0;
		ret=(int)SSL_do_handshake(ssl);

		switch (SSL_get_error(ssl,ret))
			{
		case SSL_ERROR_WANT_READ:
			BIO_set_flags(b,
				BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY);
			break;
		case SSL_ERROR_WANT_WRITE:
			BIO_set_flags(b,
				BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY);
			break;
		case SSL_ERROR_WANT_CONNECT:
			BIO_set_flags(b,
				BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY);
			b->retry_reason=b->next_bio->retry_reason;
			break;
		default:
			break;
			}
		break;
	case BIO_CTRL_DUP:
		dbio=(BIO *)ptr;
		if (dbio->ptr != NULL)
			SSL_free((SSL *)dbio->ptr);
		dbio->ptr=(char *)SSL_dup(ssl);
		ret=(dbio->ptr != NULL);
		break;
	default:
		return(0);
		break;
		}
	return(ret);
	}

static int ssl_puts(bp,str)
BIO *bp;
char *str;
	{
	int n,ret;

	n=strlen(str);
	ret=BIO_write(bp,str,n);
	return(ret);
	}

BIO *BIO_new_ssl(ctx,client)
SSL_CTX *ctx;
int client;
	{
	BIO *ret;
	SSL *ssl;

	if ((ret=BIO_new(BIO_f_ssl())) == NULL)
		return(NULL);
	if ((ssl=SSL_new(ctx)) == NULL)
		{
		BIO_free(ret);
		return(NULL);
		}
	if (client)
		SSL_set_connect_state(ssl);
	else
		SSL_set_accept_state(ssl);
		
	BIO_set_ssl(ret,ssl,BIO_CLOSE);
	return(ret);
	}

int BIO_ssl_copy_session_id(t,f)
BIO *t,*f;
	{
	t=BIO_find_type(t,BIO_TYPE_SSL);
	f=BIO_find_type(f,BIO_TYPE_SSL);
	if ((t == NULL) || (f == NULL))
		return(0);
	if ((t->ptr == NULL) || (f->ptr == NULL))
		return(0);
	SSL_copy_session_id((SSL *)t->ptr,(SSL *)f->ptr);
	return(1);
	}


