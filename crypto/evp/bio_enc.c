/* crypto/evp/bio_enc.c */
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
#include <errno.h>
#include "cryptlib.h"
#include "buffer.h"
#include "evp.h"

#ifndef NOPROTO
static int enc_write(BIO *h,char *buf,int num);
static int enc_read(BIO *h,char *buf,int size);
/*static int enc_puts(BIO *h,char *str); */
/*static int enc_gets(BIO *h,char *str,int size); */
static long enc_ctrl(BIO *h,int cmd,long arg1,char *arg2);
static int enc_new(BIO *h);
static int enc_free(BIO *data);
#else
static int enc_write();
static int enc_read();
/*static int enc_puts(); */
/*static int enc_gets(); */
static long enc_ctrl();
static int enc_new();
static int enc_free();
#endif

#define ENC_BLOCK_SIZE	(1024*4)

typedef struct enc_struct
	{
	int buf_len;
	int buf_off;
	int cont;		/* <= 0 when finished */
	int finished;
	int ok;			/* bad decrypt */
	EVP_CIPHER_CTX cipher;
	char buf[ENC_BLOCK_SIZE+10];
	} BIO_ENC_CTX;

static BIO_METHOD methods_enc=
	{
	BIO_TYPE_CIPHER,"cipher",
	enc_write,
	enc_read,
	NULL, /* enc_puts, */
	NULL, /* enc_gets, */
	enc_ctrl,
	enc_new,
	enc_free,
	};

BIO_METHOD *BIO_f_cipher()
	{
	return(&methods_enc);
	}

static int enc_new(bi)
BIO *bi;
	{
	BIO_ENC_CTX *ctx;

	ctx=(BIO_ENC_CTX *)Malloc(sizeof(BIO_ENC_CTX));
	EVP_CIPHER_CTX_init(&ctx->cipher);
	if (ctx == NULL) return(0);

	ctx->buf_len=0;
	ctx->buf_off=0;
	ctx->cont=1;
	ctx->finished=0;
	ctx->ok=1;

	bi->init=0;
	bi->ptr=(char *)ctx;
	bi->flags=0;
	return(1);
	}

static int enc_free(a)
BIO *a;
	{
	BIO_ENC_CTX *b;

	if (a == NULL) return(0);
	b=(BIO_ENC_CTX *)a->ptr;
	EVP_CIPHER_CTX_cleanup(&(b->cipher));
	memset(a->ptr,0,sizeof(BIO_ENC_CTX));
	Free(a->ptr);
	a->ptr=NULL;
	a->init=0;
	a->flags=0;
	return(1);
	}
	
static int enc_read(b,out,outl)
BIO *b;
char *out;
int outl;
	{
	int ret=0,i;
	BIO_ENC_CTX *ctx;

	if (out == NULL) return(0);
	ctx=(BIO_ENC_CTX *)b->ptr;

	if ((ctx == NULL) || (b->next_bio == NULL)) return(0);

	/* First check if there are bytes decoded/encoded */
	if (ctx->buf_len > 0)
		{
		i=ctx->buf_len-ctx->buf_off;
		if (i > outl) i=outl;
		memcpy(out,&(ctx->buf[ctx->buf_off]),i);
		ret=i;
		out+=i;
		outl-=i;
		ctx->buf_off+=i;
		if (ctx->buf_len == ctx->buf_off)
			{
			ctx->buf_len=0;
			ctx->buf_off=0;
			}
		}

	/* At this point, we have room of outl bytes and an empty
	 * buffer, so we should read in some more. */

	while (outl > 0)
		{
		if (ctx->cont <= 0) break;

		/* read in at offset 8, read the EVP_Cipher
		 * documentation about why */
		i=BIO_read(b->next_bio,&(ctx->buf[8]),ENC_BLOCK_SIZE);

		if (i <= 0)
			{
			/* Should be continue next time we are called? */
			if (!BIO_should_retry(b->next_bio))
				{
				ctx->cont=i;
				i=EVP_CipherFinal(&(ctx->cipher),
					(unsigned char *)ctx->buf,
					&(ctx->buf_len));
				ctx->ok=i;
				ctx->buf_off=0;
				}
			else
				ret=(ret == 0)?i:ret;
			break;
			}
		else
			{
			EVP_CipherUpdate(&(ctx->cipher),
				(unsigned char *)ctx->buf,&ctx->buf_len,
				(unsigned char *)&(ctx->buf[8]),i);
			ctx->cont=1;
			}

		if (ctx->buf_len <= outl)
			i=ctx->buf_len;
		else
			i=outl;

		if (i <= 0) break;
		memcpy(out,ctx->buf,i);
		ret+=i;
		ctx->buf_off=i;
		outl-=i;
		out+=i;
		}

	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);
	return((ret == 0)?ctx->cont:ret);
	}

static int enc_write(b,in,inl)
BIO *b;
char *in;
int inl;
	{
	int ret=0,n,i;
	BIO_ENC_CTX *ctx;

	ctx=(BIO_ENC_CTX *)b->ptr;
	ret=inl;

	BIO_clear_retry_flags(b);
	n=ctx->buf_len-ctx->buf_off;
	while (n > 0)
		{
		i=BIO_write(b->next_bio,&(ctx->buf[ctx->buf_off]),n);
		if (i <= 0)
			{
			BIO_copy_next_retry(b);
			return(i);
			}
		ctx->buf_off+=i;
		n-=i;
		}
	/* at this point all pending data has been written */

	if ((in == NULL) || (inl <= 0)) return(0);

	ctx->buf_off=0;
	while (inl > 0)
		{
		n=(inl > ENC_BLOCK_SIZE)?ENC_BLOCK_SIZE:inl;
		EVP_CipherUpdate(&(ctx->cipher),
			(unsigned char *)ctx->buf,&ctx->buf_len,
			(unsigned char *)in,n);
		inl-=n;
		in+=n;

		ctx->buf_off=0;
		n=ctx->buf_len;
		while (n > 0)
			{
			i=BIO_write(b->next_bio,&(ctx->buf[ctx->buf_off]),n);
			if (i <= 0)
				{
				BIO_copy_next_retry(b);
				return(i);
				}
			n-=i;
			ctx->buf_off+=i;
			}
		ctx->buf_len=0;
		ctx->buf_off=0;
		}
	BIO_copy_next_retry(b);
	return(ret);
	}

static long enc_ctrl(b,cmd,num,ptr)
BIO *b;
int cmd;
long num;
char *ptr;
	{
	BIO *dbio;
	BIO_ENC_CTX *ctx,*dctx;
	long ret=1;
	int i;

	ctx=(BIO_ENC_CTX *)b->ptr;

	switch (cmd)
		{
	case BIO_CTRL_RESET:
		ctx->ok=1;
		ctx->finished=0;
		EVP_CipherInit(&(ctx->cipher),NULL,NULL,NULL,
			ctx->cipher.encrypt);
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
	case BIO_CTRL_EOF:	/* More to read */
		if (ctx->cont <= 0)
			ret=1;
		else
			ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
	case BIO_CTRL_WPENDING:
		ret=ctx->buf_len-ctx->buf_off;
		if (ret <= 0)
			ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
	case BIO_CTRL_PENDING: /* More to read in buffer */
		ret=ctx->buf_len-ctx->buf_off;
		if (ret <= 0)
			ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
	case BIO_CTRL_FLUSH:
		/* do a final write */
again:
		while (ctx->buf_len != ctx->buf_off)
			{
			i=enc_write(b,NULL,0);
			if (i < 0)
				{
				ret=i;
				break;
				}
			}

		if (!ctx->finished)
			{
			ctx->finished=1;
			ctx->buf_off=0;
			ret=EVP_CipherFinal(&(ctx->cipher),
				(unsigned char *)ctx->buf,
				&(ctx->buf_len));
			ctx->ok=(int)ret;
			if (ret <= 0) break;

			/* push out the bytes */
			goto again;
			}
		
		/* Finally flush the underlying BIO */
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
	case BIO_C_GET_CIPHER_STATUS:
		ret=(long)ctx->ok;
		break;
	case BIO_C_DO_STATE_MACHINE:
		BIO_clear_retry_flags(b);
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		BIO_copy_next_retry(b);
		break;

	case BIO_CTRL_DUP:
		dbio=(BIO *)ptr;
		dctx=(BIO_ENC_CTX *)dbio->ptr;
		memcpy(&(dctx->cipher),&(ctx->cipher),sizeof(ctx->cipher));
		dbio->init=1;
		break;
	default:
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
		}
	return(ret);
	}

/*
void BIO_set_cipher_ctx(b,c)
BIO *b;
EVP_CIPHER_ctx *c;
	{
	if (b == NULL) return;

	if ((b->callback != NULL) &&
		(b->callback(b,BIO_CB_CTRL,(char *)c,BIO_CTRL_SET,e,0L) <= 0))
		return;

	b->init=1;
	ctx=(BIO_ENC_CTX *)b->ptr;
	memcpy(ctx->cipher,c,sizeof(EVP_CIPHER_CTX));
	
	if (b->callback != NULL)
		b->callback(b,BIO_CB_CTRL,(char *)c,BIO_CTRL_SET,e,1L);
	}
*/

void BIO_set_cipher(b,c,k,i,e)
BIO *b;
EVP_CIPHER *c;
unsigned char *k;
unsigned char *i;
int e;
	{
	BIO_ENC_CTX *ctx;

	if (b == NULL) return;

	if ((b->callback != NULL) &&
		(b->callback(b,BIO_CB_CTRL,(char *)c,BIO_CTRL_SET,e,0L) <= 0))
		return;

	b->init=1;
	ctx=(BIO_ENC_CTX *)b->ptr;
	EVP_CipherInit(&(ctx->cipher),c,k,i,e);
	
	if (b->callback != NULL)
		b->callback(b,BIO_CB_CTRL,(char *)c,BIO_CTRL_SET,e,1L);
	}

