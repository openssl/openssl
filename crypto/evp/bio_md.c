/* crypto/evp/bio_md.c */
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

/* BIO_put and BIO_get both add to the digest,
 * BIO_gets returns the digest */

#ifndef NOPROTO
static int md_write(BIO *h,char *buf,int num);
static int md_read(BIO *h,char *buf,int size);
/*static int md_puts(BIO *h,char *str); */
static int md_gets(BIO *h,char *str,int size);
static long md_ctrl(BIO *h,int cmd,long arg1,char *arg2);
static int md_new(BIO *h);
static int md_free(BIO *data);
#else
static int md_write();
static int md_read();
/*static int md_puts(); */
static int md_gets();
static long md_ctrl();
static int md_new();
static int md_free();
#endif

static BIO_METHOD methods_md=
	{
	BIO_TYPE_MD,"message digest",
	md_write,
	md_read,
	NULL, /* md_puts, */
	md_gets,
	md_ctrl,
	md_new,
	md_free,
	};

BIO_METHOD *BIO_f_md()
	{
	return(&methods_md);
	}

static int md_new(bi)
BIO *bi;
	{
	EVP_MD_CTX *ctx;

	ctx=(EVP_MD_CTX *)Malloc(sizeof(EVP_MD_CTX));
	if (ctx == NULL) return(0);

	bi->init=0;
	bi->ptr=(char *)ctx;
	bi->flags=0;
	return(1);
	}

static int md_free(a)
BIO *a;
	{
	if (a == NULL) return(0);
	Free(a->ptr);
	a->ptr=NULL;
	a->init=0;
	a->flags=0;
	return(1);
	}
	
static int md_read(b,out,outl)
BIO *b;
char *out;
int outl;
	{
	int ret=0;
	EVP_MD_CTX *ctx;

	if (out == NULL) return(0);
	ctx=(EVP_MD_CTX *)b->ptr;

	if ((ctx == NULL) || (b->next_bio == NULL)) return(0);

	ret=BIO_read(b->next_bio,out,outl);
	if (b->init)
		{
		if (ret > 0)
			{
			EVP_DigestUpdate(ctx,(unsigned char *)out,
				(unsigned int)ret);
			}
		}
	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);
	return(ret);
	}

static int md_write(b,in,inl)
BIO *b;
char *in;
int inl;
	{
	int ret=0;
	EVP_MD_CTX *ctx;

	if ((in == NULL) || (inl <= 0)) return(0);
	ctx=(EVP_MD_CTX *)b->ptr;

	if ((ctx != NULL) && (b->next_bio != NULL))
		ret=BIO_write(b->next_bio,in,inl);
	if (b->init)
		{
		if (ret > 0)
			{
			EVP_DigestUpdate(ctx,(unsigned char *)in,
				(unsigned int)ret);
			}
		}
	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);
	return(ret);
	}

static long md_ctrl(b,cmd,num,ptr)
BIO *b;
int cmd;
long num;
char *ptr;
	{
	EVP_MD_CTX *ctx,*dctx,**pctx;
	EVP_MD **ppmd;
	EVP_MD *md;
	long ret=1;
	BIO *dbio;

	ctx=(EVP_MD_CTX *)b->ptr;

	switch (cmd)
		{
	case BIO_CTRL_RESET:
		if (b->init)
			EVP_DigestInit(ctx,ctx->digest);
		else
			ret=0;
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
	case BIO_C_GET_MD:
		if (b->init)
			{
			ppmd=(EVP_MD **)ptr;
			*ppmd=ctx->digest;
			}
		else
			ret=0;
		break;
	case BIO_C_GET_MD_CTX:
		if (b->init)
			{
			pctx=(EVP_MD_CTX **)ptr;
			*pctx=ctx;
			}
		else
			ret=0;
		break;
	case BIO_C_DO_STATE_MACHINE:
		BIO_clear_retry_flags(b);
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		BIO_copy_next_retry(b);
		break;

	case BIO_C_SET_MD:
		md=(EVP_MD *)ptr;
		EVP_DigestInit(ctx,md);
		b->init=1;
		break;
	case BIO_CTRL_DUP:
		dbio=(BIO *)ptr;
		dctx=(EVP_MD_CTX *)dbio->ptr;
		memcpy(dctx,ctx,sizeof(ctx));
		b->init=1;
		break;
	default:
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
		}
	return(ret);
	}

static int md_gets(bp,buf,size)
BIO *bp;
char *buf;
int size;
	{
	EVP_MD_CTX *ctx;
	unsigned int ret;


	ctx=(EVP_MD_CTX *)bp->ptr;
	if (size < ctx->digest->md_size)
		return(0);
	EVP_DigestFinal(ctx,(unsigned char *)buf,&ret);
	return((int)ret);
	}

/*
static int md_puts(bp,str)
BIO *bp;
char *str;
	{
	return(-1);
	}
*/

