/* crypto/evp/bio_b64.c */
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
#include <openssl/buffer.h>
#include <openssl/evp.h>

static int b64_write(BIO *h,char *buf,int num);
static int b64_read(BIO *h,char *buf,int size);
/*static int b64_puts(BIO *h,char *str); */
/*static int b64_gets(BIO *h,char *str,int size); */
static long b64_ctrl(BIO *h,int cmd,long arg1,char *arg2);
static int b64_new(BIO *h);
static int b64_free(BIO *data);
#define B64_BLOCK_SIZE	1024
#define B64_BLOCK_SIZE2	768
#define B64_NONE	0
#define B64_ENCODE	1
#define B64_DECODE	2

typedef struct b64_struct
	{
	/*BIO *bio; moved to the BIO structure */
	int buf_len;
	int buf_off;
	int tmp_len;		/* used to find the start when decoding */
	int tmp_nl;		/* If true, scan until '\n' */
	int encode;
	int start;		/* have we started decoding yet? */
	int cont;		/* <= 0 when finished */
	EVP_ENCODE_CTX base64;
	char buf[EVP_ENCODE_LENGTH(B64_BLOCK_SIZE)+10];
	char tmp[B64_BLOCK_SIZE];
	} BIO_B64_CTX;

static BIO_METHOD methods_b64=
	{
	BIO_TYPE_BASE64,"base64 encoding",
	b64_write,
	b64_read,
	NULL, /* b64_puts, */
	NULL, /* b64_gets, */
	b64_ctrl,
	b64_new,
	b64_free,
	};

BIO_METHOD *BIO_f_base64(void)
	{
	return(&methods_b64);
	}

static int b64_new(BIO *bi)
	{
	BIO_B64_CTX *ctx;

	ctx=(BIO_B64_CTX *)Malloc(sizeof(BIO_B64_CTX));
	if (ctx == NULL) return(0);

	ctx->buf_len=0;
	ctx->tmp_len=0;
	ctx->tmp_nl=0;
	ctx->buf_off=0;
	ctx->cont=1;
	ctx->start=1;
	ctx->encode=0;

	bi->init=1;
	bi->ptr=(char *)ctx;
	bi->flags=0;
	return(1);
	}

static int b64_free(BIO *a)
	{
	if (a == NULL) return(0);
	Free(a->ptr);
	a->ptr=NULL;
	a->init=0;
	a->flags=0;
	return(1);
	}
	
static int b64_read(BIO *b, char *out, int outl)
	{
	int ret=0,i,ii,j,k,x,n,num,ret_code=0;
	BIO_B64_CTX *ctx;
	unsigned char *p,*q;

	if (out == NULL) return(0);
	ctx=(BIO_B64_CTX *)b->ptr;

	if ((ctx == NULL) || (b->next_bio == NULL)) return(0);

	if (ctx->encode != B64_DECODE)
		{
		ctx->encode=B64_DECODE;
		ctx->buf_len=0;
		ctx->buf_off=0;
		ctx->tmp_len=0;
		EVP_DecodeInit(&(ctx->base64));
		}

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

	ret_code=0;
	while (outl > 0)
		{
		if (ctx->cont <= 0) break;

		i=BIO_read(b->next_bio,&(ctx->tmp[ctx->tmp_len]),
			B64_BLOCK_SIZE-ctx->tmp_len);

		if (i <= 0)
			{
			ret_code=i;

			/* Should be continue next time we are called? */
			if (!BIO_should_retry(b->next_bio))
				ctx->cont=i;
			/* else we should continue when called again */
			break;
			}
		i+=ctx->tmp_len;

		/* We need to scan, a line at a time until we
		 * have a valid line if we are starting. */
		if (ctx->start && (BIO_get_flags(b) & BIO_FLAGS_BASE64_NO_NL))
			{
			/* ctx->start=1; */
			ctx->tmp_len=0;
			}
		else if (ctx->start)
			{
			q=p=(unsigned char *)ctx->tmp;
			for (j=0; j<i; j++)
				{
				if (*(q++) != '\n') continue;

				/* due to a previous very long line,
				 * we need to keep on scanning for a '\n'
				 * before we even start looking for
				 * base64 encoded stuff. */
				if (ctx->tmp_nl)
					{
					p=q;
					ctx->tmp_nl=0;
					continue;
					}

				k=EVP_DecodeUpdate(&(ctx->base64),
					(unsigned char *)ctx->buf,
					&num,p,q-p);
				if ((k <= 0) && (num == 0) && (ctx->start))
					EVP_DecodeInit(&ctx->base64);
				else 
					{
					if (p != (unsigned char *)
						&(ctx->tmp[0]))
						{
						i-=(p- (unsigned char *)
							&(ctx->tmp[0]));
						for (x=0; x < i; x++)
							ctx->tmp[x]=p[x];
						EVP_DecodeInit(&ctx->base64);
						}
					ctx->start=0;
					break;
					}
				p=q;
				}

			/* we fell off the end without starting */
			if (j == i)
				{
				/* Is this is one long chunk?, if so, keep on
				 * reading until a new line. */
				if (p == (unsigned char *)&(ctx->tmp[0]))
					{
					ctx->tmp_nl=1;
					ctx->tmp_len=0;
					}
				else if (p != q) /* finished on a '\n' */
					{
					n=q-p;
					for (ii=0; ii<n; ii++)
						ctx->tmp[ii]=p[ii];
					ctx->tmp_len=n;
					}
				/* else finished on a '\n' */
				continue;
				}
			else
				ctx->tmp_len=0;
			}

		if (BIO_get_flags(b) & BIO_FLAGS_BASE64_NO_NL)
			{
			int z,jj;

			jj=(i>>2)<<2;
			z=EVP_DecodeBlock((unsigned char *)ctx->buf,
				(unsigned char *)ctx->tmp,jj);
			if (jj > 2)
				{
				if (ctx->tmp[jj-1] == '=')
					{
					z--;
					if (ctx->tmp[jj-2] == '=')
						z--;
					}
				}
			/* z is now number of output bytes and jj is the
			 * number consumed */
			if (jj != i)
				{
				memcpy((unsigned char *)ctx->tmp,
					(unsigned char *)&(ctx->tmp[jj]),i-jj);
				ctx->tmp_len=i-jj;
				}
			ctx->buf_len=0;
			if (z > 0)
				{
				ctx->buf_len=z;
				i=1;
				}
			else
				i=z;
			}
		else
			{
			i=EVP_DecodeUpdate(&(ctx->base64),
				(unsigned char *)ctx->buf,&ctx->buf_len,
				(unsigned char *)ctx->tmp,i);
			}
		ctx->cont=i;
		ctx->buf_off=0;
		if (i < 0)
			{
			ret_code=0;
			ctx->buf_len=0;
			break;
			}

		if (ctx->buf_len <= outl)
			i=ctx->buf_len;
		else
			i=outl;

		memcpy(out,ctx->buf,i);
		ret+=i;
		ctx->buf_off=i;
		if (ctx->buf_off == ctx->buf_len)
			{
			ctx->buf_len=0;
			ctx->buf_off=0;
			}
		outl-=i;
		out+=i;
		}
	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);
	return((ret == 0)?ret_code:ret);
	}

static int b64_write(BIO *b, char *in, int inl)
	{
	int ret=inl,n,i;
	BIO_B64_CTX *ctx;

	ctx=(BIO_B64_CTX *)b->ptr;
	BIO_clear_retry_flags(b);

	if (ctx->encode != B64_ENCODE)
		{
		ctx->encode=B64_ENCODE;
		ctx->buf_len=0;
		ctx->buf_off=0;
		ctx->tmp_len=0;
		EVP_EncodeInit(&(ctx->base64));
		}

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
		n=(inl > B64_BLOCK_SIZE)?B64_BLOCK_SIZE:inl;

		if (BIO_get_flags(b) & BIO_FLAGS_BASE64_NO_NL)
			{
			if (ctx->tmp_len > 0)
				{
				n=3-ctx->tmp_len;
				memcpy(&(ctx->tmp[ctx->tmp_len]),in,n);
				ctx->tmp_len+=n;
				n=ctx->tmp_len;
				if (n < 3)
					break;
				ctx->buf_len=EVP_EncodeBlock(
					(unsigned char *)ctx->buf,
					(unsigned char *)ctx->tmp,n);
				}
			else
				{
				if (n < 3)
					{
					memcpy(&(ctx->tmp[0]),in,n);
					ctx->tmp_len=n;
					break;
					}
				n-=n%3;
				ctx->buf_len=EVP_EncodeBlock(
					(unsigned char *)ctx->buf,
					(unsigned char *)in,n);
				}
			}
		else
			{
			EVP_EncodeUpdate(&(ctx->base64),
				(unsigned char *)ctx->buf,&ctx->buf_len,
				(unsigned char *)in,n);
			}
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
				return((ret == 0)?i:ret);
				}
			n-=i;
			ctx->buf_off+=i;
			}
		ctx->buf_len=0;
		ctx->buf_off=0;
		}
	return(ret);
	}

static long b64_ctrl(BIO *b, int cmd, long num, char *ptr)
	{
	BIO_B64_CTX *ctx;
	long ret=1;
	int i;

	ctx=(BIO_B64_CTX *)b->ptr;

	switch (cmd)
		{
	case BIO_CTRL_RESET:
		ctx->cont=1;
		ctx->start=1;
		ctx->encode=B64_NONE;
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
	case BIO_CTRL_EOF:	/* More to read */
		if (ctx->cont <= 0)
			ret=1;
		else
			ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
	case BIO_CTRL_WPENDING: /* More to write in buffer */
		ret=ctx->buf_len-ctx->buf_off;
		if ((ret == 0) && (ctx->base64.num != 0))
			ret=1;
		else if (ret <= 0)
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
			i=b64_write(b,NULL,0);
			if (i < 0)
				{
				ret=i;
				break;
				}
			}
		if (BIO_get_flags(b) & BIO_FLAGS_BASE64_NO_NL)
			{
			if (ctx->tmp_len != 0)
				{
				ctx->buf_len=EVP_EncodeBlock(
					(unsigned char *)ctx->buf,
					(unsigned char *)ctx->tmp,
					ctx->tmp_len);
				ctx->buf_off=0;
				ctx->tmp_len=0;
				goto again;
				}
			}
		else if (ctx->base64.num != 0)
			{
			ctx->buf_off=0;
			EVP_EncodeFinal(&(ctx->base64),
				(unsigned char *)ctx->buf,
				&(ctx->buf_len));
			/* push out the bytes */
			goto again;
			}
		/* Finally flush the underlying BIO */
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;

	case BIO_C_DO_STATE_MACHINE:
		BIO_clear_retry_flags(b);
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		BIO_copy_next_retry(b);
		break;

	case BIO_CTRL_DUP:
		break;
	case BIO_CTRL_INFO:
	case BIO_CTRL_GET:
	case BIO_CTRL_SET:
	default:
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
		}
	return(ret);
	}

