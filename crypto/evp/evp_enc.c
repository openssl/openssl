/* crypto/evp/evp_enc.c */
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
#include "cryptlib.h"
#include <openssl/evp.h>

const char *EVP_version="EVP" OPENSSL_VERSION_PTEXT;

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx)
	{
	memset(ctx,0,sizeof(EVP_CIPHER_CTX));
	/* ctx->cipher=NULL; */
	}

void EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *data,
	     unsigned char *key, unsigned char *iv, int enc)
	{
	if (enc)
		EVP_EncryptInit(ctx,data,key,iv);
	else	
		EVP_DecryptInit(ctx,data,key,iv);
	}

void EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
	     unsigned char *in, int inl)
	{
	if (ctx->encrypt)
		EVP_EncryptUpdate(ctx,out,outl,in,inl);
	else	EVP_DecryptUpdate(ctx,out,outl,in,inl);
	}

int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
	{
	if (ctx->encrypt)
		{
		EVP_EncryptFinal(ctx,out,outl);
		return(1);
		}
	else	return(EVP_DecryptFinal(ctx,out,outl));
	}

void EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
	     unsigned char *key, unsigned char *iv)
	{
	if (cipher != NULL)
		ctx->cipher=cipher;
	ctx->cipher->init(ctx,key,iv,1);
	ctx->encrypt=1;
	ctx->buf_len=0;
	}

void EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
	     unsigned char *key, unsigned char *iv)
	{
	if (cipher != NULL)
		ctx->cipher=cipher;
	ctx->cipher->init(ctx,key,iv,0);
	ctx->encrypt=0;
	ctx->buf_len=0;
	}


void EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
	     unsigned char *in, int inl)
	{
	int i,j,bl;

	i=ctx->buf_len;
	bl=ctx->cipher->block_size;
	*outl=0;
	if ((inl == 0) && (i != bl)) return;
	if (i != 0)
		{
		if (i+inl < bl)
			{
			memcpy(&(ctx->buf[i]),in,inl);
			ctx->buf_len+=inl;
			return;
			}
		else
			{
			j=bl-i;
			if (j != 0) memcpy(&(ctx->buf[i]),in,j);
			ctx->cipher->do_cipher(ctx,out,ctx->buf,bl);
			inl-=j;
			in+=j;
			out+=bl;
			*outl+=bl;
			}
		}
	i=inl%bl; /* how much is left */
	inl-=i;
	if (inl > 0)
		{
		ctx->cipher->do_cipher(ctx,out,in,inl);
		*outl+=inl;
		}

	if (i != 0)
		memcpy(ctx->buf,&(in[inl]),i);
	ctx->buf_len=i;
	}

void EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
	{
	int i,n,b,bl;

	b=ctx->cipher->block_size;
	if (b == 1)
		{
		*outl=0;
		return;
		}
	bl=ctx->buf_len;
	n=b-bl;
	for (i=bl; i<b; i++)
		ctx->buf[i]=n;
	ctx->cipher->do_cipher(ctx,out,ctx->buf,b);
	*outl=b;
	}

void EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
	     unsigned char *in, int inl)
	{
	int b,bl,n;
	int keep_last=0;

	*outl=0;
	if (inl == 0) return;

	b=ctx->cipher->block_size;
	if (b > 1)
		{
		/* Is the input a multiple of the block size? */
		bl=ctx->buf_len;
		n=inl+bl;
		if (n%b == 0)
			{
			if (inl < b) /* must be 'just one' buff */
				{
				memcpy(&(ctx->buf[bl]),in,inl);
				ctx->buf_len=b;
				*outl=0;
				return;
				}
			keep_last=1;
			inl-=b; /* don't do the last block */
			}
		}
	EVP_EncryptUpdate(ctx,out,outl,in,inl);

	/* if we have 'decrypted' a multiple of block size, make sure
	 * we have a copy of this last block */
	if (keep_last)
		{
		memcpy(&(ctx->buf[0]),&(in[inl]),b);
#ifdef DEBUG
		if (ctx->buf_len != 0)
			{
			abort();
			}
#endif
		ctx->buf_len=b;
		}
	}

int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
	{
	int i,b;
	int n;

	*outl=0;
	b=ctx->cipher->block_size;
	if (b > 1)
		{
		if (ctx->buf_len != b)
			{
			EVPerr(EVP_F_EVP_DECRYPTFINAL,EVP_R_WRONG_FINAL_BLOCK_LENGTH);
			return(0);
			}
		EVP_EncryptUpdate(ctx,ctx->buf,&n,ctx->buf,0);
		if (n != b)
			return(0);
		n=ctx->buf[b-1];
		if (n > b)
			{
			EVPerr(EVP_F_EVP_DECRYPTFINAL,EVP_R_BAD_DECRYPT);
			return(0);
			}
		for (i=0; i<n; i++)
			{
			if (ctx->buf[--b] != n)
				{
				EVPerr(EVP_F_EVP_DECRYPTFINAL,EVP_R_BAD_DECRYPT);
				return(0);
				}
			}
		n=ctx->cipher->block_size-n;
		for (i=0; i<n; i++)
			out[i]=ctx->buf[i];
		*outl=n;
		}
	else
		*outl=0;
	return(1);
	}

void EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *c)
	{
	if ((c->cipher != NULL) && (c->cipher->cleanup != NULL))
		c->cipher->cleanup(c);
	memset(c,0,sizeof(EVP_CIPHER_CTX));
	}

