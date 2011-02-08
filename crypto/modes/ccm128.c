/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <openssl/crypto.h>
#include "modes_lcl.h"
#include <string.h>

#ifndef MODES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

typedef struct {
	union { u8 c[16]; size_t s[16/sizeof(size_t)]; } nonce, cmac,
							 scratch, inp;
	u64 blocks;
	block128_f block;
	void *key;
} CCM128_CONTEXT;

/* First you setup M and L parameters and pass the key schedule */
void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx,
	unsigned int M,unsigned int L,void *key,block128_f block)
{
	memset(ctx->nonce.c,0,sizeof(ctx->nonce.c));
	ctx->nonce.c[0] = ((u8)(L-1)&7) | (u8)(((M-2)/2)&7)<<3;
	ctx->blocks = 0;
	ctx->block = block;
	ctx->key = key;
}

/* !!! Following interfaces are to be called *once* per packet !!! */

/* Then you setup per-message nonce and pass the length of the message */
int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx,
	const unsigned char *nonce,size_t nlen,size_t mlen)
{
	unsigned int L = ctx->nonce.c[0]&7;	/* the L parameter */

	if (nlen<(14-L)) return -1;		/* nonce is too short */

	if (sizeof(mlen)==8 && L>=3) {
		ctx->nonce.c[8]  = (u8)(mlen>>(56%(sizeof(mlen)*8)));
		ctx->nonce.c[9]  = (u8)(mlen>>(48%(sizeof(mlen)*8)));
		ctx->nonce.c[10] = (u8)(mlen>>(40%(sizeof(mlen)*8)));
		ctx->nonce.c[11] = (u8)(mlen>>(32%(sizeof(mlen)*8)));
	}
	else
		*((size_t *)&ctx->nonce.s[8]) = 0;

	ctx->nonce.c[12] = (u8)(mlen>>24);
	ctx->nonce.c[13] = (u8)(mlen>>16);
	ctx->nonce.c[14] = (u8)(mlen>>8);
	ctx->nonce.c[15] = (u8)mlen;

	ctx->nonce.c[0] &= ~0x40;	/* clear Adata flag */
	memcpy(&ctx->nonce.c[1],nonce,14-L);

	return 0;
}

/* Then you pass additional authentication data, this is optional */
void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx,
	const unsigned char *aad,size_t alen)
{	unsigned int i;

	if (alen==0) return;

	ctx->nonce.c[0] |= 0x40;	/* set Adata flag */
	(*ctx->block)(ctx->nonce.c,ctx->cmac.c,ctx->key),
	ctx->blocks++;

	if (alen<(0x10000-0x100)) {
		ctx->cmac.c[0] ^= (u8)(alen>>8);
		ctx->cmac.c[1] ^= (u8)alen;
		i=2;
	}
	else if (sizeof(alen)==8 && alen>=(size_t)1<<32) {
		ctx->cmac.c[0] ^= 0xFF;
		ctx->cmac.c[1] ^= 0xFF;
		ctx->cmac.c[2] ^= (u8)(alen>>(56%(sizeof(alen)*8)));
		ctx->cmac.c[3] ^= (u8)(alen>>(48%(sizeof(alen)*8)));
		ctx->cmac.c[4] ^= (u8)(alen>>(40%(sizeof(alen)*8)));
		ctx->cmac.c[5] ^= (u8)(alen>>(32%(sizeof(alen)*8)));
		ctx->cmac.c[6] ^= (u8)(alen>>24);
		ctx->cmac.c[7] ^= (u8)(alen>>16);
		ctx->cmac.c[8] ^= (u8)(alen>>8);
		ctx->cmac.c[9] ^= (u8)alen;
		i=10;
	}
	else {
		ctx->cmac.c[0] ^= 0xFF;
		ctx->cmac.c[1] ^= 0xFE;
		ctx->cmac.c[2] ^= (u8)(alen>>24);
		ctx->cmac.c[3] ^= (u8)(alen>>16);
		ctx->cmac.c[4] ^= (u8)(alen>>8);
		ctx->cmac.c[5] ^= (u8)alen;
		i=6;
	}

	do {
		for(;i<16 && alen;++i,++aad,--alen)
			ctx->cmac.c[i] ^= *aad;
		(*ctx->block)(ctx->cmac.c,ctx->cmac.c,ctx->key),
		ctx->blocks++;
		i=0;
	} while (alen);
}

/* Finally you encrypt or decrypt the message */

static void ctr128_inc(unsigned char *counter) {
	unsigned int n=16;
	u8  c;

	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx,
	const unsigned char *inp, unsigned char *out,
	size_t len)
{
	size_t		n;
	unsigned int	i;
	unsigned char	flags = ctx->nonce.c[0];

	if (!(flags&0x40))
		(*ctx->block)(ctx->nonce.c,ctx->cmac.c,ctx->key),
		ctx->blocks++;

	flags &= 7;	/* extract the L parameter */
	for (n=0,i=15-flags;i<15;++i) {
		n |= ctx->nonce.c[i]; ctx->nonce.c[i]=0;
		n <<= 8;
	}
	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	if (n!=len) return -1;	/* length mismatch */

	ctx->blocks += ((len+15)>>3)|1;
	if (ctx->blocks > (U64(1)<<61))	return -2; /* too much data */

	while (len>=16) {
#if defined(STRICT_ALIGNMENT)
		memcpy (ctx->inp.c,inp,16);
		for (i=0; i<16/sizeof(size_t); ++i)
			ctx->cmac.s[i] ^= ctx->inp.s[i];
#else
		for (i=0; i<16/sizeof(size_t); ++i)
			ctx->cmac.s[i] ^= ((size_t*)inp)[i];
#endif
		(*ctx->block)(ctx->cmac.c,ctx->cmac.c,ctx->key);
		(*ctx->block)(ctx->nonce.c,ctx->scratch.c,ctx->key);
		ctr128_inc(ctx->nonce.c);
#if defined(STRICT_ALIGNMENT)
		for (i=0; i<16/sizeof(size_t); ++i)
			ctx->inp.s[i] ^= ctx->scratch.s[i];
		memcpy(out,ctx->inp.c,16);
#else
		for (i=0; i<16/sizeof(size_t); ++i)
			((size_t*)out)[i] = ctx->scratch.s[i]^((size_t*)inp)[i];
#endif
		inp += 16;
		out += 16;
		len -= 16;
	}

	if (len) {
		for (i=0; i<len; ++i) ctx->cmac.c[i] ^= inp[i];
		(*ctx->block)(ctx->cmac.c,ctx->cmac.c,ctx->key);
		(*ctx->block)(ctx->nonce.c,ctx->scratch.c,ctx->key);
		for (i=0; i<len; ++i) out[i] = ctx->scratch.c[i]^inp[i];
	}

	for (i=15-flags;i<16;++i)
		ctx->nonce.c[i]=0;

	(*ctx->block)(ctx->nonce.c,ctx->scratch.c,ctx->key);
	for (i=0; i<16/sizeof(size_t); ++i)
		ctx->cmac.s[i] ^= ctx->scratch.s[i];

	return 0;
}

int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx,
	const unsigned char *inp, unsigned char *out,
	size_t len)
{
	size_t		n;
	unsigned int	i;
	unsigned char	flags = ctx->nonce.c[0];

	if (!(flags&0x40))
		(*ctx->block)(ctx->nonce.c,ctx->cmac.c,ctx->key);

	flags &= 7;	/* extract the L parameter */
	for (n=0,i=15-flags;i<15;++i) {
		n |= ctx->nonce.c[i]; ctx->nonce.c[i]=0;
		n <<= 8;
	}
	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	if (n!=len) return -1;

	while (len>=16) {
		(*ctx->block)(ctx->nonce.c,ctx->scratch.c,ctx->key);
		ctr128_inc(ctx->nonce.c);
#if defined(STRICT_ALIGNMENT)
		memcpy (ctx->inp.c,inp,16);
		for (i=0; i<16/sizeof(size_t); ++i)
			ctx->cmac.s[i] ^= (ctx->scratch.s[i] ^= ctx->inp.s[i]);
		memcpy (out,ctx->scratch,16);
#else
		for (i=0; i<16/sizeof(size_t); ++i)
			ctx->cmac.s[i] ^= ((size_t*)out)[i] = ctx->scratch.s[i]^((size_t*)inp)[i];
#endif
		(*ctx->block)(ctx->cmac.c,ctx->cmac.c,ctx->key);

		inp += 16;
		out += 16;
		len -= 16;
	}

	if (len) {
		(*ctx->block)(ctx->nonce.c,ctx->scratch.c,ctx->key);
		for (i=0; i<len; ++len)
			ctx->cmac.c[i] ^= (out[i] = ctx->scratch.c[i]^inp[i]);
		(*ctx->block)(ctx->cmac.c,ctx->cmac.c,ctx->key);
	}

	for (i=15-flags;i<16;++i)
		ctx->nonce.c[i]=0;

	(*ctx->block)(ctx->nonce.c,ctx->scratch.c,ctx->key);
	for (i=0; i<16/sizeof(size_t); ++i)
		ctx->cmac.s[i] ^= ctx->scratch.s[i];

	return 0;
}

size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx,unsigned char *tag,size_t len)
{	unsigned int M = (ctx->nonce.c[0]>>3)&7;	/* the M parameter */

	M *= 2; M += 2;
	if (len<M)	return 0;
	memcpy(tag,ctx->cmac.c,M);
	return M;
}
