/* crypto/bn/bn_mul.c */
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
#include "bn_lcl.h"

static int bn_mm(BIGNUM *m,BIGNUM *A,BIGNUM *B, BIGNUM *sk,BN_CTX *ctx);

/* r must be different to a and b */
/* int BN_mmul(r, a, b) */
int BN_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b)
	{
	BN_ULONG *ap,*bp,*rp;
	BIGNUM *sk;
	int i,n,ret;
	int max,al,bl;
	BN_CTX ctx;

	bn_check_top(a);
	bn_check_top(b);

	al=a->top;
	bl=b->top;
	if ((al == 0) || (bl == 0))
		{
		r->top=0;
		return(1);
		}
#ifdef BN_MUL_DEBUG
printf("BN_mul(%d,%d)\n",a->top,b->top);
#endif

	if (	(bn_limit_bits > 0) &&
		(bl > bn_limit_num) && (al > bn_limit_num))
		{
		n=(BN_num_bits_word(al|bl)-bn_limit_bits);
		n*=2;
		sk=(BIGNUM *)Malloc(sizeof(BIGNUM)*n);
		memset(sk,0,sizeof(BIGNUM)*n);
		memset(&ctx,0,sizeof(ctx));

		ret=bn_mm(r,a,b,&(sk[0]),&ctx);
		for (i=0; i<n; i+=2)
			{
			BN_clear_free(&sk[i]);
			BN_clear_free(&sk[i+1]);
			}
		Free(sk);
		return(ret);
		}

	max=(al+bl);
	if (bn_wexpand(r,max) == NULL) return(0);
	r->top=max;
	r->neg=a->neg^b->neg;
	ap=a->d;
	bp=b->d;
	rp=r->d;

	rp[al]=bn_mul_words(rp,ap,al,*(bp++));
	rp++;
	for (i=1; i<bl; i++)
		{
		rp[al]=bn_mul_add_words(rp,ap,al,*(bp++));
		rp++;
		}
	if ((max > 0) && (r->d[max-1] == 0)) r->top--;
	return(1);
	}


#define ahal	(sk[0])
#define blbh	(sk[1])

/* r must be different to a and b */
int bn_mm(BIGNUM *m, BIGNUM *A, BIGNUM *B, BIGNUM *sk, BN_CTX *ctx)
	{
	int n,num,sqr=0;
	int an,bn;
	BIGNUM ah,al,bh,bl;

	an=A->top;
	bn=B->top;
#ifdef BN_MUL_DEBUG
printf("bn_mm(%d,%d)\n",A->top,B->top);
#endif

	if (A == B) sqr=1;
	num=(an>bn)?an:bn;
	n=(num+1)/2;
	/* Are going to now chop things into 'num' word chunks. */

	BN_init(&ah);
	BN_init(&al);
	BN_init(&bh);
	BN_init(&bl);

	bn_set_low (&al,A,n);
	bn_set_high(&ah,A,n);
	bn_set_low (&bl,B,n);
	bn_set_high(&bh,B,n);

	BN_sub(&ahal,&ah,&al);
	BN_sub(&blbh,&bl,&bh);

	if (num <= (bn_limit_num+bn_limit_num))
		{
		BN_mul(m,&ahal,&blbh);
		if (sqr)
			{
			BN_sqr(&ahal,&al,ctx);
			BN_sqr(&blbh,&ah,ctx);
			}
		else
			{
			BN_mul(&ahal,&al,&bl);
			BN_mul(&blbh,&ah,&bh);
			}
		}
	else
		{
		bn_mm(m,&ahal,&blbh,&(sk[2]),ctx);
		bn_mm(&ahal,&al,&bl,&(sk[2]),ctx);
		bn_mm(&blbh,&ah,&bh,&(sk[2]),ctx);
		}

	BN_add(m,m,&ahal);
	BN_add(m,m,&blbh);

	BN_lshift(m,m,n*BN_BITS2);
	BN_lshift(&blbh,&blbh,n*BN_BITS2*2);

	BN_add(m,m,&ahal);
	BN_add(m,m,&blbh);

	m->neg=A->neg^B->neg;
	return(1);
	}
#undef ahal	(sk[0])
#undef blbh	(sk[1])

#include "bn_low.c"
#include "bn_high.c"
