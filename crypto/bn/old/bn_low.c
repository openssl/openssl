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

static int bn_mm_low(BIGNUM *m,BIGNUM *A,BIGNUM *B, int num,
		BIGNUM *sk,BN_CTX *ctx);
int BN_mul_low(BIGNUM *r, BIGNUM *a, BIGNUM *b,int words);

/* r must be different to a and b */
int BN_mul_low(BIGNUM *r, BIGNUM *a, BIGNUM *b, int num)
	{
	BN_ULONG *ap,*bp,*rp;
	BIGNUM *sk;
	int j,i,n,ret;
	int max,al,bl;
	BN_CTX ctx;

	bn_check_top(a);
	bn_check_top(b);

#ifdef BN_MUL_DEBUG
printf("BN_mul_low(%d,%d,%d)\n",a->top,b->top,num);
#endif

	al=a->top;
	bl=b->top;
	if ((al == 0) || (bl == 0))
		{
		r->top=0;
		return(1);
		}

	if ((bn_limit_bits_low > 0) && (num > bn_limit_num_low))
		{
		n=BN_num_bits_word(num*2)-bn_limit_bits_low;
		n*=2;
		sk=(BIGNUM *)Malloc(sizeof(BIGNUM)*n);
		memset(sk,0,sizeof(BIGNUM)*n);
		memset(&ctx,0,sizeof(ctx));

		ret=bn_mm_low(r,a,b,num,&(sk[0]),&ctx);
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
	r->neg=a->neg^b->neg;
	ap=a->d;
	bp=b->d;
	rp=r->d;
	r->top=(max > num)?num:max;

	rp[al]=bn_mul_words(rp,ap,al,*(bp++));
	rp++;
	j=bl;
	for (i=1; i<j; i++)
		{
		if (al >= num--)
			{
			al--;
			if (al <= 0) break;
			}
		rp[al]=bn_mul_add_words(rp,ap,al,*(bp++));
		rp++;
		}
	
	while ((r->top > 0) && (r->d[r->top-1] == 0))
		r->top--;
	return(1);
	}


#define t1	(sk[0])
#define t2	(sk[1])

/* r must be different to a and b */
int bn_mm_low(BIGNUM *m, BIGNUM *A, BIGNUM *B, int num, BIGNUM *sk,
	     BN_CTX *ctx)
	{
	int n; /* ,sqr=0; */
	int an,bn;
	BIGNUM ah,al,bh,bl;

	bn_wexpand(m,num+3);
	an=A->top;
	bn=B->top;

#ifdef BN_MUL_DEBUG
printf("bn_mm_low(%d,%d,%d)\n",A->top,B->top,num);
#endif

	n=(num+1)/2;

	BN_init(&ah); BN_init(&al); BN_init(&bh); BN_init(&bl);

	bn_set_low( &al,A,n);
	bn_set_high(&ah,A,n);
	bn_set_low( &bl,B,n);
	bn_set_high(&bh,B,n);

	if (num <= (bn_limit_num_low+bn_limit_num_low))
		{
		BN_mul(m,&al,&bl);
		BN_mul_low(&t1,&al,&bh,n);
		BN_mul_low(&t2,&ah,&bl,n);
		}
	else
		{
		bn_mm(m  ,&al,&bl,&(sk[2]),ctx);
		bn_mm_low(&t1,&al,&bh,n,&(sk[2]),ctx);
		bn_mm_low(&t2,&ah,&bl,n,&(sk[2]),ctx);
		}

	BN_add(&t1,&t1,&t2);

	/* We will now do an evil hack instead of
	 * BN_lshift(&t1,&t1,n*BN_BITS2);
	 * BN_add(m,m,&t1);
	 * BN_mask_bits(m,num*BN_BITS2);
	 */
	bn_set_high(&ah,m,n); ah.max=num+2;
	BN_add(&ah,&ah,&t1);
	m->top=num;

	m->neg=A->neg^B->neg;
	return(1);
	}

#undef t1	(sk[0])
#undef t2	(sk[1])
