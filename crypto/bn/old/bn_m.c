/* crypto/bn/bn_m.c */
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
/*#include "cryptlib.h"*/
#include "bn_lcl.h"

#define limit_bits 5			/* 2^5, or 32 words */
#define limit_num (1<<limit_bits)

int BN_m(BIGNUM *r, BIGNUM *a, BIGNUM *b)
	{
	BIGNUM *sk;
	int i,n;

	n=(BN_num_bits_word(a->top|b->top)-limit_bits);
	n*=2;
	sk=(BIGNUM *)malloc(sizeof(BIGNUM)*n);
	for (i=0; i<n; i++)
		BN_init(&(sk[i]));

	return(BN_mm(r,a,b,&(sk[0])));
	}

#define ahal	(sk[0])
#define blbh	(sk[1])

/* r must be different to a and b */
int BN_mm(BIGNUM *m, BIGNUM *A, BIGNUM *B, BIGNUM *sk)
	{
	int i,num,anum,bnum;
	int an,bn;
	BIGNUM ah,al,bh,bl;

	an=A->top;
	bn=B->top;
	if ((an <= limit_num) || (bn <= limit_num))
		{
		return(BN_mul(m,A,B));
		}

	anum=(an>bn)?an:bn;
	num=(anum)/2;

	/* Are going to now chop things into 'num' word chunks. */
	bnum=num*BN_BITS2;

	BN_init(&ahal);
	BN_init(&blbh);
	BN_init(&ah);
	BN_init(&al);
	BN_init(&bh);
	BN_init(&bl);

	al.top=num;
	al.d=A->d;
	ah.top=A->top-num;
	ah.d= &(A->d[num]);

	bl.top=num;
	bl.d=B->d;
	bh.top=B->top-num;
	bh.d= &(B->d[num]);

	BN_sub(&ahal,&ah,&al);
	BN_sub(&blbh,&bl,&bh);

	BN_mm(m,&ahal,&blbh,&(sk[2]));
	BN_mm(&ahal,&al,&bl,&(sk[2]));
	BN_mm(&blbh,&ah,&bh,&(sk[2]));

	BN_add(m,m,&ahal);
	BN_add(m,m,&blbh);

	BN_lshift(m,m,bnum);
	BN_add(m,m,&ahal);

	BN_lshift(&blbh,&blbh,bnum*2);
	BN_add(m,m,&blbh);

	m->neg=A->neg^B->neg;
	return(1);
	}

