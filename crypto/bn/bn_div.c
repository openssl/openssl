/* crypto/bn/bn_div.c */
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

/* The old slow way */
#if 0
int BN_div(dv, rem, m, d,ctx)
BIGNUM *dv;
BIGNUM *rem;
BIGNUM *m;
BIGNUM *d;
BN_CTX *ctx;
	{
	int i,nm,nd;
	BIGNUM *D;

	if (BN_is_zero(d))
		{
		BNerr(BN_F_BN_DIV,BN_R_DIV_BY_ZERO);
		return(0);
		}

	if (BN_ucmp(m,d) < 0)
		{
		if (rem != NULL)
			{ if (BN_copy(rem,m) == NULL) return(0); }
		if (dv != NULL) BN_zero(dv);
		return(1);
		}

	D=ctx->bn[ctx->tos];
	if (dv == NULL) dv=ctx->bn[ctx->tos+1];
	if (rem == NULL) rem=ctx->bn[ctx->tos+2];

	nd=BN_num_bits(d);
	nm=BN_num_bits(m);
	if (BN_copy(D,d) == NULL) return(0);
	if (BN_copy(rem,m) == NULL) return(0);

	/* The next 2 are needed so we can do a dv->d[0]|=1 later
	 * since BN_lshift1 will only work once there is a value :-) */
	BN_zero(dv);
	dv->top=1;

	if (!BN_lshift(D,D,nm-nd)) return(0);
	for (i=nm-nd; i>=0; i--)
		{
		if (!BN_lshift1(dv,dv)) return(0);
		if (BN_ucmp(rem,D) >= 0)
			{
			dv->d[0]|=1;
			bn_qsub(rem,rem,D);
			}
/* CAN IMPROVE (and have now :=) */
		if (!BN_rshift1(D,D)) return(0);
		}
	rem->neg=BN_is_zero(rem)?0:m->neg;
	dv->neg=m->neg^d->neg;
	return(1);
	}

#else

int BN_div(dv, rm, num, divisor,ctx)
BIGNUM *dv;
BIGNUM *rm;
BIGNUM *num;
BIGNUM *divisor;
BN_CTX *ctx;
	{
	int norm_shift,i,j,loop;
	BIGNUM *tmp,wnum,*snum,*sdiv,*res;
	BN_ULONG *resp,*wnump;
	BN_ULONG d0,d1;
	int num_n,div_n;

	if (BN_is_zero(divisor))
		{
		BNerr(BN_F_BN_DIV,BN_R_DIV_BY_ZERO);
		return(0);
		}

	if (BN_ucmp(num,divisor) < 0)
		{
		if (rm != NULL)
			{ if (BN_copy(rm,num) == NULL) return(0); }
		if (dv != NULL) BN_zero(dv);
		return(1);
		}

	tmp=ctx->bn[ctx->tos]; 
	tmp->neg=0;
	snum=ctx->bn[ctx->tos+1];
	sdiv=ctx->bn[ctx->tos+2];
	if (dv == NULL)
		res=ctx->bn[ctx->tos+3];
	else	res=dv;

	/* First we normalise the numbers */
	norm_shift=BN_BITS2-((BN_num_bits(divisor))%BN_BITS2);
	BN_lshift(sdiv,divisor,norm_shift);
	sdiv->neg=0;
	norm_shift+=BN_BITS2;
	BN_lshift(snum,num,norm_shift);
	snum->neg=0;
	div_n=sdiv->top;
	num_n=snum->top;
	loop=num_n-div_n;

	/* Lets setup a 'window' into snum
	 * This is the part that corresponds to the current
	 * 'area' being divided */
	wnum.d=	 &(snum->d[loop]);
	wnum.top= div_n;
	wnum.max= snum->max; /* a bit of a lie */
	wnum.neg= 0;

	/* Get the top 2 words of sdiv */
	/* i=sdiv->top; */
	d0=sdiv->d[div_n-1];
	d1=(div_n == 1)?0:sdiv->d[div_n-2];

	/* pointer to the 'top' of snum */
	wnump= &(snum->d[num_n-1]);

	/* Setup to 'res' */
	res->neg= (num->neg^divisor->neg);
	res->top=loop;
	if (!bn_wexpand(res,(loop+1))) goto err;
	resp= &(res->d[loop-1]);

	/* space for temp */
	if (!bn_wexpand(tmp,(div_n+1))) goto err;

	if (BN_ucmp(&wnum,sdiv) >= 0)
		{
		bn_qsub(&wnum,&wnum,sdiv);
		*resp=1;
		res->d[res->top-1]=1;
		}
	else
		res->top--;
	resp--;

	for (i=0; i<loop-1; i++)
		{
		BN_ULONG q,n0,n1;
		BN_ULONG l0;

		wnum.d--; wnum.top++;
		n0=wnump[0];
		n1=wnump[-1];
		if (n0 == d0)
			q=BN_MASK2;
		else
			q=bn_div64(n0,n1,d0);
		{
#ifdef BN_LLONG
		BN_ULLONG t1,t2,rem;
		t1=((BN_ULLONG)n0<<BN_BITS2)|n1;
		for (;;)
			{
			t2=(BN_ULLONG)d1*q;
			rem=t1-(BN_ULLONG)q*d0;
			if ((rem>>BN_BITS2) ||
				(t2 <= ((BN_ULLONG)(rem<<BN_BITS2)+wnump[-2])))
				break;
			q--;
			}
#else
		BN_ULONG t1l,t1h,t2l,t2h,t3l,t3h,ql,qh,t3t;
		t1h=n0;
		t1l=n1;
		for (;;)
			{
			t2l=LBITS(d1); t2h=HBITS(d1);
			ql =LBITS(q);  qh =HBITS(q);
			mul64(t2l,t2h,ql,qh); /* t2=(BN_ULLONG)d1*q; */

			t3t=LBITS(d0); t3h=HBITS(d0);
			mul64(t3t,t3h,ql,qh); /* t3=t1-(BN_ULLONG)q*d0; */
			t3l=(t1l-t3t)&BN_MASK2;
			if (t3l > t1l) t3h++;
			t3h=(t1h-t3h)&BN_MASK2;

			/*if ((t3>>BN_BITS2) ||
				(t2 <= ((t3<<BN_BITS2)+wnump[-2])))
				break; */
			if (t3h) break;
			if (t2h < t3l) break;
			if ((t2h == t3l) && (t2l <= wnump[-2])) break;

			q--;
			}
#endif
		}
		l0=bn_mul_words(tmp->d,sdiv->d,div_n,q);
		tmp->d[div_n]=l0;
		for (j=div_n+1; j>0; j--)
			if (tmp->d[j-1]) break;
		tmp->top=j;

		j=wnum.top;
		BN_sub(&wnum,&wnum,tmp);

		snum->top=snum->top+wnum.top-j;

		if (wnum.neg)
			{
			q--;
			j=wnum.top;
			BN_add(&wnum,&wnum,sdiv);
			snum->top+=wnum.top-j;
			}
		*(resp--)=q;
		wnump--;
		}
	if (rm != NULL)
		{
		BN_rshift(rm,snum,norm_shift);
		rm->neg=num->neg;
		}
	return(1);
err:
	return(0);
	}

#endif
