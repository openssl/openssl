/* crypto/bn/bn_mont.c */
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

/*
 * Details about Montgomery multiplication algorithms can be found at
 * http://security.ece.orst.edu/publications.html, e.g.
 * http://security.ece.orst.edu/koc/papers/j37acmon.pdf and
 * sections 3.8 and 4.2 in http://security.ece.orst.edu/koc/papers/r01rsasw.pdf
 */

#include <stdio.h>
#include "cryptlib.h"
#include "bn_lcl.h"

#define MONT_WORD /* use the faster word-based algorithm */

int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
			  BN_MONT_CTX *mont, BN_CTX *ctx)
	{
	BIGNUM *tmp;
	int ret=0;

	BN_CTX_start(ctx);
	tmp = BN_CTX_get(ctx);
	if (tmp == NULL) goto err;

	bn_check_top(tmp);
	if (a == b)
		{
		if (!BN_sqr(tmp,a,ctx)) goto err;
		}
	else
		{
		if (!BN_mul(tmp,a,b,ctx)) goto err;
		}
	/* reduce from aRR to aR */
	if (!BN_from_montgomery(r,tmp,mont,ctx)) goto err;
	ret=1;
err:
	BN_CTX_end(ctx);
	return(ret);
	}

int BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
	     BN_CTX *ctx)
	{
	int retn=0;

#ifdef MONT_WORD
	BIGNUM *n,*r;
	BN_ULONG *ap,*np,*rp,n0,v,*nrp;
	int al,nl,max,i,x,ri;

	BN_CTX_start(ctx);
	if ((r = BN_CTX_get(ctx)) == NULL) goto err;

	if (!BN_copy(r,a)) goto err;
	n= &(mont->N);

	ap=a->d;
	/* mont->ri is the size of mont->N in bits (rounded up
	   to the word size) */
	al=ri=mont->ri/BN_BITS2;
	
	nl=n->top;
	if ((al == 0) || (nl == 0)) { r->top=0; return(1); }

	max=(nl+al+1); /* allow for overflow (no?) XXX */
	if (bn_wexpand(r,max) == NULL) goto err;
	if (bn_wexpand(ret,max) == NULL) goto err;

	r->neg=a->neg^n->neg;
	np=n->d;
	rp=r->d;
	nrp= &(r->d[nl]);

	/* clear the top words of T */
#if 1
	for (i=r->top; i<max; i++) /* memset? XXX */
		r->d[i]=0;
#else
	memset(&(r->d[r->top]),0,(max-r->top)*sizeof(BN_ULONG)); 
#endif

	r->top=max;
	n0=mont->n0;

#ifdef BN_COUNT
	fprintf(stderr,"word BN_from_montgomery %d * %d\n",nl,nl);
#endif
	for (i=0; i<nl; i++)
		{
#ifdef __TANDEM
                {
                   long long t1;
                   long long t2;
                   long long t3;
                   t1 = rp[0] * (n0 & 0177777);
                   t2 = 037777600000l;
                   t2 = n0 & t2;
                   t3 = rp[0] & 0177777;
                   t2 = (t3 * t2) & BN_MASK2;
                   t1 = t1 + t2;
                   v=bn_mul_add_words(rp,np,nl,(BN_ULONG) t1);
                }
#else
		v=bn_mul_add_words(rp,np,nl,(rp[0]*n0)&BN_MASK2);
#endif
		nrp++;
		rp++;
		if (((nrp[-1]+=v)&BN_MASK2) >= v)
			continue;
		else
			{
			if (((++nrp[0])&BN_MASK2) != 0) continue;
			if (((++nrp[1])&BN_MASK2) != 0) continue;
			for (x=2; (((++nrp[x])&BN_MASK2) == 0); x++) ;
			}
		}
	bn_fix_top(r);
	
	/* mont->ri will be a multiple of the word size */
#if 0
	BN_rshift(ret,r,mont->ri);
#else
	ret->neg = r->neg;
	x=ri;
	rp=ret->d;
	ap= &(r->d[x]);
	if (r->top < x)
		al=0;
	else
		al=r->top-x;
	ret->top=al;
	al-=4;
	for (i=0; i<al; i+=4)
		{
		BN_ULONG t1,t2,t3,t4;
		
		t1=ap[i+0];
		t2=ap[i+1];
		t3=ap[i+2];
		t4=ap[i+3];
		rp[i+0]=t1;
		rp[i+1]=t2;
		rp[i+2]=t3;
		rp[i+3]=t4;
		}
	al+=4;
	for (; i<al; i++)
		rp[i]=ap[i];
#endif
#else /* !MONT_WORD */ 
	BIGNUM *t1,*t2;

	BN_CTX_start(ctx);
	t1 = BN_CTX_get(ctx);
	t2 = BN_CTX_get(ctx);
	if (t1 == NULL || t2 == NULL) goto err;
	
	if (!BN_copy(t1,a)) goto err;
	BN_mask_bits(t1,mont->ri);

	if (!BN_mul(t2,t1,&mont->Ni,ctx)) goto err;
	BN_mask_bits(t2,mont->ri);

	if (!BN_mul(t1,t2,&mont->N,ctx)) goto err;
	if (!BN_add(t2,a,t1)) goto err;
	if (!BN_rshift(ret,t2,mont->ri)) goto err;
#endif /* MONT_WORD */

	if (BN_ucmp(ret, &(mont->N)) >= 0)
		{
		if (!BN_usub(ret,ret,&(mont->N))) goto err;
		}
	retn=1;
 err:
	BN_CTX_end(ctx);
	return(retn);
	}

BN_MONT_CTX *BN_MONT_CTX_new(void)
	{
	BN_MONT_CTX *ret;

	if ((ret=(BN_MONT_CTX *)OPENSSL_malloc(sizeof(BN_MONT_CTX))) == NULL)
		return(NULL);

	BN_MONT_CTX_init(ret);
	ret->flags=BN_FLG_MALLOCED;
	return(ret);
	}

void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
	{
	ctx->ri=0;
	BN_init(&(ctx->RR));
	BN_init(&(ctx->N));
	BN_init(&(ctx->Ni));
	ctx->flags=0;
	}

void BN_MONT_CTX_free(BN_MONT_CTX *mont)
	{
	if(mont == NULL)
	    return;

	BN_free(&(mont->RR));
	BN_free(&(mont->N));
	BN_free(&(mont->Ni));
	if (mont->flags & BN_FLG_MALLOCED)
		OPENSSL_free(mont);
	}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
	{
	BIGNUM Ri,*R;

	BN_init(&Ri);
	R= &(mont->RR);					/* grab RR as a temp */
	BN_copy(&(mont->N),mod);			/* Set N */
	mont->N.neg = 0;

#ifdef MONT_WORD
		{
		BIGNUM tmod;
		BN_ULONG buf[2];

		mont->ri=(BN_num_bits(mod)+(BN_BITS2-1))/BN_BITS2*BN_BITS2;
		if (!(BN_zero(R))) goto err;
		if (!(BN_set_bit(R,BN_BITS2))) goto err;	/* R */

		buf[0]=mod->d[0]; /* tmod = N mod word size */
		buf[1]=0;
		tmod.d=buf;
		tmod.top=1;
		tmod.dmax=2;
		tmod.neg=0;
							/* Ri = R^-1 mod N*/
		if ((BN_mod_inverse(&Ri,R,&tmod,ctx)) == NULL)
			goto err;
		if (!BN_lshift(&Ri,&Ri,BN_BITS2)) goto err; /* R*Ri */
		if (!BN_is_zero(&Ri))
			{
			if (!BN_sub_word(&Ri,1)) goto err;
			}
		else /* if N mod word size == 1 */
			{
			if (!BN_set_word(&Ri,BN_MASK2)) goto err;  /* Ri-- (mod word size) */
			}
		if (!BN_div(&Ri,NULL,&Ri,&tmod,ctx)) goto err;
		/* Ni = (R*Ri-1)/N,
		 * keep only least significant word: */
		mont->n0 = (Ri.top > 0) ? Ri.d[0] : 0;
		BN_free(&Ri);
		}
#else /* !MONT_WORD */
		{ /* bignum version */
		mont->ri=BN_num_bits(&mont->N);
		if (!BN_zero(R)) goto err;
		if (!BN_set_bit(R,mont->ri)) goto err;  /* R = 2^ri */
		                                        /* Ri = R^-1 mod N*/
		if ((BN_mod_inverse(&Ri,R,&mont->N,ctx)) == NULL)
			goto err;
		if (!BN_lshift(&Ri,&Ri,mont->ri)) goto err; /* R*Ri */
		if (!BN_sub_word(&Ri,1)) goto err;
							/* Ni = (R*Ri-1) / N */
		if (!BN_div(&(mont->Ni),NULL,&Ri,&mont->N,ctx)) goto err;
		BN_free(&Ri);
		}
#endif

	/* setup RR for conversions */
	if (!BN_zero(&(mont->RR))) goto err;
	if (!BN_set_bit(&(mont->RR),mont->ri*2)) goto err;
	if (!BN_mod(&(mont->RR),&(mont->RR),&(mont->N),ctx)) goto err;

	return(1);
err:
	return(0);
	}

BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from)
	{
	if (to == from) return(to);

	if (!BN_copy(&(to->RR),&(from->RR))) return NULL;
	if (!BN_copy(&(to->N),&(from->N))) return NULL;
	if (!BN_copy(&(to->Ni),&(from->Ni))) return NULL;
	to->ri=from->ri;
	to->n0=from->n0;
	return(to);
	}

