/* crypto/bn/bn_exp.c */
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

#define TABLE_SIZE	16

/* slow but works */
int BN_mod_mul(BIGNUM *ret, BIGNUM *a, BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
	{
	BIGNUM *t;
	int r=0;

	bn_check_top(a);
	bn_check_top(b);
	bn_check_top(m);

	t= &(ctx->bn[ctx->tos++]);
	if (a == b)
		{ if (!BN_sqr(t,a,ctx)) goto err; }
	else
		{ if (!BN_mul(t,a,b,ctx)) goto err; }
	if (!BN_mod(ret,t,m,ctx)) goto err;
	r=1;
err:
	ctx->tos--;
	return(r);
	}

#if 0
/* this one works - simple but works */
int BN_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m, BN_CTX *ctx)
	{
	int i,bits,ret=0;
	BIGNUM *v,*tmp;

	v= &(ctx->bn[ctx->tos++]);
	tmp= &(ctx->bn[ctx->tos++]);

	if (BN_copy(v,a) == NULL) goto err;
	bits=BN_num_bits(p);

	if (BN_is_odd(p))
		{ if (BN_copy(r,a) == NULL) goto err; }
	else	{ if (!BN_one(r)) goto err; }

	for (i=1; i<bits; i++)
		{
		if (!BN_sqr(tmp,v,ctx)) goto err;
		if (!BN_mod(v,tmp,m,ctx)) goto err;
		if (BN_is_bit_set(p,i))
			{
			if (!BN_mul(tmp,r,v,ctx)) goto err;
			if (!BN_mod(r,tmp,m,ctx)) goto err;
			}
		}
	ret=1;
err:
	ctx->tos-=2;
	return(ret);
	}

#endif

/* this one works - simple but works */
int BN_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BN_CTX *ctx)
	{
	int i,bits,ret=0,tos;
	BIGNUM *v,*rr;

	tos=ctx->tos;
	v= &(ctx->bn[ctx->tos++]);
	if ((r == a) || (r == p))
		rr= &(ctx->bn[ctx->tos++]);
	else
		rr=r;

	if (BN_copy(v,a) == NULL) goto err;
	bits=BN_num_bits(p);

	if (BN_is_odd(p))
		{ if (BN_copy(rr,a) == NULL) goto err; }
	else	{ if (!BN_one(rr)) goto err; }

	for (i=1; i<bits; i++)
		{
		if (!BN_sqr(v,v,ctx)) goto err;
		if (BN_is_bit_set(p,i))
			{
			if (!BN_mul(rr,rr,v,ctx)) goto err;
			}
		}
	ret=1;
err:
	ctx->tos=tos;
	if (r != rr) BN_copy(r,rr);
	return(ret);
	}

int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
	       BN_CTX *ctx)
	{
	int ret;

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

#ifdef MONT_MUL_MOD
	/* I have finally been able to take out this pre-condition of
	 * the top bit being set.  It was caused by an error in BN_div
	 * with negatives.  There was also another problem when for a^b%m
	 * a >= m.  eay 07-May-97 */
/*	if ((m->d[m->top-1]&BN_TBIT) && BN_is_odd(m)) */

	if (BN_is_odd(m))
		{ ret=BN_mod_exp_mont(r,a,p,m,ctx,NULL); }
	else
#endif
#ifdef RECP_MUL_MOD
		{ ret=BN_mod_exp_recp(r,a,p,m,ctx); }
#else
		{ ret=BN_mod_exp_simple(r,a,p,m,ctx); }
#endif

	return(ret);
	}

/* #ifdef RECP_MUL_MOD */
int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
		    const BIGNUM *m, BN_CTX *ctx)
	{
	int i,j,bits,ret=0,wstart,wend,window,wvalue;
	int start=1,ts=0;
	BIGNUM *aa;
	BIGNUM val[TABLE_SIZE];
	BN_RECP_CTX recp;

	aa= &(ctx->bn[ctx->tos++]);
	bits=BN_num_bits(p);

	if (bits == 0)
		{
		BN_one(r);
		return(1);
		}
	BN_RECP_CTX_init(&recp);
	if (BN_RECP_CTX_set(&recp,m,ctx) <= 0) goto err;

	BN_init(&(val[0]));
	ts=1;

	if (!BN_mod(&(val[0]),a,m,ctx)) goto err;		/* 1 */
	if (!BN_mod_mul_reciprocal(aa,&(val[0]),&(val[0]),&recp,ctx))
		goto err;				/* 2 */

	if (bits <= 17) /* This is probably 3 or 0x10001, so just do singles */
		window=1;
	else if (bits >= 256)
		window=5;	/* max size of window */
	else if (bits >= 128)
		window=4;
	else
		window=3;

	j=1<<(window-1);
	for (i=1; i<j; i++)
		{
		BN_init(&val[i]);
		if (!BN_mod_mul_reciprocal(&(val[i]),&(val[i-1]),aa,&recp,ctx))
			goto err;
		}
	ts=i;

	start=1;	/* This is used to avoid multiplication etc
			 * when there is only the value '1' in the
			 * buffer. */
	wvalue=0;	/* The 'value' of the window */
	wstart=bits-1;	/* The top bit of the window */
	wend=0;		/* The bottom bit of the window */

	if (!BN_one(r)) goto err;

	for (;;)
		{
		if (BN_is_bit_set(p,wstart) == 0)
			{
			if (!start)
				if (!BN_mod_mul_reciprocal(r,r,r,&recp,ctx))
				goto err;
			if (wstart == 0) break;
			wstart--;
			continue;
			}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j=wstart;
		wvalue=1;
		wend=0;
		for (i=1; i<window; i++)
			{
			if (wstart-i < 0) break;
			if (BN_is_bit_set(p,wstart-i))
				{
				wvalue<<=(i-wend);
				wvalue|=1;
				wend=i;
				}
			}

		/* wend is the size of the current window */
		j=wend+1;
		/* add the 'bytes above' */
		if (!start)
			for (i=0; i<j; i++)
				{
				if (!BN_mod_mul_reciprocal(r,r,r,&recp,ctx))
					goto err;
				}
		
		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul_reciprocal(r,r,&(val[wvalue>>1]),&recp,ctx))
			goto err;

		/* move the 'window' down further */
		wstart-=wend+1;
		wvalue=0;
		start=0;
		if (wstart < 0) break;
		}
	ret=1;
err:
	ctx->tos--;
	for (i=0; i<ts; i++)
		BN_clear_free(&(val[i]));
	BN_RECP_CTX_free(&recp);
	return(ret);
	}
/* #endif */

/* #ifdef MONT_MUL_MOD */
int BN_mod_exp_mont(BIGNUM *rr, BIGNUM *a, const BIGNUM *p,
		    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	int i,j,bits,ret=0,wstart,wend,window,wvalue;
	int start=1,ts=0;
	BIGNUM *d,*r;
	BIGNUM *aa;
	BIGNUM val[TABLE_SIZE];
	BN_MONT_CTX *mont=NULL;

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

	if (!(m->d[0] & 1))
		{
		BNerr(BN_F_BN_MOD_EXP_MONT,BN_R_CALLED_WITH_EVEN_MODULUS);
		return(0);
		}
	d= &(ctx->bn[ctx->tos++]);
	r= &(ctx->bn[ctx->tos++]);
	bits=BN_num_bits(p);
	if (bits == 0)
		{
		BN_one(r);
		return(1);
		}

	/* If this is not done, things will break in the montgomery
	 * part */

#if 1
	if (in_mont != NULL)
		mont=in_mont;
	else
#endif
		{
		if ((mont=BN_MONT_CTX_new()) == NULL) goto err;
		if (!BN_MONT_CTX_set(mont,m,ctx)) goto err;
		}

	BN_init(&val[0]);
	ts=1;
	if (BN_ucmp(a,m) >= 0)
		{
		BN_mod(&(val[0]),a,m,ctx);
		aa= &(val[0]);
		}
	else
		aa=a;
	if (!BN_to_montgomery(&(val[0]),aa,mont,ctx)) goto err; /* 1 */
	if (!BN_mod_mul_montgomery(d,&(val[0]),&(val[0]),mont,ctx)) goto err; /* 2 */

	if (bits <= 20) /* This is probably 3 or 0x10001, so just do singles */
		window=1;
	else if (bits >= 256)
		window=5;	/* max size of window */
	else if (bits >= 128)
		window=4;
	else
		window=3;

	j=1<<(window-1);
	for (i=1; i<j; i++)
		{
		BN_init(&(val[i]));
		if (!BN_mod_mul_montgomery(&(val[i]),&(val[i-1]),d,mont,ctx))
			goto err;
		}
	ts=i;

	start=1;	/* This is used to avoid multiplication etc
			 * when there is only the value '1' in the
			 * buffer. */
	wvalue=0;	/* The 'value' of the window */
	wstart=bits-1;	/* The top bit of the window */
	wend=0;		/* The bottom bit of the window */

        if (!BN_to_montgomery(r,BN_value_one(),mont,ctx)) goto err;
	for (;;)
		{
		if (BN_is_bit_set(p,wstart) == 0)
			{
			if (!start)
				{
				if (!BN_mod_mul_montgomery(r,r,r,mont,ctx))
				goto err;
				}
			if (wstart == 0) break;
			wstart--;
			continue;
			}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j=wstart;
		wvalue=1;
		wend=0;
		for (i=1; i<window; i++)
			{
			if (wstart-i < 0) break;
			if (BN_is_bit_set(p,wstart-i))
				{
				wvalue<<=(i-wend);
				wvalue|=1;
				wend=i;
				}
			}

		/* wend is the size of the current window */
		j=wend+1;
		/* add the 'bytes above' */
		if (!start)
			for (i=0; i<j; i++)
				{
				if (!BN_mod_mul_montgomery(r,r,r,mont,ctx))
					goto err;
				}
		
		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul_montgomery(r,r,&(val[wvalue>>1]),mont,ctx))
			goto err;

		/* move the 'window' down further */
		wstart-=wend+1;
		wvalue=0;
		start=0;
		if (wstart < 0) break;
		}
	BN_from_montgomery(rr,r,mont,ctx);
	ret=1;
err:
	if ((in_mont == NULL) && (mont != NULL)) BN_MONT_CTX_free(mont);
	ctx->tos-=2;
	for (i=0; i<ts; i++)
		BN_clear_free(&(val[i]));
	return(ret);
	}
/* #endif */

/* The old fallback, simple version :-) */
int BN_mod_exp_simple(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m,
	     BN_CTX *ctx)
	{
	int i,j,bits,ret=0,wstart,wend,window,wvalue,ts=0;
	int start=1;
	BIGNUM *d;
	BIGNUM val[TABLE_SIZE];

	d= &(ctx->bn[ctx->tos++]);
	bits=BN_num_bits(p);

	if (bits == 0)
		{
		BN_one(r);
		return(1);
		}

	BN_init(&(val[0]));
	ts=1;
	if (!BN_mod(&(val[0]),a,m,ctx)) goto err;		/* 1 */
	if (!BN_mod_mul(d,&(val[0]),&(val[0]),m,ctx))
		goto err;				/* 2 */

	if (bits <= 17) /* This is probably 3 or 0x10001, so just do singles */
		window=1;
	else if (bits >= 256)
		window=5;	/* max size of window */
	else if (bits >= 128)
		window=4;
	else
		window=3;

	j=1<<(window-1);
	for (i=1; i<j; i++)
		{
		BN_init(&(val[i]));
		if (!BN_mod_mul(&(val[i]),&(val[i-1]),d,m,ctx))
			goto err;
		}
	ts=i;

	start=1;	/* This is used to avoid multiplication etc
			 * when there is only the value '1' in the
			 * buffer. */
	wvalue=0;	/* The 'value' of the window */
	wstart=bits-1;	/* The top bit of the window */
	wend=0;		/* The bottom bit of the window */

	if (!BN_one(r)) goto err;

	for (;;)
		{
		if (BN_is_bit_set(p,wstart) == 0)
			{
			if (!start)
				if (!BN_mod_mul(r,r,r,m,ctx))
				goto err;
			if (wstart == 0) break;
			wstart--;
			continue;
			}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j=wstart;
		wvalue=1;
		wend=0;
		for (i=1; i<window; i++)
			{
			if (wstart-i < 0) break;
			if (BN_is_bit_set(p,wstart-i))
				{
				wvalue<<=(i-wend);
				wvalue|=1;
				wend=i;
				}
			}

		/* wend is the size of the current window */
		j=wend+1;
		/* add the 'bytes above' */
		if (!start)
			for (i=0; i<j; i++)
				{
				if (!BN_mod_mul(r,r,r,m,ctx))
					goto err;
				}
		
		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul(r,r,&(val[wvalue>>1]),m,ctx))
			goto err;

		/* move the 'window' down further */
		wstart-=wend+1;
		wvalue=0;
		start=0;
		if (wstart < 0) break;
		}
	ret=1;
err:
	ctx->tos--;
	for (i=0; i<ts; i++)
		BN_clear_free(&(val[i]));
	return(ret);
	}

