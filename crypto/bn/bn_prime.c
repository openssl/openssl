/* crypto/bn/bn_prime.c */
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
#include <time.h>
#include "cryptlib.h"
#include "bn_lcl.h"
#include "rand.h"

/* The quick seive algorithm approach to weeding out primes is
 * Philip Zimmermann's, as implemented in PGP.  I have had a read of
 * his comments and implemented my own version.
 */
#include "bn_prime.h"

#ifndef NOPROTO
static int witness(BIGNUM *a, BIGNUM *n, BN_CTX *ctx,BN_CTX *ctx2,
	BN_MONT_CTX *mont);
static int probable_prime(BIGNUM *rnd, int bits);
static int probable_prime_dh(BIGNUM *rnd, int bits,
	BIGNUM *add, BIGNUM *rem, BN_CTX *ctx);
static int probable_prime_dh_strong(BIGNUM *rnd, int bits,
	BIGNUM *add, BIGNUM *rem, BN_CTX *ctx);
#else
static int witness();
static int probable_prime();
static int probable_prime_dh();
static int probable_prime_dh_strong();
#endif

BIGNUM *BN_generate_prime(bits,strong,add,rem,callback,cb_arg)
int bits;
int strong;
BIGNUM *add;
BIGNUM *rem;
void (*callback)(P_I_I_P); 
char *cb_arg;
	{
	BIGNUM *rnd=NULL;
	BIGNUM *ret=NULL;
	BIGNUM *t=NULL;
	int i,j,c1=0;
	BN_CTX *ctx;

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;
	if ((rnd=BN_new()) == NULL) goto err;
	if (strong)
		if ((t=BN_new()) == NULL) goto err;
loop: 
	/* make a random number and set the top and bottom bits */
	if (add == NULL)
		{
		if (!probable_prime(rnd,bits)) goto err;
		}
	else
		{
		if (strong)
			{
			if (!probable_prime_dh_strong(rnd,bits,add,rem,ctx))
				 goto err;
			}
		else
			{
			if (!probable_prime_dh(rnd,bits,add,rem,ctx))
				goto err;
			}
		}
	/* if (BN_mod_word(rnd,(BN_ULONG)3) == 1) goto loop; */
	if (callback != NULL) callback(0,c1++,cb_arg);

	if (!strong)
		{
		i=BN_is_prime(rnd,BN_prime_checks,callback,ctx,cb_arg);
		if (i == -1) goto err;
		if (i == 0) goto loop;
		}
	else
		{
		/* for a strong prime generation,
		 * check that (p-1)/2 is prime.
		 * Since a prime is odd, We just
		 * need to divide by 2 */
		if (!BN_rshift1(t,rnd)) goto err;

		for (i=0; i<BN_prime_checks; i++)
			{
			j=BN_is_prime(rnd,1,callback,ctx,cb_arg);
			if (j == -1) goto err;
			if (j == 0) goto loop;

			j=BN_is_prime(t,1,callback,ctx,cb_arg);
			if (j == -1) goto err;
			if (j == 0) goto loop;

			if (callback != NULL) callback(2,c1-1,cb_arg);
			/* We have a strong prime test pass */
			}
		}
	/* we have a prime :-) */
	ret=rnd;
err:
	if ((ret == NULL) && (rnd != NULL)) BN_free(rnd);
	if (t != NULL) BN_free(t);
	if (ctx != NULL) BN_CTX_free(ctx);
	return(ret);
	}

int BN_is_prime(a,checks,callback,ctx_passed,cb_arg)
BIGNUM *a;
int checks;
void (*callback)(P_I_I_P);
BN_CTX *ctx_passed;
char *cb_arg;
	{
	int i,j,c2=0,ret= -1;
	BIGNUM *check;
	BN_CTX *ctx=NULL,*ctx2=NULL;
	BN_MONT_CTX *mont=NULL;

	if (!BN_is_odd(a))
		return(0);
	if (ctx_passed != NULL)
		ctx=ctx_passed;
	else
		if ((ctx=BN_CTX_new()) == NULL) goto err;

	if ((ctx2=BN_CTX_new()) == NULL) goto err;
	if ((mont=BN_MONT_CTX_new()) == NULL) goto err;

	check=ctx->bn[ctx->tos++];

	/* Setup the montgomery structure */
	if (!BN_MONT_CTX_set(mont,a,ctx2)) goto err;

	for (i=0; i<checks; i++)
		{
		if (!BN_rand(check,BN_num_bits(a)-1,0,0)) goto err;
		j=witness(check,a,ctx,ctx2,mont);
		if (j == -1) goto err;
		if (j)
			{
			ret=0;
			goto err;
			}
		if (callback != NULL) callback(1,c2++,cb_arg);
		}
	ret=1;
err:
	ctx->tos--;
	if ((ctx_passed == NULL) && (ctx != NULL))
		BN_CTX_free(ctx);
	if (ctx2 != NULL)
		BN_CTX_free(ctx2);
	if (mont != NULL) BN_MONT_CTX_free(mont);
		
	return(ret);
	}

#define RECP_MUL_MOD

static int witness(a,n,ctx,ctx2,mont)
BIGNUM *a;
BIGNUM *n;
BN_CTX *ctx,*ctx2;
BN_MONT_CTX *mont;
	{
	int k,i,ret= -1,good;
	BIGNUM *d,*dd,*tmp,*d1,*d2,*n1;
	BIGNUM *mont_one,*mont_n1,*mont_a;

	d1=ctx->bn[ctx->tos];
	d2=ctx->bn[ctx->tos+1];
	n1=ctx->bn[ctx->tos+2];
	ctx->tos+=3;

	mont_one=ctx2->bn[ctx2->tos];
	mont_n1=ctx2->bn[ctx2->tos+1];
	mont_a=ctx2->bn[ctx2->tos+2];
	ctx2->tos+=3;

	d=d1;
	dd=d2;
	if (!BN_one(d)) goto err;
	if (!BN_sub(n1,n,d)) goto err; /* n1=n-1; */
	k=BN_num_bits(n1);

	if (!BN_to_montgomery(mont_one,BN_value_one(),mont,ctx2)) goto err;
	if (!BN_to_montgomery(mont_n1,n1,mont,ctx2)) goto err;
	if (!BN_to_montgomery(mont_a,a,mont,ctx2)) goto err;

	BN_copy(d,mont_one);
	for (i=k-1; i>=0; i--)
		{
		if (	(BN_cmp(d,mont_one) != 0) &&
			(BN_cmp(d,mont_n1) != 0))
			good=1;
		else
			good=0;

		BN_mod_mul_montgomery(dd,d,d,mont,ctx2);
		
		if (good && (BN_cmp(dd,mont_one) == 0))
			{
			ret=1;
			goto err;
			}
		if (BN_is_bit_set(n1,i))
			{
			BN_mod_mul_montgomery(d,dd,mont_a,mont,ctx2);
			}
		else
			{
			tmp=d;
			d=dd;
			dd=tmp;
			}
		}
	if (BN_cmp(d,mont_one) == 0)
		i=0;
	else	i=1;
	ret=i;
err:
	ctx->tos-=3;
	ctx2->tos-=3;
	return(ret);
	}

static int probable_prime(rnd, bits)
BIGNUM *rnd;
int bits;
	{
	int i;
	MS_STATIC BN_ULONG mods[NUMPRIMES];
	BN_ULONG delta;

	if (!BN_rand(rnd,bits,1,1)) return(0);
	/* we now have a random number 'rand' to test. */
	for (i=1; i<NUMPRIMES; i++)
		mods[i]=BN_mod_word(rnd,(BN_ULONG)primes[i]);
	delta=0;
	loop: for (i=1; i<NUMPRIMES; i++)
		{
		/* check that rnd is not a prime and also
		 * that gcd(rnd-1,primes) == 1 (except for 2) */
		if (((mods[i]+delta)%primes[i]) <= 1)
			{
			delta+=2;
			/* perhaps need to check for overflow of
			 * delta (but delta can be upto 2^32) */
			goto loop;
			}
		}
	if (!BN_add_word(rnd,delta)) return(0);
	return(1);
	}

static int probable_prime_dh(rnd, bits, add, rem,ctx)
BIGNUM *rnd;
int bits;
BIGNUM *add;
BIGNUM *rem;
BN_CTX *ctx;
	{
	int i,ret=0;
	BIGNUM *t1;

	t1=ctx->bn[ctx->tos++];

	if (!BN_rand(rnd,bits,0,1)) goto err;

	/* we need ((rnd-rem) % add) == 0 */

	if (!BN_mod(t1,rnd,add,ctx)) goto err;
	if (!BN_sub(rnd,rnd,t1)) goto err;
	if (rem == NULL)
		{ if (!BN_add_word(rnd,1)) goto err; }
	else
		{ if (!BN_add(rnd,rnd,rem)) goto err; }

	/* we now have a random number 'rand' to test. */

	loop: for (i=1; i<NUMPRIMES; i++)
		{
		/* check that rnd is a prime */
		if (BN_mod_word(rnd,(BN_LONG)primes[i]) <= 1)
			{
			if (!BN_add(rnd,rnd,add)) goto err;
			goto loop;
			}
		}
	ret=1;
err:
	ctx->tos--;
	return(ret);
	}

static int probable_prime_dh_strong(p, bits, padd, rem,ctx)
BIGNUM *p;
int bits;
BIGNUM *padd;
BIGNUM *rem;
BN_CTX *ctx;
	{
	int i,ret=0;
	BIGNUM *t1,*qadd=NULL,*q=NULL;

	bits--;
	t1=ctx->bn[ctx->tos++];
	q=ctx->bn[ctx->tos++];
	qadd=ctx->bn[ctx->tos++];

	if (!BN_rshift1(qadd,padd)) goto err;
		
	if (!BN_rand(q,bits,0,1)) goto err;

	/* we need ((rnd-rem) % add) == 0 */
	if (!BN_mod(t1,q,qadd,ctx)) goto err;
	if (!BN_sub(q,q,t1)) goto err;
	if (rem == NULL)
		{ if (!BN_add_word(q,1)) goto err; }
	else
		{
		if (!BN_rshift1(t1,rem)) goto err;
		if (!BN_add(q,q,t1)) goto err;
		}

	/* we now have a random number 'rand' to test. */
	if (!BN_lshift1(p,q)) goto err;
	if (!BN_add_word(p,1)) goto err;

	loop: for (i=1; i<NUMPRIMES; i++)
		{
		/* check that p and q are prime */
		/* check that for p and q
		 * gcd(p-1,primes) == 1 (except for 2) */
		if (	(BN_mod_word(p,(BN_LONG)primes[i]) == 0) ||
			(BN_mod_word(q,(BN_LONG)primes[i]) == 0))
			{
			if (!BN_add(p,p,padd)) goto err;
			if (!BN_add(q,q,qadd)) goto err;
			goto loop;
			}
		}
	ret=1;
err:
	ctx->tos-=3;
	return(ret);
	}

#if 0
static int witness(a, n,ctx)
BIGNUM *a;
BIGNUM *n;
BN_CTX *ctx;
	{
	int k,i,nb,ret= -1;
	BIGNUM *d,*dd,*tmp;
	BIGNUM *d1,*d2,*x,*n1,*inv;

	d1=ctx->bn[ctx->tos];
	d2=ctx->bn[ctx->tos+1];
	x=ctx->bn[ctx->tos+2];
	n1=ctx->bn[ctx->tos+3];
	inv=ctx->bn[ctx->tos+4];
	ctx->tos+=5;

	d=d1;
	dd=d2;
	if (!BN_one(d)) goto err;
	if (!BN_sub(n1,n,d)) goto err; /* n1=n-1; */
	k=BN_num_bits(n1);

	/* i=BN_num_bits(n); */
#ifdef RECP_MUL_MOD
	nb=BN_reciprocal(inv,n,ctx); /**/
	if (nb == -1) goto err;
#endif

	for (i=k-1; i>=0; i--)
		{
		if (BN_copy(x,d) == NULL) goto err;
#ifndef RECP_MUL_MOD
		if (!BN_mod_mul(dd,d,d,n,ctx)) goto err;
#else
		if (!BN_mod_mul_reciprocal(dd,d,d,n,inv,nb,ctx)) goto err;
#endif
		if (	BN_is_one(dd) &&
			!BN_is_one(x) &&
			(BN_cmp(x,n1) != 0))
			{
			ret=1;
			goto err;
			}
		if (BN_is_bit_set(n1,i))
			{
#ifndef RECP_MUL_MOD
			if (!BN_mod_mul(d,dd,a,n,ctx)) goto err;
#else
			if (!BN_mod_mul_reciprocal(d,dd,a,n,inv,nb,ctx)) goto err; 
#endif
			}
		else
			{
			tmp=d;
			d=dd;
			dd=tmp;
			}
		}
	if (BN_is_one(d))
		i=0;
	else	i=1;
	ret=i;
err:
	ctx->tos-=5;
	return(ret);
	}
#endif
