/* crypto/dsa/dsa_gen.c */
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

#undef GENUINE_DSA

#ifdef GENUINE_DSA
#define HASH    SHA
#else
#define HASH    SHA1
#endif 

#include <stdio.h>
#include <time.h>
#include "cryptlib.h"
#include "sha.h"
#include "bn.h"
#include "dsa.h"
#include "rand.h"

DSA *DSA_generate_parameters(bits,seed_in,seed_len,counter_ret,h_ret,callback,
	cb_arg)
int bits;
unsigned char *seed_in;
int seed_len;
int *counter_ret;
unsigned long *h_ret;
void (*callback)();
char *cb_arg;
	{
	int ok=0;
	unsigned char seed[SHA_DIGEST_LENGTH];
	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned char buf[SHA_DIGEST_LENGTH],buf2[SHA_DIGEST_LENGTH];
	BIGNUM *r0,*W,*X,*c,*test;
	BIGNUM *g=NULL,*q=NULL,*p=NULL;
	int k,n=0,i,b,m=0;
	int counter=0;
	BN_CTX *ctx=NULL,*ctx2=NULL;
	unsigned int h=2;
	DSA *ret=NULL;

	if (bits < 512) bits=512;
	bits=(bits+63)/64*64;

	if ((seed_in != NULL) && (seed_len == 20))
		memcpy(seed,seed_in,seed_len);

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;
	ctx2=BN_CTX_new();
	if (ctx2 == NULL) goto err;
	ret=DSA_new();
	if (ret == NULL) goto err;
	r0=ctx2->bn[0];
	g=ctx2->bn[1];
	W=ctx2->bn[2];
	q=ctx2->bn[3];
	X=ctx2->bn[4];
	c=ctx2->bn[5];
	p=ctx2->bn[6];
	test=ctx2->bn[7];

	BN_lshift(test,BN_value_one(),bits-1);

	for (;;)
		{
		for (;;)
			{
			/* step 1 */
			if (callback != NULL) callback(0,m++,cb_arg);

			if (!seed_len)
				RAND_bytes(seed,SHA_DIGEST_LENGTH);
			else
				seed_len=0;

			memcpy(buf,seed,SHA_DIGEST_LENGTH);
			memcpy(buf2,seed,SHA_DIGEST_LENGTH);
			for (i=SHA_DIGEST_LENGTH-1; i >= 0; i--)
				{
				buf[i]++;
				if (buf[i] != 0) break;
				}

			/* step 2 */
			HASH(seed,SHA_DIGEST_LENGTH,md);
			HASH(buf,SHA_DIGEST_LENGTH,buf2);
			for (i=0; i<SHA_DIGEST_LENGTH; i++)
				md[i]^=buf2[i];

			/* step 3 */
			md[0]|=0x80;
			md[SHA_DIGEST_LENGTH-1]|=0x01;
			if (!BN_bin2bn(md,SHA_DIGEST_LENGTH,q)) abort();

			/* step 4 */
			if (DSA_is_prime(q,callback,cb_arg) > 0) break;
			/* do a callback call */
			/* step 5 */
			}

		if (callback != NULL) callback(2,0,cb_arg);
		if (callback != NULL) callback(3,0,cb_arg);

		/* step 6 */
		counter=0;

		n=(bits-1)/160;
		b=(bits-1)-n*160;

		for (;;)
			{
			/* step 7 */
			BN_zero(W);
			for (k=0; k<=n; k++)
				{
				for (i=SHA_DIGEST_LENGTH-1; i >= 0; i--)
					{
					buf[i]++;
					if (buf[i] != 0) break;
					}

				HASH(buf,SHA_DIGEST_LENGTH,md);

				/* step 8 */
				if (!BN_bin2bn(md,SHA_DIGEST_LENGTH,r0)) abort();
				BN_lshift(r0,r0,160*k);
				BN_add(W,W,r0);
				}

			/* more of step 8 */
			BN_mask_bits(W,bits-1);
			BN_copy(X,W); /* this should be ok */
			BN_add(X,X,test); /* this should be ok */

			/* step 9 */
			BN_lshift1(r0,q);
			BN_mod(c,X,r0,ctx);
			BN_sub(r0,c,BN_value_one());
			BN_sub(p,X,r0);

			/* step 10 */
			if (BN_cmp(p,test) >= 0)
				{
				/* step 11 */
				if (DSA_is_prime(p,callback,cb_arg) > 0)
					goto end;
				}

			/* step 13 */
			counter++;

			/* step 14 */
			if (counter >= 4096) break;

			if (callback != NULL) callback(0,counter,cb_arg);
			}
		}
end:
	if (callback != NULL) callback(2,1,cb_arg);

	/* We now need to gernerate g */
	/* Set r0=(p-1)/q */
        BN_sub(test,p,BN_value_one());
        BN_div(r0,NULL,test,q,ctx);

	BN_set_word(test,h);
	for (;;)
		{
		/* g=test^r0%p */
		BN_mod_exp(g,test,r0,p,ctx);
		if (!BN_is_one(g)) break;
		BN_add(test,test,BN_value_one());
		h++;
		}

	if (callback != NULL) callback(3,1,cb_arg);

	ok=1;
err:
	if (!ok)
		{
		if (ret != NULL) DSA_free(ret);
		}
	else
		{
		ret->p=BN_dup(p);
		ret->q=BN_dup(q);
		ret->g=BN_dup(g);
		if ((m > 1) && (seed_in != NULL)) memcpy(seed_in,seed,20);
		if (counter_ret != NULL) *counter_ret=counter;
		if (h_ret != NULL) *h_ret=h;
		}
	BN_CTX_free(ctx);
	BN_CTX_free(ctx2);
	return(ok?ret:NULL);
	}

int DSA_is_prime(w, callback,cb_arg)
BIGNUM *w;
void (*callback)();
char *cb_arg;
	{
	int ok= -1,j,i,n;
	BN_CTX *ctx=NULL,*ctx2=NULL;
	BIGNUM *w_1,*b,*m,*z;
	int a;

	if (!BN_is_bit_set(w,0)) return(0);

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;
	ctx2=BN_CTX_new();
	if (ctx2 == NULL) goto err;

	m=  ctx2->bn[2];
	b=  ctx2->bn[3];
	z=  ctx2->bn[4];
	w_1=ctx2->bn[5];

	/* step 1 */
	n=50;

	/* step 2 */
	if (!BN_sub(w_1,w,BN_value_one())) goto err;
	for (a=1; !BN_is_bit_set(w_1,a); a++)
		;
	if (!BN_rshift(m,w_1,a)) goto err;

	for (i=1; i < n; i++)
		{
		/* step 3 */
		BN_rand(b,BN_num_bits(w)-2/*-1*/,0,0);
		BN_set_word(b,0x10001L);

		/* step 4 */
		j=0;
		if (!BN_mod_exp(z,b,m,w,ctx)) goto err;

		/* step 5 */
		for (;;)
			{
			if (((j == 0) && BN_is_one(z)) || (BN_cmp(z,w_1) == 0))
				break;

			/* step 6 */
			if ((j > 0) && BN_is_one(z))
				{
				ok=0;
				goto err;
				}

			j++;
			if (j >= a)
				{
				ok=0;
				goto err;
				}

			if (!BN_mod_mul(z,z,z,w,ctx)) goto err;
			if (callback != NULL) callback(1,j,cb_arg);
			}
		}

	ok=1;
err:
	if (ok == -1) DSAerr(DSA_F_DSA_IS_PRIME,ERR_R_BN_LIB);
	BN_CTX_free(ctx);
	BN_CTX_free(ctx2);
	
	return(ok);
	}

