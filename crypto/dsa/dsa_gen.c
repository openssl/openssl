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
/* Parameter generation follows the original release of FIPS PUB 186,
 * Appendix 2.2 (i.e. use SHA as defined in FIPS PUB 180) */
#define HASH    EVP_sha()
#else
/* Parameter generation follows the updated Appendix 2.2 for FIPS PUB 186,
 * also Appendix 2.2 of FIPS PUB 186-1 (i.e. use SHA as defined in
 * FIPS PUB 180-1) */
#define HASH    EVP_sha1()
#endif 

#ifndef OPENSSL_NO_SHA

#include <stdio.h>
#include <time.h>
#include "cryptlib.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

DSA *DSA_generate_parameters(int bits,
		unsigned char *seed_in, int seed_len,
		int *counter_ret, unsigned long *h_ret,
		void (*callback)(int, int, void *),
		void *cb_arg)
	{
	int ok=0;
	unsigned char seed[SHA_DIGEST_LENGTH];
	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned char buf[SHA_DIGEST_LENGTH],buf2[SHA_DIGEST_LENGTH];
	BIGNUM *r0,*W,*X,*c,*test;
	BIGNUM *g=NULL,*q=NULL,*p=NULL;
	BN_MONT_CTX *mont=NULL;
	int k,n=0,i,b,m=0;
	int counter=0;
	int r=0;
	BN_CTX *ctx=NULL,*ctx2=NULL,*ctx3=NULL;
	unsigned int h=2;
	DSA *ret=NULL;

	if (bits < 512) bits=512;
	bits=(bits+63)/64*64;

	if (seed_len < 20)
		seed_in = NULL; /* seed buffer too small -- ignore */
	if (seed_len > 20) 
		seed_len = 20; /* App. 2.2 of FIPS PUB 186 allows larger SEED,
		                * but our internal buffers are restricted to 160 bits*/
	if ((seed_in != NULL) && (seed_len == 20))
		memcpy(seed,seed_in,seed_len);

	if ((ctx=BN_CTX_new()) == NULL) goto err;
	if ((ctx2=BN_CTX_new()) == NULL) goto err;
	if ((ctx3=BN_CTX_new()) == NULL) goto err;
	if ((ret=DSA_new()) == NULL) goto err;

	if ((mont=BN_MONT_CTX_new()) == NULL) goto err;

	BN_CTX_start(ctx2);
	r0 = BN_CTX_get(ctx2);
	g = BN_CTX_get(ctx2);
	W = BN_CTX_get(ctx2);
	q = BN_CTX_get(ctx2);
	X = BN_CTX_get(ctx2);
	c = BN_CTX_get(ctx2);
	p = BN_CTX_get(ctx2);
	test = BN_CTX_get(ctx2);

	BN_lshift(test,BN_value_one(),bits-1);

	for (;;)
		{
		for (;;) /* find q */
			{
			int seed_is_random;

			/* step 1 */
			if (callback != NULL) callback(0,m++,cb_arg);

			if (!seed_len)
				{
				RAND_pseudo_bytes(seed,SHA_DIGEST_LENGTH);
				seed_is_random = 1;
				}
			else
				{
				seed_is_random = 0;
				seed_len=0; /* use random seed if 'seed_in' turns out to be bad*/
				}
			memcpy(buf,seed,SHA_DIGEST_LENGTH);
			memcpy(buf2,seed,SHA_DIGEST_LENGTH);
			/* precompute "SEED + 1" for step 7: */
			for (i=SHA_DIGEST_LENGTH-1; i >= 0; i--)
				{
				buf[i]++;
				if (buf[i] != 0) break;
				}

			/* step 2 */
			EVP_Digest(seed,SHA_DIGEST_LENGTH,md,NULL,HASH, NULL);
			EVP_Digest(buf,SHA_DIGEST_LENGTH,buf2,NULL,HASH, NULL);
			for (i=0; i<SHA_DIGEST_LENGTH; i++)
				md[i]^=buf2[i];

			/* step 3 */
			md[0]|=0x80;
			md[SHA_DIGEST_LENGTH-1]|=0x01;
			if (!BN_bin2bn(md,SHA_DIGEST_LENGTH,q)) goto err;

			/* step 4 */
			r = BN_is_prime_fasttest(q, DSS_prime_checks, callback, ctx3, cb_arg, seed_is_random);
			if (r > 0)
				break;
			if (r != 0)
				goto err;

			/* do a callback call */
			/* step 5 */
			}

		if (callback != NULL) callback(2,0,cb_arg);
		if (callback != NULL) callback(3,0,cb_arg);

		/* step 6 */
		counter=0;
		/* "offset = 2" */

		n=(bits-1)/160;
		b=(bits-1)-n*160;

		for (;;)
			{
			if (callback != NULL && counter != 0)
				callback(0,counter,cb_arg);

			/* step 7 */
			BN_zero(W);
			/* now 'buf' contains "SEED + offset - 1" */
			for (k=0; k<=n; k++)
				{
				/* obtain "SEED + offset + k" by incrementing: */
				for (i=SHA_DIGEST_LENGTH-1; i >= 0; i--)
					{
					buf[i]++;
					if (buf[i] != 0) break;
					}

				EVP_Digest(buf,SHA_DIGEST_LENGTH,md,NULL,HASH, NULL);

				/* step 8 */
				if (!BN_bin2bn(md,SHA_DIGEST_LENGTH,r0))
					goto err;
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
				r = BN_is_prime_fasttest(p, DSS_prime_checks, callback, ctx3, cb_arg, 1);
				if (r > 0)
						goto end; /* found it */
				if (r != 0)
					goto err;
				}

			/* step 13 */
			counter++;
			/* "offset = offset + n + 1" */

			/* step 14 */
			if (counter >= 4096) break;
			}
		}
end:
	if (callback != NULL) callback(2,1,cb_arg);

	/* We now need to generate g */
	/* Set r0=(p-1)/q */
	BN_sub(test,p,BN_value_one());
	BN_div(r0,NULL,test,q,ctx);

	BN_set_word(test,h);
	BN_MONT_CTX_set(mont,p,ctx);

	for (;;)
		{
		/* g=test^r0%p */
		BN_mod_exp_mont(g,test,r0,p,ctx,mont);
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
	if (ctx != NULL) BN_CTX_free(ctx);
	if (ctx2 != NULL)
		{
		BN_CTX_end(ctx2);
		BN_CTX_free(ctx2);
		}
	if (ctx3 != NULL) BN_CTX_free(ctx3);
	if (mont != NULL) BN_MONT_CTX_free(mont);
	return(ok?ret:NULL);
	}
#endif
