/* crypto/rsa/rsa_gen.c */
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
#include <openssl/bn.h>
#include <openssl/rsa.h>

RSA *RSA_generate_key(int bits, unsigned long e_value,
	     void (*callback)(int,int,void *), void *cb_arg)
	{
	RSA *rsa=NULL;
	BIGNUM *r0=NULL,*r1=NULL,*r2=NULL,*r3=NULL,*tmp;
	int bitsp,bitsq,ok= -1,n=0,i;
	BN_CTX *ctx=NULL,*ctx2=NULL;

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;
	ctx2=BN_CTX_new();
	if (ctx2 == NULL) goto err;
	BN_CTX_start(ctx);
	r0 = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	r3 = BN_CTX_get(ctx);
	if (r3 == NULL) goto err;

	bitsp=(bits+1)/2;
	bitsq=bits-bitsp;
	rsa=RSA_new();
	if (rsa == NULL) goto err;

	/* set e */ 
	rsa->e=BN_new();
	if (rsa->e == NULL) goto err;

#if 1
	/* The problem is when building with 8, 16, or 32 BN_ULONG,
	 * unsigned long can be larger */
	for (i=0; i<sizeof(unsigned long)*8; i++)
		{
		if (e_value & (1UL<<i))
			BN_set_bit(rsa->e,i);
		}
#else
	if (!BN_set_word(rsa->e,e_value)) goto err;
#endif

	/* generate p and q */
	for (;;)
		{
		rsa->p=BN_generate_prime(NULL,bitsp,0,NULL,NULL,callback,cb_arg);
		if (rsa->p == NULL) goto err;
		if (!BN_sub(r2,rsa->p,BN_value_one())) goto err;
		if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
		if (BN_is_one(r1)) break;
		if (callback != NULL) callback(2,n++,cb_arg);
		BN_free(rsa->p);
		}
	if (callback != NULL) callback(3,0,cb_arg);
	for (;;)
		{
		rsa->q=BN_generate_prime(NULL,bitsq,0,NULL,NULL,callback,cb_arg);
		if (rsa->q == NULL) goto err;
		if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;
		if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
		if (BN_is_one(r1) && (BN_cmp(rsa->p,rsa->q) != 0))
			break;
		if (callback != NULL) callback(2,n++,cb_arg);
		BN_free(rsa->q);
		}
	if (callback != NULL) callback(3,1,cb_arg);
	if (BN_cmp(rsa->p,rsa->q) < 0)
		{
		tmp=rsa->p;
		rsa->p=rsa->q;
		rsa->q=tmp;
		}

	/* calculate n */
	rsa->n=BN_new();
	if (rsa->n == NULL) goto err;
	if (!BN_mul(rsa->n,rsa->p,rsa->q,ctx)) goto err;

	/* calculate d */
	if (!BN_sub(r1,rsa->p,BN_value_one())) goto err;	/* p-1 */
	if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;	/* q-1 */
	if (!BN_mul(r0,r1,r2,ctx)) goto err;	/* (p-1)(q-1) */

/* should not be needed, since gcd(p-1,e) == 1 and gcd(q-1,e) == 1 */
/*	for (;;)
		{
		if (!BN_gcd(r3,r0,rsa->e,ctx)) goto err;
		if (BN_is_one(r3)) break;

		if (1)
			{
			if (!BN_add_word(rsa->e,2L)) goto err;
			continue;
			}
		RSAerr(RSA_F_RSA_GENERATE_KEY,RSA_R_BAD_E_VALUE);
		goto err;
		}
*/
	rsa->d=BN_mod_inverse(NULL,rsa->e,r0,ctx2);	/* d */
	if (rsa->d == NULL) goto err;

	/* calculate d mod (p-1) */
	rsa->dmp1=BN_new();
	if (rsa->dmp1 == NULL) goto err;
	if (!BN_mod(rsa->dmp1,rsa->d,r1,ctx)) goto err;

	/* calculate d mod (q-1) */
	rsa->dmq1=BN_new();
	if (rsa->dmq1 == NULL) goto err;
	if (!BN_mod(rsa->dmq1,rsa->d,r2,ctx)) goto err;

	/* calculate inverse of q mod p */
	rsa->iqmp=BN_mod_inverse(NULL,rsa->q,rsa->p,ctx2);
	if (rsa->iqmp == NULL) goto err;

	ok=1;
err:
	if (ok == -1)
		{
		RSAerr(RSA_F_RSA_GENERATE_KEY,ERR_LIB_BN);
		ok=0;
		}
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	BN_CTX_free(ctx2);
	
	if (!ok)
		{
		if (rsa != NULL) RSA_free(rsa);
		return(NULL);
		}
	else
		return(rsa);
	}

