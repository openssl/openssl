/* crypto/dsa/dsa_sign.c */
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

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>

DSA_SIG * DSA_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
	{
	BIGNUM *kinv=NULL,*r=NULL,*s=NULL;
	BIGNUM m;
	BIGNUM xr;
	BN_CTX *ctx=NULL;
	int i,reason=ERR_R_BN_LIB;
	DSA_SIG *ret=NULL;

	BN_init(&m);
	BN_init(&xr);
	s=BN_new();
	if (s == NULL) goto err;

	i=BN_num_bytes(dsa->q); /* should be 20 */
	if ((dlen > i) || (dlen > 50))
		{
		reason=DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE;
		goto err;
		}

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;

	if ((dsa->kinv == NULL) || (dsa->r == NULL))
		{
		if (!DSA_sign_setup(dsa,ctx,&kinv,&r)) goto err;
		}
	else
		{
		kinv=dsa->kinv;
		dsa->kinv=NULL;
		r=dsa->r;
		dsa->r=NULL;
		}

	if (BN_bin2bn(dgst,dlen,&m) == NULL) goto err;

	/* Compute  s = inv(k) (m + xr) mod q */
	if (!BN_mod_mul(&xr,dsa->priv_key,r,dsa->q,ctx)) goto err;/* s = xr */
	if (!BN_add(s, &xr, &m)) goto err;		/* s = m + xr */
	if (BN_cmp(s,dsa->q) > 0)
		BN_sub(s,s,dsa->q);
	if (!BN_mod_mul(s,s,kinv,dsa->q,ctx)) goto err;

	ret=DSA_SIG_new();
	if (ret == NULL) goto err;
	ret->r = r;
	ret->s = s;
	
err:
	if (!ret)
		{
		DSAerr(DSA_F_DSA_DO_SIGN,reason);
		BN_free(r);
		BN_free(s);
		}
	if (ctx != NULL) BN_CTX_free(ctx);
	BN_clear_free(&m);
	BN_clear_free(&xr);
	if (kinv != NULL) /* dsa->kinv is NULL now if we used it */
	    BN_clear_free(kinv);
	return(ret);
	}

/* data has already been hashed (probably with SHA or SHA-1). */

/* unsigned char *sig:  out    */
/* unsigned int *siglen:  out    */
int DSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
	     unsigned int *siglen, DSA *dsa)
	{
	DSA_SIG *s;
	s=DSA_do_sign(dgst,dlen,dsa);
	if (s == NULL)
		{
		*siglen=0;
		return(0);
		}
	*siglen=i2d_DSA_SIG(s,&sig);
	DSA_SIG_free(s);
	return(1);
	}

int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
	{
	BN_CTX *ctx;
	BIGNUM k,*kinv=NULL,*r=NULL;
	int ret=0;

	if (ctx_in == NULL)
		{
		if ((ctx=BN_CTX_new()) == NULL) goto err;
		}
	else
		ctx=ctx_in;

	BN_init(&k);
	if ((r=BN_new()) == NULL) goto err;
	kinv=NULL;

	/* Get random k */
	for (;;)
		{
		if (!BN_rand(&k, BN_num_bits(dsa->q), 1, 0)) goto err;
		if (BN_cmp(&k,dsa->q) >= 0)
			BN_sub(&k,&k,dsa->q);
		if (!BN_is_zero(&k)) break;
		}

	if ((dsa->method_mont_p == NULL) && (dsa->flags & DSA_FLAG_CACHE_MONT_P))
		{
		if ((dsa->method_mont_p=(char *)BN_MONT_CTX_new()) != NULL)
			if (!BN_MONT_CTX_set((BN_MONT_CTX *)dsa->method_mont_p,
				dsa->p,ctx)) goto err;
		}

	/* Compute r = (g^k mod p) mod q */
	if (!BN_mod_exp_mont(r,dsa->g,&k,dsa->p,ctx,
		(BN_MONT_CTX *)dsa->method_mont_p)) goto err;
	if (!BN_mod(r,r,dsa->q,ctx)) goto err;

	/* Compute  part of 's = inv(k) (m + xr) mod q' */
	if ((kinv=BN_mod_inverse(NULL,&k,dsa->q,ctx)) == NULL) goto err;

	if (*kinvp != NULL) BN_clear_free(*kinvp);
	*kinvp=kinv;
	kinv=NULL;
	if (*rp != NULL) BN_clear_free(*rp);
	*rp=r;
	ret=1;
err:
	if (!ret)
		{
		DSAerr(DSA_F_DSA_SIGN_SETUP,ERR_R_BN_LIB);
		if (kinv != NULL) BN_clear_free(kinv);
		if (r != NULL) BN_clear_free(r);
		}
	if (ctx_in == NULL) BN_CTX_free(ctx);
	if (kinv != NULL) BN_clear_free(kinv);
	BN_clear_free(&k);
	return(ret);
	}

