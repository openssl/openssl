/* crypto/dsa/dsa_vrf.c */
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
#include <openssl/asn1_mac.h>

int DSA_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig,
		  DSA *dsa)
	{
	BN_CTX *ctx;
	BIGNUM u1,u2,t1;
	BN_MONT_CTX *mont=NULL;
	int ret = -1;

	if ((ctx=BN_CTX_new()) == NULL) goto err;
	BN_init(&u1);
	BN_init(&u2);
	BN_init(&t1);

	/* Calculate W = inv(S) mod Q
	 * save W in u2 */
	if ((BN_mod_inverse(&u2,sig->s,dsa->q,ctx)) == NULL) goto err;

	/* save M in u1 */
	if (BN_bin2bn(dgst,dgst_len,&u1) == NULL) goto err;

	/* u1 = M * w mod q */
	if (!BN_mod_mul(&u1,&u1,&u2,dsa->q,ctx)) goto err;

	/* u2 = r * w mod q */
	if (!BN_mod_mul(&u2,sig->r,&u2,dsa->q,ctx)) goto err;

	if ((dsa->method_mont_p == NULL) && (dsa->flags & DSA_FLAG_CACHE_MONT_P))
		{
		if ((dsa->method_mont_p=(char *)BN_MONT_CTX_new()) != NULL)
			if (!BN_MONT_CTX_set((BN_MONT_CTX *)dsa->method_mont_p,
				dsa->p,ctx)) goto err;
		}
	mont=(BN_MONT_CTX *)dsa->method_mont_p;

#if 0
	{
	BIGNUM t2;

	BN_init(&t2);
	/* v = ( g^u1 * y^u2 mod p ) mod q */
	/* let t1 = g ^ u1 mod p */
	if (!BN_mod_exp_mont(&t1,dsa->g,&u1,dsa->p,ctx,mont)) goto err;
	/* let t2 = y ^ u2 mod p */
	if (!BN_mod_exp_mont(&t2,dsa->pub_key,&u2,dsa->p,ctx,mont)) goto err;
	/* let u1 = t1 * t2 mod p */
	if (!BN_mod_mul(&u1,&t1,&t2,dsa->p,ctx)) goto err_bn;
	BN_free(&t2);
	}
	/* let u1 = u1 mod q */
	if (!BN_mod(&u1,&u1,dsa->q,ctx)) goto err;
#else
	{
	if (!BN_mod_exp2_mont(&t1,dsa->g,&u1,dsa->pub_key,&u2,dsa->p,ctx,mont))
		goto err;
	/* BN_copy(&u1,&t1); */
	/* let u1 = u1 mod q */
	if (!BN_mod(&u1,&t1,dsa->q,ctx)) goto err;
	}
#endif
	/* V is now in u1.  If the signature is correct, it will be
	 * equal to R. */
	ret=(BN_ucmp(&u1, sig->r) == 0);

	err:
	if (ret != 1) DSAerr(DSA_F_DSA_DO_VERIFY,ERR_R_BN_LIB);
	if (ctx != NULL) BN_CTX_free(ctx);
	BN_free(&u1);
	BN_free(&u2);
	BN_free(&t1);
	return(ret);
	}

/* data has already been hashed (probably with SHA or SHA-1). */
/* returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int DSA_verify(int type, const unsigned char *dgst, int dgst_len,
	     unsigned char *sigbuf, int siglen, DSA *dsa)
	{
	DSA_SIG *s;
	int ret=-1;

	s = DSA_SIG_new();
	if (s == NULL) return(ret);
	if (d2i_DSA_SIG(&s,&sigbuf,siglen) == NULL) goto err;
	ret=DSA_do_verify(dgst,dgst_len,s,dsa);
err:
	DSA_SIG_free(s);
	return(ret);
	}
