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

/* Origional version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

#include <stdio.h>
#include "cryptlib.h"
#include "bn.h"
#include "dsa.h"
#include "rand.h"
#include "asn1.h"

/* data has already been hashed (probably with SHA or SHA-1). */
/*	DSAerr(DSA_F_DSA_SIGN,DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE); */

int DSA_sign(type,dgst,dlen,sig,siglen,dsa)
int type;
unsigned char *dgst;
int dlen;
unsigned char *sig;	/* out */
unsigned int *siglen;	/* out */
DSA *dsa;
	{
	BIGNUM *kinv=NULL,*r=NULL;
	BIGNUM *m=NULL;
	BIGNUM *xr=NULL,*s=NULL;
	BN_CTX *ctx=NULL;
	unsigned char *p;
	int i,len=0,ret=0,reason=ERR_R_BN_LIB;
        ASN1_INTEGER rbs,sbs;
	MS_STATIC unsigned char rbuf[50]; /* assuming r is 20 bytes +extra */
	MS_STATIC unsigned char sbuf[50]; /* assuming s is 20 bytes +extra */

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

	m=BN_new();
	xr=BN_new();
	s=BN_new();
	if (m == NULL || xr == NULL || s == NULL) goto err;

	if (BN_bin2bn(dgst,dlen,m) == NULL) goto err;

	/* Compute  s = inv(k) (m + xr) mod q */
	if (!BN_mul(xr, dsa->priv_key, r)) goto err;	/* s = xr */
	if (!BN_add(s, xr, m)) goto err;		/* s = m + xr */
	if (!BN_mod_mul(s,s,kinv,dsa->q,ctx)) goto err;

	/*
	 * Now create a ASN.1 sequence of the integers R and S.
	 */
	rbs.data=rbuf;
	sbs.data=sbuf;
	rbs.type = V_ASN1_INTEGER;
	sbs.type = V_ASN1_INTEGER;
	rbs.length=BN_bn2bin(r,rbs.data);
	sbs.length=BN_bn2bin(s,sbs.data);

	len =i2d_ASN1_INTEGER(&rbs,NULL);
	len+=i2d_ASN1_INTEGER(&sbs,NULL);

	p=sig;
	ASN1_put_object(&p,1,len,V_ASN1_SEQUENCE,V_ASN1_UNIVERSAL);
	i2d_ASN1_INTEGER(&rbs,&p);
	i2d_ASN1_INTEGER(&sbs,&p);
	*siglen=(p-sig);
	ret=1;
err:
	if (!ret) DSAerr(DSA_F_DSA_SIGN,reason);
		
#if 1 /* do the right thing :-) */
	if (kinv != NULL) BN_clear_free(kinv);
	if (r != NULL) BN_clear_free(r);
#endif
	if (ctx != NULL) BN_CTX_free(ctx);
	if (m != NULL) BN_clear_free(m);
	if (xr != NULL) BN_clear_free(xr);
	if (s != NULL) BN_clear_free(s);
	return(ret);
	}

int DSA_sign_setup(dsa,ctx_in,kinvp,rp)
DSA *dsa;
BN_CTX *ctx_in;
BIGNUM **kinvp;
BIGNUM **rp;
	{
	BN_CTX *ctx;
	BIGNUM *k=NULL,*kinv=NULL,*r=NULL;
	int ret=0;

	if (ctx_in == NULL)
		{
		if ((ctx=BN_CTX_new()) == NULL) goto err;
		}
	else
		ctx=ctx_in;

	r=BN_new();
	k=BN_new();
	if ((r == NULL) || (k == NULL))
		goto err;
	kinv=NULL;

	if (r == NULL) goto err;

	/* Get random k */
	for (;;)
		{
		if (!BN_rand(k, BN_num_bits(dsa->q), 1, 0)) goto err;
		if (BN_cmp(k,dsa->q) >= 0)
			BN_sub(k,k,dsa->q);
		if (!BN_is_zero(k)) break;
		}

	/* Compute r = (g^k mod p) mod q */
	if (!BN_mod_exp(r,dsa->g,k,dsa->p,ctx)) goto err;
	if (!BN_mod(r,r,dsa->q,ctx)) goto err;

	/* Compute  part of 's = inv(k) (m + xr) mod q' */
	if ((kinv=BN_mod_inverse(k,dsa->q,ctx)) == NULL) goto err;

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
	if (k != NULL) BN_clear_free(k);
	if (kinv != NULL) BN_clear_free(kinv);
	return(ret);
	}

