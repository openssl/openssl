/* crypto/ecdsa/ecs_ossl.c */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "ecdsa.h"
#include <openssl/err.h>

/* TODO : general case */
#define	EC_POINT_get_affine_coordinates EC_POINT_get_affine_coordinates_GFp

static ECDSA_SIG *ecdsa_do_sign(const unsigned char *dgst, int dlen, ECDSA *ecdsa);
static int ecdsa_sign_setup(ECDSA *ecdsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);
static int ecdsa_do_verify(const unsigned char *dgst, int dgst_len, ECDSA_SIG *sig,
		           ECDSA *ecdsa);

static ECDSA_METHOD openssl_ecdsa_meth = {
"OpenSSL ECDSA method",
ecdsa_do_sign,
ecdsa_sign_setup,
ecdsa_do_verify,
0,
NULL
};

const ECDSA_METHOD *ECDSA_OpenSSL(void)
{
	return &openssl_ecdsa_meth;
}

static int ecdsa_sign_setup(ECDSA *ecdsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
	BN_CTX   *ctx = NULL;
	BIGNUM	 k,*kinv=NULL,*r=NULL,*order=NULL,*X=NULL;
	EC_POINT *tmp_point=NULL;
	int 	 ret = 0,reason = ERR_R_BN_LIB;
	if (!ecdsa  || !ecdsa->group || !ecdsa->pub_key || !ecdsa->priv_key)
	{
		reason = ECDSA_R_MISSING_PARAMETERS;
		return 0;
	}
	if (ctx_in == NULL) 
	{
		if ((ctx=BN_CTX_new()) == NULL) goto err;
	}
	else
		ctx=ctx_in;

	if ((r = BN_new()) == NULL) goto err;
	if ((order = BN_new()) == NULL) goto err;
	if ((X = BN_new()) == NULL) goto err;
	if ((tmp_point = EC_POINT_new(ecdsa->group)) == NULL)
	{
		reason = ERR_R_EC_LIB;
		goto err;
	}
	if (!EC_GROUP_get_order(ecdsa->group,order,ctx))
	{
		reason = ERR_R_EC_LIB;
		goto err;
	}
	
	do
	{
		/* get random k */	
		BN_init(&k);
		do
			if (!BN_rand_range(&k,order))
			{
				reason = ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED;
				goto err;
			}
		while (BN_is_zero(&k));

		/* compute r the x-coordinate of generator * k */
		if (!EC_POINT_mul(ecdsa->group,tmp_point,&k,NULL,NULL,ctx) 
		    || !EC_POINT_get_affine_coordinates(ecdsa->group,tmp_point,X,NULL,ctx))
		{
			reason = ERR_R_EC_LIB;
			goto err;
		}
		if (!BN_nnmod(r,X,order,ctx)) goto err;
	}
	while (BN_is_zero(r));

	/* compute the inverse of k */
	if ((kinv = BN_mod_inverse(NULL,&k,order,ctx)) == NULL) goto err;

	if (*rp == NULL)
		BN_clear_free(*rp);
	*rp = r;
	if (*kinvp == NULL) 
		BN_clear_free(*kinvp);
	*kinvp = kinv;
	kinv = NULL;
	ret = 1;
err:
	if (!ret)
	{
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,reason);
		if (kinv != NULL) BN_clear_free(kinv);
		if (r != NULL) BN_clear_free(r);
	}
	if (ctx_in == NULL) 
		BN_CTX_free(ctx);
	if (kinv != NULL)
		BN_clear_free(kinv);
	if (order != NULL)
		BN_clear_free(order);
	if (tmp_point != NULL) 
		EC_POINT_free(tmp_point);
	if (X)	BN_clear_free(X);
	BN_clear_free(&k);
	return(ret);
}


static ECDSA_SIG *ecdsa_do_sign(const unsigned char *dgst, int dgst_len, ECDSA *ecdsa)
{
	BIGNUM *kinv=NULL,*r=NULL,*s=NULL,*m=NULL,*tmp=NULL,*order=NULL;
	BIGNUM xr;
	BN_CTX *ctx=NULL;
	int reason=ERR_R_BN_LIB;
	ECDSA_SIG *ret=NULL;

	if (!ecdsa || !ecdsa->group || !ecdsa->pub_key || !ecdsa->priv_key)
	{
		reason = ECDSA_R_MISSING_PARAMETERS;
		goto err;
	}
	BN_init(&xr);

	if ((ctx = BN_CTX_new()) == NULL) goto err;
	if ((order = BN_new()) == NULL) goto err;
	if ((tmp = BN_new()) == NULL) goto err;
	if ((m = BN_new()) == NULL) goto err;
	if ((s = BN_new()) == NULL) goto err;

	if (!EC_GROUP_get_order(ecdsa->group,order,ctx))
	{
		reason = ECDSA_R_ERR_EC_LIB;
		goto err;
	}
	if (dgst_len > BN_num_bytes(order))
	{
		reason = ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE;
		goto err;
	}

	if (BN_bin2bn(dgst,dgst_len,m) == NULL) goto err;
	do
	{
		if ((ecdsa->kinv == NULL) || (ecdsa->r == NULL))
		{
			if (!ECDSA_sign_setup(ecdsa,ctx,&kinv,&r)) goto err;
		}
		else
		{
			kinv = ecdsa->kinv;
			ecdsa->kinv = NULL;
			r = ecdsa->r;
			ecdsa->r = NULL;
		}

		if (!BN_mod_mul(tmp,ecdsa->priv_key,r,order,ctx)) goto err;
		if (!BN_add(s,tmp,m)) goto err;
		if (BN_cmp(s,order) > 0)
			BN_sub(s,s,order);
		if (!BN_mod_mul(s,s,kinv,order,ctx)) goto err;
	}
	while (BN_is_zero(s));

	if ((ret = ECDSA_SIG_new()) == NULL)
	{
		reason = ECDSA_R_SIGNATURE_MALLOC_FAILED;
		goto err;
	}
	if (BN_copy(ret->r, r) == NULL || BN_copy(ret->s, s) == NULL)
	{
		ECDSA_SIG_free(ret);
		ret = NULL;
		reason = ERR_R_BN_LIB;
	}
	
err:
	if (!ret)
		{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN,reason);
		}
	if (r     != NULL) BN_clear_free(r);
	if (s     != NULL) BN_clear_free(s);
	if (ctx   != NULL) BN_CTX_free(ctx);
	if (m     != NULL) BN_clear_free(m);
	if (tmp   != NULL) BN_clear_free(tmp);
	if (order != NULL) BN_clear_free(order);
	if (kinv  != NULL) BN_clear_free(kinv);
	return(ret);
}

static int ecdsa_do_verify(const unsigned char *dgst, int dgst_len, ECDSA_SIG *sig,
		  	   ECDSA *ecdsa)
{
	BN_CTX *ctx;
	BIGNUM *order=NULL,*u1=NULL,*u2=NULL,*m=NULL,*X=NULL;
	EC_POINT *point=NULL;
	int ret = -1,reason = ERR_R_BN_LIB;
	if (!ecdsa || !ecdsa->group || !ecdsa->pub_key || !sig)
	{
		reason = ECDSA_R_MISSING_PARAMETERS;
		return -1;
	}

	if ((ctx = BN_CTX_new()) == NULL) goto err;
	if ((order = BN_new()) == NULL) goto err;
	if ((u1 = BN_new()) == NULL) goto err;
	if ((u2 = BN_new()) == NULL) goto err;
	if ((m  = BN_new()) == NULL) goto err;
	if ((X  = BN_new()) == NULL) goto err;
	if (!EC_GROUP_get_order(ecdsa->group,order,ctx)) goto err;

	if (BN_is_zero(sig->r) || sig->r->neg || BN_ucmp(sig->r, order) >= 0)
	{
		reason = ECDSA_R_BAD_SIGNATURE;
		ret = 0;
		goto err;
	}
	if (BN_is_zero(sig->s) || sig->s->neg || BN_ucmp(sig->s, order) >= 0)
	{
		reason = ECDSA_R_BAD_SIGNATURE;
		ret = 0;
		goto err;
	}

	/* calculate tmp1 = inv(S) mod order */
	if ((BN_mod_inverse(u2,sig->s,order,ctx)) == NULL) goto err;
	/* digest -> m */
	if (BN_bin2bn(dgst,dgst_len,m) == NULL) goto err;
	/* u1 = m * tmp mod order */
	if (!BN_mod_mul(u1,m,u2,order,ctx)) goto err;
	/* u2 = r * w mod q */
	if (!BN_mod_mul(u2,sig->r,u2,order,ctx)) goto err;

	if ((point = EC_POINT_new(ecdsa->group)) == NULL)
	{
		reason = ERR_R_EC_LIB;
		goto err;
	}
	if (!EC_POINT_mul(ecdsa->group,point,u1,ecdsa->pub_key,u2,ctx)
	    || !EC_POINT_get_affine_coordinates(ecdsa->group,point,X,NULL,ctx))
	{
		reason = ERR_R_EC_LIB;
		goto err;
	}
	if (!BN_nnmod(u1,X,order,ctx)) goto err;

	/*  is now in u1.  If the signature is correct, it will be
	 * equal to R. */
	ret = (BN_ucmp(u1,sig->r) == 0);

	err:
	if (ret != 1) ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY,reason);
	if (ctx != NULL) BN_CTX_free(ctx);
	if (u1  != NULL) BN_clear_free(u1);
	if (u2  != NULL) BN_clear_free(u2);
	if (m   != NULL) BN_clear_free(m);
	if (X   != NULL) BN_clear_free(X);
	if (order != NULL) BN_clear_free(order);
	if (point != NULL) EC_POINT_free(point);
	return(ret);
}
