/* crypto/ec/ec_key.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions originally developed by SUN MICROSYSTEMS, INC., and 
 * contributed to the OpenSSL project.
 */

#include <string.h>
#include "ec_lcl.h"
#include <openssl/err.h>
#include <string.h>

EC_KEY *EC_KEY_new(void)
	{
	EC_KEY *ret;

	ret=(EC_KEY *)OPENSSL_malloc(sizeof(EC_KEY));
	if (ret == NULL)
		{
		ECerr(EC_F_EC_NEW, ERR_R_MALLOC_FAILURE);
		return(NULL);
		}

	ret->version = 1;	
	ret->group   = NULL;
	ret->pub_key = NULL;
	ret->priv_key= NULL;
	ret->enc_flag= 0; 
	ret->conv_form = POINT_CONVERSION_UNCOMPRESSED;
	ret->references= 1;
	ret->meth_data = NULL;
	return(ret);
	}


void EC_KEY_free(EC_KEY *r)
	{
	int i;

	if (r == NULL) return;

	i=CRYPTO_add(&r->references,-1,CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("EC_KEY",r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"EC_KEY_free, bad reference count\n");
		abort();
		}
#endif

	if (r->group    != NULL) 
		EC_GROUP_free(r->group);
	if (r->pub_key  != NULL)
		EC_POINT_free(r->pub_key);
	if (r->priv_key != NULL)
		BN_clear_free(r->priv_key);

	if (r->meth_data && r->meth_data->finish)
		r->meth_data->finish(r);

	memset((void *)r, 0x0, sizeof(EC_KEY));

	OPENSSL_free(r);
	}

EC_KEY *EC_KEY_copy(EC_KEY *dest, const EC_KEY *src)
	{
	if (dest == NULL || src == NULL)
		{
		ECerr(EC_F_EC_KEY_COPY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	/* copy the parameters */
	if (src->group)
		{
		const EC_METHOD *meth = EC_GROUP_method_of(src->group);
		/* clear the old group */
		if (dest->group)
			EC_GROUP_free(dest->group);
		dest->group = EC_GROUP_new(meth);
		if (dest->group == NULL)
			return NULL;
		if (!EC_GROUP_copy(dest->group, src->group))
			return NULL;
		}
	/*  copy the public key */
	if (src->pub_key && src->group)
		{
		if (dest->pub_key)
			EC_POINT_free(dest->pub_key);
		dest->pub_key = EC_POINT_new(src->group);
		if (dest->pub_key == NULL)
			return NULL;
		if (!EC_POINT_copy(dest->pub_key, src->pub_key))
			return NULL;
		}
	/* copy the private key */
	if (src->priv_key)
		{
		if (dest->priv_key == NULL)
			{
			dest->priv_key = BN_new();
			if (dest->priv_key == NULL)
				return NULL;
			}
		if (!BN_copy(dest->priv_key, src->priv_key))
			return NULL;
		}
	/* copy the rest */
	dest->enc_flag  = src->enc_flag;
	dest->conv_form = src->conv_form;
	dest->version   = src->version;

	return dest;
	}

EC_KEY *EC_KEY_dup(const EC_KEY *eckey)
	{
	EC_KEY *ret = NULL;
	int	ok = 1;

	ret = EC_KEY_new();
	if (ret == NULL)
		return NULL;
	/* copy the parameters */
	if (eckey->group)
		{
		ret->group = EC_GROUP_dup(eckey->group);
		if (ret->group == NULL)
			ok = 0;
		}
	/*  copy the public key */
	if (eckey->pub_key && eckey->group)
		{
		ret->pub_key = EC_POINT_dup(eckey->pub_key, eckey->group);
		if (ret->pub_key == NULL)
			ok = 0;
		}
	/* copy the private key */
	if (eckey->priv_key)
		{
		ret->priv_key = BN_dup(ret->priv_key);
		if (ret->priv_key == NULL)
			ok = 0;
		}
	/* copy the rest */
	ret->enc_flag  = eckey->enc_flag;
	ret->conv_form = eckey->conv_form;
	ret->version   = eckey->version;

	if (!ok)
		{
		EC_KEY_free(ret);
		ret = NULL;
		}

	return ret;
	}

int EC_KEY_up_ref(EC_KEY *r)
	{
	int i = CRYPTO_add(&r->references, 1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("EC_KEY",r);
#endif
#ifdef REF_CHECK
	if (i < 2)
		{
		fprintf(stderr, "EC_KEY_up, bad reference count\n");
		abort();
		}
#endif
	return ((i > 1) ? 1 : 0);
	}

int EC_KEY_generate_key(EC_KEY *eckey)
	{	
	int	ok = 0;
	BN_CTX	*ctx = NULL;
	BIGNUM	*priv_key = NULL, *order = NULL;
	EC_POINT *pub_key = NULL;

	if (!eckey || !eckey->group)
		{
		ECerr(EC_F_EC_KEY_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}

	if ((order = BN_new()) == NULL) goto err;
	if ((ctx = BN_CTX_new()) == NULL) goto err;

	if (eckey->priv_key == NULL)
		{
		priv_key = BN_new();
		if (priv_key == NULL)
			goto err;
		}
	else
		priv_key = eckey->priv_key;

	if (!EC_GROUP_get_order(eckey->group, order, ctx))
		goto err;

	do
		if (!BN_rand_range(priv_key, order))
			goto err;
	while (BN_is_zero(priv_key));

	if (eckey->pub_key == NULL)
		{
		pub_key = EC_POINT_new(eckey->group);
		if (pub_key == NULL)
			goto err;
		}
	else
		pub_key = eckey->pub_key;

	if (!EC_POINT_mul(eckey->group, pub_key, priv_key, NULL, NULL, ctx))
		goto err;

	eckey->priv_key = priv_key;
	eckey->pub_key  = pub_key;

	ok=1;

err:	
	if (order)
		BN_free(order);
	if (pub_key  != NULL && eckey->pub_key  == NULL)
		EC_POINT_free(pub_key);
	if (priv_key != NULL && eckey->priv_key == NULL)
		BN_free(priv_key);
	if (ctx != NULL)
		BN_CTX_free(ctx);
	return(ok);
	}

int EC_KEY_check_key(const EC_KEY *eckey)
	{
	int	ok   = 0;
	BN_CTX	*ctx = NULL;
	BIGNUM	*order  = NULL;
	EC_POINT *point = NULL;

	if (!eckey || !eckey->group || !eckey->pub_key)
		{
		ECerr(EC_F_EC_KEY_CHECK_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	
	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
	if ((order = BN_new()) == NULL)
		goto err;
	if ((point = EC_POINT_new(eckey->group)) == NULL)
		goto err;

	/* testing whether the pub_key is on the elliptic curve */
	if (!EC_POINT_is_on_curve(eckey->group, eckey->pub_key, ctx))
		{
		ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_POINT_IS_NOT_ON_CURVE);
		goto err;
		}
	/* testing whether pub_key * order is the point at infinity */
	if (!EC_GROUP_get_order(eckey->group, order, ctx))
		{
		ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_INVALID_GROUP_ORDER);
		goto err;
		}
	if (!EC_POINT_copy(point, eckey->pub_key))
		{
		ECerr(EC_F_EC_KEY_CHECK_KEY, ERR_R_EC_LIB);
		goto err;
		}
	if (!EC_POINT_mul(eckey->group, point, order, NULL, NULL, ctx))
		{
		ECerr(EC_F_EC_KEY_CHECK_KEY, ERR_R_EC_LIB);
		goto err;
		}
	if (!EC_POINT_is_at_infinity(eckey->group, point))
		{
		ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_WRONG_ORDER);
		goto err;
		}
	/* in case the priv_key is present : 
	 * check if generator * priv_key == pub_key 
	 */
	if (eckey->priv_key)
		{
		if (BN_cmp(eckey->priv_key, order) >= 0)
			{
			ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_WRONG_ORDER);
			goto err;
			}
		if (!EC_POINT_mul(eckey->group, point, eckey->priv_key,
			NULL, NULL, ctx))
			{
			ECerr(EC_F_EC_KEY_CHECK_KEY, ERR_R_EC_LIB);
			goto err;
			}
		if (EC_POINT_cmp(eckey->group, point, eckey->pub_key, 
			ctx) != 0)
			{
			ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_INVALID_PRIVATE_KEY);
			goto err;
			}
		}
	ok = 1;
err:
	if (ctx   != NULL)
		BN_CTX_free(ctx);
	if (order != NULL)
		BN_free(order);
	if (point != NULL)
		EC_POINT_free(point);
	return(ok);
	}
