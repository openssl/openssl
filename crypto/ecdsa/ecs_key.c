/* crypto/ecdsa/ecs_key.c */
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

int ECDSA_generate_key(ECDSA *ecdsa)
{	
	int ok=0;
	BN_CTX *ctx=NULL;
	BIGNUM *priv_key=NULL,*order=NULL;
	EC_POINT *pub_key=NULL;

	if (!ecdsa || !ecdsa->group)
	{
		ECDSAerr(ECDSA_F_ECDSA_GENERATE_KEY,ECDSA_R_MISSING_PARAMETERS);
		return 0;
	}

	if ((order = BN_new()) == NULL) goto err;
	if ((ctx = BN_CTX_new()) == NULL) goto err;

	if (ecdsa->priv_key == NULL)
	{
		if ((priv_key = BN_new()) == NULL) goto err;
	}
	else
		priv_key = ecdsa->priv_key;

	if (!EC_GROUP_get_order(ecdsa->group, order, ctx)) goto err;
	do
		if (!BN_rand_range(priv_key, order)) goto err;
	while (BN_is_zero(priv_key));

	if (ecdsa->pub_key == NULL)
	{
		if ((pub_key = EC_POINT_new(ecdsa->group)) == NULL) goto err;
	}
	else
		pub_key = ecdsa->pub_key;

	if (!EC_POINT_mul(ecdsa->group, pub_key, priv_key, NULL, NULL, ctx)) goto err;

	ecdsa->priv_key = priv_key;
	ecdsa->pub_key  = pub_key;
	ok=1;
err:	if (order)	BN_free(order);
	if ((pub_key  != NULL) && (ecdsa->pub_key  == NULL)) EC_POINT_free(pub_key);
	if ((priv_key != NULL) && (ecdsa->priv_key == NULL)) BN_free(priv_key);
	if (ctx != NULL) BN_CTX_free(ctx);
	return(ok);
}

int ECDSA_check_key(ECDSA *ecdsa)
{
	int ok=0;
	BN_CTX *ctx=NULL;
	BIGNUM *order=NULL;
	EC_POINT *point=NULL;

	if (!ecdsa || !ecdsa->group || !ecdsa->pub_key)
		return 0;
	
	if ((ctx = BN_CTX_new()) == NULL) goto err;
	if ((order = BN_new()) == NULL) goto err;
	if ((point = EC_POINT_new(ecdsa->group)) == NULL) goto err;

	/* testing whether pub_key is a valid point on the elliptic curve */
	if (!EC_POINT_is_on_curve(ecdsa->group,ecdsa->pub_key,ctx)) goto err;
	/* testing whether pub_key * order is the point at infinity */
	if (!EC_GROUP_get_order(ecdsa->group,order,ctx)) goto err;
	if (!EC_POINT_copy(point,ecdsa->pub_key)) goto err;
	if (!EC_POINT_mul(ecdsa->group,point,order,NULL,NULL,ctx)) goto err;
	if (!EC_POINT_is_at_infinity(ecdsa->group,point)) goto err;
	/* in case the priv_key is present : check if generator * priv_key == pub_key */
	if (ecdsa->priv_key)
	{
		if (BN_cmp(ecdsa->priv_key,order) >= 0) goto err;
		if (!EC_POINT_mul(ecdsa->group,point,ecdsa->priv_key,NULL,NULL,ctx)) goto err;
		if (EC_POINT_cmp(ecdsa->group,point,ecdsa->pub_key,ctx) != 0) goto err;
	}
	ok = 1;
err:
	if (ctx   != NULL) BN_CTX_free(ctx);
	if (order != NULL) BN_free(order);
	if (point != NULL) EC_POINT_free(point);
	return(ok);
}
