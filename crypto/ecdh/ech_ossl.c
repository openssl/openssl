/* crypto/ecdh/ech_ossl.c */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * The ECDH software is originally written by Douglas Stebila of
 * Sun Microsystems Laboratories.
 *
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


#include "ecdh.h"
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

static int ecdh_compute_key(unsigned char *key, const EC_POINT *pub_key, EC_KEY *ecdh);

static ECDH_METHOD openssl_ecdh_meth = {
	"OpenSSL ECDH method",
	ecdh_compute_key,
#if 0
	NULL, /* init     */
	NULL, /* finish   */
#endif
	0,    /* flags    */
	NULL  /* app_data */
};

const ECDH_METHOD *ECDH_OpenSSL(void)
	{
	return &openssl_ecdh_meth;
	}


/* This implementation is based on the following primitives in the IEEE 1363 standard:
 *  - ECKAS-DH1
 *  - ECSVDP-DH
 *  - KDF1 with SHA-1
 */
static int ecdh_compute_key(unsigned char *key, const EC_POINT *pub_key, EC_KEY *ecdh)
	{
	BN_CTX *ctx;
	EC_POINT *tmp=NULL;
	BIGNUM *x=NULL, *y=NULL;
	int ret= -1, len;
	unsigned char *buf=NULL;

	if ((ctx = BN_CTX_new()) == NULL) goto err;
	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	
	if (ecdh->priv_key == NULL)
		{
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ECDH_R_NO_PRIVATE_VALUE);
		goto err;
		}

	if ((tmp=EC_POINT_new(ecdh->group)) == NULL)
		{
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (!EC_POINT_mul(ecdh->group, tmp, NULL, pub_key, ecdh->priv_key, ctx)) 
		{
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ECDH_R_POINT_ARITHMETIC_FAILURE);
		goto err;
		}
		
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ecdh->group)) == NID_X9_62_prime_field) 
		{
		if (!EC_POINT_get_affine_coordinates_GFp(ecdh->group, tmp, x, y, ctx)) 
			{
			ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ECDH_R_POINT_ARITHMETIC_FAILURE);
			goto err;
			}
		}
	else
		{
		if (!EC_POINT_get_affine_coordinates_GF2m(ecdh->group, tmp, x, y, ctx)) 
			{
			ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ECDH_R_POINT_ARITHMETIC_FAILURE);
			goto err;
			}
		}

	if ((buf = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * BN_num_bytes(x))) == NULL) 
		{
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	
	if ((len = BN_bn2bin(x,buf)) <= 0)
		{
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ERR_R_BN_LIB);
		goto err;
		}

	if ((SHA1(buf, len, key) == NULL))
		{
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ECDH_R_SHA1_DIGEST_FAILED);
		goto err;
		}
	
	ret = 20;

err:
	if (tmp) EC_POINT_free(tmp);
	if (ctx) BN_CTX_end(ctx);
	if (ctx) BN_CTX_free(ctx);
	if (buf) OPENSSL_free(buf);
	return(ret);
	}
