/* TODO */
/* crypto/ec/ec_lcl.h */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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


#include <stdlib.h>

#include <openssl/ec.h>


/* Structure details are not part of the exported interface,
 * so all this may change in future versions. */

struct ec_method_st {
	/* used by EC_GROUP_new, EC_GROUP_set_GFp, EC_GROUP_free: */
	int (*group_init)(EC_GROUP *);
	/* int (*group_set)(EC_GROUP *, .....); */
	int (*group_set_GFp)(EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b);
	void (*group_finish)(EC_GROUP *);

	/* used by EC_POINT_new, EC_POINT_free: */
	int (*point_init)(EC_POINT *);
	void (*point_finish)(EC_POINT *);

	/* used by EC_POINT_add, EC_POINT_dbl: */
	int (*add)(const EC_GROUP *, EC_POINT *r, EC_POINT *a, EC_POINT *b);
	int (*dbl)(const EC_GROUP *, EC_POINT *r, EC_POINT *a);

	/* used by EC_POINT_add, EC_POINT_dbl: */
	size_t (*point2oct)(const EC_GROUP *, EC_POINT *, unsigned char *buf,
	        size_t len, point_conversion_form_t form);
	int (*oct2point)(const EC_GROUP *, EC_POINT *, unsigned char *buf, size_t len);


	/* internal functions */

	/* 'field_mult' and 'field_sqr' can be used by 'add' and 'dbl' so that
	 * the same implementations of point operations can be used with different
	 * implementations of field operations: */
	int (*field_mult)(const EC_GROUP *, BIGNUM *r, BIGNUM *a, BIGNUM *b);
	int (*field_sqr)(const EC_GROUP *, BIGNUM *r, BIGNUM *a);
} /* EC_METHOD */;


struct ec_group_st {
	EC_METHOD *meth;

	BIGNUM field; /* Field specification.
	               * For curves over GF(p), this is the modulus. */
	void *field_data; /* method-specific (e.g., Montgomery structure) */

	BIGNUM a, b; /* Curve coefficients.
	              * (Here the assumption is that BIGNUMs can be used
	              * or abused for all kinds of fields, not just GF(p).) */
	int a_is_minus3; /* enable optimized point arithmetics for special case */

	/* TODO: optional generator with associated information (order, cofactor) */
	/*       optional Lim/Lee precomputation table */
} /* EC_GROUP */;


struct ec_point_st {
	EC_METHOD *meth;

	BIGNUM x;
	BIGNUM y;
	BIGNUM z; /* Jacobian projective coordinates */
	int z_is_one; /* enable optimized point arithmetics for special case */
} /* EC_POINT */;
