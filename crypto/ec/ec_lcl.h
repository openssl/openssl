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
	/* used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free, EC_GROUP_copy: */
	int (*group_init)(EC_GROUP *);
	void (*group_finish)(EC_GROUP *);
	void (*group_clear_finish)(EC_GROUP *);
	int (*group_copy)(EC_GROUP *, const EC_GROUP *);

	/* used by EC_GROUP_set_curve_GFp and EC_GROUP_get_curve_GFp: */
	int (*group_set_curve_GFp)(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int (*group_get_curve_GFp)(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);

	/* used by EC_GROUP_set_generator, EC_GROUP_get0_generator,
	 * EC_GROUP_get_order, EC_GROUP_get_cofactor:
	 */
	int (*group_set_generator)(EC_GROUP *, const EC_POINT *generator,
	        const BIGNUM *order, const BIGNUM *cofactor);
	EC_POINT *(*group_get0_generator)(const EC_GROUP *);
	int (*group_get_order)(const EC_GROUP *, BIGNUM *order, BN_CTX *);
	int (*group_get_cofactor)(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);

	/* used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free, EC_POINT_copy: */
	int (*point_init)(EC_POINT *);
	void (*point_finish)(EC_POINT *);
	void (*point_clear_finish)(EC_POINT *);
	int (*point_copy)(EC_POINT *, const EC_POINT *);

	/* used by EC_POINT_set_to_infinity,
	 * EC_POINT_set_Jprojective_coordinates_GFp, EC_POINT_get_Jprojective_coordinates_GFp,
	 * EC_POINT_set_affine_coordinates_GFp, EC_POINT_get_affine_coordinates_GFp,
	 * EC_POINT_set_compressed_coordinates_GFp:
	 */
	int (*point_set_to_infinity)(const EC_GROUP *, EC_POINT *);
	int (*point_set_Jprojective_coordinates_GFp)(const EC_GROUP *, EC_POINT *,
		const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
	int (*point_get_Jprojective_coordinates_GFp)(const EC_GROUP *, const EC_POINT *,
		BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
	int (*point_set_affine_coordinates_GFp)(const EC_GROUP *, EC_POINT *,
		const BIGNUM *x, const BIGNUM *y, BN_CTX *);
	int (*point_get_affine_coordinates_GFp)(const EC_GROUP *, const EC_POINT *,
		BIGNUM *x, BIGNUM *y, BN_CTX *);
	int (*point_set_compressed_coordinates_GFp)(const EC_GROUP *, EC_POINT *,
		const BIGNUM *x, int y_bit, BN_CTX *);

	/* used by EC_POINT_point2oct, EC_POINT_oct2point: */
	size_t (*point2oct)(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
	        unsigned char *buf, size_t len, BN_CTX *);
	int (*oct2point)(const EC_GROUP *, EC_POINT *,
	        const unsigned char *buf, size_t len, BN_CTX *);

	/* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
	int (*add)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
	int (*dbl)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
	int (*invert)(const EC_GROUP *, EC_POINT *, BN_CTX *);

	/* used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp: */
	int (*is_at_infinity)(const EC_GROUP *, const EC_POINT *);
	int (*is_on_curve)(const EC_GROUP *, const EC_POINT *, BN_CTX *);
	int (*point_cmp)(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

	/* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
	int (*make_affine)(const EC_GROUP *, EC_POINT *, BN_CTX *);
	int (*points_make_affine)(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


	/* internal functions */

	/* 'field_mul' and 'field_sqr' can be used by 'add' and 'dbl' so that
	 * the same implementations of point operations can be used with different
	 * optimized implementations of expensive field operations: */
	int (*field_mul)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int (*field_sqr)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);

	int (*field_encode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. to Montgomery */
	int (*field_decode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. from Montgomery */
	int (*field_set_to_one)(const EC_GROUP *, BIGNUM *r, BN_CTX *);
} /* EC_METHOD */;


struct ec_group_st {
	const EC_METHOD *meth;

	void *extra_data;
	void *(*extra_data_dup_func)(void *);
	void (*extra_data_free_func)(void *);
	void (*extra_data_clear_free_func)(void *);

	/* All members except 'meth' and 'extra_data...' are handled by
	 * the method functions, even if they appear generic */
	
	BIGNUM field; /* Field specification.
	               * For curves over GF(p), this is the modulus. */

	BIGNUM a, b; /* Curve coefficients.
	              * (Here the assumption is that BIGNUMs can be used
	              * or abused for all kinds of fields, not just GF(p).)
	              * For characteristic  > 3,  the curve is defined
	              * by a Weierstrass equation of the form
	              *     y^2 = x^3 + a*x + b.
	              */
	int a_is_minus3; /* enable optimized point arithmetics for special case */

	EC_POINT *generator; /* optional */
	BIGNUM order, cofactor;

	void *field_data1; /* method-specific (e.g., Montgomery structure) */
	void *field_data2; /* method-specific */
} /* EC_GROUP */;


/* Basically a 'mixin' for extra data, but available for EC_GROUPs only
 * (with visibility limited to 'package' level for now).
 * We use the function pointers as index for retrieval; this obviates
 * global ex_data-style index tables.
 * (Currently, we have one slot only, but is is possible to extend this
 * if necessary.) */
int EC_GROUP_set_extra_data(EC_GROUP *, void *extra_data, void *(*extra_data_dup_func)(void *),
	void (*extra_data_free_func)(void *), void (*extra_data_clear_free_func)(void *));
void *EC_GROUP_get_extra_data(const EC_GROUP *, void *(*extra_data_dup_func)(void *),
	void (*extra_data_free_func)(void *), void (*extra_data_clear_free_func)(void *));
void EC_GROUP_free_extra_data(EC_GROUP *);
void EC_GROUP_clear_free_extra_data(EC_GROUP *);



struct ec_point_st {
	const EC_METHOD *meth;

	/* All members except 'meth' are handled by the method functions,
	 * even if they appear generic */

	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z; /* Jacobian projective coordinates:
	           * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */
} /* EC_POINT */;



/* method functions in ecp_smpl.c */
int ec_GFp_simple_group_init(EC_GROUP *);
void ec_GFp_simple_group_finish(EC_GROUP *);
void ec_GFp_simple_group_clear_finish(EC_GROUP *);
int ec_GFp_simple_group_copy(EC_GROUP *, const EC_GROUP *);
int ec_GFp_simple_group_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int ec_GFp_simple_group_get_curve_GFp(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
int ec_GFp_simple_group_set_generator(EC_GROUP *, const EC_POINT *generator,
	const BIGNUM *order, const BIGNUM *cofactor);
EC_POINT *ec_GFp_simple_group_get0_generator(const EC_GROUP *);
int ec_GFp_simple_group_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int ec_GFp_simple_group_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);
int ec_GFp_simple_point_init(EC_POINT *);
void ec_GFp_simple_point_finish(EC_POINT *);
void ec_GFp_simple_point_clear_finish(EC_POINT *);
int ec_GFp_simple_point_copy(EC_POINT *, const EC_POINT *);
int ec_GFp_simple_point_set_to_infinity(const EC_GROUP *, EC_POINT *);
int ec_GFp_simple_set_Jprojective_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
int ec_GFp_simple_get_Jprojective_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
int ec_GFp_simple_point_set_affine_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int ec_GFp_simple_point_get_affine_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BN_CTX *);
int ec_GFp_simple_set_compressed_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, int y_bit, BN_CTX *);
size_t ec_GFp_simple_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
	unsigned char *buf, size_t len, BN_CTX *);
int ec_GFp_simple_oct2point(const EC_GROUP *, EC_POINT *,
	const unsigned char *buf, size_t len, BN_CTX *);
int ec_GFp_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int ec_GFp_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int ec_GFp_simple_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ec_GFp_simple_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int ec_GFp_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int ec_GFp_simple_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int ec_GFp_simple_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ec_GFp_simple_points_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);
int ec_GFp_simple_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int ec_GFp_simple_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);


/* method functions in ecp_mont.c */
int ec_GFp_mont_group_init(EC_GROUP *);
int ec_GFp_mont_group_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
void ec_GFp_mont_group_finish(EC_GROUP *);
void ec_GFp_mont_group_clear_finish(EC_GROUP *);
int ec_GFp_mont_group_copy(EC_GROUP *, const EC_GROUP *);
int ec_GFp_mont_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int ec_GFp_mont_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int ec_GFp_mont_field_encode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int ec_GFp_mont_field_decode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int ec_GFp_mont_field_set_to_one(const EC_GROUP *, BIGNUM *r, BN_CTX *);


/* method functions in ecp_recp.c */
int ec_GFp_recp_group_init(EC_GROUP *);
int ec_GFp_recp_group_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
void ec_GFp_recp_group_finish(EC_GROUP *);
void ec_GFp_recp_group_clear_finish(EC_GROUP *);
int ec_GFp_recp_group_copy(EC_GROUP *, const EC_GROUP *);
int ec_GFp_recp_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int ec_GFp_recp_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);


/* method functions in ecp_nist.c */
int ec_GFp_nist_group_init(EC_GROUP *);
int ec_GFp_nist_group_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
void ec_GFp_nist_group_finish(EC_GROUP *);
void ec_GFp_nist_group_clear_finish(EC_GROUP *);
int ec_GFp_nist_group_copy(EC_GROUP *, const EC_GROUP *);
int ec_GFp_nist_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int ec_GFp_nist_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
