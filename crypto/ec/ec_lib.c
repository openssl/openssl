/* crypto/ec/ec_lib.c */
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

#include <string.h>

#include <openssl/err.h>
#include <openssl/opensslv.h>

#include "ec_lcl.h"

static const char EC_version[] = "EC" OPENSSL_VERSION_PTEXT;


/* functions for EC_GROUP objects */

EC_GROUP *EC_GROUP_new(const EC_METHOD *meth)
	{
	EC_GROUP *ret;

	if (meth == NULL)
		{
		ECerr(EC_F_EC_GROUP_NEW, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	if (meth->group_init == 0)
		{
		ECerr(EC_F_EC_GROUP_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return NULL;
		}

	ret = OPENSSL_malloc(sizeof *ret);
	if (ret == NULL)
		{
		ECerr(EC_F_EC_GROUP_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	ret->meth = meth;

	ret->extra_data = NULL;
	ret->extra_data_dup_func = 0;
	ret->extra_data_free_func = 0;
	ret->extra_data_clear_free_func = 0;
	
	if (!meth->group_init(ret))
		{
		OPENSSL_free(ret);
		return NULL;
		}
	
	return ret;
	}


void EC_GROUP_free(EC_GROUP *group)
	{
	if (!group) return;

	if (group->meth->group_finish != 0)
		group->meth->group_finish(group);

	EC_GROUP_free_extra_data(group);

	OPENSSL_free(group);
	}
 

void EC_GROUP_clear_free(EC_GROUP *group)
	{
	if (!group) return;

	if (group->meth->group_clear_finish != 0)
		group->meth->group_clear_finish(group);
	else if (group->meth != NULL && group->meth->group_finish != 0)
		group->meth->group_finish(group);

	EC_GROUP_clear_free_extra_data(group);

	OPENSSL_cleanse(group, sizeof *group);
	OPENSSL_free(group);
	}


int EC_GROUP_copy(EC_GROUP *dest, const EC_GROUP *src)
	{
	if (dest->meth->group_copy == 0)
		{
		ECerr(EC_F_EC_GROUP_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (dest->meth != src->meth)
		{
		ECerr(EC_F_EC_GROUP_COPY, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	if (dest == src)
		return 1;
	
	EC_GROUP_clear_free_extra_data(dest);
	if (src->extra_data_dup_func)
		{
		if (src->extra_data != NULL)
			{
			dest->extra_data = src->extra_data_dup_func(src->extra_data);
			if (dest->extra_data == NULL)
				return 0;
			}

		dest->extra_data_dup_func = src->extra_data_dup_func;
		dest->extra_data_free_func = src->extra_data_free_func;
		dest->extra_data_clear_free_func = src->extra_data_clear_free_func;
		}

	return dest->meth->group_copy(dest, src);
	}


const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group)
	{
	return group->meth;
	}


int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	if (group->meth->group_set_curve_GFp == 0)
		{
		ECerr(EC_F_EC_GROUP_SET_CURVE_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_set_curve_GFp(group, p, a, b, ctx);
	}


int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
	{
	if (group->meth->group_get_curve_GFp == 0)
		{
		ECerr(EC_F_EC_GROUP_GET_CURVE_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_get_curve_GFp(group, p, a, b, ctx);
	}


int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor)
	{
	if (group->meth->group_set_generator == 0)
		{
		ECerr(EC_F_EC_GROUP_SET_GENERATOR, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_set_generator(group, generator, order, cofactor);
	}


EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group)
	{
	if (group->meth->group_get0_generator == 0)
		{
		ECerr(EC_F_EC_GROUP_GET0_GENERATOR, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_get0_generator(group);
	}


int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx)
	{
	if (group->meth->group_get_order == 0)
		{
		ECerr(EC_F_EC_GROUP_GET_ORDER, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_get_order(group, order, ctx);
	}


int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx)
	{
	if (group->meth->group_get_cofactor == 0)
		{
		ECerr(EC_F_EC_GROUP_GET_COFACTOR, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_get_cofactor(group, cofactor, ctx);
	}


/* this has 'package' visibility */
int EC_GROUP_set_extra_data(EC_GROUP *group, void *extra_data, void *(*extra_data_dup_func)(void *),
	void (*extra_data_free_func)(void *), void (*extra_data_clear_free_func)(void *))
	{
	if ((group->extra_data != NULL)
		|| (group->extra_data_dup_func != 0)
		|| (group->extra_data_free_func != 0)
		|| (group->extra_data_clear_free_func != 0))
		{
		ECerr(EC_F_EC_GROUP_SET_EXTRA_DATA, EC_R_SLOT_FULL);
		return 0;
		}

	group->extra_data = extra_data;
	group->extra_data_dup_func = extra_data_dup_func;
	group->extra_data_free_func = extra_data_free_func;
	group->extra_data_clear_free_func = extra_data_clear_free_func;
	return 1;
	}


/* this has 'package' visibility */
void *EC_GROUP_get_extra_data(const EC_GROUP *group, void *(*extra_data_dup_func)(void *),
	void (*extra_data_free_func)(void *), void (*extra_data_clear_free_func)(void *))
	{
	if ((group->extra_data_dup_func != extra_data_dup_func)
		|| (group->extra_data_free_func != extra_data_free_func)
		|| (group->extra_data_clear_free_func != extra_data_clear_free_func))
		{
		ECerr(EC_F_EC_GROUP_GET_EXTRA_DATA, EC_R_NO_SUCH_EXTRA_DATA);
		return NULL;
		}

	return group->extra_data;
	}


/* this has 'package' visibility */
void EC_GROUP_free_extra_data(EC_GROUP *group)
	{
	if (group->extra_data_free_func)
		group->extra_data_free_func(group->extra_data);
	group->extra_data = NULL;
	group->extra_data_dup_func = 0;
	group->extra_data_free_func = 0;
	group->extra_data_clear_free_func = 0;
	}


/* this has 'package' visibility */
void EC_GROUP_clear_free_extra_data(EC_GROUP *group)
	{
	if (group->extra_data_clear_free_func)
		group->extra_data_clear_free_func(group->extra_data);
	else if (group->extra_data_free_func)
		group->extra_data_free_func(group->extra_data);
	group->extra_data = NULL;
	group->extra_data_dup_func = 0;
	group->extra_data_free_func = 0;
	group->extra_data_clear_free_func = 0;
	}



/* functions for EC_POINT objects */

EC_POINT *EC_POINT_new(const EC_GROUP *group)
	{
	EC_POINT *ret;

	if (group == NULL)
		{
		ECerr(EC_F_EC_POINT_NEW, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	if (group->meth->point_init == 0)
		{
		ECerr(EC_F_EC_POINT_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return NULL;
		}

	ret = OPENSSL_malloc(sizeof *ret);
	if (ret == NULL)
		{
		ECerr(EC_F_EC_POINT_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	ret->meth = group->meth;
	
	if (!ret->meth->point_init(ret))
		{
		OPENSSL_free(ret);
		return NULL;
		}
	
	return ret;
	}


void EC_POINT_free(EC_POINT *point)
	{
	if (!point) return;

	if (point->meth->point_finish != 0)
		point->meth->point_finish(point);
	OPENSSL_free(point);
	}
 

void EC_POINT_clear_free(EC_POINT *point)
	{
	if (!point) return;

	if (point->meth->point_clear_finish != 0)
		point->meth->point_clear_finish(point);
	else if (point->meth != NULL && point->meth->point_finish != 0)
		point->meth->point_finish(point);
	OPENSSL_cleanse(point, sizeof *point);
	OPENSSL_free(point);
	}


int EC_POINT_copy(EC_POINT *dest, const EC_POINT *src)
	{
	if (dest->meth->point_copy == 0)
		{
		ECerr(EC_F_EC_POINT_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (dest->meth != src->meth)
		{
		ECerr(EC_F_EC_POINT_COPY, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	if (dest == src)
		return 1;
	return dest->meth->point_copy(dest, src);
	}


const EC_METHOD *EC_POINT_method_of(const EC_POINT *point)
	{
	return point->meth;
	}


int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point)
	{
	if (group->meth->point_set_to_infinity == 0)
		{
		ECerr(EC_F_EC_POINT_SET_TO_INFINITY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_SET_TO_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point_set_to_infinity(group, point);
	}


int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
	const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *ctx)
	{
	if (group->meth->point_set_Jprojective_coordinates_GFp == 0)
		{
		ECerr(EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point_set_Jprojective_coordinates_GFp(group, point, x, y, z, ctx);
	}


int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group, const EC_POINT *point,
	BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *ctx)
	{
	if (group->meth->point_get_Jprojective_coordinates_GFp == 0)
		{
		ECerr(EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point_get_Jprojective_coordinates_GFp(group, point, x, y, z, ctx);
	}


int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)
	{
	if (group->meth->point_set_affine_coordinates_GFp == 0)
		{
		ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point_set_affine_coordinates_GFp(group, point, x, y, ctx);
	}


int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group, const EC_POINT *point,
	BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
	{
	if (group->meth->point_get_affine_coordinates_GFp == 0)
		{
		ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point_get_affine_coordinates_GFp(group, point, x, y, ctx);
	}


int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
	const BIGNUM *x, int y_bit, BN_CTX *ctx)
	{
	if (group->meth->point_set_compressed_coordinates_GFp == 0)
		{
		ECerr(EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point_set_compressed_coordinates_GFp(group, point, x, y_bit, ctx);
	}


size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *point, point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *ctx)
	{
	if (group->meth->point2oct == 0)
		{
		ECerr(EC_F_EC_POINT_POINT2OCT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_POINT2OCT, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point2oct(group, point, form, buf, len, ctx);
	}


int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *point,
        const unsigned char *buf, size_t len, BN_CTX *ctx)
	{
	if (group->meth->oct2point == 0)
		{
		ECerr(EC_F_EC_POINT_OCT2POINT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_OCT2POINT, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->oct2point(group, point, buf, len, ctx);
	}


int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)
	{
	if (group->meth->add == 0)
		{
		ECerr(EC_F_EC_POINT_ADD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if ((group->meth != r->meth) || (r->meth != a->meth) || (a->meth != b->meth))
		{
		ECerr(EC_F_EC_POINT_ADD, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->add(group, r, a, b, ctx);
	}


int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx)
	{
	if (group->meth->dbl == 0)
		{
		ECerr(EC_F_EC_POINT_DBL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if ((group->meth != r->meth) || (r->meth != a->meth))
		{
		ECerr(EC_F_EC_POINT_DBL, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->dbl(group, r, a, ctx);
	}


int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx)
	{
	if (group->meth->dbl == 0)
		{
		ECerr(EC_F_EC_POINT_DBL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != a->meth)
		{
		ECerr(EC_F_EC_POINT_DBL, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->invert(group, a, ctx);
	}


int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *point)
	{
	if (group->meth->is_at_infinity == 0)
		{
		ECerr(EC_F_EC_POINT_IS_AT_INFINITY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_IS_AT_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->is_at_infinity(group, point);
	}


int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx)
	{
	if (group->meth->is_on_curve == 0)
		{
		ECerr(EC_F_EC_POINT_IS_ON_CURVE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_IS_ON_CURVE, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->is_on_curve(group, point, ctx);
	}


int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)
	{
	if (group->meth->point_cmp == 0)
		{
		ECerr(EC_F_EC_POINT_CMP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if ((group->meth != a->meth) || (a->meth != b->meth))
		{
		ECerr(EC_F_EC_POINT_CMP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point_cmp(group, a, b, ctx);
	}


int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)
	{
	if (group->meth->make_affine == 0)
		{
		ECerr(EC_F_EC_POINT_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->make_affine(group, point, ctx);
	}


int EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx)
	{
	size_t i;

	if (group->meth->points_make_affine == 0)
		{
		ECerr(EC_F_EC_POINTS_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	for (i = 0; i < num; i++)
		{
		if (group->meth != points[i]->meth)
			{
			ECerr(EC_F_EC_POINTS_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
			return 0;
			}
		}
	return group->meth->points_make_affine(group, num, points, ctx);
	}
