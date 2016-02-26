/*
 * Written by Diego F. Aranha (d@miracl.com) and contributed to the
 * the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
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
 *    licensing@OpenSSL.org.
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
/*
 * ====================================================================
 * Copyright 2016 MIRACL UK Ltd., All Rights Reserved. Portions of the
 * attached software ("Contribution") are developed by MIRACL UK LTD., and
 * are contributed to the OpenSSL project. The Contribution is licensed
 * pursuant to the OpenSSL open source license provided above.
 */
#ifndef HEADER_BP_H
# define HEADER_BP_H

# include <stdint.h>
# include "openssl/ec.h"
# include "openssl/bn.h"

# ifdef  __cplusplus
extern "C" {
# endif

# include <stdlib.h>

# include <openssl/obj_mac.h>
# include <openssl/ec.h>
# include <openssl/bn.h>

/********************************************************************/
/*               Types for bilinear group elements                  */
/********************************************************************/

/** Represents a set of bilinear groups G1, G2, GT.
 */
typedef struct bp_group_st BP_GROUP;

/** Element from additive group G1.
 */
typedef struct bp_g1_elem_st G1_ELEM;

/** Element from additive group G2.
 */
typedef struct bp_g2_elem_st G2_ELEM;

/** Element from multiplicative target group G_T.
 */
typedef struct bp_gt_elem_st GT_ELEM;

/********************************************************************/
/*            Functions for managing bilinear groups                */
/********************************************************************/

/** Creates a new BP_GROUP object
 *  \return newly created BP_GROUP object or NULL in case of error.
 */
BP_GROUP *BP_GROUP_new(void);

/** The curve identifier assigned to the only supported curve.
 */
# define NID_fp254bnb          1

/** Creates a new BP_GROUP object from a curve identifier
 *  \param  nid    the curve identifier
 *  \return newly created BP_GROUP object or NULL in case of error.
 */
BP_GROUP *BP_GROUP_new_by_curve_name(int nid);

/** Creates a new BP_GROUP object from the curve parameters
 *  \param  p      the prime modulus
 *  \param  a      the a-coefficient of the curve
 *  \param  b      the b-coefficient of the curve
 *  \param  ctx    BN_CTX object (optional)
 *  \return newly created BP_GROUP object or NULL in case of error.
 */
BP_GROUP *BP_GROUP_new_curve(const BIGNUM *p, const BIGNUM *a,
                             const BIGNUM *b, BN_CTX *ctx);

/** Frees a BP_GROUP object
 *  \param group   the BP_GROUP object to be freed.
 */
void BP_GROUP_free(BP_GROUP *group);

/** Clears and frees a BP_GROUP object
 *  \param group   the BP_GROUP object to be cleared and freed.
 */
void BP_GROUP_clear_free(BP_GROUP *group);

/** Copies BP_GROUP objects
 *  \param  dst    destination BP_GROUP object
 *  \param  src    source BP_GROUP object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_GROUP_copy(BP_GROUP *dest, const BP_GROUP *src);

/** Creates a new BP_GROUP object and copies the copies the content
 *  form src to the newly created BP_GROUP object
 *  \param  src    source BP_GROUP object
 *  \return newly created BP_GROUP object or NULL in case of an error.
 */
BP_GROUP *BP_GROUP_dup(const BP_GROUP *a);

/** Assigns a set of curve parameters to a BP_GROUP object
 *  \param  group  the BP_GROUP object
 *  \param  p      the prime modulus
 *  \param  a      the a-coefficient of the curve
 *  \param  b      the b-coefficient of the curve
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_set_curve(BP_GROUP *group, const BIGNUM *p,
                       const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

/** Returns the set of curve parameters from a BP_GROUP object
 *  \param  group  the BP_GROUP object
 *  \param  p      the BIGNUM to which the prime modulus is copied
 *  \param  a      the BIGNUM to which the a-coefficient is copied
 *  \param  b      the BIGNUM to which the b-coefficient is copied
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_get_curve(const BP_GROUP *group, BIGNUM *p, BIGNUM *a,
                       BIGNUM *b, BN_CTX *ctx);

/** Returns an EC_GROUP object corresponding to group G1.
 *  \param  group  the BP_GROUP object
 *  \return EC_GROUP correspoding to group G1
 */
 const EC_GROUP *BP_GROUP_get_group_G1(BP_GROUP *group);

/** Returns the order of the bilinear groups.
 *  \param  group  the BP_GROUP object
 *  \param  order  BIGNUM to which the group order is copied
 *  \param  ctx    unused
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_get_order(const BP_GROUP *group, BIGNUM *order, BN_CTX *ctx);

/** Assigns the integer parameter of the curve.
 *  \param  group  the BP_GROUP object
 *  \param  param  the integer parameterizing the curve
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_set_param(BP_GROUP *group, BIGNUM *param);

/** Returns the integer parameter of the curve.
 *  \param  group  the BP_GROUP object
 *  \param  param  the BIGNUM to which the parameter is copied
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_get_param(const BP_GROUP *group, BIGNUM *param);

/********************************************************************/
/*      Functions for managing generators and precomputation        */
/********************************************************************/

/** Assigns the generator and its prime order to group G1.
 *  \param  group  the BP_GROUP object
 *  \param  g      the group generator
 *  \param  n      the order of the generator
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_set_generator_G1(const BP_GROUP *group, G1_ELEM *g, BIGNUM *n);

/** Returns the generator assigned to group G1.
 *  \param  group  the BP_GROUP object
 *  \param  g      the group generator
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_get_generator_G1(const BP_GROUP *group, G1_ELEM *g);

/** Precomputes and stores multiples of the generator of group G1 to
 *  accelerate fixed-point multiplication.
 *  \param  group  the BP_GROUP object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_precompute_mult_G1(BP_GROUP *group, BN_CTX *ctx);

/** Reports whether a precomputation for the G1 generator has been done
 *  \param  group  BP_GROUP object
 *  \return 1 if a pre-computation has been done and 0 otherwise
 */
int BP_GROUP_have_precompute_mult_G1(const BP_GROUP *group);

/** Assigns the generator and its prime order to group G2.
 *  \param  group  the BP_GROUP object
 *  \param  g      the group generator
 *  \param  n      the order of the generator
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_get_generator_G2(const BP_GROUP *group, G2_ELEM *g);

/** Returns the generator assigned to group G2.
 *  \param  group  the BP_GROUP object
 *  \param  g      the group generator
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_set_generator_G2(const BP_GROUP *group, G2_ELEM *g);

/** Precomputes and stores multiples of the generator of group G2 to
 *  accelerate fixed-point multiplication.
 *  \param  group  the BP_GROUP object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int BP_GROUP_precompute_mult_G2(BP_GROUP *group, BN_CTX *ctx);

/** Reports whether a precomputation for the G2 generator has been done
 *  \param  group  BP_GROUP object
 *  \return 1 if a pre-computation has been done and 0 otherwise
 */
int BP_GROUP_have_precompute_mult_G2(const BP_GROUP *group);

/********************************************************************/
/*              Functions for managing G1 elements                  */
/********************************************************************/

/** Creates a new G1_ELEM object for the specified BP_GROUP
 *  \param  group  the underlying G1_ELEM object
 *  \return newly created G1_ELEM object or NULL if an error occurred
 */
G1_ELEM *G1_ELEM_new(const BP_GROUP *group);

/** Frees a G1_ELEM object
 *  \param  point  G1_ELEM object to be freed
 */
void G1_ELEM_free(G1_ELEM *point);

/** Clears and frees a G1_ELEM object
 *  \param  point  G1_ELEM object to be cleared and freed
 */
void G1_ELEM_clear_free(G1_ELEM *point);

/** Copies a G1_ELEM object
 *  \param  dst  destination G1_ELEM object
 *  \param  src  source G1_ELEM object
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_copy(G1_ELEM *dst, const G1_ELEM *src);

/** Creates a new G1_ELEM object and copies the content of the supplied
 *  G1_ELEM
 *  \param  src    source G1_ELEM object
 *  \param  group  underlying the G1_ELEM object
 *  \return newly created G1_ELEM object or NULL if an error occurred
 */
G1_ELEM *G1_ELEM_dup(const G1_ELEM *src, const BP_GROUP *group);

/** Sets a G1_ELEM to infinity (neutral element)
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G1_ELEM to set to infinity
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_set_to_infinity(const BP_GROUP *group, G1_ELEM *point);

/** Sets the Jacobian projective coordinates of a G1_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G1_ELEM object
 *  \param  x      BIGNUM with the x-coordinate
 *  \param  y      BIGNUM with the y-coordinate
 *  \param  z      BIGNUM with the z-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_set_Jprojective_coordinates(const BP_GROUP *group,
                                        G1_ELEM *point, const BIGNUM *x,
                                        const BIGNUM *y,
                                        const BIGNUM *z, BN_CTX *ctx);
/** Gets the Jacobian projective coordinates of a G1_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G1_ELEM object
 *  \param  x      BIGNUM for the x-coordinate
 *  \param  y      BIGNUM for the y-coordinate
 *  \param  z      BIGNUM for the z-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_get_Jprojective_coordinates(const BP_GROUP *group,
                                        const G1_ELEM *point, BIGNUM *x,
                                        BIGNUM *y, BIGNUM *z,
                                        BN_CTX *ctx);

/** Sets the affine coordinates of a G1_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G1_ELEM object
 *  \param  x      BIGNUM with the x-coordinate
 *  \param  y      BIGNUM with the y-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_set_affine_coordinates(const BP_GROUP *group, G1_ELEM *point,
                                   const BIGNUM *x, const BIGNUM *y,
                                   BN_CTX *ctx);

/** Gets the affine coordinates of a G1_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G1_ELEM object
 *  \param  x      BIGNUM for the x-coordinate
 *  \param  y      BIGNUM for the y-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_get_affine_coordinates(const BP_GROUP *group,
                                   const G1_ELEM *point, BIGNUM *x,
                                   BIGNUM *y, BN_CTX *ctx);

/** Sets the compressed coordinates of a G1_ELEM over GFp
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G1_ELEM object
 *  \param  x      BIGNUM with x-coordinate
 *  \param  y_bit  integer with the y-Bit (either 0 or 1)
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_set_compressed_coordinates(const BP_GROUP *group,
                                       G1_ELEM *point, const BIGNUM *x,
                                       int y_bit, BN_CTX *ctx);

/** Encodes a G1_ELEM object to an octet string
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G1_ELEM object
 *  \param  form   point conversion form
 *  \param  buf    memory buffer for the result. If NULL the function returns
 *                 required buffer size.
 *  \param  len    length of the memory buffer
 *  \param  ctx    BN_CTX object (optional)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t G1_ELEM_point2oct(const BP_GROUP *group, const G1_ELEM *point,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *ctx);

/** Decodes a G1_ELEM from a octet string
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G1_ELEM object
 *  \param  buf    memory buffer with the encoded ec point
 *  \param  len    length of the encoded ec point
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_oct2point(const BP_GROUP *group, const G1_ELEM *point,
                      const unsigned char *buf, size_t len, BN_CTX *ctx);

/********************************************************************/
/*              Functions for arithmetic in group G1                */
/********************************************************************/

/** Computes the sum of two G1_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  r      G1_ELEM object for the result (r = a + b)
 *  \param  a      G1_ELEM object with the first summand
 *  \param  b      G1_ELEM object with the second summand
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_add(const BP_GROUP *group, G1_ELEM *r, const G1_ELEM *a,
                const G1_ELEM *b, BN_CTX *ctx);

/** Computes the double of a G1_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  r      G1_ELEM object for the result (r = 2 * a)
 *  \param  a      G1_ELEM object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_dbl(const BP_GROUP *group, G1_ELEM *r, const G1_ELEM *a,
                BN_CTX *ctx);

/** Computes the inverse of a G1_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  a      G1_ELEM object to be inverted inplace
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_invert(const BP_GROUP *group, G1_ELEM *a, BN_CTX *ctx);

/** Checks whether the point is the neutral element of the group
 *  \param  group  the underlying BP_GROUP object
 *  \param  point  G1_ELEM object
 *  \return 1 if the point is the neutral element and 0 otherwise
 */
int G1_ELEM_is_at_infinity(const BP_GROUP *group, const G1_ELEM *point);

/** Checks whether the point is on the curve
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G1_POINT object to check
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 if point if on the curve and 0 otherwise
 */
int G1_ELEM_is_on_curve(const BP_GROUP *group, const G1_ELEM *point,
                        BN_CTX *ctx);

/** Compares two G1_ELEMs
 *  \param  group  underlying BP_GROUP object
 *  \param  a      first G1_ELEM object
 *  \param  b      second G1_ELEM object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 0 if both points are equal and a value != 0 otherwise
 */
int G1_ELEM_cmp(const BP_GROUP *group, const G1_ELEM *point,
                const G1_ELEM *b, BN_CTX *ctx);

/** Converts a G1_ELEM to affine coordinates
 *  \param  group  underlying BP_GROUP object
 *  \param  point  the point to convert
 *  \param  ctx    BN_CTX object (optional)
 */
int G1_ELEM_make_affine(const BP_GROUP *group, G1_ELEM *point, BN_CTX *ctx);

/** Converts multiple G1_ELEMs simultaneously to affine coordinates
 *  \param  group  underlying BP_GROUP object
 *  \param  num    the number of points to convert
 *  \param  points the points to convert
 *  \param  ctx    BN_CTX object (optional)
 */
int G1_ELEMs_make_affine(const BP_GROUP *group, size_t num,
                         G1_ELEM *points[], BN_CTX *ctx);

/** Computes r = generator * n + q * m
 *  \param  group  underlying BP_GROUP object
 *  \param  r      G1_ELEM object for the result
 *  \param  n      BIGNUM with the multiplier for the group generator (optional)
 *  \param  q      G1_ELEM object with the first factor of the second summand
 *  \param  m      BIGNUM with the second factor of the second summand
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEM_mul(const BP_GROUP *group, G1_ELEM *r, const BIGNUM *g_scalar,
                const G1_ELEM *point, const BIGNUM *p_scalar,
                BN_CTX *ctx);

/** Computes r = generator * n sum_{i=0}^{num-1} p[i] * m[i]
 *  \param  group  underlying BP_GROUP object
 *  \param  r      G1_ELEM object for the result
 *  \param  n      BIGNUM with the multiplier for the group generator (optional)
 *  \param  num    number futher summands
 *  \param  p      array of size num of G1_ELEM objects
 *  \param  m      array of size num of BIGNUM objects
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G1_ELEMs_mul(const BP_GROUP *group, G1_ELEM *r, const BIGNUM *scalar,
                 size_t num, const G1_ELEM *points[],
                 const BIGNUM *scalars[], BN_CTX *ctx);

/********************************************************************/
/*              Functions for managing G2 elements                  */
/********************************************************************/

/** Creates a new G2_ELEM object for the specified BP_GROUP
 *  \param  group  the underlying G2_ELEM object
 *  \return newly created G2_ELEM object or NULL if an error occurred
 */
G2_ELEM *G2_ELEM_new(const BP_GROUP *group);

/** Frees a G2_ELEM object
 *  \param  point  G2_ELEM object to be freed
 */
void G2_ELEM_free(G2_ELEM *point);

/** Clears and frees a G2_ELEM object
 *  \param  point  G2_ELEM object to be cleared and freed
 */
void G2_ELEM_clear_free(G2_ELEM *point);

/** Copies G2_ELEM object
 *  \param  dst  destination G2_ELEM object
 *  \param  src  source G2_ELEM object
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_copy(G2_ELEM *dst, const G2_ELEM *src);

/** Creates a new G2_ELEM object and copies the content of the supplied
 *  G2_ELEM
 *  \param  src    source G2_ELEM object
 *  \param  group  underlying the G2_ELEM object
 *  \return newly created G2_ELEM object or NULL if an error occurred
 */
G2_ELEM *G2_ELEM_dup(const G2_ELEM *src, const BP_GROUP *group);

/********************************************************************/
/*              Functions for arithmetic in group G2                */
/********************************************************************/

/** Sets a G2_ELEM to infinity (neutral element)
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G2_ELEM to set to infinity
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_set_to_infinity(const BP_GROUP *group, G2_ELEM *point);

/** Sets the Jacobian projective coordinates of a G2_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G2_ELEM object
 *  \param  x      BIGNUM with the x-coordinate
 *  \param  y      BIGNUM with the y-coordinate
 *  \param  z      BIGNUM with the z-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_set_Jprojective_coordinates(const BP_GROUP *group,
                                        G2_ELEM *point, const BIGNUM *x[2],
                                        const BIGNUM *y[2],
                                        const BIGNUM *z[2], BN_CTX *ctx);

/** Gets the Jacobian projective coordinates of a G2_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G2_ELEM object
 *  \param  x      BIGNUM for the x-coordinate
 *  \param  y      BIGNUM for the y-coordinate
 *  \param  z      BIGNUM for the z-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_get_Jprojective_coordinates(const BP_GROUP *group,
                                        const G2_ELEM *point, BIGNUM *x[2],
                                        BIGNUM *y[2], BIGNUM *z[2],
                                        BN_CTX *ctx);

/** Sets the affine coordinates of a G2_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G2_ELEM object
 *  \param  x      BIGNUM with the x-coordinate
 *  \param  y      BIGNUM with the y-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_set_affine_coordinates(const BP_GROUP *group, G2_ELEM *point,
                                   const BIGNUM *x[2], const BIGNUM *y[2],
                                   BN_CTX *ctx);

/** Gets the affine coordinates of a G2_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G2_ELEM object
 *  \param  x      BIGNUM for the x-coordinate
 *  \param  y      BIGNUM for the y-coordinate
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_get_affine_coordinates(const BP_GROUP *group,
                                   const G2_ELEM *point, BIGNUM *x[2], BIGNUM *y[2],
                                   BN_CTX *ctx);

/** Encodes a G2_ELEM object to an octet string
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G2_ELEM object
 *  \param  form   point conversion form
 *  \param  buf    memory buffer for the result. If NULL the function returns
 *                 required buffer size.
 *  \param  len    length of the memory buffer
 *  \param  ctx    BN_CTX object (optional)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t G2_ELEM_point2oct(const BP_GROUP *group, const G2_ELEM *point,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *ctx);

/** Decodes a G2_ELEM from a octet string
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G2_ELEM object
 *  \param  buf    memory buffer with the encoded ec point
 *  \param  len    length of the encoded ec point
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_oct2point(const BP_GROUP *group, G2_ELEM *point,
                      const unsigned char *buf, size_t len, BN_CTX *ctx);

/********************************************************************/
/*              Functions for arithmetic in group G2                */
/********************************************************************/

/** Computes the sum of two G2_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  r      G2_ELEM object for the result (r = a + b)
 *  \param  a      G2_ELEM object with the first summand
 *  \param  b      G2_ELEM object with the second summand
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_add(const BP_GROUP *group, G2_ELEM *r, const G2_ELEM *a,
                const G2_ELEM *b, BN_CTX *ctx);

/** Computes the double of a G2_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  r      G2_ELEM object for the result (r = 2 * a)
 *  \param  a      G2_ELEM object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_dbl(const BP_GROUP *group, G2_ELEM *r, const G2_ELEM *a,
                BN_CTX *ctx);

/** Computes the inverse of a G2_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  a      G2_ELEM object to be inverted inplace
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_invert(const BP_GROUP *group, G2_ELEM *point, BN_CTX *ctx);

/** Checks whether the point is the neutral element of the group
 *  \param  group  the underlying BP_GROUP object
 *  \param  point  G2_ELEM object
 *  \return 1 if the point is the neutral element and 0 otherwise
 */
int G2_ELEM_is_at_infinity(const BP_GROUP *group, const G2_ELEM *point);

/** Checks whether the point is on the curve
 *  \param  group  underlying BP_GROUP object
 *  \param  point  G2_POINT object to check
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 if point if on the curve and 0 otherwise
 */
int G2_ELEM_is_on_curve(const BP_GROUP *group, const G2_ELEM *point,
                        BN_CTX *ctx);

/** Compares two G2_ELEMs
 *  \param  group  underlying BP_GROUP object
 *  \param  a      first G2_ELEM object
 *  \param  b      second G2_ELEM object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 0 if both points are equal and a value != 0 otherwise
 */
int G2_ELEM_cmp(const BP_GROUP *group, const G2_ELEM *point,
                const G2_ELEM *b, BN_CTX *ctx);

/** Converts a G2_ELEM to affine coordinates
 *  \param  group  underlying BP_GROUP object
 *  \param  point  the point to convert
 *  \param  ctx    BN_CTX object (optional)
 */
int G2_ELEM_make_affine(const BP_GROUP *group, G2_ELEM *point, BN_CTX *ctx);

/** Converts multiple G2_ELEMs simultaneously to affine coordinates.
 *  \param  group  underlying BP_GROUP object
 *  \param  num    the number of points to convert
 *  \param  points the points to convert
 *  \param  ctx    BN_CTX object (optional)
 */
int G2_ELEMs_make_affine(const BP_GROUP *group, size_t num,
                         G2_ELEM *points[], BN_CTX *ctx);

/** Computes r = generator * n + q * m
 *  \param  group  underlying BP_GROUP object
 *  \param  r      G2_ELEM object for the result
 *  \param  n      BIGNUM with the multiplier for the group generator (optional)
 *  \param  q      G2_ELEM object with the first factor of the second summand
 *  \param  m      BIGNUM with the second factor of the second summand
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEM_mul(const BP_GROUP *group, G2_ELEM *r, const BIGNUM *g_scalar,
                const G2_ELEM *point, const BIGNUM *p_scalar,
                BN_CTX *ctx);

/** Computes r = generator * n sum_{i=0}^{num-1} p[i] * m[i]
 *  \param  group  underlying BP_GROUP object
 *  \param  r      G2_ELEM object for the result
 *  \param  n      BIGNUM with the multiplier for the group generator (optional)
 *  \param  num    number futher summands
 *  \param  p      array of size num of G2_ELEM objects
 *  \param  m      array of size num of BIGNUM objects
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int G2_ELEMs_mul(const BP_GROUP *group, G2_ELEM *r, const BIGNUM *scalar,
                 size_t num, const G2_ELEM *points[],
                 const BIGNUM *scalars[], BN_CTX *ctx);

/********************************************************************/
/*              Functions for managing GT elements                  */
/********************************************************************/

/** Creates a new GT_ELEM object for the specified BP_GROUP
 *  \param  group  the underlying GT_ELEM object
 *  \return newly created GT_ELEM object or NULL if an error occurred
 */
GT_ELEM *GT_ELEM_new(const BP_GROUP *group);

/** Frees a GT_ELEM object
 *  \param  elem   GT_ELEM object to be freed
 */
void GT_ELEM_free(GT_ELEM *elem);

/** Clears and frees a GT_ELEM object
 *  \param  elem   GT_ELEM object to be cleared and freed
 */
void GT_clear_free(GT_ELEM *a);

/** Copies GT_ELEM object
 *  \param  dst  destination GT_ELEM object
 *  \param  src  source GT_ELEM object
 *  \return 1 on success and 0 if an error occurred
 */
int GT_ELEM_copy(GT_ELEM *dst, const GT_ELEM *src);

/** Creates a new GT_ELEM object and copies the content of the supplied
 *  GT_ELEM
 *  \param  src    source GT_ELEM object
 *  \param  group  underlying the GT_ELEM object
 *  \return newly created GT_ELEM object or NULL if an error occurred
 */
GT_ELEM *GT_ELEM_dup(const GT_ELEM *src, const BP_GROUP *group);

/** Assigns a GT_ELEM to zero
 *  \param  a     the field element to assign
 *  \return 1 on success and 0 if an error occurred
 */
int GT_ELEM_zero(GT_ELEM *a);

/** Checks if a GT_ELEM equals zero
 *  \param  a     the field element to check
 *  \return 1 is equal to 0, and 0 otherwise.
 */
int GT_ELEM_is_zero(GT_ELEM *a);

/** Assigns a GT_ELEM to 1
 *  \param  a     the field element to assign
 *  \return 1 on success and 0 if an error occurred
 */
int GT_ELEM_set_to_unity(const BP_GROUP *group, GT_ELEM *a);

/** Checks if a GT_ELEM equals the 1
 *  \param  a     the field element to check
 *  \return 1 is equal to 1, and 0 otherwise.
 */
int GT_ELEM_is_unity(const BP_GROUP *group, const GT_ELEM *a);

/** Encodes a GT_ELEM object to an octet string
 *  \param  group  underlying BP_GROUP object
 *  \param  a      GT_ELEM object
 *  \param  buf    memory buffer for the result. If NULL the function returns
 *                 required buffer size.
 *  \param  len    length of the memory buffer
 *  \param  ctx    BN_CTX object (optional)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t GT_ELEM_elem2oct(const BP_GROUP *group, const GT_ELEM *a,
                         unsigned char *buf, size_t len, BN_CTX *ctx);

/** Decodes a GT_ELEM from a octet string
 *  \param  group  underlying BP_GROUP object
 *  \param  a      GT_ELEM object
 *  \param  buf    memory buffer with the encoded ec point
 *  \param  len    length of the encoded ec point
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int GT_ELEM_oct2elem(const BP_GROUP *group, GT_ELEM *a,
                      const unsigned char *buf, size_t len, BN_CTX *ctx);

/********************************************************************/
/*              Functions for arithmetic in group GT                */
/********************************************************************/

/** Adds two GT_ELEMs
 *  \param  group  underlying BP_GROUP object
 *  \param  a      first GT_ELEM object to add
 *  \param  b      second GT_ELEM object to add
 *  \param  ctx    BN_CTX object (optional)
 *  \return 0 if both elements are equal and a value != 0 otherwise
 */
int GT_ELEM_add(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                const GT_ELEM *b, BN_CTX *ctx);

/** Subtracts a GT_ELEM from another
 *  \param  group  underlying BP_GROUP object
 *  \param  a      GT_ELEM object to subtract from
 *  \param  b      GT_ELEM object to subtract
 *  \param  ctx    BN_CTX object (optional)
 *  \return 0 if both elements are equal and a value != 0 otherwise
 */
int GT_ELEM_sub(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                const GT_ELEM *b, BN_CTX *ctx);

/** Squares a GT_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  r      GT_ELEM object for the result
 *  \param  a      GT_ELEM to inver
 *  \param  ctx    BN_CTX object (optional)
 *  \return 0 if both elements are equal and a value != 0 otherwise
 */
int GT_ELEM_sqr(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                BN_CTX *ctx);

/** Multiplies two GT_ELEMs
 *  \param  group  underlying BP_GROUP object
 *  \param  a      first GT_ELEM object to multiply
 *  \param  b      second GT_ELEM object to multiply
 *  \param  ctx    BN_CTX object (optional)
 *  \return 0 if both elements are equal and a value != 0 otherwise
 */
int GT_ELEM_mul(const BP_GROUP *group, GT_ELEM *r, GT_ELEM *a, GT_ELEM *b, BN_CTX *ctx);

/** Inverts a GT_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  r      GT_ELEM object for the result
 *  \param  a      GT_ELEM to inver
 *  \param  ctx    BN_CTX object (optional)
 *  \return 0 if both elements are equal and a value != 0 otherwise
 */
int GT_ELEM_inv(const BP_GROUP *group, GT_ELEM *r, GT_ELEM *a, BN_CTX *ctx);

/** Compares two GT_ELEMs
 *  \param  group  underlying BP_GROUP object
 *  \param  a      first GT_ELEM object
 *  \param  b      second GT_ELEM object
 *  \param  ctx    BN_CTX object (optional)
 *  \return 0 if both elements are equal and a value != 0 otherwise
 */
int GT_ELEM_cmp(const GT_ELEM *a, const GT_ELEM *b);

/** Exponentiates a GT_ELEM
 *  \param  group  underlying BP_GROUP object
 *  \param  r      GT_ELEM object for the result
 *  \param  a      GT_ELEM object for the basis
 *  \param  b      BIGNUM for the exponent
 *  \param  ctx    BN_CTX object (optional)
 *  \return 0 if both elements are equal and a value != 0 otherwise
 */
int GT_ELEM_exp(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a, const BIGNUM *b,
                BN_CTX *ctx);

/** Computes the pairing r  = e(p,q)
 *  \param  group  underlying BP_GROUP object
 *  \param  r      GT_ELEM object for the result
 *  \param  p      G1_ELEM for the first pairing argument
 *  \param  q      G2_ELEM for the second pairing argument
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int GT_ELEM_pairing(const BP_GROUP *group, GT_ELEM *r, const G1_ELEM *p,
                    const G2_ELEM *q, BN_CTX *ctx);

/** Computes r = prod_{i=0}^{num-1} e(p[i],q[i])
 *  \param  group  underlying BP_GROUP object
 *  \param  r      GT_ELEM object for the result
 *  \param  num    number of pairings to evaluate
 *  \param  p      G1_ELEMs for the first pairing arguments
 *  \param  q      G2_ELEMs for the second pairing arguments
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int GT_ELEMs_pairing(const BP_GROUP *group, GT_ELEM *r, size_t num,
                     const G1_ELEM *p[], const G2_ELEM *q[], BN_CTX *ctx);

# ifdef  __cplusplus
}
# endif
#endif
