/**
 * @file decaf/point_448.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief A group of prime order p, based on Ed448-Goldilocks.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */

#ifndef __DECAF_POINT_448_H__
#define __DECAF_POINT_448_H__ 1

#include "curve448utils.h"
#include "field.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @cond internal */
#define DECAF_448_SCALAR_LIMBS ((446-1)/DECAF_WORD_BITS+1)
/** @endcond */

/** The number of bits in a scalar */
#define DECAF_448_SCALAR_BITS 446

/** Number of bytes in a serialized point. */
#define DECAF_448_SER_BYTES 56

/** Number of bytes in an elligated point.  For now set the same as SER_BYTES
 * but could be different for other curves.
 */
#define DECAF_448_HASH_BYTES 56

/** Number of bytes in a serialized scalar. */
#define DECAF_448_SCALAR_BYTES 56

/** Number of bits in the "which" field of an elligator inverse */
#define DECAF_448_INVERT_ELLIGATOR_WHICH_BITS 3

/** The cofactor the curve would have, if we hadn't removed it */
#define DECAF_448_REMOVED_COFACTOR 4

/** X448 encoding ratio. */
#define DECAF_X448_ENCODE_RATIO 2

/** Number of bytes in an x448 public key */
#define DECAF_X448_PUBLIC_BYTES 56

/** Number of bytes in an x448 private key */
#define DECAF_X448_PRIVATE_BYTES 56

/** Twisted Edwards extended homogeneous coordinates */
typedef struct curve448_point_s {
    /** @cond internal */
    gf_448_t x,y,z,t;
    /** @endcond */
} curve448_point_t[1];

/** Precomputed table based on a point.  Can be trivial implementation. */
struct curve448_precomputed_s;

/** Precomputed table based on a point.  Can be trivial implementation. */
typedef struct curve448_precomputed_s curve448_precomputed_s; 

/** Scalar is stored packed, because we don't need the speed. */
typedef struct curve448_scalar_s {
    /** @cond internal */
    decaf_word_t limb[DECAF_448_SCALAR_LIMBS];
    /** @endcond */
} curve448_scalar_t[1];

/** A scalar equal to 1. */
extern const curve448_scalar_t curve448_scalar_one;

/** A scalar equal to 0. */
extern const curve448_scalar_t curve448_scalar_zero;

/** The identity point on the curve. */
extern const curve448_point_t curve448_point_identity;

/** An arbitrarily chosen base point on the curve. */
extern const curve448_point_t curve448_point_base;

/** Precomputed table for the base point on the curve. */
extern const struct curve448_precomputed_s *curve448_precomputed_base;

/**
 * @brief Read a scalar from wire format or from bytes.
 *
 * @param [in] ser Serialized form of a scalar.
 * @param [out] out Deserialized form.
 *
 * @retval DECAF_SUCCESS The scalar was correctly encoded.
 * @retval DECAF_FAILURE The scalar was greater than the modulus,
 * and has been reduced modulo that modulus.
 */
__owur decaf_error_t curve448_scalar_decode (
    curve448_scalar_t out,
    const unsigned char ser[DECAF_448_SCALAR_BYTES]
);

/**
 * @brief Read a scalar from wire format or from bytes.  Reduces mod
 * scalar prime.
 *
 * @param [in] ser Serialized form of a scalar.
 * @param [in] ser_len Length of serialized form.
 * @param [out] out Deserialized form.
 */
void curve448_scalar_decode_long (
    curve448_scalar_t out,
    const unsigned char *ser,
    size_t ser_len
);
    
/**
 * @brief Serialize a scalar to wire format.
 *
 * @param [out] ser Serialized form of a scalar.
 * @param [in] s Deserialized scalar.
 */
void curve448_scalar_encode (
    unsigned char ser[DECAF_448_SCALAR_BYTES],
    const curve448_scalar_t s
);
        
/**
 * @brief Add two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a+b.
 */
void curve448_scalar_add (
    curve448_scalar_t out,
    const curve448_scalar_t a,
    const curve448_scalar_t b
);

/**
 * @brief Subtract two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a-b.
 */  
void curve448_scalar_sub (
    curve448_scalar_t out,
    const curve448_scalar_t a,
    const curve448_scalar_t b
);

/**
 * @brief Multiply two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a*b.
 */  
void curve448_scalar_mul (
    curve448_scalar_t out,
    const curve448_scalar_t a,
    const curve448_scalar_t b
);
        
/**
* @brief Halve a scalar.  The scalars may use the same memory.
* @param [in] a A scalar.
* @param [out] out a/2.
*/
void curve448_scalar_halve (
   curve448_scalar_t out,
   const curve448_scalar_t a
);

/**
 * @brief Copy a scalar.  The scalars may use the same memory, in which
 * case this function does nothing.
 * @param [in] a A scalar.
 * @param [out] out Will become a copy of a.
 */
static ossl_inline void curve448_scalar_copy (
    curve448_scalar_t out,
    const curve448_scalar_t a
) {
    *out = *a;
}

/**
 * @brief Copy a point.  The input and output may alias,
 * in which case this function does nothing.
 *
 * @param [out] a A copy of the point.
 * @param [in] b Any point.
 */
static ossl_inline void curve448_point_copy (
    curve448_point_t a,
    const curve448_point_t b
) {
    *a=*b;
}

/**
 * @brief Test whether two points are equal.  If yes, return
 * DECAF_TRUE, else return DECAF_FALSE.
 *
 * @param [in] a A point.
 * @param [in] b Another point.
 * @retval DECAF_TRUE The points are equal.
 * @retval DECAF_FALSE The points are not equal.
 */
__owur decaf_bool_t curve448_point_eq (
    const curve448_point_t a,
    const curve448_point_t b
);

/**
 * @brief Double a point.  Equivalent to
 * curve448_point_add(two_a,a,a), but potentially faster.
 *
 * @param [out] two_a The sum a+a.
 * @param [in] a A point.
 */
void curve448_point_double (
    curve448_point_t two_a,
    const curve448_point_t a
);

/**
 * @brief RFC 7748 Diffie-Hellman scalarmul.  This function uses a different
 * (non-Decaf) encoding.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 *
 * @retval DECAF_SUCCESS The scalarmul succeeded.
 * @retval DECAF_FAILURE The scalarmul didn't succeed, because the base
 * point is in a small subgroup.
 */
__owur decaf_error_t decaf_x448 (
    uint8_t out[DECAF_X448_PUBLIC_BYTES],
    const uint8_t base[DECAF_X448_PUBLIC_BYTES],
    const uint8_t scalar[DECAF_X448_PRIVATE_BYTES]
);

/**
 * @brief Multiply a point by DECAF_X448_ENCODE_RATIO,
 * then encode it like RFC 7748.
 *
 * This function is mainly used internally, but is exported in case
 * it will be useful.
 *
 * The ratio is necessary because the internal representation doesn't
 * track the cofactor information, so on output we must clear the cofactor.
 * This would multiply by the cofactor, but in fact internally libdecaf's
 * points are always even, so it multiplies by half the cofactor instead.
 *
 * As it happens, this aligns with the base point definitions; that is,
 * if you pass the Decaf/Ristretto base point to this function, the result
 * will be DECAF_X448_ENCODE_RATIO times the X448
 * base point.
 *
 * @param [out] out The scaled and encoded point.
 * @param [in] p The point to be scaled and encoded.
 */
void curve448_point_mul_by_ratio_and_encode_like_x448 (
    uint8_t out[DECAF_X448_PUBLIC_BYTES],
    const curve448_point_t p
);

/** The base point for X448 Diffie-Hellman */
extern const uint8_t decaf_x448_base_point[DECAF_X448_PUBLIC_BYTES];
    
/**
 * @brief RFC 7748 Diffie-Hellman base point scalarmul.  This function uses
 * a different (non-Decaf) encoding.
 *
 * Does exactly the same thing as decaf_x448_generate_key,
 * but has a better name.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] scalar The scalar to multiply by.
 */
void decaf_x448_derive_public_key (
    uint8_t out[DECAF_X448_PUBLIC_BYTES],
    const uint8_t scalar[DECAF_X448_PRIVATE_BYTES]
);


/**
 * @brief Multiply a precomputed base point by a scalar:
 * scaled = scalar*base.
 * Some implementations do not include precomputed points; for
 * those implementations, this function is the same as
 * curve448_point_scalarmul
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 */
void curve448_precomputed_scalarmul (
    curve448_point_t scaled,
    const curve448_precomputed_s *base,
    const curve448_scalar_t scalar
);


/**
 * @brief Multiply two base points by two scalars:
 * scaled = scalar1*curve448_point_base + scalar2*base2.
 *
 * Otherwise equivalent to curve448_point_double_scalarmul, but may be
 * faster at the expense of being variable time.
 *
 * @param [out] combo The linear combination scalar1*base + scalar2*base2.
 * @param [in] scalar1 A first scalar to multiply by.
 * @param [in] base2 A second point to be scaled.
 * @param [in] scalar2 A second scalar to multiply by.
 *
 * @warning: This function takes variable time, and may leak the scalars
 * used.  It is designed for signature verification.
 */
void curve448_base_double_scalarmul_non_secret (
    curve448_point_t combo,
    const curve448_scalar_t scalar1,
    const curve448_point_t base2,
    const curve448_scalar_t scalar2
);

/**
 * @brief Test that a point is valid, for debugging purposes.
 *
 * @param [in] to_test The point to test.
 * @retval DECAF_TRUE The point is valid.
 * @retval DECAF_FALSE The point is invalid.
 */
__owur decaf_bool_t curve448_point_valid (
    const curve448_point_t to_test
);

/**
 * @brief Overwrite scalar with zeros.
 */
void curve448_scalar_destroy (
    curve448_scalar_t scalar
);

/**
 * @brief Overwrite point with zeros.
 */
void curve448_point_destroy (
    curve448_point_t point
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __DECAF_POINT_448_H__ */
