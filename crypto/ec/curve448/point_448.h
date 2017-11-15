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

#include <decaf/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond internal */
#define DECAF_448_SCALAR_LIMBS ((446-1)/DECAF_WORD_BITS+1)
/** @endcond */

/** The number of bits in a scalar */
#define DECAF_448_SCALAR_BITS 446

/** @cond internal */
#ifndef __DECAF_448_GF_DEFINED__
#define __DECAF_448_GF_DEFINED__ 1
/** @brief Galois field element internal structure */
typedef struct gf_448_s {
    decaf_word_t limb[512/DECAF_WORD_BITS];
} __attribute__((aligned(32))) gf_448_s, gf_448_t[1];
#endif /* __DECAF_448_GF_DEFINED__ */
/** @endcond */

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
typedef struct decaf_448_point_s {
    /** @cond internal */
    gf_448_t x,y,z,t;
    /** @endcond */
} decaf_448_point_t[1];

/** Precomputed table based on a point.  Can be trivial implementation. */
struct decaf_448_precomputed_s;

/** Precomputed table based on a point.  Can be trivial implementation. */
typedef struct decaf_448_precomputed_s decaf_448_precomputed_s; 

/** Size and alignment of precomputed point tables. */
extern const size_t decaf_448_sizeof_precomputed_s DECAF_API_VIS, decaf_448_alignof_precomputed_s DECAF_API_VIS;

/** Scalar is stored packed, because we don't need the speed. */
typedef struct decaf_448_scalar_s {
    /** @cond internal */
    decaf_word_t limb[DECAF_448_SCALAR_LIMBS];
    /** @endcond */
} decaf_448_scalar_t[1];

/** A scalar equal to 1. */
extern const decaf_448_scalar_t decaf_448_scalar_one DECAF_API_VIS;

/** A scalar equal to 0. */
extern const decaf_448_scalar_t decaf_448_scalar_zero DECAF_API_VIS;

/** The identity point on the curve. */
extern const decaf_448_point_t decaf_448_point_identity DECAF_API_VIS;

/** An arbitrarily chosen base point on the curve. */
extern const decaf_448_point_t decaf_448_point_base DECAF_API_VIS;

/** Precomputed table for the base point on the curve. */
extern const struct decaf_448_precomputed_s *decaf_448_precomputed_base DECAF_API_VIS;

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
decaf_error_t decaf_448_scalar_decode (
    decaf_448_scalar_t out,
    const unsigned char ser[DECAF_448_SCALAR_BYTES]
) DECAF_API_VIS DECAF_WARN_UNUSED DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Read a scalar from wire format or from bytes.  Reduces mod
 * scalar prime.
 *
 * @param [in] ser Serialized form of a scalar.
 * @param [in] ser_len Length of serialized form.
 * @param [out] out Deserialized form.
 */
void decaf_448_scalar_decode_long (
    decaf_448_scalar_t out,
    const unsigned char *ser,
    size_t ser_len
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;
    
/**
 * @brief Serialize a scalar to wire format.
 *
 * @param [out] ser Serialized form of a scalar.
 * @param [in] s Deserialized scalar.
 */
void decaf_448_scalar_encode (
    unsigned char ser[DECAF_448_SCALAR_BYTES],
    const decaf_448_scalar_t s
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE DECAF_NOINLINE;
        
/**
 * @brief Add two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a+b.
 */
void decaf_448_scalar_add (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Compare two scalars.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @retval DECAF_TRUE The scalars are equal.
 * @retval DECAF_FALSE The scalars are not equal.
 */    
decaf_bool_t decaf_448_scalar_eq (
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) DECAF_API_VIS DECAF_WARN_UNUSED DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Subtract two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a-b.
 */  
void decaf_448_scalar_sub (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Multiply two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a*b.
 */  
void decaf_448_scalar_mul (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;
        
/**
* @brief Halve a scalar.  The scalars may use the same memory.
* @param [in] a A scalar.
* @param [out] out a/2.
*/
void decaf_448_scalar_halve (
   decaf_448_scalar_t out,
   const decaf_448_scalar_t a
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Invert a scalar.  When passed zero, return 0.  The input and output may alias.
 * @param [in] a A scalar.
 * @param [out] out 1/a.
 * @return DECAF_SUCCESS The input is nonzero.
 */  
decaf_error_t decaf_448_scalar_invert (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a
) DECAF_API_VIS DECAF_WARN_UNUSED DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Copy a scalar.  The scalars may use the same memory, in which
 * case this function does nothing.
 * @param [in] a A scalar.
 * @param [out] out Will become a copy of a.
 */
static inline void DECAF_NONNULL decaf_448_scalar_copy (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a
) {
    *out = *a;
}

/**
 * @brief Set a scalar to an unsigned 64-bit integer.
 * @param [in] a An integer.
 * @param [out] out Will become equal to a.
 */  
void decaf_448_scalar_set_unsigned (
    decaf_448_scalar_t out,
    uint64_t a
) DECAF_API_VIS DECAF_NONNULL;

/**
 * @brief Encode a point as a sequence of bytes.
 *
 * @param [out] ser The byte representation of the point.
 * @param [in] pt The point to encode.
 */
void decaf_448_point_encode (
    uint8_t ser[DECAF_448_SER_BYTES],
    const decaf_448_point_t pt
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Decode a point from a sequence of bytes.
 *
 * Every point has a unique encoding, so not every
 * sequence of bytes is a valid encoding.  If an invalid
 * encoding is given, the output is undefined.
 *
 * @param [out] pt The decoded point.
 * @param [in] ser The serialized version of the point.
 * @param [in] allow_identity DECAF_TRUE if the identity is a legal input.
 * @retval DECAF_SUCCESS The decoding succeeded.
 * @retval DECAF_FAILURE The decoding didn't succeed, because
 * ser does not represent a point.
 */
decaf_error_t decaf_448_point_decode (
    decaf_448_point_t pt,
    const uint8_t ser[DECAF_448_SER_BYTES],
    decaf_bool_t allow_identity
) DECAF_API_VIS DECAF_WARN_UNUSED DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Copy a point.  The input and output may alias,
 * in which case this function does nothing.
 *
 * @param [out] a A copy of the point.
 * @param [in] b Any point.
 */
static inline void DECAF_NONNULL decaf_448_point_copy (
    decaf_448_point_t a,
    const decaf_448_point_t b
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
decaf_bool_t decaf_448_point_eq (
    const decaf_448_point_t a,
    const decaf_448_point_t b
) DECAF_API_VIS DECAF_WARN_UNUSED DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Add two points to produce a third point.  The
 * input points and output point can be pointers to the same
 * memory.
 *
 * @param [out] sum The sum a+b.
 * @param [in] a An addend.
 * @param [in] b An addend.
 */
void decaf_448_point_add (
    decaf_448_point_t sum,
    const decaf_448_point_t a,
    const decaf_448_point_t b
) DECAF_API_VIS DECAF_NONNULL;

/**
 * @brief Double a point.  Equivalent to
 * decaf_448_point_add(two_a,a,a), but potentially faster.
 *
 * @param [out] two_a The sum a+a.
 * @param [in] a A point.
 */
void decaf_448_point_double (
    decaf_448_point_t two_a,
    const decaf_448_point_t a
) DECAF_API_VIS DECAF_NONNULL;

/**
 * @brief Subtract two points to produce a third point.  The
 * input points and output point can be pointers to the same
 * memory.
 *
 * @param [out] diff The difference a-b.
 * @param [in] a The minuend.
 * @param [in] b The subtrahend.
 */
void decaf_448_point_sub (
    decaf_448_point_t diff,
    const decaf_448_point_t a,
    const decaf_448_point_t b
) DECAF_API_VIS DECAF_NONNULL;
    
/**
 * @brief Negate a point to produce another point.  The input
 * and output points can use the same memory.
 *
 * @param [out] nega The negated input point
 * @param [in] a The input point.
 */
void decaf_448_point_negate (
   decaf_448_point_t nega,
   const decaf_448_point_t a
) DECAF_API_VIS DECAF_NONNULL;

/**
 * @brief Multiply a base point by a scalar: scaled = scalar*base.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 */
void decaf_448_point_scalarmul (
    decaf_448_point_t scaled,
    const decaf_448_point_t base,
    const decaf_448_scalar_t scalar
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Multiply a base point by a scalar: scaled = scalar*base.
 * This function operates directly on serialized forms.
 *
 * @warning This function is experimental.  It may not be supported
 * long-term.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 * @param [in] allow_identity Allow the input to be the identity.
 * @param [in] short_circuit Allow a fast return if the input is illegal.
 *
 * @retval DECAF_SUCCESS The scalarmul succeeded.
 * @retval DECAF_FAILURE The scalarmul didn't succeed, because
 * base does not represent a point.
 */
decaf_error_t decaf_448_direct_scalarmul (
    uint8_t scaled[DECAF_448_SER_BYTES],
    const uint8_t base[DECAF_448_SER_BYTES],
    const decaf_448_scalar_t scalar,
    decaf_bool_t allow_identity,
    decaf_bool_t short_circuit
) DECAF_API_VIS DECAF_NONNULL DECAF_WARN_UNUSED DECAF_NOINLINE;

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
decaf_error_t decaf_x448 (
    uint8_t out[DECAF_X448_PUBLIC_BYTES],
    const uint8_t base[DECAF_X448_PUBLIC_BYTES],
    const uint8_t scalar[DECAF_X448_PRIVATE_BYTES]
) DECAF_API_VIS DECAF_NONNULL DECAF_WARN_UNUSED DECAF_NOINLINE;

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
void decaf_448_point_mul_by_ratio_and_encode_like_x448 (
    uint8_t out[DECAF_X448_PUBLIC_BYTES],
    const decaf_448_point_t p
) DECAF_API_VIS DECAF_NONNULL;

/** The base point for X448 Diffie-Hellman */
extern const uint8_t decaf_x448_base_point[DECAF_X448_PUBLIC_BYTES] DECAF_API_VIS;

/**
 * @brief RFC 7748 Diffie-Hellman base point scalarmul.  This function uses
 * a different (non-Decaf) encoding.
 *
 * @deprecated Renamed to decaf_x448_derive_public_key.
 * I have no particular timeline for removing this name.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] scalar The scalar to multiply by.
 */
void decaf_x448_generate_key (
    uint8_t out[DECAF_X448_PUBLIC_BYTES],
    const uint8_t scalar[DECAF_X448_PRIVATE_BYTES]
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE DECAF_DEPRECATED("Renamed to decaf_x448_derive_public_key");
    
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
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/* FUTURE: uint8_t decaf_448_encode_like_curve448) */

/**
 * @brief Precompute a table for fast scalar multiplication.
 * Some implementations do not include precomputed points; for
 * those implementations, this implementation simply copies the
 * point.
 *
 * @param [out] a A precomputed table of multiples of the point.
 * @param [in] b Any point.
 */
void decaf_448_precompute (
    decaf_448_precomputed_s *a,
    const decaf_448_point_t b
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Multiply a precomputed base point by a scalar:
 * scaled = scalar*base.
 * Some implementations do not include precomputed points; for
 * those implementations, this function is the same as
 * decaf_448_point_scalarmul
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 */
void decaf_448_precomputed_scalarmul (
    decaf_448_point_t scaled,
    const decaf_448_precomputed_s *base,
    const decaf_448_scalar_t scalar
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Multiply two base points by two scalars:
 * scaled = scalar1*base1 + scalar2*base2.
 *
 * Equivalent to two calls to decaf_448_point_scalarmul, but may be
 * faster.
 *
 * @param [out] combo The linear combination scalar1*base1 + scalar2*base2.
 * @param [in] base1 A first point to be scaled.
 * @param [in] scalar1 A first scalar to multiply by.
 * @param [in] base2 A second point to be scaled.
 * @param [in] scalar2 A second scalar to multiply by.
 */
void decaf_448_point_double_scalarmul (
    decaf_448_point_t combo,
    const decaf_448_point_t base1,
    const decaf_448_scalar_t scalar1,
    const decaf_448_point_t base2,
    const decaf_448_scalar_t scalar2
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;
    
/**
 * Multiply one base point by two scalars:
 *
 * a1 = scalar1 * base
 * a2 = scalar2 * base
 *
 * Equivalent to two calls to decaf_448_point_scalarmul, but may be
 * faster.
 *
 * @param [out] a1 The first multiple.  It may be the same as the input point.
 * @param [out] a2 The second multiple.  It may be the same as the input point.
 * @param [in] base1 A point to be scaled.
 * @param [in] scalar1 A first scalar to multiply by.
 * @param [in] scalar2 A second scalar to multiply by.
 */
void decaf_448_point_dual_scalarmul (
    decaf_448_point_t a1,
    decaf_448_point_t a2,
    const decaf_448_point_t base1,
    const decaf_448_scalar_t scalar1,
    const decaf_448_scalar_t scalar2
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Multiply two base points by two scalars:
 * scaled = scalar1*decaf_448_point_base + scalar2*base2.
 *
 * Otherwise equivalent to decaf_448_point_double_scalarmul, but may be
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
void decaf_448_base_double_scalarmul_non_secret (
    decaf_448_point_t combo,
    const decaf_448_scalar_t scalar1,
    const decaf_448_point_t base2,
    const decaf_448_scalar_t scalar2
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Constant-time decision between two points.  If pick_b
 * is zero, out = a; else out = b.
 *
 * @param [out] out The output.  It may be the same as either input.
 * @param [in] a Any point.
 * @param [in] b Any point.
 * @param [in] pick_b If nonzero, choose point b.
 */
void decaf_448_point_cond_sel (
    decaf_448_point_t out,
    const decaf_448_point_t a,
    const decaf_448_point_t b,
    decaf_word_t pick_b
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Constant-time decision between two scalars.  If pick_b
 * is zero, out = a; else out = b.
 *
 * @param [out] out The output.  It may be the same as either input.
 * @param [in] a Any scalar.
 * @param [in] b Any scalar.
 * @param [in] pick_b If nonzero, choose scalar b.
 */
void decaf_448_scalar_cond_sel (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b,
    decaf_word_t pick_b
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Test that a point is valid, for debugging purposes.
 *
 * @param [in] to_test The point to test.
 * @retval DECAF_TRUE The point is valid.
 * @retval DECAF_FALSE The point is invalid.
 */
decaf_bool_t decaf_448_point_valid (
    const decaf_448_point_t to_test
) DECAF_API_VIS DECAF_WARN_UNUSED DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Torque a point, for debugging purposes.  The output
 * will be equal to the input.
 *
 * @param [out] q The point to torque.
 * @param [in] p The point to torque.
 */
void decaf_448_point_debugging_torque (
    decaf_448_point_t q,
    const decaf_448_point_t p
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Projectively scale a point, for debugging purposes.
 * The output will be equal to the input, and will be valid
 * even if the factor is zero.
 *
 * @param [out] q The point to scale.
 * @param [in] p The point to scale.
 * @param [in] factor Serialized GF factor to scale.
 */
void decaf_448_point_debugging_pscale (
    decaf_448_point_t q,
    const decaf_448_point_t p,
    const unsigned char factor[DECAF_448_SER_BYTES]
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Almost-Elligator-like hash to curve.
 *
 * Call this function with the output of a hash to make a hash to the curve.
 *
 * This function runs Elligator2 on the decaf_448 Jacobi quartic model.  It then
 * uses the isogeny to put the result in twisted Edwards form.  As a result,
 * it is safe (cannot produce points of order 4), and would be compatible with
 * hypothetical other implementations of Decaf using a Montgomery or untwisted
 * Edwards model.
 *
 * Unlike Elligator, this function may be up to 4:1 on [0,(p-1)/2]:
 *   A factor of 2 due to the isogeny.
 *   A factor of 2 because we quotient out the 2-torsion.
 *
 * This makes it about 8:1 overall, or 16:1 overall on curves with cofactor 8.
 *
 * Negating the input (mod q) results in the same point.  Inverting the input
 * (mod q) results in the negative point.  This is the same as Elligator.
 *
 * This function isn't quite indifferentiable from a random oracle.
 * However, it is suitable for many protocols, including SPEKE and SPAKE2 EE. 
 * Furthermore, calling it twice with independent seeds and adding the results
 * is indifferentiable from a random oracle.
 *
 * @param [in] hashed_data Output of some hash function.
 * @param [out] pt The data hashed to the curve.
 */
void
decaf_448_point_from_hash_nonuniform (
    decaf_448_point_t pt,
    const unsigned char hashed_data[DECAF_448_HASH_BYTES]
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Indifferentiable hash function encoding to curve.
 *
 * Equivalent to calling decaf_448_point_from_hash_nonuniform twice and adding.
 *
 * @param [in] hashed_data Output of some hash function.
 * @param [out] pt The data hashed to the curve.
 */ 
void decaf_448_point_from_hash_uniform (
    decaf_448_point_t pt,
    const unsigned char hashed_data[2*DECAF_448_HASH_BYTES]
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE;

/**
 * @brief Inverse of elligator-like hash to curve.
 *
 * This function writes to the buffer, to make it so that
 * decaf_448_point_from_hash_nonuniform(buffer) = pt if
 * possible.  Since there may be multiple preimages, the
 * "which" parameter chooses between them.  To ensure uniform
 * inverse sampling, this function succeeds or fails
 * independently for different "which" values.
 *
 * This function isn't guaranteed to find every possible
 * preimage, but it finds all except a small finite number.
 * In particular, when the number of bits in the modulus isn't
 * a multiple of 8 (i.e. for curve25519), it sets the high bits
 * independently, which enables the generated data to be uniform.
 * But it doesn't add p, so you'll never get exactly p from this
 * function.  This might change in the future, especially if
 * we ever support eg Brainpool curves, where this could cause
 * real nonuniformity.
 *
 * @param [out] recovered_hash Encoded data.
 * @param [in] pt The point to encode.
 * @param [in] which A value determining which inverse point
 * to return.
 *
 * @retval DECAF_SUCCESS The inverse succeeded.
 * @retval DECAF_FAILURE The inverse failed.
 */
decaf_error_t
decaf_448_invert_elligator_nonuniform (
    unsigned char recovered_hash[DECAF_448_HASH_BYTES],
    const decaf_448_point_t pt,
    uint32_t which
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE DECAF_WARN_UNUSED;

/**
 * @brief Inverse of elligator-like hash to curve.
 *
 * This function writes to the buffer, to make it so that
 * decaf_448_point_from_hash_uniform(buffer) = pt if
 * possible.  Since there may be multiple preimages, the
 * "which" parameter chooses between them.  To ensure uniform
 * inverse sampling, this function succeeds or fails
 * independently for different "which" values.
 *
 * @param [out] recovered_hash Encoded data.
 * @param [in] pt The point to encode.
 * @param [in] which A value determining which inverse point
 * to return.
 *
 * @retval DECAF_SUCCESS The inverse succeeded.
 * @retval DECAF_FAILURE The inverse failed.
 */
decaf_error_t
decaf_448_invert_elligator_uniform (
    unsigned char recovered_hash[2*DECAF_448_HASH_BYTES],
    const decaf_448_point_t pt,
    uint32_t which
) DECAF_API_VIS DECAF_NONNULL DECAF_NOINLINE DECAF_WARN_UNUSED;

/**
 * @brief Overwrite scalar with zeros.
 */
void decaf_448_scalar_destroy (
    decaf_448_scalar_t scalar
) DECAF_NONNULL DECAF_API_VIS;

/**
 * @brief Overwrite point with zeros.
 */
void decaf_448_point_destroy (
    decaf_448_point_t point
) DECAF_NONNULL DECAF_API_VIS;

/**
 * @brief Overwrite precomputed table with zeros.
 */
void decaf_448_precomputed_destroy (
    decaf_448_precomputed_s *pre
) DECAF_NONNULL DECAF_API_VIS;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __DECAF_POINT_448_H__ */
