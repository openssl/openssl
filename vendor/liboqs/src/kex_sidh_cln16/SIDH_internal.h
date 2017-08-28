/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: internal header file
*
*********************************************************************************************/

#ifndef __SIDH_INTERNAL_H__
#define __SIDH_INTERNAL_H__

// For C++
#ifdef __cplusplus
extern "C" {
#endif

#if defined(WINDOWS)
#define UNUSED
#else
#define UNUSED __attribute__((unused))
#endif

#include "SIDH.h"

// Basic constants

#define SIDH_ALICE 0
#define SIDH_BOB 1
#define SIDH_MAX_INT_POINTS_ALICE 8
// Fixed parameters for isogeny tree computation
#define SIDH_MAX_INT_POINTS_BOB 10
#define SIDH_MAX_Alice 185
#define SIDH_MAX_Bob 239

// SIDH's basic element definitions and point representations

typedef digit_t oqs_sidh_cln16_felm_t[NWORDS_FIELD];          // Datatype for representing 751-bit field elements (768-bit max.)
typedef digit_t oqs_sidh_cln16_dfelm_t[2 * NWORDS_FIELD];     // Datatype for representing double-precision 2x751-bit field elements (2x768-bit max.)
typedef oqs_sidh_cln16_felm_t oqs_sidh_cln16_f2elm_t[2];      // Datatype for representing quadratic extension field elements GF(p751^2)
typedef oqs_sidh_cln16_f2elm_t oqs_sidh_cln16_publickey_t[3]; // Datatype for representing public keys equivalent to three GF(p751^2) elements

typedef struct {
	oqs_sidh_cln16_f2elm_t x;
	oqs_sidh_cln16_f2elm_t y;
} oqs_sidh_cln16_point_affine; // Point representation in affine coordinates on Montgomery curve.
typedef oqs_sidh_cln16_point_affine oqs_sidh_cln16_point_t[1];

typedef struct {
	oqs_sidh_cln16_f2elm_t X;
	oqs_sidh_cln16_f2elm_t Z;
} oqs_sidh_cln16_point_proj; // Point representation in projective XZ Montgomery coordinates.
typedef oqs_sidh_cln16_point_proj oqs_sidh_cln16_point_proj_t[1];

typedef struct {
	oqs_sidh_cln16_f2elm_t X;
	oqs_sidh_cln16_f2elm_t Y;
	oqs_sidh_cln16_f2elm_t Z;
} oqs_sidh_cln16_point_full_proj; // Point representation in projective XYZ Montgomery coordinates.
typedef oqs_sidh_cln16_point_full_proj oqs_sidh_cln16_point_full_proj_t[1];

typedef struct {
	oqs_sidh_cln16_f2elm_t X2;
	oqs_sidh_cln16_f2elm_t XZ;
	oqs_sidh_cln16_f2elm_t Z2;
	oqs_sidh_cln16_f2elm_t YZ;
} oqs_sidh_cln16_point_ext_proj;
typedef oqs_sidh_cln16_point_ext_proj oqs_sidh_cln16_point_ext_proj_t[1]; // Point representation in extended projective XYZ Montgomery coordinates.

typedef struct {
	oqs_sidh_cln16_felm_t x;
	oqs_sidh_cln16_felm_t y;
} oqs_sidh_cln16_point_basefield_affine; // Point representation in affine coordinates on Montgomery curve over the base field.
typedef oqs_sidh_cln16_point_basefield_affine oqs_sidh_cln16_point_basefield_t[1];

typedef struct {
	oqs_sidh_cln16_felm_t X;
	oqs_sidh_cln16_felm_t Z;
} oqs_sidh_cln16_point_basefield_proj; // Point representation in projective XZ Montgomery coordinates over the base field.
typedef oqs_sidh_cln16_point_basefield_proj oqs_sidh_cln16_point_basefield_proj_t[1];

// Macro definitions

#define NBITS_TO_NBYTES(nbits) (((nbits) + 7) / 8)                                             // Conversion macro from number of bits to number of bytes
#define NBITS_TO_NWORDS(nbits) (((nbits) + (sizeof(digit_t) * 8) - 1) / (sizeof(digit_t) * 8)) // Conversion macro from number of bits to number of computer words
#define NBYTES_TO_NWORDS(nbytes) (((nbytes) + sizeof(digit_t) - 1) / sizeof(digit_t))          // Conversion macro from number of bytes to number of computer words

// Macro to avoid compiler warnings when detecting unreferenced parameters
#define UNREFERENCED_PARAMETER(PAR) (PAR)

/********************** Constant-time unsigned comparisons ***********************/

// The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise

static __inline unsigned int is_digit_nonzero_ct(digit_t x) { // Is x != 0?
	return (unsigned int) ((x | (0 - x)) >> (RADIX - 1));
}

static __inline unsigned int is_digit_zero_ct(digit_t x) { // Is x = 0?
	return (unsigned int) (1 ^ is_digit_nonzero_ct(x));
}

static __inline unsigned int is_digit_lessthan_ct(digit_t x, digit_t y) { // Is x < y?
	return (unsigned int) ((x ^ ((x ^ y) | ((x - y) ^ y))) >> (RADIX - 1));
}

/********************** Macros for platform-dependent operations **********************/

#if defined(GENERIC_IMPLEMENTATION)
// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo) \
	oqs_sidh_cln16_digit_x_digit((multiplier), (multiplicand), &(lo));

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                                           \
	{                                                                                                               \
		digit_t tempReg = (addend1) + (digit_t)(carryIn);                                                           \
		(sumOut) = (addend2) + tempReg;                                                                             \
		(carryOut) = (is_digit_lessthan_ct(tempReg, (digit_t)(carryIn)) | is_digit_lessthan_ct((sumOut), tempReg)); \
	}

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                                                       \
	{                                                                                                                       \
		digit_t tempReg = (minuend) - (subtrahend);                                                                         \
		unsigned int borrowReg = (is_digit_lessthan_ct((minuend), (subtrahend)) | ((borrowIn) &is_digit_zero_ct(tempReg))); \
		(differenceOut) = tempReg - (digit_t)(borrowIn);                                                                    \
		(borrowOut) = borrowReg;                                                                                            \
	}

// Shift right with flexible datatype
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize) \
	(shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (DigitSize - (shift)));

// Shift left with flexible datatype
#define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize) \
	(shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (DigitSize - (shift)));

// 64x64-bit multiplication
#define MUL128(multiplier, multiplicand, product) \
	oqs_sidh_cln16_mp_mul((digit_t *) &(multiplier), (digit_t *) &(multiplicand), (digit_t *) &(product), NWORDS_FIELD / 2);

// 128-bit addition, inputs < 2^127
#define ADD128(addend1, addend2, addition) \
	oqs_sidh_cln16_mp_add((digit_t *) (addend1), (digit_t *) (addend2), (digit_t *) (addition), NWORDS_FIELD);

// 128-bit addition with output carry
#define ADC128(addend1, addend2, carry, addition) \
	(carry) = oqs_sidh_cln16_mp_add((digit_t *) (addend1), (digit_t *) (addend2), (digit_t *) (addition), NWORDS_FIELD);

#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_WIN)

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo) \
	(lo) = _umul128((multiplier), (multiplicand), (hi));

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut) \
	(carryOut) = _addcarry_u64((carryIn), (addend1), (addend2), &(sumOut));

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut) \
	(borrowOut) = _subborrow_u64((borrowIn), (minuend), (subtrahend), &(differenceOut));

// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize) \
	(shiftOut) = __shiftright128((lowIn), (highIn), (shift));

// Digit shift left
#define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize) \
	(shiftOut) = __shiftleft128((lowIn), (highIn), (shift));

// 64x64-bit multiplication
#define MUL128(multiplier, multiplicand, product) \
	(product)[0] = _umul128((multiplier), (multiplicand), &(product)[1]);

// 128-bit addition, inputs < 2^127
#define ADD128(addend1, addend2, addition)                                                  \
	{                                                                                       \
		unsigned char carry = _addcarry_u64(0, (addend1)[0], (addend2)[0], &(addition)[0]); \
		_addcarry_u64(carry, (addend1)[1], (addend2)[1], &(addition)[1]);                   \
	}

// 128-bit addition with output carry
#define ADC128(addend1, addend2, carry, addition)                           \
	(carry) = _addcarry_u64(0, (addend1)[0], (addend2)[0], &(addition)[0]); \
	(carry) = _addcarry_u64((carry), (addend1)[1], (addend2)[1], &(addition)[1]);

// 128-bit subtraction, subtrahend < 2^127
#define SUB128(minuend, subtrahend, difference)                                                    \
	{                                                                                              \
		unsigned char borrow = _subborrow_u64(0, (minuend)[0], (subtrahend)[0], &(difference)[0]); \
		_subborrow_u64(borrow, (minuend)[1], (subtrahend)[1], &(difference)[1]);                   \
	}

// 128-bit right shift, max. shift value is 64
#define SHIFTR128(Input, shift, shiftOut)                             \
	(shiftOut)[0] = __shiftright128((Input)[0], (Input)[1], (shift)); \
	(shiftOut)[1] = (Input)[1] >> (shift);

// 128-bit left shift, max. shift value is 64
#define SHIFTL128(Input, shift, shiftOut)                            \
	(shiftOut)[1] = __shiftleft128((Input)[0], (Input)[1], (shift)); \
	(shiftOut)[0] = (Input)[0] << (shift);

#define MULADD128(multiplier, multiplicand, addend, carry, result) \
	;                                                              \
	{                                                              \
		uint128_t product;                                         \
		MUL128(multiplier, multiplicand, product);                 \
		ADC128(addend, product, carry, result);                    \
	}

#elif ((TARGET == TARGET_AMD64 || TARGET == TARGET_ARM64) && OS_TARGET == OS_LINUX)

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                                    \
	{                                                                            \
		uint128_t tempReg = (uint128_t)(multiplier) * (uint128_t)(multiplicand); \
		*(hi) = (digit_t)(tempReg >> RADIX);                                     \
		(lo) = (digit_t) tempReg;                                                \
	}

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                       \
	{                                                                                           \
		uint128_t tempReg = (uint128_t)(addend1) + (uint128_t)(addend2) + (uint128_t)(carryIn); \
		(carryOut) = (digit_t)(tempReg >> RADIX);                                               \
		(sumOut) = (digit_t) tempReg;                                                           \
	}

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                               \
	{                                                                                               \
		uint128_t tempReg = (uint128_t)(minuend) - (uint128_t)(subtrahend) - (uint128_t)(borrowIn); \
		(borrowOut) = (digit_t)(tempReg >> (sizeof(uint128_t) * 8 - 1));                            \
		(differenceOut) = (digit_t) tempReg;                                                        \
	}

// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize) \
	(shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (RADIX - (shift)));

// Digit shift left
#define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize) \
	(shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (RADIX - (shift)));

#endif

// Multiprecision multiplication selection
#if defined(GENERIC_IMPLEMENTATION) && (TARGET == TARGET_AMD64)
#define oqs_sidh_cln16_mp_mul_comba oqs_sidh_cln16_mp_mul
#else
#define oqs_sidh_cln16_mp_mul_schoolbook oqs_sidh_cln16_mp_mul
#endif

/**************** Function prototypes ****************/
/************* Multiprecision functions **************/

// Copy wordsize digits, c = a, where lng(a) = nwords
void oqs_sidh_cln16_copy_words(const digit_t *a, digit_t *c, const unsigned int nwords);

// Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit
unsigned int oqs_sidh_cln16_mp_add(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords);

// 751-bit multiprecision addition, c = a+b
void oqs_sidh_cln16_mp_add751(const digit_t *a, const digit_t *b, digit_t *c);
void oqs_sidh_cln16_mp_add751_asm(const digit_t *a, const digit_t *b, digit_t *c);

// 2x751-bit multiprecision addition, c = a+b
void oqs_sidh_cln16_mp_add751x2(const digit_t *a, const digit_t *b, digit_t *c);
void oqs_sidh_cln16_mp_add751x2_asm(const digit_t *a, const digit_t *b, digit_t *c);

// Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit
unsigned int oqs_sidh_cln16_mp_sub(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords);

// Multiprecision right shift by one
void oqs_sidh_cln16_mp_shiftr1(digit_t *x, const unsigned int nwords);

// Multiprecision left right shift by one
void oqs_sidh_cln16_mp_shiftl1(digit_t *x, const unsigned int nwords);

// Digit multiplication, digit * digit -> 2-digit result
void oqs_sidh_cln16_digit_x_digit(const digit_t a, const digit_t b, digit_t *c);

// Multiprecision schoolbook multiply, c = a*b, where lng(a) = lng(b) = nwords.
void oqs_sidh_cln16_mp_mul_schoolbook(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords);

// Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
void oqs_sidh_cln16_mp_mul_comba(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords);

void oqs_sidh_cln16_multiply(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords);

// Montgomery multiplication modulo the group order, mc = ma*mb*r' mod order, where ma,mb,mc in [0, order-1]
void oqs_sidh_cln16_Montgomery_multiply_mod_order(const digit_t *ma, const digit_t *mb, digit_t *mc, const digit_t *order, const digit_t *Montgomery_rprime);

// (Non-constant time) Montgomery inversion modulo the curve order using a^(-1) = a^(order-2) mod order
void oqs_sidh_cln16_Montgomery_inversion_mod_order(const digit_t *ma, digit_t *mc, const digit_t *order, const digit_t *Montgomery_rprime);

void oqs_sidh_cln16_Montgomery_inversion_mod_order_bingcd(const digit_t *a, digit_t *c, const digit_t *order, const digit_t *Montgomery_rprime, const digit_t *Montgomery_R2);

// Conversion of elements in Z_r to Montgomery representation, where the order r is up to 384 bits.
void oqs_sidh_cln16_to_Montgomery_mod_order(const digit_t *a, digit_t *mc, const digit_t *order, const digit_t *Montgomery_rprime, const digit_t *Montgomery_Rprime);

// Conversion of elements in Z_r from Montgomery to standard representation, where the order is up to 384 bits.
void oqs_sidh_cln16_from_Montgomery_mod_order(const digit_t *ma, digit_t *c, const digit_t *order, const digit_t *Montgomery_rprime);

// Inversion modulo Alice's order 2^372.
void oqs_sidh_cln16_inv_mod_orderA(const digit_t *a, digit_t *c);

/************ Field arithmetic functions *************/

// Copy of a field element, c = a
void oqs_sidh_cln16_fpcopy751(const oqs_sidh_cln16_felm_t a, oqs_sidh_cln16_felm_t c);

// Zeroing a field element, a = 0
void oqs_sidh_cln16_fpzero751(oqs_sidh_cln16_felm_t a);

// Non constant-time comparison of two field elements. If a = b return TRUE, otherwise, return FALSE
bool oqs_sidh_cln16_fpequal751_non_constant_time(const oqs_sidh_cln16_felm_t a, const oqs_sidh_cln16_felm_t b);

// Modular addition, c = a+b mod p751
extern void oqs_sidh_cln16_fpadd751(const digit_t *a, const digit_t *b, digit_t *c);
extern void oqs_sidh_cln16_fpadd751_asm(const digit_t *a, const digit_t *b, digit_t *c);

// Modular subtraction, c = a-b mod p751
extern void oqs_sidh_cln16_fpsub751(const digit_t *a, const digit_t *b, digit_t *c);
extern void oqs_sidh_cln16_fpsub751_asm(const digit_t *a, const digit_t *b, digit_t *c);

// Modular negation, a = -a mod p751
extern void oqs_sidh_cln16_fpneg751(digit_t *a);

// Modular division by two, c = a/2 mod p751.
void oqs_sidh_cln16_fpdiv2_751(const digit_t *a, digit_t *c);

// Modular correction to reduce field element a in [0, 2*p751-1] to [0, p751-1].
void oqs_sidh_cln16_fpcorrection751(digit_t *a);

// 751-bit Montgomery reduction, c = a mod p
void oqs_sidh_cln16_rdc_mont(const digit_t *a, digit_t *c);

// Field multiplication using Montgomery arithmetic, c = a*b*R^-1 mod p751, where R=2^768
void oqs_sidh_cln16_fpmul751_mont(const oqs_sidh_cln16_felm_t a, const oqs_sidh_cln16_felm_t b, oqs_sidh_cln16_felm_t c);
void oqs_sidh_cln16_mul751_asm(const oqs_sidh_cln16_felm_t a, const oqs_sidh_cln16_felm_t b, oqs_sidh_cln16_dfelm_t c);
void oqs_sidh_cln16_rdc751_asm(const oqs_sidh_cln16_dfelm_t ma, oqs_sidh_cln16_dfelm_t mc);

// Field squaring using Montgomery arithmetic, c = a*b*R^-1 mod p751, where R=2^768
void oqs_sidh_cln16_fpsqr751_mont(const oqs_sidh_cln16_felm_t ma, oqs_sidh_cln16_felm_t mc);

// Conversion to Montgomery representation
void oqs_sidh_cln16_to_mont(const oqs_sidh_cln16_felm_t a, oqs_sidh_cln16_felm_t mc);

// Conversion from Montgomery representation to standard representation
void oqs_sidh_cln16_from_mont(const oqs_sidh_cln16_felm_t ma, oqs_sidh_cln16_felm_t c);

// Field inversion, a = a^-1 in GF(p751)
void oqs_sidh_cln16_fpinv751_mont(oqs_sidh_cln16_felm_t a);

// Field inversion, a = a^-1 in GF(p751) using the binary GCD
void oqs_sidh_cln16_fpinv751_mont_bingcd(oqs_sidh_cln16_felm_t a);

// Chain to compute (p751-3)/4 using Montgomery arithmetic
void oqs_sidh_cln16_fpinv751_chain_mont(oqs_sidh_cln16_felm_t a);

/************ GF(p^2) arithmetic functions *************/

// Copy of a GF(p751^2) element, c = a
void oqs_sidh_cln16_fp2copy751(const oqs_sidh_cln16_f2elm_t a, oqs_sidh_cln16_f2elm_t c);

// Zeroing a GF(p751^2) element, a = 0
void oqs_sidh_cln16_fp2zero751(oqs_sidh_cln16_f2elm_t a);

// GF(p751^2) negation, a = -a in GF(p751^2)
void oqs_sidh_cln16_fp2neg751(oqs_sidh_cln16_f2elm_t a);

// GF(p751^2) addition, c = a+b in GF(p751^2)
extern void oqs_sidh_cln16_fp2add751(const oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_f2elm_t b, oqs_sidh_cln16_f2elm_t c);

// GF(p751^2) subtraction, c = a-b in GF(p751^2)
extern void oqs_sidh_cln16_fp2sub751(const oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_f2elm_t b, oqs_sidh_cln16_f2elm_t c);

// GF(p751^2) division by two, c = a/2  in GF(p751^2)
void oqs_sidh_cln16_fp2div2_751(const oqs_sidh_cln16_f2elm_t a, oqs_sidh_cln16_f2elm_t c);

// Modular correction, a = a in GF(p751^2)
void oqs_sidh_cln16_fp2correction751(oqs_sidh_cln16_f2elm_t a);

// GF(p751^2) squaring using Montgomery arithmetic, c = a^2 in GF(p751^2)
void oqs_sidh_cln16_fp2sqr751_mont(const oqs_sidh_cln16_f2elm_t a, oqs_sidh_cln16_f2elm_t c);

// GF(p751^2) multiplication using Montgomery arithmetic, c = a*b in GF(p751^2)
void oqs_sidh_cln16_fp2mul751_mont(const oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_f2elm_t b, oqs_sidh_cln16_f2elm_t c);

// Conversion of a GF(p751^2) element to Montgomery representation
void oqs_sidh_cln16_to_fp2mont(const oqs_sidh_cln16_f2elm_t a, oqs_sidh_cln16_f2elm_t mc);

// Conversion of a GF(p751^2) element from Montgomery representation to standard representation
void oqs_sidh_cln16_from_fp2mont(const oqs_sidh_cln16_f2elm_t ma, oqs_sidh_cln16_f2elm_t c);

// GF(p751^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
void oqs_sidh_cln16_fp2inv751_mont(oqs_sidh_cln16_f2elm_t a);

// GF(p751^2) inversion, a = (a0-i*a1)/(a0^2+a1^2), GF(p751) inversion done using the binary GCD
void oqs_sidh_cln16_fp2inv751_mont_bingcd(oqs_sidh_cln16_f2elm_t a);

// n-way Montgomery inversion
void oqs_sidh_cln16_mont_n_way_inv(const oqs_sidh_cln16_f2elm_t *vec, const int n, oqs_sidh_cln16_f2elm_t *out);

// Select either x or y depending on value of option
void oqs_sidh_cln16_select_f2elm(const oqs_sidh_cln16_f2elm_t x, const oqs_sidh_cln16_f2elm_t y, oqs_sidh_cln16_f2elm_t z, const digit_t option);

// Computes square roots of elements in (Fp2)^2 using Hamburg's trick.
void oqs_sidh_cln16_sqrt_Fp2(const oqs_sidh_cln16_f2elm_t u, oqs_sidh_cln16_f2elm_t y);

// Computes square roots of elements in (Fp2)^2 using Hamburg's trick
void oqs_sidh_cln16_sqrt_Fp2_frac(const oqs_sidh_cln16_f2elm_t u, const oqs_sidh_cln16_f2elm_t v, oqs_sidh_cln16_f2elm_t y);

// Cyclotomic cubing on elements of norm 1, using a^(p+1) = 1
void oqs_sidh_cln16_cube_Fp2_cycl(oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_felm_t one);

// Cyclotomic squaring on elements of norm 1, using a^(p+1) = 1
void oqs_sidh_cln16_sqr_Fp2_cycl(oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_felm_t one);

// Cyclotomic inversion, a^(p+1) = 1 => a^(-1) = a^p = a0 - i*a1
extern void oqs_sidh_cln16_inv_Fp2_cycl(oqs_sidh_cln16_f2elm_t a);

// Check if GF(p751^2) element is cube
bool oqs_sidh_cln16_is_cube_Fp2(oqs_sidh_cln16_f2elm_t u, PCurveIsogenyStruct CurveIsogeny);

// Exponentiation y^t via square and multiply in the cyclotomic group. Exponent t is 6 bits at most
void oqs_sidh_cln16_exp6_Fp2_cycl(const oqs_sidh_cln16_f2elm_t y, const uint64_t t, const oqs_sidh_cln16_felm_t one, oqs_sidh_cln16_f2elm_t res);

// Exponentiation y^t via square and multiply in the cyclotomic group. Exponent t is 21 bits at most
void oqs_sidh_cln16_exp21_Fp2_cycl(const oqs_sidh_cln16_f2elm_t y, const uint64_t t, const oqs_sidh_cln16_felm_t one, oqs_sidh_cln16_f2elm_t res);

// Exponentiation y^t via square and multiply in the cyclotomic group. Exponent t is 84 bits at most
void oqs_sidh_cln16_exp84_Fp2_cycl(const oqs_sidh_cln16_f2elm_t y, uint64_t *t, const oqs_sidh_cln16_felm_t one, oqs_sidh_cln16_f2elm_t res);

// Exponentiation y^t via square and multiply in the cyclotomic group. Exponent t is length bits.
void oqs_sidh_cln16_exp_Fp2_cycl(const oqs_sidh_cln16_f2elm_t y, uint64_t *t, const oqs_sidh_cln16_felm_t one, oqs_sidh_cln16_f2elm_t res, int length);

/************ Elliptic curve and isogeny functions *************/

// Check if curve isogeny structure is NULL
bool oqs_sidh_cln16_is_CurveIsogenyStruct_null(PCurveIsogenyStruct pCurveIsogeny);

// Swap points over the base field
void oqs_sidh_cln16_swap_points_basefield(oqs_sidh_cln16_point_basefield_proj_t P, oqs_sidh_cln16_point_basefield_proj_t Q, const digit_t option);

// Swap points
void oqs_sidh_cln16_swap_points(oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, const digit_t option);

// Computes the j-invariant of a Montgomery curve with projective constant.
void oqs_sidh_cln16_j_inv(const oqs_sidh_cln16_f2elm_t A, const oqs_sidh_cln16_f2elm_t C, oqs_sidh_cln16_f2elm_t jinv);

// Simultaneous doubling and differential addition.
void oqs_sidh_cln16_xDBLADD(oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, const oqs_sidh_cln16_f2elm_t xPQ, const oqs_sidh_cln16_f2elm_t A24);

// Doubling of a Montgomery point in projective coordinates (X:Z).
void oqs_sidh_cln16_xDBL(const oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, const oqs_sidh_cln16_f2elm_t A24, const oqs_sidh_cln16_f2elm_t C24);

// Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
void oqs_sidh_cln16_xDBLe(const oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, const oqs_sidh_cln16_f2elm_t A, const oqs_sidh_cln16_f2elm_t C, const int e);

// Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings and collects a few intermediate multiples.
void oqs_sidh_cln16_xDBLe_collect(oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_f2elm_t C, unsigned int left_bound, const unsigned int right_bound, const unsigned int *col, oqs_sidh_cln16_point_proj_t *pts, unsigned int *pts_index, unsigned int *npts);

// Differential addition.
void oqs_sidh_cln16_xADD(oqs_sidh_cln16_point_proj_t P, const oqs_sidh_cln16_point_proj_t Q, const oqs_sidh_cln16_f2elm_t xPQ);

// Doubling of a Montgomery point in projective coordinates (X:Z) over the base field.
void oqs_sidh_cln16_xDBL_basefield(const oqs_sidh_cln16_point_basefield_proj_t P, oqs_sidh_cln16_point_basefield_proj_t Q);

// Simultaneous doubling and differential addition over the base field.
void oqs_sidh_cln16_xDBLADD_basefield(oqs_sidh_cln16_point_basefield_proj_t P, oqs_sidh_cln16_point_basefield_proj_t Q, const oqs_sidh_cln16_felm_t xPQ, const oqs_sidh_cln16_felm_t A24);

// The Montgomery ladder
void oqs_sidh_cln16_ladder(const oqs_sidh_cln16_felm_t x, digit_t *m, oqs_sidh_cln16_point_basefield_proj_t P, oqs_sidh_cln16_point_basefield_proj_t Q, const oqs_sidh_cln16_felm_t A24, const unsigned int order_bits, const unsigned int order_fullbits, PCurveIsogenyStruct CurveIsogeny);

// Computes key generation entirely in the base field
SIDH_CRYPTO_STATUS oqs_sidh_cln16_secret_pt(const oqs_sidh_cln16_point_basefield_t P, const digit_t *m, const unsigned int AliceOrBob, oqs_sidh_cln16_point_proj_t R, PCurveIsogenyStruct CurveIsogeny);

// Computes P+[m]Q via x-only arithmetic.
SIDH_CRYPTO_STATUS oqs_sidh_cln16_ladder_3_pt(const oqs_sidh_cln16_f2elm_t xP, const oqs_sidh_cln16_f2elm_t xQ, const oqs_sidh_cln16_f2elm_t xPQ, const digit_t *m, const unsigned int AliceOrBob, oqs_sidh_cln16_point_proj_t W, const oqs_sidh_cln16_f2elm_t A, PCurveIsogenyStruct CurveIsogeny);

// Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
void oqs_sidh_cln16_get_4_isog(const oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_f2elm_t C, oqs_sidh_cln16_f2elm_t *coeff);

// Evaluates the isogeny at the point (X:Z) in the domain of the isogeny
void oqs_sidh_cln16_eval_4_isog(oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_f2elm_t *coeff);

// Computes first 4-isogeny computed by Alice.
void oqs_sidh_cln16_first_4_isog(oqs_sidh_cln16_point_proj_t P, const oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_f2elm_t Aout, oqs_sidh_cln16_f2elm_t Cout, PCurveIsogenyStruct CurveIsogeny);

// Tripling of a Montgomery point in projective coordinates (X:Z).
void oqs_sidh_cln16_xTPL(const oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, const oqs_sidh_cln16_f2elm_t A24, const oqs_sidh_cln16_f2elm_t C24);

// Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings.
void oqs_sidh_cln16_xTPLe(const oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, const oqs_sidh_cln16_f2elm_t A, const oqs_sidh_cln16_f2elm_t C, const int e);

// Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings and collects a few intermediate multiples.
void oqs_sidh_cln16_xTPLe_collect(oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_f2elm_t C, unsigned int left_bound, const unsigned int right_bound, const unsigned int *col, oqs_sidh_cln16_point_proj_t *pts, unsigned int *pts_index, unsigned int *npts);

// Computes the corresponding 3-isogeny of a projective Montgomery point (X3:Z3) of order 3.
void oqs_sidh_cln16_get_3_isog(const oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_f2elm_t C);

// Computes the 3-isogeny R=phi(X:Z), given projective point (X3:Z3) of order 3 on a Montgomery curve and a point P = (X:Z).
void oqs_sidh_cln16_eval_3_isog(const oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q);

// 3-way simultaneous inversion
void oqs_sidh_cln16_inv_3_way(oqs_sidh_cln16_f2elm_t z1, oqs_sidh_cln16_f2elm_t z2, oqs_sidh_cln16_f2elm_t z3);

// Computing the point D = (x(Q-P),z(Q-P))
void oqs_sidh_cln16_distort_and_diff(const oqs_sidh_cln16_felm_t xP, oqs_sidh_cln16_point_proj_t d, PCurveIsogenyStruct CurveIsogeny);

// Given the x-coordinates of P, Q, and R, returns the value A corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x such that R=Q-P on E_A.
void oqs_sidh_cln16_get_A(const oqs_sidh_cln16_f2elm_t xP, const oqs_sidh_cln16_f2elm_t xQ, const oqs_sidh_cln16_f2elm_t xR, oqs_sidh_cln16_f2elm_t A, PCurveIsogenyStruct CurveIsogeny);

/************ Functions for compression *************/

// Produces points R1 and R2 as basis for E[2^372]
void oqs_sidh_cln16_generate_2_torsion_basis(const oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_point_full_proj_t R1, oqs_sidh_cln16_point_full_proj_t R2, PCurveIsogenyStruct CurveIsogeny);

// Produces points R1 and R2 as basis for E[3^239]
void oqs_sidh_cln16_generate_3_torsion_basis(oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_point_full_proj_t R1, oqs_sidh_cln16_point_full_proj_t R2, PCurveIsogenyStruct CurveIsogeny);

// 2-torsion Tate pairing
void oqs_sidh_cln16_Tate_pairings_2_torsion(const oqs_sidh_cln16_point_t R1, const oqs_sidh_cln16_point_t R2, const oqs_sidh_cln16_point_t P, const oqs_sidh_cln16_point_t Q, const oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_f2elm_t *n, PCurveIsogenyStruct CurveIsogeny);

// 3-torsion Tate pairing
void oqs_sidh_cln16_Tate_pairings_3_torsion(const oqs_sidh_cln16_point_t R1, const oqs_sidh_cln16_point_t R2, const oqs_sidh_cln16_point_t P, const oqs_sidh_cln16_point_t Q, const oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_f2elm_t *n, PCurveIsogenyStruct CurveIsogeny);

// The Montgomery ladder, running in non constant-time
void oqs_sidh_cln16_Mont_ladder(const oqs_sidh_cln16_f2elm_t x, const digit_t *m, oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, const oqs_sidh_cln16_f2elm_t A24, const unsigned int order_bits, const unsigned int order_fullbits, PCurveIsogenyStruct CurveIsogeny);

// General addition
void oqs_sidh_cln16_ADD(const oqs_sidh_cln16_point_full_proj_t P, const oqs_sidh_cln16_f2elm_t QX, const oqs_sidh_cln16_f2elm_t QY, const oqs_sidh_cln16_f2elm_t QZ, const oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_point_full_proj_t R);

// 2-torsion Pohlig-Hellman function
void oqs_sidh_cln16_ph2(const oqs_sidh_cln16_point_t phiP, const oqs_sidh_cln16_point_t phiQ, const oqs_sidh_cln16_point_t PS, const oqs_sidh_cln16_point_t QS, const oqs_sidh_cln16_f2elm_t A, uint64_t *a0, uint64_t *b0, uint64_t *a1, uint64_t *b1, PCurveIsogenyStruct CurveIsogeny);

// Lookup table generation for 2-torsion PH
void oqs_sidh_cln16_build_LUTs(const oqs_sidh_cln16_f2elm_t u, oqs_sidh_cln16_f2elm_t *t_ori, oqs_sidh_cln16_f2elm_t *LUT, oqs_sidh_cln16_f2elm_t *LUT_0, oqs_sidh_cln16_f2elm_t *LUT_1, oqs_sidh_cln16_f2elm_t *LUT_3, const oqs_sidh_cln16_felm_t one);

// Pohlig-Hellman for groups of 2-power order up to 2^6
void oqs_sidh_cln16_phn1(const oqs_sidh_cln16_f2elm_t q, const oqs_sidh_cln16_f2elm_t *LUT, const uint64_t a, const oqs_sidh_cln16_felm_t one, uint64_t *alpha_i);

// Pohlig-Hellman for groups of 2-power order 2^21
void oqs_sidh_cln16_phn5(oqs_sidh_cln16_f2elm_t q, const oqs_sidh_cln16_f2elm_t *LUT, const oqs_sidh_cln16_f2elm_t *LUT_1, const oqs_sidh_cln16_felm_t one, uint64_t *alpha_k);

// Pohlig-Hellman for groups of 2-power order 2^84
void oqs_sidh_cln16_phn21(oqs_sidh_cln16_f2elm_t q, const oqs_sidh_cln16_f2elm_t *LUT, const oqs_sidh_cln16_f2elm_t *LUT_0, const oqs_sidh_cln16_f2elm_t *LUT_1, const oqs_sidh_cln16_felm_t one, uint64_t *alpha_k);

// Pohlig-Hellman for groups of 2-power order 2^372
void oqs_sidh_cln16_phn84(oqs_sidh_cln16_f2elm_t r, const oqs_sidh_cln16_f2elm_t *t_ori, const oqs_sidh_cln16_f2elm_t *LUT, const oqs_sidh_cln16_f2elm_t *LUT_0, const oqs_sidh_cln16_f2elm_t *LUT_1, const oqs_sidh_cln16_f2elm_t *LUT_3, const oqs_sidh_cln16_felm_t one, uint64_t *alpha);

// 3-torsion Pohlig-Hellman function
void oqs_sidh_cln16_ph3(oqs_sidh_cln16_point_t phiP, oqs_sidh_cln16_point_t phiQ, oqs_sidh_cln16_point_t PS, oqs_sidh_cln16_point_t QS, oqs_sidh_cln16_f2elm_t A, uint64_t *a0, uint64_t *b0, uint64_t *a1, uint64_t *b1, PCurveIsogenyStruct CurveIsogeny);

// Lookup table generation for 3-torsion PH
void oqs_sidh_cln16_build_LUTs_3(oqs_sidh_cln16_f2elm_t g, oqs_sidh_cln16_f2elm_t *t_ori, oqs_sidh_cln16_f2elm_t *LUT, oqs_sidh_cln16_f2elm_t *LUT_0, oqs_sidh_cln16_f2elm_t *LUT_1, const oqs_sidh_cln16_felm_t one);

// Pohlig-Hellman for groups of 3-power order up to 3^2 or 3^3
void oqs_sidh_cln16_phn1_3(const oqs_sidh_cln16_f2elm_t q, const oqs_sidh_cln16_f2elm_t *LUT, const uint64_t a, const oqs_sidh_cln16_felm_t one, uint64_t *alpha_i);

// Pohlig-Hellman for groups of 3-power order up 3^15
void oqs_sidh_cln16_phn3(oqs_sidh_cln16_f2elm_t q, const oqs_sidh_cln16_f2elm_t *LUT, const oqs_sidh_cln16_f2elm_t *LUT_1, const oqs_sidh_cln16_felm_t one, uint64_t *alpha_k);

// Pohlig-Hellman for groups of 3-power order up 3^56
void oqs_sidh_cln16_phn15_1(oqs_sidh_cln16_f2elm_t q, const oqs_sidh_cln16_f2elm_t *LUT, const oqs_sidh_cln16_f2elm_t *LUT_0, const oqs_sidh_cln16_f2elm_t *LUT_1, const oqs_sidh_cln16_felm_t one, uint64_t *alpha_k);

// Pohlig-Hellman for groups of 3-power order up 3^61
void oqs_sidh_cln16_phn15(oqs_sidh_cln16_f2elm_t q, const oqs_sidh_cln16_f2elm_t *LUT, const oqs_sidh_cln16_f2elm_t *LUT_0, const oqs_sidh_cln16_f2elm_t *LUT_1, const oqs_sidh_cln16_felm_t one, uint64_t *alpha_k);

// Pohlig-Hellman for groups of 3-power order up 3^239
void oqs_sidh_cln16_phn61(oqs_sidh_cln16_f2elm_t r, oqs_sidh_cln16_f2elm_t *t_ori, const oqs_sidh_cln16_f2elm_t *LUT, const oqs_sidh_cln16_f2elm_t *LUT_0, const oqs_sidh_cln16_f2elm_t *LUT_1, const oqs_sidh_cln16_felm_t one, uint64_t *alpha);

// Recover the y-coordinates of the public key
void oqs_sidh_cln16_recover_y(const oqs_sidh_cln16_publickey_t PK, oqs_sidh_cln16_point_full_proj_t phiP, oqs_sidh_cln16_point_full_proj_t phiQ, oqs_sidh_cln16_point_full_proj_t phiX, oqs_sidh_cln16_f2elm_t A, PCurveIsogenyStruct CurveIsogeny);

// Computes the input modulo 3. The input is assumed to be SIDH_NWORDS_ORDER long
unsigned int oqs_sidh_cln16_mod3(digit_t *a);

// Computes R+aS
void oqs_sidh_cln16_mont_twodim_scalarmult(digit_t *a, const oqs_sidh_cln16_point_t R, const oqs_sidh_cln16_point_t S, const oqs_sidh_cln16_f2elm_t A, const oqs_sidh_cln16_f2elm_t A24, oqs_sidh_cln16_point_full_proj_t P, PCurveIsogenyStruct CurveIsogeny);

void oqs_sidh_cln16_compress_2_torsion(const unsigned char *PublicKeyA, unsigned char *CompressedPKA, uint64_t *a0, uint64_t *b0, uint64_t *a1, uint64_t *b1, oqs_sidh_cln16_point_t R1, oqs_sidh_cln16_point_t R2, PCurveIsogenyStruct CurveIsogeny);
void oqs_sidh_cln16_compress_3_torsion(const unsigned char *PublicKeyA, unsigned char *CompressedPKA, uint64_t *a0, uint64_t *b0, uint64_t *a1, uint64_t *b1, oqs_sidh_cln16_point_t R1, oqs_sidh_cln16_point_t R2, PCurveIsogenyStruct CurveIsogeny);
void oqs_sidh_cln16_decompress_2_torsion(const unsigned char *SecretKey, const unsigned char *CompressedPKA, oqs_sidh_cln16_point_proj_t R, oqs_sidh_cln16_f2elm_t A, PCurveIsogenyStruct CurveIsogeny);
void oqs_sidh_cln16_decompress_3_torsion(const unsigned char *SecretKey, const unsigned char *CompressedPKA, oqs_sidh_cln16_point_proj_t R, oqs_sidh_cln16_f2elm_t A, PCurveIsogenyStruct CurveIsogeny);

#ifdef __cplusplus
}
#endif

#endif
