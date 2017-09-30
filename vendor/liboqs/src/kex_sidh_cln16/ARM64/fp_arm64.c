/********************************************************************************************
 * SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
 *       Diffie-Hellman key exchange.
 *
 * Author:   David Urbanik;  dburbani@uwaterloo.ca 
 *
 * Abstract: Finite field arithmetic for ARM64 using code modified from the original x86_64
 *           and generic implementations by Microsoft.
 *
 *           Most of this file is just a wrapper for the asm file. The other routines are
 *           direct copies of their counterparts on the AMD64 side.
 *
 *           Modified to allow inputs in [0, 2*p751-1].
 *
 *********************************************************************************************/

#include "../SIDH_internal.h"

// Global constants
extern const uint64_t p751[NWORDS_FIELD];
extern const uint64_t p751x2[NWORDS_FIELD];

__inline void oqs_sidh_cln16_fpadd751(const digit_t *a, const digit_t *b, digit_t *c) { // Modular addition, c = a+b mod p751.
	// Inputs: a, b in [0, 2*p751-1]
	// Output: c in [0, 2*p751-1]

	oqs_sidh_cln16_fpadd751_asm(a, b, c);
}

__inline void oqs_sidh_cln16_fpsub751(const digit_t *a, const digit_t *b, digit_t *c) { // Modular subtraction, c = a-b mod p751.
	// Inputs: a, b in [0, 2*p751-1]
	// Output: c in [0, 2*p751-1]

	oqs_sidh_cln16_fpsub751_asm(a, b, c);
}

__inline void oqs_sidh_cln16_fpneg751(digit_t *a) { // Modular negation, a = -a mod p751.
	// Input/output: a in [0, 2*p751-1]
	unsigned int i, borrow = 0;

	for (i = 0; i < NWORDS_FIELD; i++) {
		SUBC(borrow, ((digit_t *) p751x2)[i], a[i], borrow, a[i]);
	}
}

void oqs_sidh_cln16_fpdiv2_751(const digit_t *a, digit_t *c) { // Modular division by two, c = a/2 mod p751.
	// Input : a in [0, 2*p751-1]
	// Output: c in [0, 2*p751-1]
	unsigned int i, carry = 0;
	digit_t mask;

	mask = 0 - (digit_t)(a[0] & 1); // If a is odd compute a+p521
	for (i = 0; i < NWORDS_FIELD; i++) {
		ADDC(carry, a[i], ((digit_t *) p751)[i] & mask, carry, c[i]);
	}

	oqs_sidh_cln16_mp_shiftr1(c, NWORDS_FIELD);
}

void oqs_sidh_cln16_fpcorrection751(digit_t *a) { // Modular correction to reduce field element a in [0, 2*p751-1] to [0, p751-1].
	unsigned int i, borrow = 0;
	digit_t mask;

	for (i = 0; i < NWORDS_FIELD; i++) {
		SUBC(borrow, a[i], ((digit_t *) p751)[i], borrow, a[i]);
	}
	mask = 0 - (digit_t) borrow;

	borrow = 0;
	for (i = 0; i < NWORDS_FIELD; i++) {
		ADDC(borrow, a[i], ((digit_t *) p751)[i] & mask, borrow, a[i]);
	}
}

void oqs_sidh_cln16_mp_mul(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords) { // Multiprecision multiply, c = a*b, where lng(a) = lng(b) = nwords.

	UNREFERENCED_PARAMETER(nwords);

	oqs_sidh_cln16_mul751_asm(a, b, c);
}

void oqs_sidh_cln16_rdc_mont(const digit_t *ma, digit_t *mc) { // Efficient Montgomery reduction using comba and exploiting the special form of the prime p751.
	// mc = ma*R^-1 mod p751x2, where R = 2^768.
	// If ma < 2^768*p751, the output mc is in the range [0, 2*p751-1].
	// ma is assumed to be in Montgomery representation.

	oqs_sidh_cln16_rdc751_asm(ma, mc);
}
