/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral  
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: core functions over GF(p751^2) and field operations modulo the prime p751
*
*********************************************************************************************/

#include "SIDH_internal.h"
#include <string.h>

// Global constants
const uint64_t p751[NWORDS_FIELD] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xEEAFFFFFFFFFFFFF,
                                     0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x00006FE5D541F71C};
const uint64_t p751p1[NWORDS_FIELD] = {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xEEB0000000000000,
                                       0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x00006FE5D541F71C};
const uint64_t p751x2[NWORDS_FIELD] = {0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xDD5FFFFFFFFFFFFF,
                                       0xC7D92D0A93F0F151, 0xB52B363427EF98ED, 0x109D30CFADD7D0ED, 0x0AC56A08B964AE90, 0x1C25213F2F75B8CD, 0x0000DFCBAA83EE38};
const uint64_t Montgomery_R2[NWORDS_FIELD] = {0x233046449DAD4058, 0xDB010161A696452A, 0x5E36941472E3FD8E, 0xF40BFE2082A2E706, 0x4932CCA8904F8751, 0x1F735F1F1EE7FC81,
                                              0xA24F4D80C1048E18, 0xB56C383CCDB607C5, 0x441DD47B735F9C90, 0x5673ED2C6A6AC82A, 0x06C905261132294B, 0x000041AD830F1F35};

/*******************************************************/
/************* Field arithmetic functions **************/

__inline void oqs_sidh_cln16_fpcopy751(const oqs_sidh_cln16_felm_t a, oqs_sidh_cln16_felm_t c) { // Copy a field element, c = a.
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++)
		c[i] = a[i];
}

__inline void oqs_sidh_cln16_fpzero751(oqs_sidh_cln16_felm_t a) { // Zero a field element, a = 0.
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++)
		a[i] = 0;
}

bool oqs_sidh_cln16_fpequal751_non_constant_time(const oqs_sidh_cln16_felm_t a, const oqs_sidh_cln16_felm_t b) { // Non constant-time comparison of two field elements. If a = b return TRUE, otherwise, return FALSE.
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++) {
		if (a[i] != b[i])
			return false;
	}

	return true;
}

void oqs_sidh_cln16_to_mont(const oqs_sidh_cln16_felm_t a, oqs_sidh_cln16_felm_t mc) { // Conversion to Montgomery representation,
	                                                                                   // mc = a*R^2*R^(-1) mod p751 = a*R mod p751, where a in [0, p751-1].
	                                                                                   // The Montgomery constant R^2 mod p751 is the global value "Montgomery_R2".

	oqs_sidh_cln16_fpmul751_mont(a, (digit_t *) &Montgomery_R2, mc);
}

void oqs_sidh_cln16_from_mont(const oqs_sidh_cln16_felm_t ma, oqs_sidh_cln16_felm_t c) { // Conversion from Montgomery representation to standard representation,
	                                                                                     // c = ma*R^(-1) mod p751 = a mod p751, where ma in [0, p751-1].
	digit_t one[NWORDS_FIELD] = {0};

	one[0] = 1;
	oqs_sidh_cln16_fpmul751_mont(ma, one, c);
	oqs_sidh_cln16_fpcorrection751(c);
}

static __inline unsigned int is_felm_zero(const oqs_sidh_cln16_felm_t x) { // Is x = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
	                                                                       // SECURITY NOTE: This function does not run in constant-time.
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++) {
		if (x[i] != 0)
			return false;
	}
	return true;
}

static __inline unsigned int is_felm_even(const oqs_sidh_cln16_felm_t x) { // Is x even? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
	return (unsigned int) ((x[0] & 1) ^ 1);
}

static __inline unsigned int is_felm_lt(const oqs_sidh_cln16_felm_t x, const oqs_sidh_cln16_felm_t y) { // Is x < y? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
	                                                                                                    // SECURITY NOTE: This function does not run in constant-time.
	int i;

	for (i = NWORDS_FIELD - 1; i >= 0; i--) {
		if (x[i] < y[i]) {
			return true;
		} else if (x[i] > y[i]) {
			return false;
		}
	}
	return false;
}

void oqs_sidh_cln16_copy_words(const digit_t *a, digit_t *c, const unsigned int nwords) { // Copy wordsize digits, c = a, where lng(a) = nwords.
	unsigned int i;

	for (i = 0; i < nwords; i++) {
		c[i] = a[i];
	}
}

__inline unsigned int oqs_sidh_cln16_mp_sub(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords) { // Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit.
	unsigned int i, borrow = 0;

	for (i = 0; i < nwords; i++) {
		SUBC(borrow, a[i], b[i], borrow, c[i]);
	}

	return borrow;
}

__inline unsigned int oqs_sidh_cln16_mp_add(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords) { // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit.
	unsigned int i, carry = 0;

	for (i = 0; i < nwords; i++) {
		ADDC(carry, a[i], b[i], carry, c[i]);
	}

	return carry;
}

__inline void oqs_sidh_cln16_mp_add751(const digit_t *a, const digit_t *b, digit_t *c) { // 751-bit multiprecision addition, c = a+b.

#if (OS_TARGET == OS_WIN) || defined(GENERIC_IMPLEMENTATION)

	oqs_sidh_cln16_mp_add(a, b, c, NWORDS_FIELD);

#elif (OS_TARGET == OS_LINUX)

	oqs_sidh_cln16_mp_add751_asm(a, b, c);

#endif
}

__inline void oqs_sidh_cln16_mp_add751x2(const digit_t *a, const digit_t *b, digit_t *c) { // 2x751-bit multiprecision addition, c = a+b.

#if (OS_TARGET == OS_WIN) || defined(GENERIC_IMPLEMENTATION)

	oqs_sidh_cln16_mp_add(a, b, c, 2 * NWORDS_FIELD);

#elif (OS_TARGET == OS_LINUX)

	oqs_sidh_cln16_mp_add751x2_asm(a, b, c);

#endif
}

void oqs_sidh_cln16_mp_shiftr1(digit_t *x, const unsigned int nwords) { // Multiprecision right shift by one.
	unsigned int i;

	for (i = 0; i < nwords - 1; i++) {
		SHIFTR(x[i + 1], x[i], 1, x[i], RADIX);
	}
	x[nwords - 1] >>= 1;
}

void oqs_sidh_cln16_mp_shiftl1(digit_t *x, const unsigned int nwords) { // Multiprecision left shift by one.
	int i;

	for (i = nwords - 1; i > 0; i--) {
		SHIFTL(x[i], x[i - 1], 1, x[i], RADIX);
	}
	x[0] <<= 1;
}

void oqs_sidh_cln16_fpmul751_mont(const oqs_sidh_cln16_felm_t ma, const oqs_sidh_cln16_felm_t mb, oqs_sidh_cln16_felm_t mc) { // 751-bit Comba multi-precision multiplication, c = a*b mod p751.
	oqs_sidh_cln16_dfelm_t temp = {0};

	oqs_sidh_cln16_mp_mul(ma, mb, temp, NWORDS_FIELD);
	oqs_sidh_cln16_rdc_mont(temp, mc);
}

void oqs_sidh_cln16_fpsqr751_mont(const oqs_sidh_cln16_felm_t ma, oqs_sidh_cln16_felm_t mc) { // 751-bit Comba multi-precision squaring, c = a^2 mod p751.
	oqs_sidh_cln16_dfelm_t temp = {0};

	oqs_sidh_cln16_mp_mul(ma, ma, temp, NWORDS_FIELD);
	oqs_sidh_cln16_rdc_mont(temp, mc);
}

void oqs_sidh_cln16_fpinv751_chain_mont(oqs_sidh_cln16_felm_t a) { // Chain to compute a^(p751-3)/4 using Montgomery arithmetic.
	oqs_sidh_cln16_felm_t t[27], tt;
	unsigned int i, j;

	// Precomputed table
	oqs_sidh_cln16_fpsqr751_mont(a, tt);
	oqs_sidh_cln16_fpmul751_mont(a, tt, t[0]);
	oqs_sidh_cln16_fpmul751_mont(t[0], tt, t[1]);
	oqs_sidh_cln16_fpmul751_mont(t[1], tt, t[2]);
	oqs_sidh_cln16_fpmul751_mont(t[2], tt, t[3]);
	oqs_sidh_cln16_fpmul751_mont(t[3], tt, t[3]);
	for (i = 3; i <= 8; i++)
		oqs_sidh_cln16_fpmul751_mont(t[i], tt, t[i + 1]);
	oqs_sidh_cln16_fpmul751_mont(t[9], tt, t[9]);
	for (i = 9; i <= 20; i++)
		oqs_sidh_cln16_fpmul751_mont(t[i], tt, t[i + 1]);
	oqs_sidh_cln16_fpmul751_mont(t[21], tt, t[21]);
	for (i = 21; i <= 24; i++)
		oqs_sidh_cln16_fpmul751_mont(t[i], tt, t[i + 1]);
	oqs_sidh_cln16_fpmul751_mont(t[25], tt, t[25]);
	oqs_sidh_cln16_fpmul751_mont(t[25], tt, t[26]);

	oqs_sidh_cln16_fpcopy751(a, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[20], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[24], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[11], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[8], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[2], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[23], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[2], tt, tt);
	for (i = 0; i < 9; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[2], tt, tt);
	for (i = 0; i < 10; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[15], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[13], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[26], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[20], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[11], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[10], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[14], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[4], tt, tt);
	for (i = 0; i < 10; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[18], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[1], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[22], tt, tt);
	for (i = 0; i < 10; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[6], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[24], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[9], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[18], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[17], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(a, tt, tt);
	for (i = 0; i < 10; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[16], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[7], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[0], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[12], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[19], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[22], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[25], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[2], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[10], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[22], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[18], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[4], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[14], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[13], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[5], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[23], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[21], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[2], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[23], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[12], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[9], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[3], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[13], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[17], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[26], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[5], tt, tt);
	for (i = 0; i < 8; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[8], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[2], tt, tt);
	for (i = 0; i < 6; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[11], tt, tt);
	for (i = 0; i < 7; i++)
		oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(t[20], tt, tt);
	for (j = 0; j < 61; j++) {
		for (i = 0; i < 6; i++)
			oqs_sidh_cln16_fpsqr751_mont(tt, tt);
		oqs_sidh_cln16_fpmul751_mont(t[26], tt, tt);
	}
	oqs_sidh_cln16_fpcopy751(tt, a);
}

void oqs_sidh_cln16_fpinv751_mont(oqs_sidh_cln16_felm_t a) { // Field inversion using Montgomery arithmetic, a = a^(-1)*R mod p751.
	oqs_sidh_cln16_felm_t tt;

	oqs_sidh_cln16_fpcopy751(a, tt);
	oqs_sidh_cln16_fpinv751_chain_mont(tt);
	oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpsqr751_mont(tt, tt);
	oqs_sidh_cln16_fpmul751_mont(a, tt, a);
}

static __inline void power2_setup(digit_t *x, int mark, const unsigned int nwords) { // Set up the value 2^mark.
	unsigned int i;

	for (i = 0; i < nwords; i++)
		x[i] = 0;

	i = 0;
	while (mark >= 0) {
		if (mark < RADIX) {
			x[i] = (digit_t) 1 << mark;
		}
		mark -= RADIX;
		i += 1;
	}
}

static __inline void fpinv751_mont_bingcd_partial(const oqs_sidh_cln16_felm_t a, oqs_sidh_cln16_felm_t x1, unsigned int *k) { // Partial Montgomery inversion in GF(p751) via the binary GCD algorithm.
	oqs_sidh_cln16_felm_t u, v, x2;
	unsigned int cwords; // number of words necessary for x1, x2

	oqs_sidh_cln16_fpcopy751(a, u);
	oqs_sidh_cln16_fpcopy751((digit_t *) &p751, v);
	oqs_sidh_cln16_fpzero751(x1);
	x1[0] = 1;
	oqs_sidh_cln16_fpzero751(x2);
	*k = 0;

	while (!is_felm_zero(v)) {
		cwords = ((*k + 1) / RADIX) + 1;
		if ((cwords < NWORDS_FIELD)) {
			if (is_felm_even(v)) {
				oqs_sidh_cln16_mp_shiftr1(v, NWORDS_FIELD);
				oqs_sidh_cln16_mp_shiftl1(x1, cwords);
			} else if (is_felm_even(u)) {
				oqs_sidh_cln16_mp_shiftr1(u, NWORDS_FIELD);
				oqs_sidh_cln16_mp_shiftl1(x2, cwords);
			} else if (!is_felm_lt(v, u)) {
				oqs_sidh_cln16_mp_sub(v, u, v, NWORDS_FIELD);
				oqs_sidh_cln16_mp_shiftr1(v, NWORDS_FIELD);
				oqs_sidh_cln16_mp_add(x1, x2, x2, cwords);
				oqs_sidh_cln16_mp_shiftl1(x1, cwords);
			} else {
				oqs_sidh_cln16_mp_sub(u, v, u, NWORDS_FIELD);
				oqs_sidh_cln16_mp_shiftr1(u, NWORDS_FIELD);
				oqs_sidh_cln16_mp_add(x1, x2, x1, cwords);
				oqs_sidh_cln16_mp_shiftl1(x2, cwords);
			}
		} else {
			if (is_felm_even(v)) {
				oqs_sidh_cln16_mp_shiftr1(v, NWORDS_FIELD);
				oqs_sidh_cln16_mp_shiftl1(x1, NWORDS_FIELD);
			} else if (is_felm_even(u)) {
				oqs_sidh_cln16_mp_shiftr1(u, NWORDS_FIELD);
				oqs_sidh_cln16_mp_shiftl1(x2, NWORDS_FIELD);
			} else if (!is_felm_lt(v, u)) {
				oqs_sidh_cln16_mp_sub(v, u, v, NWORDS_FIELD);
				oqs_sidh_cln16_mp_shiftr1(v, NWORDS_FIELD);
				oqs_sidh_cln16_mp_add751(x1, x2, x2);
				oqs_sidh_cln16_mp_shiftl1(x1, NWORDS_FIELD);
			} else {
				oqs_sidh_cln16_mp_sub(u, v, u, NWORDS_FIELD);
				oqs_sidh_cln16_mp_shiftr1(u, NWORDS_FIELD);
				oqs_sidh_cln16_mp_add751(x1, x2, x1);
				oqs_sidh_cln16_mp_shiftl1(x2, NWORDS_FIELD);
			}
		}
		*k += 1;
	}

	if (is_felm_lt((digit_t *) &p751, x1)) {
		oqs_sidh_cln16_mp_sub(x1, (digit_t *) &p751, x1, NWORDS_FIELD);
	}
}

void oqs_sidh_cln16_fpinv751_mont_bingcd(oqs_sidh_cln16_felm_t a) { // Field inversion via the binary GCD using Montgomery arithmetic, a = a^-1*R mod p751.
	                                                                // SECURITY NOTE: This function does not run in constant-time.
	oqs_sidh_cln16_felm_t x, t;
	unsigned int k;

	fpinv751_mont_bingcd_partial(a, x, &k);
	if (k < 768) {
		oqs_sidh_cln16_fpmul751_mont(x, (digit_t *) &Montgomery_R2, x);
		k += 768;
	}
	oqs_sidh_cln16_fpmul751_mont(x, (digit_t *) &Montgomery_R2, x);
	power2_setup(t, 2 * 768 - k, NWORDS_FIELD);
	oqs_sidh_cln16_fpmul751_mont(x, t, a);
}

/***********************************************/
/************* GF(p^2) FUNCTIONS ***************/

void oqs_sidh_cln16_fp2copy751(const oqs_sidh_cln16_f2elm_t a, oqs_sidh_cln16_f2elm_t c) { // Copy a GF(p751^2) element, c = a.
	oqs_sidh_cln16_fpcopy751(a[0], c[0]);
	oqs_sidh_cln16_fpcopy751(a[1], c[1]);
}

void oqs_sidh_cln16_fp2zero751(oqs_sidh_cln16_f2elm_t a) { // Zero a GF(p751^2) element, a = 0.
	oqs_sidh_cln16_fpzero751(a[0]);
	oqs_sidh_cln16_fpzero751(a[1]);
}

void oqs_sidh_cln16_fp2neg751(oqs_sidh_cln16_f2elm_t a) { // GF(p751^2) negation, a = -a in GF(p751^2).
	oqs_sidh_cln16_fpneg751(a[0]);
	oqs_sidh_cln16_fpneg751(a[1]);
}

__inline void oqs_sidh_cln16_fp2add751(const oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_f2elm_t b, oqs_sidh_cln16_f2elm_t c) { // GF(p751^2) addition, c = a+b in GF(p751^2).
	oqs_sidh_cln16_fpadd751(a[0], b[0], c[0]);
	oqs_sidh_cln16_fpadd751(a[1], b[1], c[1]);
}

__inline void oqs_sidh_cln16_fp2sub751(const oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_f2elm_t b, oqs_sidh_cln16_f2elm_t c) { // GF(p751^2) subtraction, c = a-b in GF(p751^2).
	oqs_sidh_cln16_fpsub751(a[0], b[0], c[0]);
	oqs_sidh_cln16_fpsub751(a[1], b[1], c[1]);
}

void oqs_sidh_cln16_fp2div2_751(const oqs_sidh_cln16_f2elm_t a, oqs_sidh_cln16_f2elm_t c) { // GF(p751^2) division by two, c = a/2  in GF(p751^2).
	oqs_sidh_cln16_fpdiv2_751(a[0], c[0]);
	oqs_sidh_cln16_fpdiv2_751(a[1], c[1]);
}

void oqs_sidh_cln16_fp2correction751(oqs_sidh_cln16_f2elm_t a) { // Modular correction, a = a in GF(p751^2).
	oqs_sidh_cln16_fpcorrection751(a[0]);
	oqs_sidh_cln16_fpcorrection751(a[1]);
}

void oqs_sidh_cln16_fp2sqr751_mont(const oqs_sidh_cln16_f2elm_t a, oqs_sidh_cln16_f2elm_t c) { // GF(p751^2) squaring using Montgomery arithmetic, c = a^2 in GF(p751^2).
	                                                                                           // Inputs: a = a0+a1*i, where a0, a1 are in [0, 2*p751-1]
	                                                                                           // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p751-1]
	oqs_sidh_cln16_felm_t t1, t2, t3;

	oqs_sidh_cln16_mp_add751(a[0], a[1], t1);     // t1 = a0+a1
	oqs_sidh_cln16_fpsub751(a[0], a[1], t2);      // t2 = a0-a1
	oqs_sidh_cln16_mp_add751(a[0], a[0], t3);     // t3 = 2a0
	oqs_sidh_cln16_fpmul751_mont(t1, t2, c[0]);   // c0 = (a0+a1)(a0-a1)
	oqs_sidh_cln16_fpmul751_mont(t3, a[1], c[1]); // c1 = 2a0*a1
}

void oqs_sidh_cln16_fp2mul751_mont(const oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_f2elm_t b, oqs_sidh_cln16_f2elm_t c) { // GF(p751^2) multiplication using Montgomery arithmetic, c = a*b in GF(p751^2).
	                                                                                                                           // Inputs: a = a0+a1*i and b = b0+b1*i, where a0, a1, b0, b1 are in [0, 2*p751-1]
	                                                                                                                           // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p751-1]
	oqs_sidh_cln16_felm_t t1, t2;
	oqs_sidh_cln16_dfelm_t tt1, tt2, tt3;
	digit_t mask;
	unsigned int i, borrow;

	oqs_sidh_cln16_mp_mul(a[0], b[0], tt1, NWORDS_FIELD);            // tt1 = a0*b0
	oqs_sidh_cln16_mp_mul(a[1], b[1], tt2, NWORDS_FIELD);            // tt2 = a1*b1
	oqs_sidh_cln16_mp_add751(a[0], a[1], t1);                        // t1 = a0+a1
	oqs_sidh_cln16_mp_add751(b[0], b[1], t2);                        // t2 = b0+b1
	borrow = oqs_sidh_cln16_mp_sub(tt1, tt2, tt3, 2 * NWORDS_FIELD); // tt3 = a0*b0 - a1*b1
	mask = 0 - (digit_t) borrow;                                     // if tt3 < 0 then mask = 0xFF..F, else if tt3 >= 0 then mask = 0x00..0
	borrow = 0;
	for (i = 0; i < NWORDS_FIELD; i++) {
		ADDC(borrow, tt3[NWORDS_FIELD + i], ((digit_t *) p751)[i] & mask, borrow, tt3[NWORDS_FIELD + i]);
	}
	oqs_sidh_cln16_rdc_mont(tt3, c[0]);                     // c[0] = a0*b0 - a1*b1
	oqs_sidh_cln16_mp_add751x2(tt1, tt2, tt1);              // tt1 = a0*b0 + a1*b1
	oqs_sidh_cln16_mp_mul(t1, t2, tt2, NWORDS_FIELD);       // tt2 = (a0+a1)*(b0+b1)
	oqs_sidh_cln16_mp_sub(tt2, tt1, tt2, 2 * NWORDS_FIELD); // tt2 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
	oqs_sidh_cln16_rdc_mont(tt2, c[1]);                     // c[1] = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
}

void oqs_sidh_cln16_to_fp2mont(const oqs_sidh_cln16_f2elm_t a, oqs_sidh_cln16_f2elm_t mc) { // Conversion of a GF(p751^2) element to Montgomery representation,
	                                                                                        // mc_i = a_i*R^2*R^(-1) = a_i*R in GF(p751^2).

	oqs_sidh_cln16_to_mont(a[0], mc[0]);
	oqs_sidh_cln16_to_mont(a[1], mc[1]);
}

void oqs_sidh_cln16_from_fp2mont(const oqs_sidh_cln16_f2elm_t ma, oqs_sidh_cln16_f2elm_t c) { // Conversion of a GF(p751^2) element from Montgomery representation to standard representation,
	                                                                                          // c_i = ma_i*R^(-1) = a_i in GF(p751^2).

	oqs_sidh_cln16_from_mont(ma[0], c[0]);
	oqs_sidh_cln16_from_mont(ma[1], c[1]);
}

void oqs_sidh_cln16_fp2inv751_mont(oqs_sidh_cln16_f2elm_t a) { // GF(p751^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2).
	oqs_sidh_cln16_f2elm_t t1;

	oqs_sidh_cln16_fpsqr751_mont(a[0], t1[0]);    // t10 = a0^2
	oqs_sidh_cln16_fpsqr751_mont(a[1], t1[1]);    // t11 = a1^2
	oqs_sidh_cln16_fpadd751(t1[0], t1[1], t1[0]); // t10 = a0^2+a1^2
	oqs_sidh_cln16_fpinv751_mont(t1[0]);          // t10 = (a0^2+a1^2)^-1
	oqs_sidh_cln16_fpneg751(a[1]);                // a = a0-i*a1
	oqs_sidh_cln16_fpmul751_mont(a[0], t1[0], a[0]);
	oqs_sidh_cln16_fpmul751_mont(a[1], t1[0], a[1]); // a = (a0-i*a1)*(a0^2+a1^2)^-1
}

void oqs_sidh_cln16_fp2inv751_mont_bingcd(oqs_sidh_cln16_f2elm_t a) { // GF(p751^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
	// This uses the binary GCD for inversion in fp and is NOT constant time!!!
	oqs_sidh_cln16_f2elm_t t1;

	oqs_sidh_cln16_fpsqr751_mont(a[0], t1[0]);    // t10 = a0^2
	oqs_sidh_cln16_fpsqr751_mont(a[1], t1[1]);    // t11 = a1^2
	oqs_sidh_cln16_fpadd751(t1[0], t1[1], t1[0]); // t10 = a0^2+a1^2
	oqs_sidh_cln16_fpinv751_mont_bingcd(t1[0]);   // t10 = (a0^2+a1^2)^-1
	oqs_sidh_cln16_fpneg751(a[1]);                // a = a0-i*a1
	oqs_sidh_cln16_fpmul751_mont(a[0], t1[0], a[0]);
	oqs_sidh_cln16_fpmul751_mont(a[1], t1[0], a[1]); // a = (a0-i*a1)*(a0^2+a1^2)^-1
}

void oqs_sidh_cln16_swap_points_basefield(oqs_sidh_cln16_point_basefield_proj_t P, oqs_sidh_cln16_point_basefield_proj_t Q, const digit_t option) { // Swap points over the base field.
	                                                                                                                                                // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
	digit_t temp;
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++) {
		temp = option & (P->X[i] ^ Q->X[i]);
		P->X[i] = temp ^ P->X[i];
		Q->X[i] = temp ^ Q->X[i];
		temp = option & (P->Z[i] ^ Q->Z[i]);
		P->Z[i] = temp ^ P->Z[i];
		Q->Z[i] = temp ^ Q->Z[i];
	}
}

void oqs_sidh_cln16_swap_points(oqs_sidh_cln16_point_proj_t P, oqs_sidh_cln16_point_proj_t Q, const digit_t option) { // Swap points.
	                                                                                                                  // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
	digit_t temp;
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++) {
		temp = option & (P->X[0][i] ^ Q->X[0][i]);
		P->X[0][i] = temp ^ P->X[0][i];
		Q->X[0][i] = temp ^ Q->X[0][i];
		temp = option & (P->Z[0][i] ^ Q->Z[0][i]);
		P->Z[0][i] = temp ^ P->Z[0][i];
		Q->Z[0][i] = temp ^ Q->Z[0][i];
		temp = option & (P->X[1][i] ^ Q->X[1][i]);
		P->X[1][i] = temp ^ P->X[1][i];
		Q->X[1][i] = temp ^ Q->X[1][i];
		temp = option & (P->Z[1][i] ^ Q->Z[1][i]);
		P->Z[1][i] = temp ^ P->Z[1][i];
		Q->Z[1][i] = temp ^ Q->Z[1][i];
	}
}

void oqs_sidh_cln16_select_f2elm(const oqs_sidh_cln16_f2elm_t x, const oqs_sidh_cln16_f2elm_t y, oqs_sidh_cln16_f2elm_t z, const digit_t option) { // Select either x or y depending on the value of option.
	                                                                                                                                               // If option = 0 then z <- x, else if option = 0xFF...FF then z <- y.
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++) {
		z[0][i] = (option & (x[0][i] ^ y[0][i])) ^ x[0][i];
		z[1][i] = (option & (x[1][i] ^ y[1][i])) ^ x[1][i];
	}
}

void oqs_sidh_cln16_mont_n_way_inv(const oqs_sidh_cln16_f2elm_t *vec, const int n, oqs_sidh_cln16_f2elm_t *out) { // n-way simultaneous inversion using Montgomery's trick.
	                                                                                                              // SECURITY NOTE: This function does not run in constant time.
	                                                                                                              //       Also, vec and out CANNOT be the same variable!
	oqs_sidh_cln16_f2elm_t t1;
	int i;

	oqs_sidh_cln16_fp2copy751(vec[0], out[0]); // out[0] = vec[0]
	for (i = 1; i < n; i++) {
		oqs_sidh_cln16_fp2mul751_mont(out[i - 1], vec[i], out[i]); // out[i] = out[i-1]*vec[i]
	}

	oqs_sidh_cln16_fp2copy751(out[n - 1], t1); // t1 = 1/out[n-1]
	oqs_sidh_cln16_fp2inv751_mont_bingcd(t1);

	for (i = n - 1; i >= 1; i--) {
		oqs_sidh_cln16_fp2mul751_mont(out[i - 1], t1, out[i]); // out[i] = t1*out[i-1]
		oqs_sidh_cln16_fp2mul751_mont(t1, vec[i], t1);         // t1 = t1*vec[i]
	}
	oqs_sidh_cln16_fp2copy751(t1, out[0]); // out[0] = t1
}

void oqs_sidh_cln16_sqrt_Fp2_frac(const oqs_sidh_cln16_f2elm_t u, const oqs_sidh_cln16_f2elm_t v, oqs_sidh_cln16_f2elm_t y) { // Computes square roots of elements in (Fp2)^2 using Hamburg's trick.
	oqs_sidh_cln16_felm_t t0, t1, t2, t3, t4, t;
	digit_t *u0 = (digit_t *) u[0], *u1 = (digit_t *) u[1];
	digit_t *v0 = (digit_t *) v[0], *v1 = (digit_t *) v[1];
	digit_t *y0 = (digit_t *) y[0], *y1 = (digit_t *) y[1];
	unsigned int i;

	oqs_sidh_cln16_fpsqr751_mont(v0, t0);     // t0 = v0^2
	oqs_sidh_cln16_fpsqr751_mont(v1, t1);     // t1 = v1^2
	oqs_sidh_cln16_fpadd751(t0, t1, t0);      // t0 = t0+t1
	oqs_sidh_cln16_fpmul751_mont(u0, v0, t1); // t1 = u0*v0
	oqs_sidh_cln16_fpmul751_mont(u1, v1, t2); // t2 = u1*v1
	oqs_sidh_cln16_fpadd751(t1, t2, t1);      // t1 = t1+t2
	oqs_sidh_cln16_fpmul751_mont(u1, v0, t2); // t2 = u1*v0
	oqs_sidh_cln16_fpmul751_mont(u0, v1, t3); // t3 = u0*v1
	oqs_sidh_cln16_fpsub751(t2, t3, t2);      // t2 = t2-t3
	oqs_sidh_cln16_fpsqr751_mont(t1, t3);     // t3 = t1^2
	oqs_sidh_cln16_fpsqr751_mont(t2, t4);     // t4 = t2^2
	oqs_sidh_cln16_fpadd751(t3, t4, t3);      // t3 = t3+t4
	oqs_sidh_cln16_fpcopy751(t3, t);
	for (i = 0; i < 370; i++) { // t = t3^((p+1)/4)
		oqs_sidh_cln16_fpsqr751_mont(t, t);
	}
	for (i = 0; i < 239; i++) {
		oqs_sidh_cln16_fpsqr751_mont(t, t3);
		oqs_sidh_cln16_fpmul751_mont(t, t3, t);
	}
	oqs_sidh_cln16_fpadd751(t1, t, t);        // t = t+t1
	oqs_sidh_cln16_fpadd751(t, t, t);         // t = 2*t
	oqs_sidh_cln16_fpsqr751_mont(t0, t3);     // t3 = t0^2
	oqs_sidh_cln16_fpmul751_mont(t0, t3, t3); // t3 = t3*t0
	oqs_sidh_cln16_fpmul751_mont(t, t3, t3);  // t3 = t3*t
	oqs_sidh_cln16_fpinv751_chain_mont(t3);   // t3 = t3^((p-3)/4)
	oqs_sidh_cln16_fpmul751_mont(t0, t3, t3); // t3 = t3*t0
	oqs_sidh_cln16_fpmul751_mont(t, t3, t1);  // t1 = t*t3
	oqs_sidh_cln16_fpdiv2_751(t1, y0);        // y0 = t1/2
	oqs_sidh_cln16_fpmul751_mont(t2, t3, y1); // y1 = t3*t2
	oqs_sidh_cln16_fpsqr751_mont(t1, t1);     // t1 = t1^2
	oqs_sidh_cln16_fpmul751_mont(t0, t1, t1); // t1 = t1*t0
	oqs_sidh_cln16_fpcorrection751(t);
	oqs_sidh_cln16_fpcorrection751(t1);

	if (oqs_sidh_cln16_fpequal751_non_constant_time(t1, t) == false) {
		oqs_sidh_cln16_fpcopy751(y0, t);
		oqs_sidh_cln16_fpcopy751(y1, y0); // Swap y0 and y1
		oqs_sidh_cln16_fpcopy751(t, y1);
	}

	oqs_sidh_cln16_fpsqr751_mont(y0, t0);     // t0 = y0^2
	oqs_sidh_cln16_fpsqr751_mont(y1, t1);     // t1 = y1^2
	oqs_sidh_cln16_fpsub751(t0, t1, t0);      // t0 = t0-t1
	oqs_sidh_cln16_fpmul751_mont(t0, v0, t0); // t0 = t0*v0
	oqs_sidh_cln16_fpmul751_mont(y0, y1, t1); // t1 = y0*y1
	oqs_sidh_cln16_fpmul751_mont(v1, t1, t1); // t1 = t1*v1
	oqs_sidh_cln16_fpadd751(t1, t1, t1);      // t1 = t1+t1
	oqs_sidh_cln16_fpsub751(t0, t1, t0);      // t0 = t0-t1
	oqs_sidh_cln16_fpcorrection751(t0);
	oqs_sidh_cln16_fpcorrection751(u0);

	if (oqs_sidh_cln16_fpequal751_non_constant_time(t0, u0) == false) {
		oqs_sidh_cln16_fpneg751(y1); // y1 = -y1
	}
}

void oqs_sidh_cln16_sqrt_Fp2(const oqs_sidh_cln16_f2elm_t u, oqs_sidh_cln16_f2elm_t y) { // Computes square roots of elements in (Fp2)^2 using Hamburg's trick.
	oqs_sidh_cln16_felm_t t0, t1, t2, t3;
	digit_t *a = (digit_t *) u[0], *b = (digit_t *) u[1];
	unsigned int i;

	oqs_sidh_cln16_fpsqr751_mont(a, t0); // t0 = a^2
	oqs_sidh_cln16_fpsqr751_mont(b, t1); // t1 = b^2
	oqs_sidh_cln16_fpadd751(t0, t1, t0); // t0 = t0+t1
	oqs_sidh_cln16_fpcopy751(t0, t1);
	for (i = 0; i < 370; i++) { // t = t3^((p+1)/4)
		oqs_sidh_cln16_fpsqr751_mont(t1, t1);
	}
	for (i = 0; i < 239; i++) {
		oqs_sidh_cln16_fpsqr751_mont(t1, t0);
		oqs_sidh_cln16_fpmul751_mont(t1, t0, t1);
	}
	oqs_sidh_cln16_fpadd751(a, t1, t0); // t0 = a+t1
	oqs_sidh_cln16_fpdiv2_751(t0, t0);  // t0 = t0/2
	oqs_sidh_cln16_fpcopy751(t0, t2);
	oqs_sidh_cln16_fpinv751_chain_mont(t2);   // t2 = t0^((p-3)/4)
	oqs_sidh_cln16_fpmul751_mont(t0, t2, t1); // t1 = t2*t0
	oqs_sidh_cln16_fpmul751_mont(t2, b, t2);  // t2 = t2*b
	oqs_sidh_cln16_fpdiv2_751(t2, t2);        // t2 = t2/2
	oqs_sidh_cln16_fpsqr751_mont(t1, t3);     // t3 = t1^2
	oqs_sidh_cln16_fpcorrection751(t0);
	oqs_sidh_cln16_fpcorrection751(t3);

	if (oqs_sidh_cln16_fpequal751_non_constant_time(t0, t3) == true) {
		oqs_sidh_cln16_fpcopy751(t1, y[0]);
		oqs_sidh_cln16_fpcopy751(t2, y[1]);
	} else {
		oqs_sidh_cln16_fpneg751(t1);
		oqs_sidh_cln16_fpcopy751(t2, y[0]);
		oqs_sidh_cln16_fpcopy751(t1, y[1]);
	}
}

void oqs_sidh_cln16_cube_Fp2_cycl(oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_felm_t one) { // Cyclotomic cubing on elements of norm 1, using a^(p+1) = 1.
	oqs_sidh_cln16_felm_t t0;

	oqs_sidh_cln16_fpadd751(a[0], a[0], t0);      // t0 = a0 + a0
	oqs_sidh_cln16_fpsqr751_mont(t0, t0);         // t0 = t0^2
	oqs_sidh_cln16_fpsub751(t0, one, t0);         // t0 = t0 - 1
	oqs_sidh_cln16_fpmul751_mont(a[1], t0, a[1]); // a1 = t0*a1
	oqs_sidh_cln16_fpsub751(t0, one, t0);
	oqs_sidh_cln16_fpsub751(t0, one, t0);         // t0 = t0 - 2
	oqs_sidh_cln16_fpmul751_mont(a[0], t0, a[0]); // a0 = t0*a0
}

void oqs_sidh_cln16_sqr_Fp2_cycl(oqs_sidh_cln16_f2elm_t a, const oqs_sidh_cln16_felm_t one) { // Cyclotomic squaring on elements of norm 1, using a^(p+1) = 1.
	oqs_sidh_cln16_felm_t t0;

	oqs_sidh_cln16_fpadd751(a[0], a[1], t0); // t0 = a0 + a1
	oqs_sidh_cln16_fpsqr751_mont(t0, t0);    // t0 = t0^2
	oqs_sidh_cln16_fpsub751(t0, one, a[1]);  // a1 = t0 - 1
	oqs_sidh_cln16_fpsqr751_mont(a[0], t0);  // t0 = a0^2
	oqs_sidh_cln16_fpadd751(t0, t0, t0);     // t0 = t0 + t0
	oqs_sidh_cln16_fpsub751(t0, one, a[0]);  // a0 = t0 - 1
}

__inline void oqs_sidh_cln16_inv_Fp2_cycl(oqs_sidh_cln16_f2elm_t a) { // Cyclotomic inversion, a^(p+1) = 1 => a^(-1) = a^p = a0 - i*a1.

	oqs_sidh_cln16_fpneg751(a[1]);
}

void oqs_sidh_cln16_exp6_Fp2_cycl(const oqs_sidh_cln16_f2elm_t y, const uint64_t t, const oqs_sidh_cln16_felm_t one, oqs_sidh_cln16_f2elm_t res) { // Exponentiation y^t via square and multiply in the cyclotomic group. Exponent t is 6 bits at most.
	unsigned int i, bit;

	oqs_sidh_cln16_fp2zero751(res);
	oqs_sidh_cln16_fpcopy751(one, res[0]); // res = 1

	if (t != 0) {
		for (i = 0; i < 6; i++) {
			oqs_sidh_cln16_sqr_Fp2_cycl(res, one);
			bit = 1 & (t >> (5 - i));
			if (bit == 1) {
				oqs_sidh_cln16_fp2mul751_mont(res, y, res);
			}
		}
	}
}

void oqs_sidh_cln16_exp21_Fp2_cycl(const oqs_sidh_cln16_f2elm_t y, const uint64_t t, const oqs_sidh_cln16_felm_t one, oqs_sidh_cln16_f2elm_t res) { // Exponentiation y^t via square and multiply in the cyclotomic group. Exponent t is 21 bits at most.
	unsigned int i, bit;

	oqs_sidh_cln16_fp2zero751(res);
	oqs_sidh_cln16_fpcopy751(one, res[0]); // res = 1

	if (t != 0) {
		for (i = 0; i < 21; i++) {
			oqs_sidh_cln16_sqr_Fp2_cycl(res, one);
			bit = 1 & (t >> (20 - i));
			if (bit == 1) {
				oqs_sidh_cln16_fp2mul751_mont(res, y, res);
			}
		}
	}
}

static bool is_zero(digit_t *a, unsigned int nwords) { // Check if multiprecision element is zero.
	                                                   // SECURITY NOTE: This function does not run in constant time.
	unsigned int i;

	for (i = 0; i < nwords; i++) {
		if (a[i] != 0) {
			return false;
		}
	}

	return true;
}

void oqs_sidh_cln16_exp_Fp2_cycl(const oqs_sidh_cln16_f2elm_t y, uint64_t *t, const oqs_sidh_cln16_felm_t one, oqs_sidh_cln16_f2elm_t res, int length) { // Exponentiation y^t via square and multiply in the cyclotomic group.
	                                                                                                                                                     // This function uses 64-bit digits for representing exponents.
	unsigned int nword, bit, nwords = (length + 63) / 64;
	int i;

	oqs_sidh_cln16_fp2zero751(res);
	oqs_sidh_cln16_fpcopy751(one, res[0]); // res = 1

	if (!is_zero((digit_t *) t, nwords)) { // Is t = 0?
		for (i = length; i >= 0; i--) {
			oqs_sidh_cln16_sqr_Fp2_cycl(res, one);
			nword = i >> 6;
			bit = 1 & (t[nword] >> (i - (nword << 6)));
			if (bit == 1) {
				oqs_sidh_cln16_fp2mul751_mont(res, y, res);
			}
		}
	}
}

void oqs_sidh_cln16_exp84_Fp2_cycl(const oqs_sidh_cln16_f2elm_t y, uint64_t *t, const oqs_sidh_cln16_felm_t one, oqs_sidh_cln16_f2elm_t res) { // Exponentiation y^t via square and multiply in the cyclotomic group. Exponent t is 84 bits at most
	                                                                                                                                           // This function uses 64-bit digits for representing exponents.
	unsigned int nword, bit, nwords = 2;
	int i;

	oqs_sidh_cln16_fp2zero751(res);
	oqs_sidh_cln16_fpcopy751(one, res[0]); // res = 1

	if (!is_zero((digit_t *) t, nwords)) { // Is t = 0?
		for (i = 83; i >= 0; i--) {
			oqs_sidh_cln16_sqr_Fp2_cycl(res, one);
			nword = i >> 6;
			bit = 1 & (t[nword] >> (i - (nword << 6)));
			if (bit == 1) {
				oqs_sidh_cln16_fp2mul751_mont(res, y, res);
			}
		}
	}
}

bool oqs_sidh_cln16_is_cube_Fp2(oqs_sidh_cln16_f2elm_t u, PCurveIsogenyStruct CurveIsogeny) { // Check if a GF(p751^2) element is a cube.
	oqs_sidh_cln16_f2elm_t v;
	oqs_sidh_cln16_felm_t t0, zero = {0}, one = {0};
	unsigned int e;

	oqs_sidh_cln16_fpcopy751(CurveIsogeny->Montgomery_one, one);
	oqs_sidh_cln16_fpsqr751_mont(u[0], v[0]);       // v0 = u0^2
	oqs_sidh_cln16_fpsqr751_mont(u[1], v[1]);       // v1 = u1^2
	oqs_sidh_cln16_fpadd751(v[0], v[1], t0);        // t0 = v0+v1
	oqs_sidh_cln16_fpinv751_mont_bingcd(t0);        // Fp inversion with binary Euclid
	oqs_sidh_cln16_fpsub751(v[0], v[1], v[0]);      // v0 = v0-v1
	oqs_sidh_cln16_fpmul751_mont(u[0], u[1], v[1]); // v1 = u0*u1
	oqs_sidh_cln16_fpadd751(v[1], v[1], v[1]);      // v1 = 2*v1
	oqs_sidh_cln16_fpneg751(v[1]);                  // v1 = -v1
	oqs_sidh_cln16_fpmul751_mont(v[0], t0, v[0]);   // v0 = v0*t0
	oqs_sidh_cln16_fpmul751_mont(v[1], t0, v[1]);   // v1 = v1*t0

	for (e = 0; e < 372; e++) {
		oqs_sidh_cln16_sqr_Fp2_cycl(v, one);
	}

	for (e = 0; e < 238; e++) {
		oqs_sidh_cln16_cube_Fp2_cycl(v, one);
	}

	oqs_sidh_cln16_fp2correction751(v);

	if (oqs_sidh_cln16_fpequal751_non_constant_time(v[0], one) == true && oqs_sidh_cln16_fpequal751_non_constant_time(v[1], zero) == true) { // v == 1?
		return true;
	} else {
		return false;
	}
}

void oqs_sidh_cln16_multiply(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords) { // Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
	                                                                                                      // NOTE: a and c CANNOT be the same variable!
	unsigned int i, j;
	digit_t t = 0, u = 0, v = 0, UV[2];
	unsigned int carry = 0;

	for (i = 0; i < nwords; i++) {
		for (j = 0; j <= i; j++) {
			MUL(a[j], b[i - j], UV + 1, UV[0]);
			ADDC(0, UV[0], v, carry, v);
			ADDC(carry, UV[1], u, carry, u);
			t += carry;
		}
		c[i] = v;
		v = u;
		u = t;
		t = 0;
	}

	for (i = nwords; i < 2 * nwords - 1; i++) {
		for (j = i - nwords + 1; j < nwords; j++) {
			MUL(a[j], b[i - j], UV + 1, UV[0]);
			ADDC(0, UV[0], v, carry, v);
			ADDC(carry, UV[1], u, carry, u);
			t += carry;
		}
		c[i] = v;
		v = u;
		u = t;
		t = 0;
	}
	c[2 * nwords - 1] = v;
}

void oqs_sidh_cln16_Montgomery_multiply_mod_order(const digit_t *ma, const digit_t *mb, digit_t *mc, const digit_t *order, const digit_t *Montgomery_rprime) { // Montgomery multiplication modulo the group order, mc = ma*mb*r' mod order, where ma,mb,mc in [0, order-1].
	                                                                                                                                                           // ma, mb and mc are assumed to be in Montgomery representation.
	                                                                                                                                                           // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is the value "Montgomery_rprime", where r is the order.
	unsigned int i, cout = 0, bout = 0;
	digit_t mask, P[2 * SIDH_NWORDS_ORDER], Q[2 * SIDH_NWORDS_ORDER], temp[2 * SIDH_NWORDS_ORDER];

	oqs_sidh_cln16_multiply(ma, mb, P, SIDH_NWORDS_ORDER);               // P = ma * mb
	oqs_sidh_cln16_multiply(P, Montgomery_rprime, Q, SIDH_NWORDS_ORDER); // Q = P * r' mod 2^(log_2(r))
	oqs_sidh_cln16_multiply(Q, order, temp, SIDH_NWORDS_ORDER);          // temp = Q * r
	cout = oqs_sidh_cln16_mp_add(P, temp, temp, 2 * SIDH_NWORDS_ORDER);  // (cout, temp) = P + Q * r

	for (i = 0; i < SIDH_NWORDS_ORDER; i++) { // (cout, mc) = (P + Q * r)/2^(log_2(r))
		mc[i] = temp[SIDH_NWORDS_ORDER + i];
	}

	// Final, constant-time subtraction
	bout = oqs_sidh_cln16_mp_sub(mc, order, mc, SIDH_NWORDS_ORDER); // (cout, mc) = (cout, mc) - r
	mask = (digit_t) cout - (digit_t) bout;                         // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F

	for (i = 0; i < SIDH_NWORDS_ORDER; i++) { // temp = mask & r
		temp[i] = (order[i] & mask);
	}
	oqs_sidh_cln16_mp_add(mc, temp, mc, SIDH_NWORDS_ORDER); //  mc = mc + (mask & r)
}

void oqs_sidh_cln16_Montgomery_inversion_mod_order(const digit_t *ma, digit_t *mc, const digit_t *order, const digit_t *Montgomery_rprime) { // (Non-constant time) Montgomery inversion modulo the curve order using a^(-1) = a^(order-2) mod order
	                                                                                                                                         // This function uses the sliding-window method.
	sdigit_t i = 384;
	unsigned int j, nwords = SIDH_NWORDS_ORDER, nbytes = (unsigned int) i / 8;
	digit_t temp, bit = 0, count, mod2, k_EXPON = 5; // Fixing parameter k to 5 for the sliding windows method
	digit_t modulus2[SIDH_NWORDS_ORDER] = {0}, npoints = 16;
	digit_t input_a[SIDH_NWORDS_ORDER];
	digit_t table[16][SIDH_NWORDS_ORDER];                    // Fixing the number of precomputed elements to 16 (assuming k = 5)
	digit_t mask = (digit_t) 1 << (sizeof(digit_t) * 8 - 1); // 0x800...000
	digit_t mask2 = ~((digit_t)(-1) >> k_EXPON);             // 0xF800...000, assuming k = 5

	// SECURITY NOTE: this function does not run in constant time.

	modulus2[0] = 2;
	oqs_sidh_cln16_mp_sub(order, modulus2, modulus2, nwords); // modulus-2

	// Precomputation stage
	memmove((unsigned char *) &table[0], (unsigned char *) ma, nbytes);                      // table[0] = ma
	oqs_sidh_cln16_Montgomery_multiply_mod_order(ma, ma, input_a, order, Montgomery_rprime); // ma^2
	for (j = 0; j < npoints - 1; j++) {
		oqs_sidh_cln16_Montgomery_multiply_mod_order(table[j], input_a, table[j + 1], order, Montgomery_rprime); // table[j+1] = table[j] * ma^2
	}

	while (bit != 1) { // Shift (modulus-2) to the left until getting first bit 1
		i--;
		temp = 0;
		for (j = 0; j < nwords; j++) {
			bit = (modulus2[j] & mask) >> (sizeof(digit_t) * 8 - 1);
			modulus2[j] = (modulus2[j] << 1) | temp;
			temp = bit;
		}
	}

	// Evaluation stage
	memmove((unsigned char *) mc, (unsigned char *) ma, nbytes);
	bit = (modulus2[nwords - 1] & mask) >> (sizeof(digit_t) * 8 - 1);
	while (i > 0) {
		if (bit == 0) {                                                                         // Square accumulated value because bit = 0 and shift (modulus-2) one bit to the left
			oqs_sidh_cln16_Montgomery_multiply_mod_order(mc, mc, mc, order, Montgomery_rprime); // mc = mc^2
			i--;
			for (j = (nwords - 1); j > 0; j--) {
				SHIFTL(modulus2[j], modulus2[j - 1], 1, modulus2[j], RADIX);
			}
			modulus2[0] = modulus2[0] << 1;
		} else { // "temp" will store the longest odd bitstring with "count" bits s.t. temp <= 2^k - 1
			count = k_EXPON;
			temp = (modulus2[nwords - 1] & mask2) >> (sizeof(digit_t) * 8 - k_EXPON); // Extracting next k bits to the left
			mod2 = temp & 1;
			while (mod2 == 0) { // if even then shift to the right and adjust count
				temp = (temp >> 1);
				mod2 = temp & 1;
				count--;
			}
			for (j = 0; j < count; j++) { // mc = mc^count
				oqs_sidh_cln16_Montgomery_multiply_mod_order(mc, mc, mc, order, Montgomery_rprime);
			}
			oqs_sidh_cln16_Montgomery_multiply_mod_order(mc, table[(temp - 1) >> 1], mc, order, Montgomery_rprime); // mc = mc * table[(temp-1)/2]
			i = i - count;

			for (j = (nwords - 1); j > 0; j--) { // Shift (modulus-2) "count" bits to the left
				SHIFTL(modulus2[j], modulus2[j - 1], count, modulus2[j], RADIX);
			}
			modulus2[0] = modulus2[0] << count;
		}
		bit = (modulus2[nwords - 1] & mask) >> (sizeof(digit_t) * 8 - 1);
	}
}

static __inline unsigned int is_zero_mod_order(const digit_t *x) { // Is x = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise
	                                                               // SECURITY NOTE: This function does not run in constant time.
	unsigned int i;

	for (i = 0; i < SIDH_NWORDS_ORDER; i++) {
		if (x[i] != 0)
			return false;
	}
	return true;
}

static __inline unsigned int is_even_mod_order(const digit_t *x) { // Is x even? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
	return (unsigned int) ((x[0] & 1) ^ 1);
}

static __inline unsigned int is_lt_mod_order(const digit_t *x, const digit_t *y) { // Is x < y? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
	                                                                               // SECURITY NOTE: This function does not run in constant time.
	int i;

	for (i = SIDH_NWORDS_ORDER - 1; i >= 0; i--) {
		if (x[i] < y[i]) {
			return true;
		} else if (x[i] > y[i]) {
			return false;
		}
	}
	return false;
}

static __inline void Montgomery_inversion_mod_order_bingcd_partial(const digit_t *a, digit_t *x1, unsigned int *k, const digit_t *order) { // Partial Montgomery inversion modulo order.
	digit_t u[SIDH_NWORDS_ORDER], v[SIDH_NWORDS_ORDER], x2[SIDH_NWORDS_ORDER] = {0};
	unsigned int cwords; // number of words necessary for x1, x2

	oqs_sidh_cln16_copy_words(a, u, SIDH_NWORDS_ORDER);
	oqs_sidh_cln16_copy_words(order, v, SIDH_NWORDS_ORDER);
	oqs_sidh_cln16_copy_words(x2, x1, SIDH_NWORDS_ORDER);
	x1[0] = 1;
	*k = 0;

	while (!is_zero_mod_order(v)) {
		cwords = ((*k + 1) / RADIX) + 1;
		if ((cwords < SIDH_NWORDS_ORDER)) {
			if (is_even_mod_order(v)) {
				oqs_sidh_cln16_mp_shiftr1(v, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftl1(x1, cwords);
			} else if (is_even_mod_order(u)) {
				oqs_sidh_cln16_mp_shiftr1(u, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftl1(x2, cwords);
			} else if (!is_lt_mod_order(v, u)) {
				oqs_sidh_cln16_mp_sub(v, u, v, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftr1(v, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_add(x1, x2, x2, cwords);
				oqs_sidh_cln16_mp_shiftl1(x1, cwords);
			} else {
				oqs_sidh_cln16_mp_sub(u, v, u, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftr1(u, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_add(x1, x2, x1, cwords);
				oqs_sidh_cln16_mp_shiftl1(x2, cwords);
			}
		} else {
			if (is_even_mod_order(v)) {
				oqs_sidh_cln16_mp_shiftr1(v, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftl1(x1, SIDH_NWORDS_ORDER);
			} else if (is_even_mod_order(u)) {
				oqs_sidh_cln16_mp_shiftr1(u, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftl1(x2, SIDH_NWORDS_ORDER);
			} else if (!is_lt_mod_order(v, u)) {
				oqs_sidh_cln16_mp_sub(v, u, v, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftr1(v, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_add(x1, x2, x2, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftl1(x1, SIDH_NWORDS_ORDER);
			} else {
				oqs_sidh_cln16_mp_sub(u, v, u, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftr1(u, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_add(x1, x2, x1, SIDH_NWORDS_ORDER);
				oqs_sidh_cln16_mp_shiftl1(x2, SIDH_NWORDS_ORDER);
			}
		}
		*k += 1;
	}

	if (is_lt_mod_order(order, x1)) {
		oqs_sidh_cln16_mp_sub(x1, order, x1, SIDH_NWORDS_ORDER);
	}
}

void oqs_sidh_cln16_Montgomery_inversion_mod_order_bingcd(const digit_t *a, digit_t *c, const digit_t *order, const digit_t *Montgomery_rprime, const digit_t *Montgomery_Rprime) { // Montgomery inversion modulo order, a = a^(-1)*R mod order.
	digit_t x[SIDH_NWORDS_ORDER], t[SIDH_NWORDS_ORDER];
	unsigned int k;

	Montgomery_inversion_mod_order_bingcd_partial(a, x, &k, order);
	if (k < 384) {
		oqs_sidh_cln16_Montgomery_multiply_mod_order(x, Montgomery_Rprime, x, order, Montgomery_rprime);
		k += 384;
	}
	oqs_sidh_cln16_Montgomery_multiply_mod_order(x, Montgomery_Rprime, x, order, Montgomery_rprime);
	power2_setup(t, 2 * 384 - k, SIDH_NWORDS_ORDER);
	oqs_sidh_cln16_Montgomery_multiply_mod_order(x, t, c, order, Montgomery_rprime);
}

void oqs_sidh_cln16_to_Montgomery_mod_order(const digit_t *a, digit_t *mc, const digit_t *order, const digit_t *Montgomery_rprime, const digit_t *Montgomery_Rprime) { // Conversion of elements in Z_r to Montgomery representation, where the order r is up to 384 bits.

	oqs_sidh_cln16_Montgomery_multiply_mod_order(a, Montgomery_Rprime, mc, order, Montgomery_rprime);
}

void oqs_sidh_cln16_from_Montgomery_mod_order(const digit_t *ma, digit_t *c, const digit_t *order, const digit_t *Montgomery_rprime) { // Conversion of elements in Z_r from Montgomery to standard representation, where the order is up to 384 bits.
	digit_t one[SIDH_NWORDS_ORDER] = {0};
	one[0] = 1;

	oqs_sidh_cln16_Montgomery_multiply_mod_order(ma, one, c, order, Montgomery_rprime);
}

void oqs_sidh_cln16_inv_mod_orderA(const digit_t *a, digit_t *c) { // Inversion modulo an even integer of the form 2^m.
	                                                               // Algorithm 3: Explicit Quadratic Modular inverse modulo 2^m from Dumas '12: http://arxiv.org/pdf/1209.6626.pdf
	                                                               // NOTE: This function is hardwired for the current parameters using 2^372.
	unsigned int i, f, s = 0;
	digit_t am1[SIDH_NWORDS_ORDER] = {0};
	digit_t tmp1[SIDH_NWORDS_ORDER] = {0};
	digit_t tmp2[2 * SIDH_NWORDS_ORDER] = {0};
	digit_t one[SIDH_NWORDS_ORDER] = {0};
	digit_t order[SIDH_NWORDS_ORDER] = {0};
	digit_t mask = (digit_t)(-1) >> 12;
	bool equal = true;

	order[SIDH_NWORDS_ORDER - 1] = (digit_t) 1 << (sizeof(digit_t) * 8 - 12); // Load most significant digit of Alice's order
	one[0] = 1;

	for (i = 0; i < SIDH_NWORDS_ORDER; i++) {
		if (a[i] != one[0])
			equal = false;
	}
	if (equal) {
		oqs_sidh_cln16_copy_words(a, c, SIDH_NWORDS_ORDER);
	} else {
		oqs_sidh_cln16_mp_sub(a, one, am1, SIDH_NWORDS_ORDER); // am1 = a-1
		oqs_sidh_cln16_mp_sub(order, am1, c, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_mp_add(c, one, c, SIDH_NWORDS_ORDER); // c = 2^m - a + 2

		oqs_sidh_cln16_copy_words(am1, tmp1, SIDH_NWORDS_ORDER);
		while ((tmp1[0] & (digit_t) 1) == 0) {
			s += 1;
			oqs_sidh_cln16_mp_shiftr1(tmp1, SIDH_NWORDS_ORDER);
		}

		f = 372 / s;
		for (i = 1; i < f; i <<= 1) {
			oqs_sidh_cln16_multiply(am1, am1, tmp2, SIDH_NWORDS_ORDER); // tmp2 = am1^2
			oqs_sidh_cln16_copy_words(tmp2, am1, SIDH_NWORDS_ORDER);
			am1[SIDH_NWORDS_ORDER - 1] &= mask;                        // am1 = tmp2 mod 2^e
			oqs_sidh_cln16_mp_add(am1, one, tmp1, SIDH_NWORDS_ORDER);  // tmp1 = am1 + 1
			tmp1[SIDH_NWORDS_ORDER - 1] &= mask;                       // mod 2^e
			oqs_sidh_cln16_multiply(c, tmp1, tmp2, SIDH_NWORDS_ORDER); // c = c*tmp1
			oqs_sidh_cln16_copy_words(tmp2, c, SIDH_NWORDS_ORDER);
			c[SIDH_NWORDS_ORDER - 1] &= mask; // mod 2^e
		}
	}
}
