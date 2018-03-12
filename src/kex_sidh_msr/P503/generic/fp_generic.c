/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: portable modular arithmetic for P503
*********************************************************************************************/

/* OQS note: not needed since this file is #included in another source file
#include "../P503_internal.h"

// Global constants
extern const uint64_t p503[NWORDS_FIELD];
extern const uint64_t p503p1[NWORDS_FIELD];
extern const uint64_t p503x2[NWORDS_FIELD];
*/

__inline void fpadd503(const digit_t *a, const digit_t *b, digit_t *c) { // Modular addition, c = a+b mod p503.
	                                                                                      // Inputs: a, b in [0, 2*p503-1]
	                                                                                      // Output: c in [0, 2*p503-1]
	unsigned int i, carry = 0;
	digit_t mask;

	for (i = 0; i < NWORDS_FIELD; i++) {
		ADDC(carry, a[i], b[i], carry, c[i]);
	}

	carry = 0;
	for (i = 0; i < NWORDS_FIELD; i++) {
		SUBC(carry, c[i], ((digit_t *) p503x2)[i], carry, c[i]);
	}
	mask = 0 - (digit_t) carry;

	carry = 0;
	for (i = 0; i < NWORDS_FIELD; i++) {
		ADDC(carry, c[i], ((digit_t *) p503x2)[i] & mask, carry, c[i]);
	}
}

__inline void fpsub503(const digit_t *a, const digit_t *b, digit_t *c) { // Modular subtraction, c = a-b mod p503.
	                                                                                      // Inputs: a, b in [0, 2*p503-1]
	                                                                                      // Output: c in [0, 2*p503-1]
	unsigned int i, borrow = 0;
	digit_t mask;

	for (i = 0; i < NWORDS_FIELD; i++) {
		SUBC(borrow, a[i], b[i], borrow, c[i]);
	}
	mask = 0 - (digit_t) borrow;

	borrow = 0;
	for (i = 0; i < NWORDS_FIELD; i++) {
		ADDC(borrow, c[i], ((digit_t *) p503x2)[i] & mask, borrow, c[i]);
	}
}

__inline void fpneg503(digit_t *a) { // Modular negation, a = -a mod p503.
	                                                  // Input/output: a in [0, 2*p503-1]
	unsigned int i, borrow = 0;

	for (i = 0; i < NWORDS_FIELD; i++) {
		SUBC(borrow, ((digit_t *) p503x2)[i], a[i], borrow, a[i]);
	}
}

void fpdiv2_503(const digit_t *a, digit_t *c) { // Modular division by two, c = a/2 mod p503.
	                                            // Input : a in [0, 2*p503-1]
	                                            // Output: c in [0, 2*p503-1]
	unsigned int i, carry = 0;
	digit_t mask;

	mask = 0 - (digit_t)(a[0] & 1); // If a is odd compute a+p503
	for (i = 0; i < NWORDS_FIELD; i++) {
		ADDC(carry, a[i], ((digit_t *) p503)[i] & mask, carry, c[i]);
	}

	mp_shiftr1(c, NWORDS_FIELD);
}

void fpcorrection503(digit_t *a) { // Modular correction to reduce field element a in [0, 2*p503-1] to [0, p503-1].
	unsigned int i, borrow = 0;
	digit_t mask;

	for (i = 0; i < NWORDS_FIELD; i++) {
		SUBC(borrow, a[i], ((digit_t *) p503)[i], borrow, a[i]);
	}
	mask = 0 - (digit_t) borrow;

	borrow = 0;
	for (i = 0; i < NWORDS_FIELD; i++) {
		ADDC(borrow, a[i], ((digit_t *) p503)[i] & mask, borrow, a[i]);
	}
}

void digit_x_digit(const digit_t a, const digit_t b, digit_t *c) { // Digit multiplication, digit * digit -> 2-digit result
	register digit_t al, ah, bl, bh, temp;
	digit_t albl, albh, ahbl, ahbh, res1, res2, res3, carry;
	digit_t mask_low = (digit_t)(-1) >> (sizeof(digit_t) * 4), mask_high = (digit_t)(-1) << (sizeof(digit_t) * 4);

	al = a & mask_low;               // Low part
	ah = a >> (sizeof(digit_t) * 4); // High part
	bl = b & mask_low;
	bh = b >> (sizeof(digit_t) * 4);

	albl = al * bl;
	albh = al * bh;
	ahbl = ah * bl;
	ahbh = ah * bh;
	c[0] = albl & mask_low; // C00

	res1 = albl >> (sizeof(digit_t) * 4);
	res2 = ahbl & mask_low;
	res3 = albh & mask_low;
	temp = res1 + res2 + res3;
	carry = temp >> (sizeof(digit_t) * 4);
	c[0] ^= temp << (sizeof(digit_t) * 4); // C01

	res1 = ahbl >> (sizeof(digit_t) * 4);
	res2 = albh >> (sizeof(digit_t) * 4);
	res3 = ahbh & mask_low;
	temp = res1 + res2 + res3 + carry;
	c[1] = temp & mask_low; // C10
	carry = temp & mask_high;
	c[1] ^= (ahbh & mask_high) + carry; // C11
}

void mp_mul(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords) { // Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
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

void rdc_mont(const digit_t *ma, digit_t *mc) { // Efficient Montgomery reduction using comba and exploiting the special form of the prime p503.
	                                            // mc = ma*R^-1 mod p503x2, where R = 2^512.
	                                            // If ma < 2^512*p503, the output mc is in the range [0, 2*p503-1].
	                                            // ma is assumed to be in Montgomery representation.
	unsigned int i, j, carry, count = p503_ZERO_WORDS;
	digit_t UV[2], t = 0, u = 0, v = 0;

	for (i = 0; i < NWORDS_FIELD; i++) {
		mc[i] = 0;
	}

	for (i = 0; i < NWORDS_FIELD; i++) {
		for (j = 0; j < i; j++) {
			if (j < (i - p503_ZERO_WORDS + 1)) {
				MUL(mc[j], ((digit_t *) p503p1)[i - j], UV + 1, UV[0]);
				ADDC(0, UV[0], v, carry, v);
				ADDC(carry, UV[1], u, carry, u);
				t += carry;
			}
		}
		ADDC(0, v, ma[i], carry, v);
		ADDC(carry, u, 0, carry, u);
		t += carry;
		mc[i] = v;
		v = u;
		u = t;
		t = 0;
	}

	for (i = NWORDS_FIELD; i < 2 * NWORDS_FIELD - 1; i++) {
		if (count > 0) {
			count -= 1;
		}
		for (j = i - NWORDS_FIELD + 1; j < NWORDS_FIELD; j++) {
			if (j < (NWORDS_FIELD - count)) {
				MUL(mc[j], ((digit_t *) p503p1)[i - j], UV + 1, UV[0]);
				ADDC(0, UV[0], v, carry, v);
				ADDC(carry, UV[1], u, carry, u);
				t += carry;
			}
		}
		ADDC(0, v, ma[i], carry, v);
		ADDC(carry, u, 0, carry, u);
		t += carry;
		mc[i - NWORDS_FIELD] = v;
		v = u;
		u = t;
		t = 0;
	}
	ADDC(0, v, ma[2 * NWORDS_FIELD - 1], carry, v);
	mc[NWORDS_FIELD - 1] = v;
}
