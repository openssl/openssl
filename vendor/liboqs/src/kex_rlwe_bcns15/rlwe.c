/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#if defined(_WIN32)
#pragma warning(disable : 4146 4244 4267)
#endif

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/rand.h>

#include "local.h"

#include "rlwe_table.h"

#define setbit(a, x) ((a)[(x) / 64] |= (((uint64_t) 1) << (uint64_t)((x) % 64)))
#define getbit(a, x) (((a)[(x) / 64] >> (uint64_t)((x) % 64)) & 1)
#define clearbit(a, x) ((a)[(x) / 64] &= ((~((uint64_t) 0)) - (((uint64_t) 1) << (uint64_t)((x) % 64))))

/* Auxiliary functions for constant-time comparison */

/*
 * Returns 1 if x != 0
 * Returns 0 if x == 0
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_isnonzero_u64(uint64_t x) {
	return (x | -x) >> 63;
}

/*
 * Returns 1 if x != y
 * Returns 0 if x == y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_ne_u64(uint64_t x, uint64_t y) {
	return ((x - y) | (y - x)) >> 63;
}

/*
 * Returns 1 if x == y
 * Returns 0 if x != y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_eq_u64(uint64_t x, uint64_t y) {
	return 1 ^ ct_ne_u64(x, y);
}

/* Returns 1 if x < y
 * Returns 0 if x >= y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_lt_u64(uint64_t x, uint64_t y) {
	return (x ^ ((x ^ y) | ((x - y) ^ y))) >> 63;
}

/*
 * Returns 1 if x > y
 * Returns 0 if x <= y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_gt_u64(uint64_t x, uint64_t y) {
	return ct_lt_u64(y, x);
}

/*
 * Returns 1 if x <= y
 * Returns 0 if x > y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_le_u64(uint64_t x, uint64_t y) {
	return 1 ^ ct_gt_u64(x, y);
}

/*
 * Returns 1 if x >= y
 * Returns 0 if x < y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_ge_u64(uint64_t x, uint64_t y) {
	return 1 ^ ct_lt_u64(x, y);
}

/* Returns 0xFFFF..FFFF if bit != 0
 * Returns            0 if bit == 0
 */
static uint64_t ct_mask_u64(uint64_t bit) {
	return 0 - (uint64_t) ct_isnonzero_u64(bit);
}

/* Conditionally return x or y depending on whether bit is set
 * Equivalent to: return bit ? x : y
 * x and y are arbitrary 64-bit unsigned integers
 * bit must be either 0 or 1.
 */
static uint64_t ct_select_u64(uint64_t x, uint64_t y, uint64_t bit) {
	uint64_t m = ct_mask_u64(bit);
	return (x & m) | (y & ~m);
}

/* Returns 0 if a >= b
 * Returns 1 if a < b
 * Where a and b are both 3-limb 64-bit integers.
 * This function runs in constant time.
 */
static int cmplt_ct(uint64_t *a, uint64_t *b) {
	uint64_t r = 0; /* result */
	uint64_t m = 0; /* mask   */
	int i;
	for (i = 2; i >= 0; --i) {
		r |= ct_lt_u64(a[i], b[i]) & ~m;
		m |= ct_mask_u64(ct_ne_u64(a[i], b[i])); /* stop when a[i] != b[i] */
	}
	return r & 1;
}

static uint32_t single_sample(uint64_t *in) {
	size_t i = 0;

	while (cmplt_ct(rlwe_table[i], in)) { // ~3.5 comparisons in expectation
		i++;
	}

	return i;
}

/* We assume that e contains two random bits in the two
 * least significant positions. */
static uint64_t dbl(const uint32_t in, int32_t e) {
	// sample uniformly from [-1, 0, 0, 1]
	// Hence, 0 is sampled with twice the probability of 1
	e = (((e >> 1) & 1) - ((int32_t)(e & 1)));
	return (uint64_t)((((uint64_t) in) << (uint64_t) 1) - e);
}

/* Constant time version. */
static uint32_t single_sample_ct(uint64_t *in) {
	uint32_t index = 0, i;
	for (i = 0; i < 52; i++) {
		index = ct_select_u64(index, i + 1, cmplt_ct(in, rlwe_table[i]));
	}
	return index;
}

void oqs_kex_rlwe_bcns15_sample_ct(uint32_t s[1024], OQS_RAND *rand) {
	int i, j;
	for (i = 0; i < 16; i++) {
		uint64_t r = rand->rand_64(rand);
		for (j = 0; j < 64; j++) {
			uint64_t rnd[3];
			uint32_t m;
			uint32_t t;
			rnd[0] = rand->rand_64(rand);
			rnd[1] = rand->rand_64(rand);
			rnd[2] = rand->rand_64(rand);
			m = (r & 1);
			r >>= 1;
			// use the constant time version single_sample
			s[i * 64 + j] = single_sample_ct(rnd);
			t = (uint32_t) -s[i * 64 + j];
			s[i * 64 + j] = ct_select_u64(t, s[i * 64 + j], ct_eq_u64(m, 0));
		}
	}
}

void oqs_kex_rlwe_bcns15_round2_ct(uint64_t out[16], const uint32_t in[1024]) {
	int i;
	memset(out, 0, 128);
	for (i = 0; i < 1024; i++) {
		uint64_t b = ct_ge_u64(in[i], 1073741824ULL) &
		             ct_le_u64(in[i], 3221225471ULL);
		out[i / 64] |= b << (uint64_t)(i % 64);
	}
}

void oqs_kex_rlwe_bcns15_crossround2_ct(uint64_t out[16], const uint32_t in[1024], OQS_RAND *rand) {
	int i, j;
	memset(out, 0, 128);
	for (i = 0; i < 64; i++) {
		uint32_t e = rand->rand_32(rand);
		for (j = 0; j < 16; j++) {
			uint64_t dd;
			uint64_t b;
			dd = dbl(in[i * 16 + j], (int32_t) e);
			e >>= 2;
			b = (ct_ge_u64(dd, 2147483648ULL) & ct_le_u64(dd, 4294967295ULL)) |
			    (ct_ge_u64(dd, 6442450942ULL) & ct_le_u64(dd, 8589934590ULL));
			out[(i * 16 + j) / 64] |= (b << (uint64_t)((i * 16 + j) % 64));
		}
	}
}

void oqs_kex_rlwe_bcns15_rec_ct(uint64_t out[16], const uint32_t w[1024], const uint64_t b[16]) {
	int i;
	memset(out, 0, 128);
	for (i = 0; i < 1024; i++) {
		uint64_t coswi;
		uint64_t B;
		coswi = (((uint64_t) w[i]) << (uint64_t) 1);
		B = (ct_eq_u64(getbit(b, i), 0) & ct_ge_u64(coswi, 3221225472ULL) &
		     ct_le_u64(coswi, 7516192766ULL)) |
		    (ct_eq_u64(getbit(b, i), 1) & ct_ge_u64(coswi, 1073741824ULL) &
		     ct_le_u64(coswi, 5368709118ULL));
		out[i / 64] |= (B << (uint64_t)(i % 64));
	}
}

void oqs_kex_rlwe_bcns15_sample(uint32_t s[1024], OQS_RAND *rand) {
	int i, j;
	for (i = 0; i < 16; i++) {
		uint64_t r = rand->rand_64(rand);
		for (j = 0; j < 64; j++) {
			uint64_t rnd[3];
			int32_t m;
			rnd[0] = rand->rand_64(rand);
			rnd[1] = rand->rand_64(rand);
			rnd[2] = rand->rand_64(rand);
			m = (r & 1);
			r >>= 1;
			s[i * 64 + j] = single_sample(rnd);
			if (m) {
				s[i * 64 + j] = (uint32_t) -s[i * 64 + j];
			}
		}
	}
}

void oqs_kex_rlwe_bcns15_round2(uint64_t out[16], const uint32_t in[1024]) {
	int i;

	// out should have enough space for 1024-bits
	memset(out, 0, 128);

	//q/4 and 3*q/4
	for (i = 0; i < 1024; i++) {
		if (in[i] >= 1073741824 && in[i] <= 3221225471) {
			setbit(out, i);
		}
	}
}

void oqs_kex_rlwe_bcns15_crossround2(uint64_t out[16], const uint32_t in[1024], OQS_RAND *rand) {
	int i, j;
	// out should have enough space for 1024-bits
	memset(out, 0, 128);

	for (i = 0; i < 64; i++) {
		uint32_t e = rand->rand_32(rand);
		for (j = 0; j < 16; j++) {
			uint64_t dd = dbl(in[i * 16 + j], (int32_t) e);
			e >>= 2;
			//q/2 to q and 3*q/2 to 2*q
			if ((dd >= (uint64_t) 2147483648 && dd <= (uint64_t) 4294967295) || (dd >= (uint64_t) 6442450942 && dd <= (uint64_t) 8589934590)) {
				setbit(out, (i * 16 + j));
			}
		}
	}
}

void oqs_kex_rlwe_bcns15_rec(uint64_t out[16], const uint32_t w[1024], const uint64_t b[16]) {
	int i;

	// out should have enough space for 1024 bits
	memset(out, 0, 128);

	for (i = 0; i < 1024; i++) {
		uint64_t coswi = (((uint64_t) w[i]) << (uint64_t) 1);
		if (getbit(b, i) == 0) {
			//Ceiling(2*3*q/8)..Floor(2*7*q/8)
			if (coswi >= (uint64_t) 3221225472 && coswi <= (uint64_t) 7516192766) {
				setbit(out, i);
			}
		} else {
			// Ceiling(2*q/8)..Floor(2*5*q/8)
			if (coswi >= (uint64_t) 1073741824 && coswi <= (uint64_t) 5368709118) {
				setbit(out, i);
			}
		}
	}
}

void oqs_kex_rlwe_bcns15_a_times_s_plus_e(uint32_t out[1024], const uint32_t a[1024], const uint32_t s[1024], const uint32_t e[1024], struct oqs_kex_rlwe_bcns15_fft_ctx *ctx) {
	oqs_kex_rlwe_bcns15_fft_mul(out, a, s, ctx);
	oqs_kex_rlwe_bcns15_fft_add(out, out, e);
}
