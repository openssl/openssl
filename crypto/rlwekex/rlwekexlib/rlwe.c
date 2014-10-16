/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "fft.h"
#include "rlwe.h"

#include "rlwe_table.h"

#define setbit(a,x) ((a)[(x)/64] |= (((uint64_t) 1) << (uint64_t) ((x)%64)))
#define getbit(a,x) (((a)[(x)/64] >> (uint64_t) ((x)%64)) & 1)
#define clearbit(a,x) ((a)[(x)/64] &= ((~((uint64_t) 0)) - (((uint64_t) 1) << (uint64_t) ((x)%64))))

#define RANDOM192(c) c[0] = RANDOM64; c[1] = RANDOM64; c[2] = RANDOM64

/* Returns 0 if a >= b
 * Returns 1 if a < b
 * Where a and b are both 3-limb 64-bit integers.
 * This function runs in constant time.
 */
static int cmplt_ct(uint64_t *a, uint64_t *b) {
	int m;
	m = (a[0] >= b[0]);
	m = ((a[1] >= b[1]) && (!(a[1] == b[1]) || m));
	m = ((a[2] >= b[2]) && (!(a[2] == b[2]) || m));
	return (m == 0);
}

static uint32_t single_sample(uint64_t *in) {
	uint32_t lower_index = 0, this_index = 32, upper_index = 64;
	int i;
	for (i = 0; i < 6; i++) {
		if (cmplt_ct(in, rlwe_table[this_index])) {
			upper_index = this_index;
		} else {
			lower_index = this_index;
		}
		this_index = (lower_index + upper_index) / 2;
	}
	return lower_index;
}

/* Constant time version. */
static uint32_t single_sample_ct(uint64_t *in) {
	uint32_t index = 0, i;

	for (i = 0; i < 52; i++) {
		uint32_t mask1, mask2;
		mask1 = cmplt_ct(in, rlwe_table[i]);
		mask1 = (uint32_t) (0 - (int32_t) mask1);
		mask2 = (~mask1);
		index = ((index & mask1) | (i & mask2));
	}
	return index;
}

void sample_ct(uint32_t *s) {
	RANDOM_VARS
	int i, j;
	for (i = 0; i < 16; i++) {
		uint64_t r = RANDOM64;
		for (j = 0; j < 64; j++) {
			uint64_t rnd[3];
			int32_t m;
			uint32_t t;
			RANDOM192(rnd);
			m = (r & 1);
			r >>= 1;
			m = 2 * m - 1;
			// use the constant time version single_sample
			s[i * 64 + j] = single_sample_ct(rnd);
			t = 0xFFFFFFFF - s[i * 64 + j];
			s[i * 64 + j] = ((t & (uint32_t) m) | (s[i * 64 + j] & (~((uint32_t) m))));
		}
	}
}

void sample(uint32_t *s) {
	RANDOM_VARS
	int i, j;
	for (i = 0; i < 16; i++) {
		uint64_t r = RANDOM64;
		for (j = 0; j < 64; j++) {
			uint64_t rnd[3];
			int32_t m;
			RANDOM192(rnd);
			m = (r & 1);
			r >>= 1;
			m = 2 * m - 1;
			s[i * 64 + j] = single_sample(rnd);
			if (m == -1) {
				s[i * 64 + j] = 0xFFFFFFFF - s[i * 64 + j];
			}
		}
	}
}

void round2(uint64_t *out, const uint32_t *in) {
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

/* Constant time version. */
void round2_ct(uint64_t *out, const uint32_t *in) {
	int i;
	memset(out, 0, 128);
	for (i = 0; i < 1024; i++) {
		uint32_t b = (in[i] >= 1073741824 && in[i] <= 3221225471);
		out[i / 64] |= (((uint64_t) b) << (uint64_t) (i % 64));
	}
}

/* We assume that e contains two random bits in the two
 * least significant positions. */
uint64_t dbl(const uint32_t in, int32_t e) {
	// sample uniformly from [-1, 0, 0, 1]
	// Hence, 0 is sampled with twice the probability of 1
	e = (((e >> 1) & 1) - ((int32_t) (e & 1)));
	return (uint64_t) ((((uint64_t) in) << (uint64_t) 1) - e);
}

void crossround2(uint64_t *out, const uint32_t *in) {
	int i, j;
	RANDOM_VARS
	// out should have enough space for 1024-bits
	memset(out, 0, 128);

	for (i = 0; i < 64; i++) {
		uint32_t e = RANDOM32;
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

void crossround2_ct(uint64_t *out, const uint32_t *in) {
	RANDOM_VARS
	int i, j;
	memset(out, 0, 128);
	for (i = 0; i < 64; i++) {
		uint32_t e = RANDOM32;
		for (j = 0; j < 16; j++) {
			uint64_t dd;
			uint32_t b;
			dd = dbl(in[i * 16 + j], (int32_t) e);
			e >>= 2;
			b = ((dd >= (uint64_t) 2147483648 && dd <= (uint64_t) 4294967295) || (dd >= (uint64_t) 6442450942 && dd <= (uint64_t) 8589934590));
			out[(i * 16 + j) / 64] |= (((uint64_t) b) << (uint64_t) ((i * 16 + j) % 64));
		}
	}
}

void rec(uint64_t *out, const uint32_t *w, const uint64_t *b) {
	int i;

	// out should have enough space for 1024-bits
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

void rec_ct(uint64_t *out, const uint32_t *w, const uint64_t *b) {
	int i;
	memset(out, 0, 128);
	for (i = 0; i < 1024; i++) {
		uint64_t coswi;
		uint32_t B;
		coswi = (((uint64_t) w[i]) << (uint64_t) 1);
		B = ((getbit(b, i) == 0 && coswi >= (uint64_t) 3221225472 && coswi <= (uint64_t) 7516192766) || (getbit(b, i) == 1 && coswi >= (uint64_t) 1073741824 && coswi <= (uint64_t) 5368709118));
		out[i / 64] |= (((uint64_t) B) << (uint64_t) (i % 64));
	}
}

void key_gen(uint32_t *out, const uint32_t *a, const uint32_t *s, const uint32_t *e, FFT_CTX *ctx) {
	FFT_mul(out, a, s, ctx);
	FFT_add(out, out, e);
}

