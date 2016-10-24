#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "local.h"

#include <oqs/aes.h>

#define min(x, y) (((x) < (y)) ? (x) : (y))

// [.]_2
void oqs_kex_lwe_frodo_round2(unsigned char *out, uint16_t *in, struct oqs_kex_lwe_frodo_params *params) {
	oqs_kex_lwe_frodo_key_round(in, params->nbar * params->nbar, params->log2_q - params->extracted_bits);
	int i;
	for (i = 0; i < params->nbar * params->nbar; i++) {
		in[i] >>= params->log2_q - params->extracted_bits;  // drop bits that were zeroed out
	}

	// out should have enough space for the key
	oqs_kex_lwe_frodo_pack(out, params->key_bits / 8, in, params->nbar * params->nbar, params->extracted_bits);
}

void oqs_kex_lwe_frodo_crossround2(unsigned char *out, const uint16_t *in, struct oqs_kex_lwe_frodo_params *params) {
	int i;
	// out should have enough space for N_BAR * N_BAR bits
	memset((unsigned char *)out, 0, params->rec_hint_len);

	uint16_t whole = 1 << (params->log2_q - params->extracted_bits);
	uint16_t half = whole >> 1;
	uint16_t mask = whole - 1;

	for (i = 0; i < params->nbar * params->nbar; i++) {
		uint16_t remainder = in[i] & mask;
		out[i / 8] += (remainder >= half) << (i % 8);
	}
}

void oqs_kex_lwe_frodo_reconcile(unsigned char *out, uint16_t *w, const unsigned char *hint, struct oqs_kex_lwe_frodo_params *params) {
	oqs_kex_lwe_frodo_key_round_hints(w, params->nbar * params->nbar, params->log2_q - params->extracted_bits, hint);
	int i;
	for (i = 0; i < params->nbar * params->nbar; i++) {
		w[i] >>= params->log2_q - params->extracted_bits;  // drop bits that were zeroed out
	}
	oqs_kex_lwe_frodo_pack(out, params->key_bits / 8, w, params->nbar * params->nbar, params->extracted_bits);
}

// Generate-and-multiply: generate A row-wise, multiply by s on the right.
int oqs_kex_lwe_frodo_mul_add_as_plus_e_on_the_fly(uint16_t *out, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_frodo_params *params) {
	// A (N x N)
	// s,e (N x N_BAR)
	// out = A * s + e (N x N_BAR)

	int i, j, k;
	int ret = 0;
	uint16_t *a_row = NULL;
	uint16_t *s_transpose = NULL;

	for (i = 0; i < params->n; i++) {
		for (j = 0; j < params->nbar; j++) {
			out[i * params->nbar + j] = e[i * params->nbar + j];
		}
	}

	size_t a_rowlen = params->n * sizeof(int16_t);
	a_row = (uint16_t *) malloc(a_rowlen);
	if (a_row == NULL) {
		goto err;
	}

	// transpose s to store it in the column-major order
	s_transpose = (uint16_t *) malloc(params->nbar * params->n * sizeof(int16_t));
	if (s_transpose == NULL) {
		goto err;
	}

	for (j = 0; j < params->n; j++) {
		for (k = 0; k < params->nbar; k++) {
			s_transpose[k * params->n + j] = s[j * params->nbar + k];
		}
	}

	assert(params->seed_len == 16);
	uint8_t aes_key_schedule[OQS_AES128_SCHEDULE_NUMBYTES];
	OQS_AES128_load_schedule(params->seed, aes_key_schedule);

	for (i = 0; i < params->n; i++) {
		// go through A's rows
		memset(a_row, 0, a_rowlen);
		for (j = 0; j < params->n; j += params->stripe_step) {
			// Loading values in the little-endian order!
			a_row[j] = i;
			a_row[j + 1] = j;
		}

		OQS_AES128_ECB_enc_sch((uint8_t *) a_row, a_rowlen, aes_key_schedule, (uint8_t *) a_row);

		for (k = 0; k < params->nbar; k++) {
			uint16_t sum = 0;
			for (j = 0; j < params->n; j++) {
				// matrix-vector multiplication happens here
				sum += a_row[j] * s_transpose[k * params->n + j];
			}
			out[i * params->nbar + k] += sum;
			out[i * params->nbar + k] %= params->q;
		}
	}

	ret = 1;
	goto cleanup;

err:
	bzero(out, params->nbar * params->n * sizeof(uint16_t));

cleanup:
	if (a_row != NULL) {
		bzero(a_row, a_rowlen);
		free(a_row);
	}

	if (s_transpose != NULL) {
		bzero(s_transpose, params->nbar * params->n * sizeof(int16_t));
		free(s_transpose);
	}

	return ret;
}

// Generate-and-multiply: generate A column-wise, multiply by s' on the left.
int oqs_kex_lwe_frodo_mul_add_sa_plus_e_on_the_fly(uint16_t *out, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_frodo_params *params) {
	// a (N x N)
	// s',e' (N_BAR x N)
	// out = s'a + e' (N_BAR x N)

	int i, j, k, kk;
	int ret = 0;
	uint16_t *a_cols = NULL;
	uint16_t *a_cols_t = NULL;

	for (i = 0; i < params->nbar; i++) {
		for (j = 0; j < params->n; j++) {
			out[i * params->n + j] = e[i * params->n + j];
		}
	}

	size_t a_colslen = params->n * params->stripe_step * sizeof(int16_t);
	// a_cols stores 8 columns of A at a time.
	a_cols = (uint16_t *) malloc(a_colslen);
	a_cols_t = (uint16_t *) malloc(a_colslen);  // a_cols transposed (stored in the column-major order).
	if ((a_cols == NULL) || (a_cols_t == NULL)) {
		goto err;
	}

	assert(params->seed_len == 16);
	uint8_t aes_key_schedule[OQS_AES128_SCHEDULE_NUMBYTES];
	OQS_AES128_load_schedule(params->seed, aes_key_schedule);

	for (kk = 0; kk < params->n; kk += params->stripe_step) {
		// Go through A's columns, 8 (== params->stripe_step) columns at a time.
		memset(a_cols, 0, a_colslen);
		for (i = 0; i < params->n; i++) {
			// Loading values in the little-endian order!
			a_cols[i * params->stripe_step] = i;
			a_cols[i * params->stripe_step + 1] = kk;
		}

		assert(params->seed_len == 16);
		OQS_AES128_ECB_enc_sch((uint8_t *) a_cols, a_colslen, aes_key_schedule, (uint8_t *) a_cols);

		// transpose a_cols to have access to it in the column-major order.
		for (i = 0; i < params->n; i++)
			for (k = 0; k < params->stripe_step; k++) {
				a_cols_t[k * params->n + i] = a_cols[i * params->stripe_step + k];
			}

		for (i = 0; i < params->nbar; i++)
			for (k = 0; k < params->stripe_step; k++) {
				uint16_t sum = 0;
				for (j = 0; j < params->n; j++) {
					sum += s[i * params->n + j] * a_cols_t[k * params->n + j];
				}
				out[i * params->n + kk + k] += sum;
				out[i * params->n + kk + k] %= params->q;
			}
	}

	ret = 1;
	goto cleanup;

err:
	bzero(out, params->nbar * params->n * sizeof(uint16_t));

cleanup:
	if (a_cols != NULL) {
		bzero(a_cols, a_colslen);
		free(a_cols);
	}

	if (a_cols_t != NULL) {
		bzero(a_cols_t, a_colslen);
		free(a_cols_t);
	}

	return ret;
}

// multiply by s on the right
void oqs_kex_lwe_frodo_mul_bs(uint16_t *out, const uint16_t *b, const uint16_t *s, struct oqs_kex_lwe_frodo_params *params) {
	// b (N_BAR x N)
	// s (N x N_BAR)
	// out = bs
	int i, j, k;
	for (i = 0; i < params->nbar; i++) {
		for (j = 0; j < params->nbar; j++) {
			out[i * params->nbar + j] = 0;
			for (k = 0; k < params->n; k++) {
				out[i * params->nbar + j] += b[i * params->n + k] * s[k * params->nbar + j];
			}
			out[i * params->nbar + j] %= params->q;  // not really necessary since LWE_Q is a power of 2.
		}
	}
}

// multiply by s on the left
void oqs_kex_lwe_frodo_mul_add_sb_plus_e(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_frodo_params *params) {
	// b (N x N_BAR)
	// s (N_BAR x N)
	// e (N_BAR x N_BAR)
	// out = sb + e
	int i, j, k;
	for (k = 0; k < params->nbar; k++) {
		for (i = 0; i < params->nbar; i++) {
			out[k * params->nbar + i] = e[k * params->nbar + i];
			for (j = 0; j < params->n; j++) {
				out[k * params->nbar + i] += s[k * params->n + j] * b[j * params->nbar + i];
			}
			out[k * params->nbar + i] %= params->q;  // not really necessary since LWE_Q is a power of 2.
		}
	}
}

// round all elements of a vector to the nearest multiple of 2^b
void oqs_kex_lwe_frodo_key_round(uint16_t *vec, const size_t length, const int b) {
	size_t i;
	uint16_t negmask = ~((1 << b) - 1);
	uint16_t half = b > 0 ? 1 << (b - 1) : 0;
	for (i = 0; i < length; i++) {
		vec[i] = (vec[i] + half) & negmask;
	}
}

// Round all elements of a vector to the multiple of 2^b, with a hint for the
// direction of rounding when close to the boundary.
void oqs_kex_lwe_frodo_key_round_hints(uint16_t *vec, const size_t length, const int b, const unsigned char *hint) {
	size_t i;
	uint16_t whole = 1 << b;
	uint16_t mask = whole - 1;
	uint16_t negmask = ~mask;
	uint16_t half = 1 << (b - 1);
	uint16_t quarter = 1 << (b - 2);

	for (i = 0; i < length; i++) {
		uint16_t remainder = vec[i] & mask;
		uint16_t use_hint = ((remainder + quarter) >> (b - 1)) & 0x1;

		unsigned char h = (hint[i / 8] >> (i % 8)) % 2;  // the hint
		uint16_t shift = use_hint * (2 * h - 1) * quarter;

		// if use_hint = 1 and h = 0, adding -quarter forces rounding down
		//                     h = 1, adding quarter forces rounding up

		vec[i] = (vec[i] + half + shift) & negmask;
	}
}

// Pack the input uint16 vector into a char output vector, copying lsb bits
// from each input element. If inlen * lsb / 8 > outlen, only outlen * 8 bits
// are copied.
void oqs_kex_lwe_frodo_pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb) {
	memset(out, 0, outlen);

	size_t i = 0;            // whole bytes already filled in
	size_t j = 0;            // whole uint16_t already copied
	uint16_t w = 0;          // the leftover, not yet copied
	unsigned char bits = 0;  // the number of lsb in w
	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
		/*
		in: |        |        |********|********|
		                      ^
		                      j
		w : |   ****|
		        ^
		       bits
		out:|**|**|**|**|**|**|**|**|* |
		                            ^^
		                            ib
		*/
		unsigned char b = 0;  // bits in out[i] already filled in
		while (b < 8) {
			int nbits = min(8 - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			unsigned char t = (w >> (bits - nbits)) & mask;  // the bits to copy from w to out
			out[i] = out[i] + (t << (8 - b - nbits));
			b += nbits;
			bits -= nbits;
			w &= ~(mask << bits);  // not strictly necessary; mostly for debugging

			if (bits == 0) {
				if (j < inlen) {
					w = in[j];
					bits = lsb;
					j++;
				} else {
					break;  // the input vector is exhausted
				}
			}
		}
		if (b == 8) {  // out[i] is filled in
			i++;
			b = 0;
		}
	}
}

// Unpack the input char vector into a uint16_t output vector, copying lsb bits
// for each output element from input. outlen must be at least ceil(inlen * 8 /
// lsb).
void oqs_kex_lwe_frodo_unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb) {
	memset(out, 0, outlen * sizeof(uint16_t));

	size_t i = 0;            // whole uint16_t already filled in
	size_t j = 0;            // whole bytes already copied
	unsigned char w = 0;     // the leftover, not yet copied
	unsigned char bits = 0;  // the number of lsb bits of w
	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
		/*
		in: |  |  |  |  |  |  |**|**|...
		                      ^
		                      j
		w : | *|
		      ^
		      bits
		out:|   *****|   *****|   ***  |        |...
		                      ^   ^
		                      i   b
		*/
		unsigned char b = 0;  // bits in out[i] already filled in
		while (b < lsb) {
			int nbits = min(lsb - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			unsigned char t = (w >> (bits - nbits)) & mask;  // the bits to copy from w to out
			out[i] = out[i] + (t << (lsb - b - nbits));
			b += nbits;
			bits -= nbits;
			w &= ~(mask << bits);  // not strictly necessary; mostly for debugging

			if (bits == 0) {
				if (j < inlen) {
					w = in[j];
					bits = 8;
					j++;
				} else {
					break;  // the input vector is exhausted
				}
			}
		}
		if (b == lsb) {  // out[i] is filled in
			i++;
			b = 0;
		}
	}
}
