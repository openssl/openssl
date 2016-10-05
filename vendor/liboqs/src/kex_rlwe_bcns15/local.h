/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef _OQS_KEX_RLWE_BCNS15_LOCAL_H_
#define _OQS_KEX_RLWE_BCNS15_LOCAL_H_

#include <stdint.h>

#include <oqs/rand.h>

struct oqs_kex_rlwe_bcns15_fft_ctx {
	uint32_t x1[64][64];
	uint32_t y1[64][64];
	uint32_t z1[64][64];
	uint32_t t1[64];
};

void oqs_kex_rlwe_bcns15_fft_mul(uint32_t z[1024], const uint32_t x[1024], const uint32_t y[1024], struct oqs_kex_rlwe_bcns15_fft_ctx *ctx);
void oqs_kex_rlwe_bcns15_fft_add(uint32_t z[1024], const uint32_t x[1024], const uint32_t y[1024]);

void oqs_kex_rlwe_bcns15_fft_ctx_clear(struct oqs_kex_rlwe_bcns15_fft_ctx *ctx);

void oqs_kex_rlwe_bcns15_sample_ct(uint32_t s[1024], OQS_RAND *rand);
void oqs_kex_rlwe_bcns15_round2_ct(uint64_t out[16], const uint32_t in[1024]);
void oqs_kex_rlwe_bcns15_crossround2_ct(uint64_t out[16], const uint32_t in[1024], OQS_RAND *rand);
void oqs_kex_rlwe_bcns15_rec_ct(uint64_t out[16], const uint32_t w[1024], const uint64_t b[16]);

void oqs_kex_rlwe_bcns15_sample(uint32_t s[1024], OQS_RAND *rand);
void oqs_kex_rlwe_bcns15_round2(uint64_t out[16], const uint32_t in[1024]);
void oqs_kex_rlwe_bcns15_crossround2(uint64_t out[16], const uint32_t in[1024], OQS_RAND *rand);
void oqs_kex_rlwe_bcns15_rec(uint64_t out[16], const uint32_t w[1024], const uint64_t b[16]);

void oqs_kex_rlwe_bcns15_a_times_s_plus_e(uint32_t out[1024], const uint32_t a[1024], const uint32_t s[1024], const uint32_t e[1024], struct oqs_kex_rlwe_bcns15_fft_ctx *fft_ctx);

void oqs_kex_rlwe_bcns15_generate_keypair(const uint32_t *a, uint32_t s[1024], uint32_t b[1024], struct oqs_kex_rlwe_bcns15_fft_ctx *ctx, OQS_RAND *rand);
void oqs_kex_rlwe_bcns15_compute_key_alice(const uint32_t b[1024], const uint32_t s[1024], const uint64_t c[16], uint64_t k[16], struct oqs_kex_rlwe_bcns15_fft_ctx *ctx);
void oqs_kex_rlwe_bcns15_compute_key_bob(const uint32_t b[1024], const uint32_t s[1024], uint64_t c[16], uint64_t k[16], struct oqs_kex_rlwe_bcns15_fft_ctx *ctx, OQS_RAND *rand);

#endif /* _OQS_KEX_RLWE_BCNS15_LOCAL_H_ */
