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
#include <stdlib.h>
#include <string.h>

#include <oqs/rand.h>

#include "local.h"

static void *(*volatile rlwe_memset_volatile)(void *, int, size_t) = memset;

void oqs_kex_rlwe_bcns15_generate_keypair(const uint32_t *a, uint32_t s[1024], uint32_t b[1024], struct oqs_kex_rlwe_bcns15_fft_ctx *ctx, OQS_RAND *rand) {
	uint32_t e[1024];
#if CONSTANT_TIME
	oqs_kex_rlwe_bcns15_sample_ct(s, rand);
	oqs_kex_rlwe_bcns15_sample_ct(e, rand);
#else
	oqs_kex_rlwe_bcns15_sample(s, rand);
	oqs_kex_rlwe_bcns15_sample(e, rand);
#endif
	oqs_kex_rlwe_bcns15_a_times_s_plus_e(b, a, s, e, ctx);
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
}

void oqs_kex_rlwe_bcns15_compute_key_alice(const uint32_t b[1024], const uint32_t s[1024], const uint64_t c[16], uint64_t k[16], struct oqs_kex_rlwe_bcns15_fft_ctx *ctx) {
	uint32_t w[1024];
	oqs_kex_rlwe_bcns15_fft_mul(w, b, s, ctx);
#if CONSTANT_TIME
	oqs_kex_rlwe_bcns15_rec_ct(k, w, c);
#else
	oqs_kex_rlwe_bcns15_rec(k, w, c);
#endif
	rlwe_memset_volatile(w, 0, 1024 * sizeof(uint32_t));
}

void oqs_kex_rlwe_bcns15_compute_key_bob(const uint32_t b[1024], const uint32_t s[1024], uint64_t c[16], uint64_t k[16], struct oqs_kex_rlwe_bcns15_fft_ctx *ctx, OQS_RAND *rand) {
	uint32_t v[1024];
	uint32_t eprimeprime[1024];
#if CONSTANT_TIME
	oqs_kex_rlwe_bcns15_sample_ct(eprimeprime, rand);
#else
	oqs_kex_rlwe_bcns15_sample(eprimeprime, rand);
#endif
	oqs_kex_rlwe_bcns15_a_times_s_plus_e(v, b, s, eprimeprime, ctx);
#if CONSTANT_TIME
	oqs_kex_rlwe_bcns15_crossround2_ct(c, v, rand);
	oqs_kex_rlwe_bcns15_round2_ct(k, v);
#else
	oqs_kex_rlwe_bcns15_crossround2(c, v, rand);
	oqs_kex_rlwe_bcns15_round2(k, v);
#endif
	rlwe_memset_volatile(v, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(eprimeprime, 0, 1024 * sizeof(uint32_t));
}
