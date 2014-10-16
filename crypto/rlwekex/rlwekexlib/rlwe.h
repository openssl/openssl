/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef _RLWE_H_
#define _RLWE_H_

#include <stdint.h>

#include "fft.h"

void sample_ct(uint32_t *s);
void sample(uint32_t *s);

void round2_ct(uint64_t *out, const uint32_t *in);
void round2(uint64_t *out, const uint32_t *in);

/* We assume that e contains two random bits in the two
 * least significant positions. */
uint64_t dbl(const uint32_t in, int32_t e);

void crossround2_ct(uint64_t *out, const uint32_t *in);
void crossround2(uint64_t *out, const uint32_t *in);

void rec_ct(uint64_t *out, const uint32_t *w, const uint64_t *b);
void rec(uint64_t *out, const uint32_t *w, const uint64_t *b);

void key_gen(uint32_t *out, const uint32_t *a, const uint32_t *s, const uint32_t *e, FFT_CTX *ctx);

#endif /* _RLWE_H_ */
