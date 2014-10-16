/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef _FFT_H_
#define _FFT_H_

#include <stdint.h>

struct fft_ctx {
	uint32_t **x1;
	uint32_t **y1;
	uint32_t **z1;
	uint32_t *t1;
};
typedef struct fft_ctx FFT_CTX;

int FFT_CTX_init(FFT_CTX *ctx);
void FFT_CTX_clear(FFT_CTX *ctx);
void FFT_CTX_free(FFT_CTX *ctx);

void FFT_mul(uint32_t *z, const uint32_t *x, const uint32_t *y, FFT_CTX *ctx);
void FFT_add(uint32_t *z, const uint32_t *x, const uint32_t *y);

#endif /* _FFT_H_ */

