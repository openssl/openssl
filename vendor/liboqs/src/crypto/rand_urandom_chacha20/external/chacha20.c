/* Adapted from chacha-ref.c version 20080118, D. J. Bernstein, Public domain.
 * http://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c
 */

#include <stdint.h>
#include <string.h>

#include "ecrypt-portable.h"

#define ROTATE(v, c) (ROTL32(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

#define QUARTERROUND(a, b, c, d)        \
	x[a] = PLUS(x[a], x[b]);            \
	x[d] = ROTATE(XOR(x[d], x[a]), 16); \
	x[c] = PLUS(x[c], x[d]);            \
	x[b] = ROTATE(XOR(x[b], x[c]), 12); \
	x[a] = PLUS(x[a], x[b]);            \
	x[d] = ROTATE(XOR(x[d], x[a]), 8);  \
	x[c] = PLUS(x[c], x[d]);            \
	x[b] = ROTATE(XOR(x[b], x[c]), 7);

static void salsa20_wordtobyte(u8 output[64], const u32 input[16]) {
	u32 x[16];
	int i;

	for (i = 0; i < 16; ++i)
		x[i] = input[i];
	for (i = 8; i > 0; i -= 2) {
		QUARTERROUND(0, 4, 8, 12)
		QUARTERROUND(1, 5, 9, 13)
		QUARTERROUND(2, 6, 10, 14)
		QUARTERROUND(3, 7, 11, 15)
		QUARTERROUND(0, 5, 10, 15)
		QUARTERROUND(1, 6, 11, 12)
		QUARTERROUND(2, 7, 8, 13)
		QUARTERROUND(3, 4, 9, 14)
	}
	for (i = 0; i < 16; ++i)
		x[i] = PLUS(x[i], input[i]);
	for (i = 0; i < 16; ++i)
		U32TO8_LITTLE(output + 4 * i, x[i]);
}

static const char sigma[16] = "expand 32-byte k";

static void ECRYPT_keysetup(u32 input[16], const u8 k[32]) {
	const char *constants;

	input[4] = U8TO32_LITTLE(k + 0);
	input[5] = U8TO32_LITTLE(k + 4);
	input[6] = U8TO32_LITTLE(k + 8);
	input[7] = U8TO32_LITTLE(k + 12);
	k += 16;
	constants = sigma;
	input[8] = U8TO32_LITTLE(k + 0);
	input[9] = U8TO32_LITTLE(k + 4);
	input[10] = U8TO32_LITTLE(k + 8);
	input[11] = U8TO32_LITTLE(k + 12);
	input[0] = U8TO32_LITTLE(constants + 0);
	input[1] = U8TO32_LITTLE(constants + 4);
	input[2] = U8TO32_LITTLE(constants + 8);
	input[3] = U8TO32_LITTLE(constants + 12);
}

static void ECRYPT_ivsetup(u32 input[16], const u8 iv[8]) {
	input[12] = 0;
	input[13] = 0;
	input[14] = U8TO32_LITTLE(iv + 0);
	input[15] = U8TO32_LITTLE(iv + 4);
}

static void ECRYPT_encrypt_bytes(u32 input[16], const u8 *m, u8 *c, size_t bytes) {
	u8 output[64];
	size_t i;

	if (!bytes)
		return;
	for (;;) {
		salsa20_wordtobyte(output, input);
		input[12] = PLUSONE(input[12]);
		if (!input[12]) {
			input[13] = PLUSONE(input[13]);
			/* stopping at 2^70 bytes per nonce is user's responsibility */
		}
		if (bytes <= 64) {
			for (i = 0; i < bytes; ++i)
				c[i] = m[i] ^ output[i];
			return;
		}
		for (i = 0; i < 64; ++i)
			c[i] = m[i] ^ output[i];
		bytes -= 64;
		c += 64;
		m += 64;
	}
}

static void ECRYPT_keystream_bytes(u32 input[16], u8 *stream, u32 bytes) {
	u32 i;
	for (i = 0; i < bytes; ++i)
		stream[i] = 0;
	ECRYPT_encrypt_bytes(input, stream, stream, bytes);
}
