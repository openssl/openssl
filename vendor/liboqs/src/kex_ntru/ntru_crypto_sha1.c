/******************************************************************************
 * NTRU Cryptography Reference Source Code
 *
 * Copyright (C) 2009-2016  Security Innovation (SI)
 *
 * SI has dedicated the work to the public domain by waiving all of its rights
 * to the work worldwide under copyright law, including all related and
 * neighboring rights, to the extent allowed by law.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * You can copy, modify, distribute and perform the work, even for commercial
 * purposes, all without asking permission. You should have received a copy of
 * the creative commons license (CC0 1.0 universal) along with this program.
 * See the license file for more information. 
 *
 *
 *********************************************************************************/

/******************************************************************************
 *
 * File: ntru_crypto_sha1.c
 *
 * Contents: Routines implementing the SHA-1 hash calculation.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_sha1.h"
#include "ntru_crypto_msbyte_uint32.h"

/* chaining state elements */

#define H0 state[0]
#define H1 state[1]
#define H2 state[2]
#define H3 state[3]
#define H4 state[4]

/* standard SHA-1 initialization values */

#define H0_INIT 0x67452301UL
#define H1_INIT 0xefcdab89UL
#define H2_INIT 0x98badcfeUL
#define H3_INIT 0x10325476UL
#define H4_INIT 0xc3d2e1f0UL

/* sha1_blk()
 *
 * This routine updates the current hash output (chaining state)
 * by performing SHA-1 on a 512-bit block of data represented as sixteen
 * 32-bit words.
 */

#define K00_19 0x5a827999UL
#define K20_39 0x6ed9eba1UL
#define K40_59 0x8f1bbcdcUL
#define K60_79 0xca62c1d6UL

#define RL(a, n) (((a) << (n)) | ((a) >> (32 - (n))))

static void
sha1_blk(
    uint32_t const *data, /*     in - ptr to 16 32-bit word input block */
    uint32_t *state)      /* in/out - ptr to 5 32-bit word chaining state */
{
	uint32_t A, B, C, D, E;
	uint32_t w[16];

	/* init A - E */

	A = H0;
	B = H1;
	C = H2;
	D = H3;
	E = H4;

	/* rounds 0 - 15 */

	E += RL(A, 5) + K00_19 + ((B & (C ^ D)) ^ D) + data[0];
	B = RL(B, 30);
	D += RL(E, 5) + K00_19 + ((A & (B ^ C)) ^ C) + data[1];
	A = RL(A, 30);
	C += RL(D, 5) + K00_19 + ((E & (A ^ B)) ^ B) + data[2];
	E = RL(E, 30);
	B += RL(C, 5) + K00_19 + ((D & (E ^ A)) ^ A) + data[3];
	D = RL(D, 30);
	A += RL(B, 5) + K00_19 + ((C & (D ^ E)) ^ E) + data[4];
	C = RL(C, 30);
	E += RL(A, 5) + K00_19 + ((B & (C ^ D)) ^ D) + data[5];
	B = RL(B, 30);
	D += RL(E, 5) + K00_19 + ((A & (B ^ C)) ^ C) + data[6];
	A = RL(A, 30);
	C += RL(D, 5) + K00_19 + ((E & (A ^ B)) ^ B) + data[7];
	E = RL(E, 30);
	B += RL(C, 5) + K00_19 + ((D & (E ^ A)) ^ A) + data[8];
	D = RL(D, 30);
	A += RL(B, 5) + K00_19 + ((C & (D ^ E)) ^ E) + data[9];
	C = RL(C, 30);
	E += RL(A, 5) + K00_19 + ((B & (C ^ D)) ^ D) + data[10];
	B = RL(B, 30);
	D += RL(E, 5) + K00_19 + ((A & (B ^ C)) ^ C) + data[11];
	A = RL(A, 30);
	C += RL(D, 5) + K00_19 + ((E & (A ^ B)) ^ B) + data[12];
	E = RL(E, 30);
	B += RL(C, 5) + K00_19 + ((D & (E ^ A)) ^ A) + data[13];
	D = RL(D, 30);
	A += RL(B, 5) + K00_19 + ((C & (D ^ E)) ^ E) + data[14];
	C = RL(C, 30);
	E += RL(A, 5) + K00_19 + ((B & (C ^ D)) ^ D) + data[15];
	B = RL(B, 30);

	/* rounds 16 - 19 */

	w[0] = data[0] ^ data[2] ^ data[8] ^ data[13];
	w[0] = RL(w[0], 1);
	D += RL(E, 5) + K00_19 + ((A & (B ^ C)) ^ C) + w[0];
	A = RL(A, 30);
	w[1] = data[1] ^ data[3] ^ data[9] ^ data[14];
	w[1] = RL(w[1], 1);
	C += RL(D, 5) + K00_19 + ((E & (A ^ B)) ^ B) + w[1];
	E = RL(E, 30);
	w[2] = data[2] ^ data[4] ^ data[10] ^ data[15];
	w[2] = RL(w[2], 1);
	B += RL(C, 5) + K00_19 + ((D & (E ^ A)) ^ A) + w[2];
	D = RL(D, 30);
	w[3] = data[3] ^ data[5] ^ data[11] ^ w[0];
	w[3] = RL(w[3], 1);
	A += RL(B, 5) + K00_19 + ((C & (D ^ E)) ^ E) + w[3];
	C = RL(C, 30);

	/* rounds 20 - 39 */

	w[4] = data[4] ^ data[6] ^ data[12] ^ w[1];
	w[4] = RL(w[4], 1);
	E += RL(A, 5) + K20_39 + (B ^ C ^ D) + w[4];
	B = RL(B, 30);
	w[5] = data[5] ^ data[7] ^ data[13] ^ w[2];
	w[5] = RL(w[5], 1);
	D += RL(E, 5) + K20_39 + (A ^ B ^ C) + w[5];
	A = RL(A, 30);
	w[6] = data[6] ^ data[8] ^ data[14] ^ w[3];
	w[6] = RL(w[6], 1);
	C += RL(D, 5) + K20_39 + (E ^ A ^ B) + w[6];
	E = RL(E, 30);
	w[7] = data[7] ^ data[9] ^ data[15] ^ w[4];
	w[7] = RL(w[7], 1);
	B += RL(C, 5) + K20_39 + (D ^ E ^ A) + w[7];
	D = RL(D, 30);
	w[8] = data[8] ^ data[10] ^ w[0] ^ w[5];
	w[8] = RL(w[8], 1);
	A += RL(B, 5) + K20_39 + (C ^ D ^ E) + w[8];
	C = RL(C, 30);
	w[9] = data[9] ^ data[11] ^ w[1] ^ w[6];
	w[9] = RL(w[9], 1);
	E += RL(A, 5) + K20_39 + (B ^ C ^ D) + w[9];
	B = RL(B, 30);
	w[10] = data[10] ^ data[12] ^ w[2] ^ w[7];
	w[10] = RL(w[10], 1);
	D += RL(E, 5) + K20_39 + (A ^ B ^ C) + w[10];
	A = RL(A, 30);
	w[11] = data[11] ^ data[13] ^ w[3] ^ w[8];
	w[11] = RL(w[11], 1);
	C += RL(D, 5) + K20_39 + (E ^ A ^ B) + w[11];
	E = RL(E, 30);
	w[12] = data[12] ^ data[14] ^ w[4] ^ w[9];
	w[12] = RL(w[12], 1);
	B += RL(C, 5) + K20_39 + (D ^ E ^ A) + w[12];
	D = RL(D, 30);
	w[13] = data[13] ^ data[15] ^ w[5] ^ w[10];
	w[13] = RL(w[13], 1);
	A += RL(B, 5) + K20_39 + (C ^ D ^ E) + w[13];
	C = RL(C, 30);
	w[14] = data[14] ^ w[0] ^ w[6] ^ w[11];
	w[14] = RL(w[14], 1);
	E += RL(A, 5) + K20_39 + (B ^ C ^ D) + w[14];
	B = RL(B, 30);
	w[15] = data[15] ^ w[1] ^ w[7] ^ w[12];
	w[15] = RL(w[15], 1);
	D += RL(E, 5) + K20_39 + (A ^ B ^ C) + w[15];
	A = RL(A, 30);
	w[0] = w[0] ^ w[2] ^ w[8] ^ w[13];
	w[0] = RL(w[0], 1);
	C += RL(D, 5) + K20_39 + (E ^ A ^ B) + w[0];
	E = RL(E, 30);
	w[1] = w[1] ^ w[3] ^ w[9] ^ w[14];
	w[1] = RL(w[1], 1);
	B += RL(C, 5) + K20_39 + (D ^ E ^ A) + w[1];
	D = RL(D, 30);
	w[2] = w[2] ^ w[4] ^ w[10] ^ w[15];
	w[2] = RL(w[2], 1);
	A += RL(B, 5) + K20_39 + (C ^ D ^ E) + w[2];
	C = RL(C, 30);
	w[3] = w[3] ^ w[5] ^ w[11] ^ w[0];
	w[3] = RL(w[3], 1);
	E += RL(A, 5) + K20_39 + (B ^ C ^ D) + w[3];
	B = RL(B, 30);
	w[4] = w[4] ^ w[6] ^ w[12] ^ w[1];
	w[4] = RL(w[4], 1);
	D += RL(E, 5) + K20_39 + (A ^ B ^ C) + w[4];
	A = RL(A, 30);
	w[5] = w[5] ^ w[7] ^ w[13] ^ w[2];
	w[5] = RL(w[5], 1);
	C += RL(D, 5) + K20_39 + (E ^ A ^ B) + w[5];
	E = RL(E, 30);
	w[6] = w[6] ^ w[8] ^ w[14] ^ w[3];
	w[6] = RL(w[6], 1);
	B += RL(C, 5) + K20_39 + (D ^ E ^ A) + w[6];
	D = RL(D, 30);
	w[7] = w[7] ^ w[9] ^ w[15] ^ w[4];
	w[7] = RL(w[7], 1);
	A += RL(B, 5) + K20_39 + (C ^ D ^ E) + w[7];
	C = RL(C, 30);

	/* rounds 40 - 59 */

	w[8] = w[8] ^ w[10] ^ w[0] ^ w[5];
	w[8] = RL(w[8], 1);
	E += RL(A, 5) + K40_59 + ((B & C) | (D & (B | C))) + w[8];
	B = RL(B, 30);
	w[9] = w[9] ^ w[11] ^ w[1] ^ w[6];
	w[9] = RL(w[9], 1);
	D += RL(E, 5) + K40_59 + ((A & B) | (C & (A | B))) + w[9];
	A = RL(A, 30);
	w[10] = w[10] ^ w[12] ^ w[2] ^ w[7];
	w[10] = RL(w[10], 1);
	C += RL(D, 5) + K40_59 + ((E & A) | (B & (E | A))) + w[10];
	E = RL(E, 30);
	w[11] = w[11] ^ w[13] ^ w[3] ^ w[8];
	w[11] = RL(w[11], 1);
	B += RL(C, 5) + K40_59 + ((D & E) | (A & (D | E))) + w[11];
	D = RL(D, 30);
	w[12] = w[12] ^ w[14] ^ w[4] ^ w[9];
	w[12] = RL(w[12], 1);
	A += RL(B, 5) + K40_59 + ((C & D) | (E & (C | D))) + w[12];
	C = RL(C, 30);
	w[13] = w[13] ^ w[15] ^ w[5] ^ w[10];
	w[13] = RL(w[13], 1);
	E += RL(A, 5) + K40_59 + ((B & C) | (D & (B | C))) + w[13];
	B = RL(B, 30);
	w[14] = w[14] ^ w[0] ^ w[6] ^ w[11];
	w[14] = RL(w[14], 1);
	D += RL(E, 5) + K40_59 + ((A & B) | (C & (A | B))) + w[14];
	A = RL(A, 30);
	w[15] = w[15] ^ w[1] ^ w[7] ^ w[12];
	w[15] = RL(w[15], 1);
	C += RL(D, 5) + K40_59 + ((E & A) | (B & (E | A))) + w[15];
	E = RL(E, 30);
	w[0] = w[0] ^ w[2] ^ w[8] ^ w[13];
	w[0] = RL(w[0], 1);
	B += RL(C, 5) + K40_59 + ((D & E) | (A & (D | E))) + w[0];
	D = RL(D, 30);
	w[1] = w[1] ^ w[3] ^ w[9] ^ w[14];
	w[1] = RL(w[1], 1);
	A += RL(B, 5) + K40_59 + ((C & D) | (E & (C | D))) + w[1];
	C = RL(C, 30);
	w[2] = w[2] ^ w[4] ^ w[10] ^ w[15];
	w[2] = RL(w[2], 1);
	E += RL(A, 5) + K40_59 + ((B & C) | (D & (B | C))) + w[2];
	B = RL(B, 30);
	w[3] = w[3] ^ w[5] ^ w[11] ^ w[0];
	w[3] = RL(w[3], 1);
	D += RL(E, 5) + K40_59 + ((A & B) | (C & (A | B))) + w[3];
	A = RL(A, 30);
	w[4] = w[4] ^ w[6] ^ w[12] ^ w[1];
	w[4] = RL(w[4], 1);
	C += RL(D, 5) + K40_59 + ((E & A) | (B & (E | A))) + w[4];
	E = RL(E, 30);
	w[5] = w[5] ^ w[7] ^ w[13] ^ w[2];
	w[5] = RL(w[5], 1);
	B += RL(C, 5) + K40_59 + ((D & E) | (A & (D | E))) + w[5];
	D = RL(D, 30);
	w[6] = w[6] ^ w[8] ^ w[14] ^ w[3];
	w[6] = RL(w[6], 1);
	A += RL(B, 5) + K40_59 + ((C & D) | (E & (C | D))) + w[6];
	C = RL(C, 30);
	w[7] = w[7] ^ w[9] ^ w[15] ^ w[4];
	w[7] = RL(w[7], 1);
	E += RL(A, 5) + K40_59 + ((B & C) | (D & (B | C))) + w[7];
	B = RL(B, 30);
	w[8] = w[8] ^ w[10] ^ w[0] ^ w[5];
	w[8] = RL(w[8], 1);
	D += RL(E, 5) + K40_59 + ((A & B) | (C & (A | B))) + w[8];
	A = RL(A, 30);
	w[9] = w[9] ^ w[11] ^ w[1] ^ w[6];
	w[9] = RL(w[9], 1);
	C += RL(D, 5) + K40_59 + ((E & A) | (B & (E | A))) + w[9];
	E = RL(E, 30);
	w[10] = w[10] ^ w[12] ^ w[2] ^ w[7];
	w[10] = RL(w[10], 1);
	B += RL(C, 5) + K40_59 + ((D & E) | (A & (D | E))) + w[10];
	D = RL(D, 30);
	w[11] = w[11] ^ w[13] ^ w[3] ^ w[8];
	w[11] = RL(w[11], 1);
	A += RL(B, 5) + K40_59 + ((C & D) | (E & (C | D))) + w[11];
	C = RL(C, 30);

	/* rounds 60 - 79 */

	w[12] = w[12] ^ w[14] ^ w[4] ^ w[9];
	w[12] = RL(w[12], 1);
	E += RL(A, 5) + K60_79 + (B ^ C ^ D) + w[12];
	B = RL(B, 30);
	w[13] = w[13] ^ w[15] ^ w[5] ^ w[10];
	w[13] = RL(w[13], 1);
	D += RL(E, 5) + K60_79 + (A ^ B ^ C) + w[13];
	A = RL(A, 30);
	w[14] = w[14] ^ w[0] ^ w[6] ^ w[11];
	w[14] = RL(w[14], 1);
	C += RL(D, 5) + K60_79 + (E ^ A ^ B) + w[14];
	E = RL(E, 30);
	w[15] = w[15] ^ w[1] ^ w[7] ^ w[12];
	w[15] = RL(w[15], 1);
	B += RL(C, 5) + K60_79 + (D ^ E ^ A) + w[15];
	D = RL(D, 30);
	w[0] = w[0] ^ w[2] ^ w[8] ^ w[13];
	w[0] = RL(w[0], 1);
	A += RL(B, 5) + K60_79 + (C ^ D ^ E) + w[0];
	C = RL(C, 30);
	w[1] = w[1] ^ w[3] ^ w[9] ^ w[14];
	w[1] = RL(w[1], 1);
	E += RL(A, 5) + K60_79 + (B ^ C ^ D) + w[1];
	B = RL(B, 30);
	w[2] = w[2] ^ w[4] ^ w[10] ^ w[15];
	w[2] = RL(w[2], 1);
	D += RL(E, 5) + K60_79 + (A ^ B ^ C) + w[2];
	A = RL(A, 30);
	w[3] = w[3] ^ w[5] ^ w[11] ^ w[0];
	w[3] = RL(w[3], 1);
	C += RL(D, 5) + K60_79 + (E ^ A ^ B) + w[3];
	E = RL(E, 30);
	w[4] = w[4] ^ w[6] ^ w[12] ^ w[1];
	w[4] = RL(w[4], 1);
	B += RL(C, 5) + K60_79 + (D ^ E ^ A) + w[4];
	D = RL(D, 30);
	w[5] = w[5] ^ w[7] ^ w[13] ^ w[2];
	w[5] = RL(w[5], 1);
	A += RL(B, 5) + K60_79 + (C ^ D ^ E) + w[5];
	C = RL(C, 30);
	w[6] = w[6] ^ w[8] ^ w[14] ^ w[3];
	w[6] = RL(w[6], 1);
	E += RL(A, 5) + K60_79 + (B ^ C ^ D) + w[6];
	B = RL(B, 30);
	w[7] = w[7] ^ w[9] ^ w[15] ^ w[4];
	w[7] = RL(w[7], 1);
	D += RL(E, 5) + K60_79 + (A ^ B ^ C) + w[7];
	A = RL(A, 30);
	w[8] = w[8] ^ w[10] ^ w[0] ^ w[5];
	w[8] = RL(w[8], 1);
	C += RL(D, 5) + K60_79 + (E ^ A ^ B) + w[8];
	E = RL(E, 30);
	w[9] = w[9] ^ w[11] ^ w[1] ^ w[6];
	w[9] = RL(w[9], 1);
	B += RL(C, 5) + K60_79 + (D ^ E ^ A) + w[9];
	D = RL(D, 30);
	w[10] = w[10] ^ w[12] ^ w[2] ^ w[7];
	w[10] = RL(w[10], 1);
	A += RL(B, 5) + K60_79 + (C ^ D ^ E) + w[10];
	C = RL(C, 30);
	w[11] = w[11] ^ w[13] ^ w[3] ^ w[8];
	w[11] = RL(w[11], 1);
	E += RL(A, 5) + K60_79 + (B ^ C ^ D) + w[11];
	B = RL(B, 30);
	w[12] = w[12] ^ w[14] ^ w[4] ^ w[9];
	w[12] = RL(w[12], 1);
	D += RL(E, 5) + K60_79 + (A ^ B ^ C) + w[12];
	A = RL(A, 30);
	w[13] = w[13] ^ w[15] ^ w[5] ^ w[10];
	C += RL(D, 5) + K60_79 + (E ^ A ^ B) + RL(w[13], 1);
	E = RL(E, 30);
	w[14] = w[14] ^ w[0] ^ w[6] ^ w[11];
	B += RL(C, 5) + K60_79 + (D ^ E ^ A) + RL(w[14], 1);
	D = RL(D, 30);

	/* update H0 - H4 */

	w[15] = w[15] ^ w[1] ^ w[7] ^ w[12];
	H0 += A + RL(B, 5) + K60_79 + (C ^ D ^ E) + RL(w[15], 1);
	H1 += B;
	H2 += RL(C, 30);
	H3 += D;
	H4 += E;

	/* clear temp variables */

	A = B = C = D = E = 0;
	memset(w, 0, sizeof(w));
}

/* ntru_crypto_sha1()
 *
 * This routine provides all operations for a SHA-1 hash, and the use
 * of SHA-1 for DSA signing and key generation.
 * It may be used to initialize, update, or complete a message digest,
 * or any combination of those actions, as determined by the SHA_INIT flag,
 * the in_len parameter, and the SHA_FINISH flag, respectively.
 *
 * When in_len == 0 (no data to hash), the parameter, in, may be NULL.
 * When the SHA_FINISH flag is not set, the parameter, md, may be NULL.
 *
 * Initialization may be standard or use a specified initialization vector,
 * and is indicated by setting the SHA_INIT flag.
 * Setting init = NULL specifies standard initialization.  Otherwise, init
 * points to the array of five alternate initialization 32-bit words.
 *
 * The hash operation can be updated with any number of input bytes, including
 * zero.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if  inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha1(
    NTRU_CRYPTO_SHA1_CTX *c, /* in/out - pointer to SHA-1 context */
    uint32_t const *init,    /*     in - pointer to alternate */
                             /*          initialization - may be NULL */
    uint8_t const *in,       /*     in - pointer to input data -
                                                may be NULL if in_len == 0 */
    uint32_t in_len,         /*     in - number of input data bytes */
    uint32_t flags,          /*     in - INIT, FINISH flags */
    uint8_t *md)             /*    out - address for message digest -
                                                may be NULL if not FINISH */
{
	uint32_t in_blk[16]; /* input block */
	uint32_t space;
	uint8_t *d = NULL;

	/* check error conditions */

	if (!c || (in_len && !in) || ((flags & SHA_FINISH) && !md)) {
		SHA_RET(SHA_BAD_PARAMETER)
	}

	/* initialize context if requested */

	if (flags & SHA_INIT) {

		/* init chaining state */

		if (!init) {
			c->state[0] = H0_INIT; /* standard initialization */
			c->state[1] = H1_INIT;
			c->state[2] = H2_INIT;
			c->state[3] = H3_INIT;
			c->state[4] = H4_INIT;
		} else {
			/* Non standard initialization values are not supported */
			SHA_RET(SHA_BAD_PARAMETER);
		}

		/* init bit count and number of unhashed data bytes */

		c->num_bits_hashed[0] = 0;
		c->num_bits_hashed[1] = 0;
		c->unhashed_len = 0;
	}

	/* determine space left in unhashed data buffer */

	if (c->unhashed_len > 63) {
		SHA_RET(SHA_FAIL)
	}

	space = 64 - c->unhashed_len;

	/* process input if it exists */

	if (in_len) {

		/* update count of bits hashed */

		{
			uint32_t bits0, bits1;

			bits0 = in_len << 3;
			bits1 = in_len >> 29;

			if ((c->num_bits_hashed[0] += bits0) < bits0) {
				bits1++;
			}

			if ((c->num_bits_hashed[1] += bits1) < bits1) {
				memset((uint8_t *) c, 0, sizeof(NTRU_CRYPTO_SHA1_CTX));
				memset((char *) in_blk, 0, sizeof(in_blk));
				SHA_RET(SHA_OVERFLOW)
			}
		}

		/* process input bytes */

		if (in_len < space) {

			/* input does not fill block buffer:
             * add input to buffer
             */

			memcpy(c->unhashed + c->unhashed_len, in, in_len);
			c->unhashed_len += in_len;

		} else {
			uint32_t blks;

			/* input will fill block buffer:
             *  fill unhashed data buffer,
             *  convert to block buffer,
             *  and process block
             */

			in_len -= space;

			for (d = c->unhashed + c->unhashed_len; space; space--) {
				*d++ = *in++;
			}

			ntru_crypto_msbyte_2_uint32(in_blk, (uint8_t const *) c->unhashed,
			                            16);
			sha1_blk((uint32_t const *) in_blk, c->state);

			/* process any remaining full blocks */

			for (blks = in_len >> 6; blks--; in += 64) {
				ntru_crypto_msbyte_2_uint32(in_blk, in, 16);
				sha1_blk((uint32_t const *) in_blk, c->state);
			}

			/* put any remaining input in the unhashed data buffer */

			in_len &= 0x3f;
			memcpy(c->unhashed, in, in_len);
			c->unhashed_len = in_len;
		}
	}

	/* complete message digest if requested */

	if (flags & SHA_FINISH) {
		space = 64 - c->unhashed_len;

		/* add 0x80 padding byte to the unhashed data buffer
         * (there is always space since the buffer can't be full)
         */

		d = c->unhashed + c->unhashed_len;
		*d++ = 0x80;
		space--;

		/* check for space for bit count */

		if (space < 8) {

			/* no space for count:
             *  fill remainder of unhashed data buffer with zeros,
             *  convert to input block,
             *  process block,
             *  fill all but 8 bytes of unhashed data buffer with zeros
             */

			memset(d, 0, space);
			ntru_crypto_msbyte_2_uint32(in_blk,
			                            (uint8_t const *) c->unhashed, 16);
			sha1_blk((uint32_t const *) in_blk, c->state);
			memset(c->unhashed, 0, 56);

		} else {

			/* fill unhashed data buffer with zeros,
             *  leaving space for bit count
             */

			for (space -= 8; space; space--) {
				*d++ = 0;
			}
		}

		/* convert partially filled unhashed data buffer to input block and
         *  add bit count to input block
         */

		ntru_crypto_msbyte_2_uint32(in_blk, (uint8_t const *) c->unhashed,
		                            14);
		in_blk[14] = c->num_bits_hashed[1];
		in_blk[15] = c->num_bits_hashed[0];

		/* process last block */

		sha1_blk((uint32_t const *) in_blk, c->state);

		/* copy result to message digest buffer */

		ntru_crypto_uint32_2_msbyte(md, c->state, 5);

		/* clear context and stack variables */

		memset((uint8_t *) c, 0, sizeof(NTRU_CRYPTO_SHA1_CTX));
		memset((char *) in_blk, 0, sizeof(in_blk));
	}

	SHA_RET(SHA_OK)
}

/* ntru_crypto_sha1_init
 *
 * This routine performs standard initialization of the SHA-1 state.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 */

uint32_t
ntru_crypto_sha1_init(
    NTRU_CRYPTO_SHA1_CTX *c) /* in/out - pointer to SHA-1 context */
{
	return ntru_crypto_sha1(c, NULL, NULL, 0, SHA_INIT, NULL);
}

/* ntru_crypto_sha1_update
 *
 * This routine processes input data and updates the SHA-1 hash calculation.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha1_update(
    NTRU_CRYPTO_SHA1_CTX *c, /* in/out - pointer to SHA-1 context */
    uint8_t const *data,     /*    in - pointer to input data */
    uint32_t data_len)       /*    in - number of bytes of input data */
{
	return ntru_crypto_sha1(c, NULL, data, data_len, SHA_DATA_ONLY, NULL);
}

/* ntru_crypto_sha1_final
 *
 * This routine completes the SHA-1 hash calculation and returns the
 * message digest.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha1_final(
    NTRU_CRYPTO_SHA1_CTX *c, /* in/out - pointer to SHA-1 context */
    uint8_t *md)             /*   out - address for message digest */
{
	return ntru_crypto_sha1(c, NULL, NULL, 0, SHA_FINISH, md);
}

/* ntru_crypto_sha1_digest
 *
 * This routine computes a SHA-1 message digest.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha1_digest(
    uint8_t const *data, /*  in - pointer to input data */
    uint32_t data_len,   /*  in - number of bytes of input data */
    uint8_t *md)         /* out - address for message digest */
{
	NTRU_CRYPTO_SHA1_CTX c;

	return ntru_crypto_sha1(&c, NULL, data, data_len, SHA_INIT | SHA_FINISH, md);
}
