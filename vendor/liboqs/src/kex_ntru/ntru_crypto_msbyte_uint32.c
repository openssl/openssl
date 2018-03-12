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
 * File: ntru_crypto_msbyte_uint32.c
 *
 * Contents: Routines to convert between an array of bytes in network byte
 *           order (most-significant byte first) and an array of uint32 words.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_msbyte_uint32.h"

/* ntru_crypto_msbyte_2_uint32()
 *
 * This routine converts an array of bytes in network byte order to an array
 * of uint32_t, placing the first byte in the most significant byte of the
 * first uint32_t word.
 *
 * The number of bytes in the input stream MUST be at least 4 times the
 * number of words expected in the output array.
 */

void ntru_crypto_msbyte_2_uint32(
    uint32_t *words,      /* out - pointer to the output uint32_t array */
    uint8_t const *bytes, /*  in - pointer to the input byte array */
    uint32_t n)           /*  in - number of words in the output array */
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		words[i] = ((uint32_t)(*bytes++)) << 24;
		words[i] |= ((uint32_t)(*bytes++)) << 16;
		words[i] |= ((uint32_t)(*bytes++)) << 8;
		words[i] |= (uint32_t)(*bytes++);
	}

	return;
}

/* ntru_crypto_uint32_2_msbyte()
 *
 * This routine converts an array of uint32_t to an array of bytes in
 * network byte order, placing the most significant byte of the first uint32_t
 * word as the first byte of the output array.
 *
 * The number of bytes in the output stream will be 4 times the number of words
 * specified in the input array.
 */

void ntru_crypto_uint32_2_msbyte(
    uint8_t *bytes,        /* out - pointer to the output byte array */
    uint32_t const *words, /*  in - pointer to the input uint32_t array */
    uint32_t n)            /*  in - number of words in the input array */
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		*bytes++ = (uint8_t)(words[i] >> 24);
		*bytes++ = (uint8_t)(words[i] >> 16);
		*bytes++ = (uint8_t)(words[i] >> 8);
		*bytes++ = (uint8_t)(words[i]);
	}

	return;
}
