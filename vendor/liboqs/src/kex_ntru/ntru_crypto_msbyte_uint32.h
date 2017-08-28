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
 * File: ntru_crypto_msbyte_uint32.h
 *
 * Contents: Definitions and declarations for converting between a most-
 *           significant-first byte stream and a uint32_t array.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_MSBYTE_UINT32_H
#define NTRU_CRYPTO_MSBYTE_UINT32_H

#include "ntru_crypto_platform.h"

/* ntru_crypto_msbyte_2_uint32()
 *
 * This routine converts an array of bytes in network byte order to an array
 * of uint32_t, placing the first byte in the most significant byte of the
 * first uint32_t word.
 *
 * The number of bytes in the input stream MUST be at least 4 times the
 * number of words expected in the output array.
 */

extern void
ntru_crypto_msbyte_2_uint32(
    uint32_t *words,      /* out - pointer to the output uint32_t array */
    uint8_t const *bytes, /*  in - pointer to the input byte array */
    uint32_t n);          /*  in - number of words in the output array */

/* ntru_crypto_uint32_2_msbyte()
 *
 * This routine converts an array of uint32_t to an array of bytes in
 * network byte order, placing the most significant byte of the first uint32_t
 * word as the first byte of the output array.
 *
 * The number of bytes in the output stream will be 4 times the number of words
 * specified in the input array.
 */

extern void
ntru_crypto_uint32_2_msbyte(
    uint8_t *bytes,        /* out - pointer to the output byte array */
    uint32_t const *words, /*  in - pointer to the input uint32_t array */
    uint32_t n);           /*  in - number of words in the input array */

#endif /* NTRU_CRYPTO_MSBYTE_UINT32_H */
