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
 * File: ntru_crypto_sha256.c
 *
 * Contents: Routines implementing the SHA-256 hash calculations.
 *
 *****************************************************************************/

#include "ntru_crypto_sha256.h"

/* ntru_crypto_sha256_init
 *
 * This routine performs standard initialization of the SHA-256 state.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 */

uint32_t
ntru_crypto_sha256_init(
    NTRU_CRYPTO_SHA2_CTX *c) /* in/out - pointer to SHA-2 context */
{
	return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, NULL, 0,
	                        SHA_INIT, NULL);
}

/* ntru_crypto_sha256_update
 *
 * This routine processes input data and updates the SHA-256 hash calculation.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha256_update(
    NTRU_CRYPTO_SHA2_CTX *c, /* in/out - pointer to SHA-2 context */
    uint8_t const *data,     /*     in - pointer to input data */
    uint32_t data_len)       /*     in - no. of bytes of input data */
{
	return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, data,
	                        data_len, SHA_DATA_ONLY, NULL);
}

/* ntru_crypto_sha256_final
 *
 * This routine completes the SHA-256 hash calculation and returns the
 * message digest.
 * 
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha256_final(
    NTRU_CRYPTO_SHA2_CTX *c, /* in/out - pointer to SHA-2 context */
    uint8_t *md)             /*    out - address for message digest */
{
	return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, NULL, 0,
	                        SHA_FINISH, md);
}

/* ntru_crypto_sha256_digest
 *
 * This routine computes a SHA-256 message digest.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha256_digest(
    uint8_t const *data, /*  in - pointer to input data */
    uint32_t data_len,   /*  in - number of bytes of input data */
    uint8_t *md)         /* out - address for message digest */
{
	NTRU_CRYPTO_SHA2_CTX c;

	return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, &c, NULL, data,
	                        data_len, SHA_INIT | SHA_FINISH, md);
}
