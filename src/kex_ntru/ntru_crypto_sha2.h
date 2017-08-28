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
 * File: ntru_crypto_sha2.h
 *
 * Contents: Definitions and declarations for the SHA-256 implementation.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_SHA2_H
#define NTRU_CRYPTO_SHA2_H

#include "ntru_crypto_platform.h"
#include "ntru_crypto_sha.h"

/*************************
 * structure definitions *
 *************************/

/* SHA-256 context structure */

typedef struct {
	uint32_t state[8];           /* chaining state */
	uint32_t num_bits_hashed[2]; /* number of bits hashed */
	uint8_t unhashed[64];        /* input data not yet hashed */
	uint32_t unhashed_len;       /* number of bytes of unhashed input data */
} NTRU_CRYPTO_SHA2_CTX;

/*************************
 * function declarations *
 *************************/

/* ntru_crypto_sha2()
 *
 * This routine provides all operations for a SHA-256 hash,
 * and the use of SHA-256 for DSA signing and key generation.
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
 * points to the array of eight alternate initialization 32-bit words.
 *
 * The hash operation can be updated with any number of input bytes, including
 * zero.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

extern uint32_t
ntru_crypto_sha2(
    NTRU_CRYPTO_HASH_ALGID algid, /*     in - hash algorithm ID */
    NTRU_CRYPTO_SHA2_CTX *c,      /* in/out - pointer to SHA-2 context */
    uint32_t const *init,         /*     in - pointer to alternate */
                                  /*          initialization - may be NULL */
    uint8_t const *in,            /*     in - pointer to input data -
                                                may be NULL if in_len == 0 */
    uint32_t in_len,              /*     in - number of input data bytes */
    uint32_t flags,               /*     in - INIT, FINISH */
    uint8_t *md);                 /*    out - address for message digest -
                                                may be NULL if not FINISH */

#endif /* NTRU_CRYPTO_SHA2_H */
