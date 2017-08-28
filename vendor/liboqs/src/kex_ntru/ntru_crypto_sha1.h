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
 * File: ntru_crypto_sha1.h
 *
 * Contents: Definitions and declarations for the SHA-1 implementation.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_SHA1_H
#define NTRU_CRYPTO_SHA1_H

#include "ntru_crypto_platform.h"
#include "ntru_crypto_sha.h"

/******************************************
 * macros needed for generic hash objects * 
 ******************************************/

#define SHA_1_CTX_LEN sizeof(SHA1_CTX)           /* no. bytes in SHA-1 ctx */
#define SHA_1_BLK_LEN 64                         /* 64 bytes in input block */
#define SHA_1_MD_LEN 20                          /* 20 bytes in msg digest */
#define SHA_1_INIT_FN &ntru_crypto_sha1_init     /* init function */
#define SHA_1_UPDATE_FN &ntru_crypto_sha1_update /* update function */
#define SHA_1_FINAL_FN &ntru_crypto_sha1_final   /* final function */
#define SHA_1_DIGEST_FN &ntru_crypto_sha1_digest /* digest function */

/*************************
 * structure definitions *
 *************************/

/* SHA-1 context structure */

typedef struct {
	uint32_t state[5];           /* chaining state */
	uint32_t num_bits_hashed[2]; /* number of bits hashed */
	uint8_t unhashed[64];        /* input data not yet hashed */
	uint32_t unhashed_len;       /* number of bytes of unhashed input data */
} NTRU_CRYPTO_SHA1_CTX;

/*************************
 * function declarations *
 *************************/

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
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

extern uint32_t
ntru_crypto_sha1(
    NTRU_CRYPTO_SHA1_CTX *c, /* in/out - pointer to SHA-1 context */
    uint32_t const *init,    /*     in - pointer to alternate */
                             /*          initialization - may be NULL */
    uint8_t const *in,       /*     in - pointer to input data -
                                                may be NULL if in_len == 0 */
    uint32_t in_len,         /*     in - number of input data bytes */
    uint32_t flags,          /*     in - INIT, FINISH */
    uint8_t *md);            /*    out - address for message digest -
                                                may be NULL if not FINISH */

/* ntru_crypto_sha1_init
 *
 * This routine performs standard initialization of the SHA-1 state.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 */

extern uint32_t
ntru_crypto_sha1_init(
    NTRU_CRYPTO_SHA1_CTX *c); /* in/out - pointer to SHA-1 context */

/* ntru_crypto_sha1_update
 *
 * This routine processes input data and updates the SHA-1 hash calculation.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

extern uint32_t
ntru_crypto_sha1_update(
    NTRU_CRYPTO_SHA1_CTX *c, /* in/out - pointer to SHA-1 context */
    uint8_t const *data,     /*    in - pointer to input data */
    uint32_t data_len);      /*    in - number of bytes of input data */

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

extern uint32_t
ntru_crypto_sha1_final(
    NTRU_CRYPTO_SHA1_CTX *c, /* in/out - pointer to SHA-1 context */
    uint8_t *md);            /*   out - address for message digest */

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
    uint8_t *md);        /* out - address for message digest */

#endif /* NTRU_CRYPTO_SHA1_H */
