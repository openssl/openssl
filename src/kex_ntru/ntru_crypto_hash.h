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
 * File: ntru_crypto_hash.h
 *
 * Contents: Definitions and declarations for the hash object abstraction.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_HASH_H
#define NTRU_CRYPTO_HASH_H

#include "ntru_crypto_platform.h"
#include "ntru_crypto_error.h"
#include "ntru_crypto_hash_basics.h"
#include "ntru_crypto_sha1.h"
#include "ntru_crypto_sha256.h"

/***************
 * error macro *
 ***************/

#define HASH_RESULT(r) ((uint32_t)((r) ? HASH_ERROR_BASE + (r) : (r)))
#define HASH_RET(r) return HASH_RESULT(r);

/*************************
 * structure definitions *
 *************************/

/* _NTRU_CRYPTO_HASH_ALG_PARAMS
 *
 * An opaque forward declaration for a private structure used
 * internally by the hash object interface.
 */

struct _NTRU_CRYPTO_HASH_ALG_PARAMS;

/* NTRU_CRYPTO_HASH_CTX
 *
 * Hash object context information.
 */

typedef struct {
	struct _NTRU_CRYPTO_HASH_ALG_PARAMS const *alg_params;
	union {
		NTRU_CRYPTO_SHA1_CTX sha1;
		NTRU_CRYPTO_SHA2_CTX sha256;
	} alg_ctx;
} NTRU_CRYPTO_HASH_CTX;

/*************************
 * function declarations *
 *************************/

/* ntru_crypto_hash_set_alg
 *
 * Sets the hash algorithm for the hash context.  This must be called before
 * any calls to crypto_hash_block_length(), crypto_hash_digest_length(), or
 * crypto_hash_init() are made.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the specified algorithm is not supported.
 */

extern uint32_t
ntru_crypto_hash_set_alg(
    NTRU_CRYPTO_HASH_ALGID algid, /*      in - hash algoirithm to be used */
    NTRU_CRYPTO_HASH_CTX *c);     /* in/out - pointer to the hash context */

/* ntru_crypto_hash_block_length
 *
 * Gets the number of bytes in an input block for the hash algorithm
 * specified in the hash context.  The hash algorithm must have been set
 * in the hash context with a call to crypto_hash_set_alg() prior to
 * calling this function.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

extern uint32_t
ntru_crypto_hash_block_length(
    NTRU_CRYPTO_HASH_CTX *c, /*  in - pointer to the hash context */
    uint16_t *blk_len);      /* out - address for block length in bytes */

/* ntru_crypto_hash_digest_length
 *
 * Gets the number of bytes needed to hold the message digest for the
 * hash algorithm specified in the hash context.  The algorithm must have
 * been set in the hash context with a call to crypto_hash_set_alg() prior
 * to calling this function.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

extern uint32_t
ntru_crypto_hash_digest_length(
    NTRU_CRYPTO_HASH_CTX const *c, /*  in - pointer to the hash context */
    uint16_t *md_len);             /*out - addr for digest length in bytes*/

/* ntru_crypto_hash_init
 *
 * This routine initializes the hash state.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

extern uint32_t
ntru_crypto_hash_init(
    NTRU_CRYPTO_HASH_CTX *c); /* in/out - pointer to hash context */

/* ntru_crypto_hash_update
 *
 * This routine processes input data and updates the hash calculation.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_OVERFLOW if too much text has been fed to the
 *         hash algorithm. The size limit is dependent on the hash algorithm,
 *         and not all algorithms have this limit.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

extern uint32_t
ntru_crypto_hash_update(
    NTRU_CRYPTO_HASH_CTX *c, /* in/out - pointer to hash context */
    uint8_t const *data,     /*     in - pointer to input data */
    uint32_t data_len);      /*     in - number of bytes of input data */

/* ntru_crypto_hash_final
 *
 * This routine completes the hash calculation and returns the message digest.
 * 
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

extern uint32_t
ntru_crypto_hash_final(
    NTRU_CRYPTO_HASH_CTX *c, /* in/out - pointer to hash context */
    uint8_t *md);            /*   out  - address for message digest */

/* ntru_crypto_hash_digest
 *
 * This routine computes a message digest. It is assumed that the
 * output buffer md is large enough to hold the output (see
 * crypto_hash_digest_length)
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns NTRU_CRYPTO_HASH_OVERFLOW if too much text has been fed to the
 *         hash algorithm. The size limit is dependent on the hash algorithm,
 *         and not all algorithms have this limit.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the specified algorithm is not supported.
 */

extern uint32_t
ntru_crypto_hash_digest(
    NTRU_CRYPTO_HASH_ALGID algid, /*  in - the hash algorithm to use */
    uint8_t const *data,          /*  in - pointer to input data */
    uint32_t data_len,            /*  in - number of bytes of input data */
    uint8_t *md);                 /* out - address for message digest */

#endif /* NTRU_CRYPTO_HASH_H */
