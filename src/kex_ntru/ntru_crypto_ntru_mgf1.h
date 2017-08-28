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
 * File:  ntru_crypto_ntru_mgf1.h
 *
 * Contents: Public header file for MGF-1 in the NTRU algorithm.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_NTRU_MGF1_H
#define NTRU_CRYPTO_NTRU_MGF1_H

#include "ntru_crypto.h"
#include "ntru_crypto_hash.h"

/* function declarations */

/* ntru_mgf1
 *
 * Implements a basic mask-generation function, generating an arbitrary
 * number of octets based on hashing a digest-length string concatenated
 * with a 4-octet counter.
 *
 * The state (string and counter) is initialized when a seed is present.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_CRYPTO_HASH_ errors if they occur.
 *
 */

extern uint32_t
ntru_mgf1(
    uint8_t *state,               /* in/out - pointer to the state */
    NTRU_CRYPTO_HASH_ALGID algid, /*     in - hash algorithm ID */
    uint8_t md_len,               /*     in - no. of octets in digest */
    uint8_t num_calls,            /*     in - no. of hash calls */
    uint16_t seed_len,            /*     in - no. of octets in seed */
    uint8_t const *seed,          /*     in - pointer to seed */
    uint8_t *out);                /*    out - address for output */

/* ntru_mgftp1
 *
 * Implements a mask-generation function for trinary polynomials,
 * MGF-TP-1, generating an arbitrary number of octets based on hashing
 * a digest-length string concatenated with a 4-octet counter.  From
 * these octets, N trits are derived.
 *
 * The state (string and counter) is initialized when a seed is present.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_CRYPTO_HASH_ errors if they occur.
 *
 */

extern uint32_t
ntru_mgftp1(
    NTRU_CRYPTO_HASH_ALGID hash_algid, /*  in - hash alg ID for
                                                       MGF-TP-1 */
    uint8_t md_len,                    /*  in - no. of octets in
                                                       digest */
    uint8_t min_calls,                 /*  in - minimum no. of hash
                                                       calls */
    uint16_t seed_len,                 /*  in - no. of octets in seed */
    uint8_t *seed,                     /*  in - pointer to seed */
    uint8_t *buf,                      /*  in - pointer to working
                                                       buffer */
    uint16_t num_trits_needed,         /*  in - no. of trits in mask */
    uint8_t *mask);                    /* out - address for mask trits */

#endif /* NTRU_CRYPTO_NTRU_MGF1_H */
