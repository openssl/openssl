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
 * File: ntru_crypto_ntru_mgf1.c
 *
 * Contents: Routines implementing MGF-TP-1 and MGF-1.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_mgf1.h"
#include "ntru_crypto_ntru_convert.h"

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

uint32_t
ntru_mgf1(
    uint8_t *state,               /* in/out - pointer to the state */
    NTRU_CRYPTO_HASH_ALGID algid, /*     in - hash algorithm ID */
    uint8_t md_len,               /*     in - no. of octets in digest */
    uint8_t num_calls,            /*     in - no. of hash calls */
    uint16_t seed_len,            /*     in - no. of octets in seed */
    uint8_t const *seed,          /*     in - pointer to seed */
    uint8_t *out)                 /*    out - address for output */
{
	uint8_t *ctr = state + md_len;
	uint32_t retcode;

	/* if seed present, init state */

	if (seed) {
		if ((retcode = ntru_crypto_hash_digest(algid, seed, seed_len, state)) !=
		    NTRU_CRYPTO_HASH_OK) {
			return retcode;
		}

		memset(ctr, 0, 4);
	}

	/* generate output */

	while (num_calls-- > 0) {
		if ((retcode = ntru_crypto_hash_digest(algid, state, md_len + 4,
		                                       out)) != NTRU_CRYPTO_HASH_OK) {
			return retcode;
		}

		out += md_len;

		/* increment counter */

		if (++ctr[3] == 0) {
			if (++ctr[2] == 0) {
				if (++ctr[1] == 0) {
					++ctr[0];
				}
			}
		}
	}

	NTRU_RET(NTRU_OK);
}

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

uint32_t
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
    uint8_t *mask)                     /* out - address for mask trits */
{
	uint8_t *mgf_out;
	uint8_t *octets;
	uint16_t octets_available;
	uint32_t retcode;

	/* generate minimum MGF1 output */

	mgf_out = buf + md_len + 4;
	if ((retcode = ntru_mgf1(buf, hash_algid, md_len, min_calls,
	                         seed_len, seed, mgf_out)) != NTRU_OK) {
		return retcode;
	}

	octets = mgf_out;
	octets_available = min_calls * md_len;

	/* get trits for mask */

	while (num_trits_needed >= 5) {
		/* get another octet and convert it to 5 trits */

		if (octets_available == 0) {
			if ((retcode = ntru_mgf1(buf, hash_algid, md_len, 1,
			                         0, NULL, mgf_out)) != NTRU_OK) {
				return retcode;
			}

			octets = mgf_out;
			octets_available = md_len;
		}

		if (*octets < 243) {
			ntru_octet_2_trits(*octets, mask);
			mask += 5;
			num_trits_needed -= 5;
		}

		octets++;
		--octets_available;
	}

	/* get any remaining trits */

	while (num_trits_needed) {
		uint8_t trits[5];

		/* get another octet and convert it to remaining trits */

		if (octets_available == 0) {
			if ((retcode = ntru_mgf1(buf, hash_algid, md_len, 1,
			                         0, NULL, mgf_out)) != NTRU_OK) {
				return retcode;
			}

			octets = mgf_out;
			octets_available = md_len;
		}

		if (*octets < 243) {
			ntru_octet_2_trits(*octets, trits);
			memcpy(mask, trits, num_trits_needed);
			num_trits_needed = 0;
		} else {
			octets++;
			--octets_available;
		}
	}

	NTRU_RET(NTRU_OK);
}
