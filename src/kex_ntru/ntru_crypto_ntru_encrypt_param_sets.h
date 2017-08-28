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
 * File: ntru_crypto_ntru_encrypt_param_sets.h
 *
 * Contents: Definitions and declarations for the NTRUEncrypt parameter sets.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_NTRU_ENCRYPT_PARAM_SETS_H
#define NTRU_CRYPTO_NTRU_ENCRYPT_PARAM_SETS_H

#include "ntru_crypto.h"
#include "ntru_crypto_hash_basics.h"

/* structures */

typedef struct _NTRU_ENCRYPT_PARAM_SET {
	NTRU_ENCRYPT_PARAM_SET_ID id;      /* parameter-set ID */
	const char *name;                  /* human readable param set name */
	uint8_t const OID[3];              /* pointer to OID */
	uint8_t der_id;                    /* parameter-set DER id */
	uint8_t N_bits;                    /* no. of bits in N (i.e. in
                                                     an index */
	uint16_t N;                        /* ring dimension */
	uint16_t sec_strength_len;         /* no. of octets of
                                                     security strength */
	uint16_t b_len;                    /* no. of octets for random
                                                     string b */
	uint16_t q;                        /* big modulus */
	uint8_t q_bits;                    /* no. of bits in q (i.e. in
                                                     a coefficient */
	bool is_product_form;              /* if product form used */
	uint32_t dF_r;                     /* no. of 1 or -1 coefficients
                                                     in ring elements F, r */
	uint16_t dg;                       /* no. - 1 of 1 coefficients
                                                     or no. of -1 coefficients
                                                     in ring element g */
	uint16_t m_len_max;                /* max no. of plaintext
                                                     octets */
	uint16_t min_msg_rep_wt;           /* min. message
                                                     representative weight */
	uint16_t no_bias_limit;            /* limit for no bias in
                                                     IGF-2 */
	uint8_t c_bits;                    /* no. bits in candidate for
                                                     deriving an index in
                                                     IGF-2 */
	uint8_t m_len_len;                 /* no. of octets to hold
                                                     mLenOctets */
	uint8_t min_IGF_hash_calls;        /* min. no. of hash calls for
                                                     IGF-2 */
	uint8_t min_MGF_hash_calls;        /* min. no. of hash calls for
                                                     MGF-TP-1 */
	NTRU_CRYPTO_HASH_ALGID hash_algid; /* hash function for MGF-TP-1,
                                                     HMAC-DRBG, etc. */
} NTRU_ENCRYPT_PARAM_SET;

/* function declarations */

/* ntru_encrypt_get_params_with_id
 *
 * Looks up a set of NTRU Encrypt parameters based on the id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

extern NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_id(
    NTRU_ENCRYPT_PARAM_SET_ID id); /*  in - parameter-set id */

/* ntru_encrypt_get_params_with_OID
 *
 * Looks up a set of NTRU Encrypt parameters based on the OID of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

extern NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_OID(
    uint8_t const *oid); /*  in - pointer to parameter-set OID */

/* ntru_encrypt_get_params_with_DER_id
 *
 * Looks up a set of NTRUEncrypt parameters based on the DER id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

extern NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_DER_id(
    uint8_t der_id); /*  in - parameter-set DER id */

#endif /* NTRU_CRYPTO_NTRU_ENCRYPT_PARAM_SETS_H */
