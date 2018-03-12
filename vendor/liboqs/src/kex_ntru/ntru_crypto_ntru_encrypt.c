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
 * File: ntru_crypto_ntru_encrypt.c
 *
 * Contents: Routines implementing NTRUEncrypt encryption and decryption and
 *           key generation.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_encrypt_param_sets.h"
#include "ntru_crypto_ntru_encrypt_key.h"
#include "ntru_crypto_ntru_convert.h"
#include "ntru_crypto_ntru_poly.h"
#include "ntru_crypto_ntru_mgf1.h"
#include "ntru_crypto_drbg.h"

/* ntru_crypto_ntru_encrypt
 *
 * Implements NTRU encryption (SVES) for the parameter set specified in
 * the public key blob.
 *
 * Before invoking this function, a DRBG must be instantiated using
 * ntru_crypto_drbg_instantiate() to obtain a DRBG handle, and in that
 * instantiation the requested security strength must be at least as large
 * as the security strength of the NTRU parameter set being used.
 * Failure to instantiate the DRBG with the proper security strength will
 * result in this function returning DRBG_ERROR_BASE + DRBG_BAD_LENGTH.
 *
 * The required minimum size of the output ciphertext buffer (ct) may be
 * queried by invoking this function with ct = NULL.  In this case, no
 * encryption is performed, NTRU_OK is returned, and the required minimum
 * size for ct is returned in ct_len.
 *
 * When ct != NULL, at invocation *ct_len must be the size of the ct buffer.
 * Upon return it is the actual size of the ciphertext.
 *
 * Returns NTRU_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_PARAMETER if the DRBG handle is invalid.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_PARAMETER if an argument pointer
 *  (other than ct) is NULL.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_LENGTH if a length argument
 *  (pubkey_blob_len or pt_len) is zero, or if pt_len exceeds the
 *  maximum plaintext length for the parameter set.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_PUBLIC_KEY if the public-key blob is
 *  invalid (unknown format, corrupt, bad length).
 * Returns NTRU_ERROR_BASE + NTRU_BUFFER_TOO_SMALL if the ciphertext buffer
 *  is too small.
 * Returns NTRU_ERROR_BASE + NTRU_NO_MEMORY if memory needed cannot be
 *  allocated from the heap.
 */

uint32_t
ntru_crypto_ntru_encrypt(
    DRBG_HANDLE drbg_handle,    /*     in - handle of DRBG */
    uint16_t pubkey_blob_len,   /*     in - no. of octets in public key
                                                 blob */
    uint8_t const *pubkey_blob, /*     in - pointer to public key */
    uint16_t pt_len,            /*     in - no. of octets in plaintext */
    uint8_t const *pt,          /*     in - pointer to plaintext */
    uint16_t *ct_len,           /* in/out - no. of octets in ct, addr for
                                                 no. of octets in ciphertext */
    uint8_t *ct)                /*    out - address for ciphertext */
{
	NTRU_ENCRYPT_PARAM_SET *params = NULL;
	uint8_t const *pubkey_packed = NULL;
	uint8_t pubkey_pack_type = 0x00;
	uint16_t packed_ct_len;
	size_t scratch_buf_len;
	uint32_t dr;
	uint32_t dr1 = 0;
	uint32_t dr2 = 0;
	uint32_t dr3 = 0;
	uint16_t num_scratch_polys;
	uint16_t pad_deg;
	uint16_t ring_mult_tmp_len;
	uint16_t *scratch_buf = NULL;
	uint16_t *ringel_buf = NULL;
	uint16_t *r_buf = NULL;
	uint8_t *b_buf = NULL;
	uint8_t *tmp_buf = NULL;
	bool msg_rep_good = FALSE;
	NTRU_CRYPTO_HASH_ALGID hash_algid;
	uint8_t md_len;
	uint16_t mod_q_mask;
	uint32_t result = NTRU_OK;

	/* check for bad parameters */

	if (!pubkey_blob || !ct_len) {
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	if (pubkey_blob_len == 0) {
		NTRU_RET(NTRU_BAD_LENGTH);
	}

	/* get a pointer to the parameter-set parameters, the packing type for
     * the public key, and a pointer to the packed public key
     */

	if (!ntru_crypto_ntru_encrypt_key_parse(TRUE /* pubkey */, pubkey_blob_len,
	                                        pubkey_blob, &pubkey_pack_type,
	                                        NULL, &params, &pubkey_packed,
	                                        NULL)) {
		NTRU_RET(NTRU_BAD_PUBLIC_KEY);
	}

	if (params->q_bits <= 8 || params->q_bits >= 16 || pubkey_pack_type != NTRU_ENCRYPT_KEY_PACKED_COEFFICIENTS) {
		NTRU_RET(NTRU_UNSUPPORTED_PARAM_SET);
	}

	/* return the ciphertext size if requested */

	packed_ct_len = (params->N * params->q_bits + 7) >> 3;

	if (!ct) {
		*ct_len = packed_ct_len;
		NTRU_RET(NTRU_OK);
	}

	/* check the ciphertext buffer size */

	if (*ct_len < packed_ct_len) {
		NTRU_RET(NTRU_BUFFER_TOO_SMALL);
	}

	/* check that a plaintext was provided */

	if (!pt) {
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	/* check the plaintext length */

	if (pt_len > params->m_len_max) {
		NTRU_RET(NTRU_BAD_LENGTH);
	}

	/* allocate memory for all operations */

	ntru_ring_mult_indices_memreq(params->N, &num_scratch_polys, &pad_deg);

	if (params->is_product_form) {
		dr1 = params->dF_r & 0xff;
		dr2 = (params->dF_r >> 8) & 0xff;
		dr3 = (params->dF_r >> 16) & 0xff;
		dr = dr1 + dr2 + dr3;
		num_scratch_polys += 1; /* mult_product_indices needs space for a
                                   mult_indices and one intermediate result */
	} else {
		dr = params->dF_r;
	}
	ring_mult_tmp_len = num_scratch_polys * pad_deg;

	scratch_buf_len = (ring_mult_tmp_len << 1) +
	                  /* X-byte temp buf for ring mult and
                                                other intermediate results */
	                  (pad_deg << 1) + /* 2N-byte buffer for ring elements
                                                and overflow from temp buffer */
	                  (dr << 2) +      /* buffer for r indices */
	                  params->b_len;
	/* buffer for b */
	scratch_buf = MALLOC(scratch_buf_len);
	if (!scratch_buf) {
		NTRU_RET(NTRU_OUT_OF_MEMORY);
	}

	ringel_buf = scratch_buf + ring_mult_tmp_len;
	r_buf = ringel_buf + pad_deg;
	b_buf = (uint8_t *) (r_buf + (dr << 1));
	tmp_buf = (uint8_t *) scratch_buf;

	/* set hash algorithm and seed length based on security strength */

	if (params->hash_algid == NTRU_CRYPTO_HASH_ALGID_SHA1) {
		hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA1;
		md_len = SHA_1_MD_LEN;
	} else if (params->hash_algid == NTRU_CRYPTO_HASH_ALGID_SHA256) {
		hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA256;
		md_len = SHA_256_MD_LEN;
	} else {
		FREE(scratch_buf);
		NTRU_RET(NTRU_UNSUPPORTED_PARAM_SET);
	}

	/* set constants */

	mod_q_mask = params->q - 1;

	/* loop until a message representative with proper weight is achieved */

	do {
		uint8_t *ptr = tmp_buf;

		/* get b */
		result = ntru_crypto_drbg_generate(drbg_handle,
		                                   params->sec_strength_len << 3,
		                                   params->b_len, b_buf);

		if (result == NTRU_OK) {
			/* form sData (OID || m || b || hTrunc) */

			memcpy(ptr, params->OID, 3);
			ptr += 3;
			memcpy(ptr, pt, pt_len);
			ptr += pt_len;
			memcpy(ptr, b_buf, params->b_len);
			ptr += params->b_len;
			memcpy(ptr, pubkey_packed, params->sec_strength_len);
			ptr += params->sec_strength_len;

			/* generate r */

			result = ntru_gen_poly(hash_algid, md_len,
			                       params->min_IGF_hash_calls,
			                       (uint16_t)(ptr - tmp_buf),
			                       tmp_buf, tmp_buf,
			                       params->N, params->c_bits,
			                       params->no_bias_limit,
			                       params->is_product_form,
			                       params->dF_r << 1, r_buf);
		}

		if (result == NTRU_OK) {
			uint16_t pubkey_packed_len;

			/* unpack the public key */
			pubkey_packed_len = (params->N * params->q_bits + 7) >> 3;
			ntru_octets_2_elements(pubkey_packed_len, pubkey_packed,
			                       params->q_bits, ringel_buf);

			/* form R = h * r */

			if (params->is_product_form) {
				ntru_ring_mult_product_indices(ringel_buf, (uint16_t) dr1,
				                               (uint16_t) dr2, (uint16_t) dr3,
				                               r_buf, params->N, params->q,
				                               scratch_buf, ringel_buf);
			} else {
				ntru_ring_mult_indices(ringel_buf, (uint16_t) dr, (uint16_t) dr,
				                       r_buf, params->N, params->q,
				                       scratch_buf, ringel_buf);
			}

			/* form R mod 4 */

			ntru_coeffs_mod4_2_octets(params->N, ringel_buf, tmp_buf);

			/* form mask */

			result = ntru_mgftp1(hash_algid, md_len,
			                     params->min_MGF_hash_calls,
			                     (params->N + 3) / 4, tmp_buf,
			                     tmp_buf + params->N, params->N, tmp_buf);
		}

		if (result == NTRU_OK) {
			uint8_t *Mtrin_buf = tmp_buf + params->N;
			uint8_t *M_buf = Mtrin_buf + params->N -
			                 (params->b_len + params->m_len_len +
			                  params->m_len_max + 2);
			uint16_t i;

			/* form the padded message M */

			ptr = M_buf;
			memcpy(ptr, b_buf, params->b_len);
			ptr += params->b_len;
			if (params->m_len_len == 2)
				*ptr++ = (uint8_t)((pt_len >> 8) & 0xff);
			*ptr++ = (uint8_t)(pt_len & 0xff);
			memcpy(ptr, pt, pt_len);
			ptr += pt_len;

			/* add an extra zero byte in case without it the bit string
             * is not a multiple of 3 bits and therefore might not be
             * able to produce enough trits
             */

			memset(ptr, 0, params->m_len_max - pt_len + 2);

			/* convert M to trits (Mbin to Mtrin) */

			ntru_bits_2_trits(M_buf, params->N, Mtrin_buf);

			/* form the msg representative m' by adding Mtrin to mask, mod p */

			for (i = 0; i < params->N; i++) {
				tmp_buf[i] = tmp_buf[i] + Mtrin_buf[i];

				if (tmp_buf[i] >= 3) {
					tmp_buf[i] -= 3;
				}
			}

			/* check that message representative meets minimum weight
             * requirements
             */
			msg_rep_good = ntru_poly_check_min_weight(params->N, tmp_buf,
			                                          params->min_msg_rep_wt);
		}
	} while ((result == NTRU_OK) && !msg_rep_good);

	if (result == NTRU_OK) {
		uint16_t i;

		/* form ciphertext e by adding m' to R mod q */

		for (i = 0; i < params->N; i++) {
			if (tmp_buf[i] == 1) {
				ringel_buf[i] = (ringel_buf[i] + 1) & mod_q_mask;
			} else if (tmp_buf[i] == 2) {
				ringel_buf[i] = (ringel_buf[i] - 1) & mod_q_mask;
			} else {
				;
			}
		}

		/* pack ciphertext */

		ntru_elements_2_octets(params->N, ringel_buf, params->q_bits, ct);
		*ct_len = packed_ct_len;
	}

	/* cleanup */

	memset(scratch_buf, 0, scratch_buf_len);
	FREE(scratch_buf);

	return result;
}

/* ntru_crypto_ntru_decrypt
 *
 * Implements NTRU decryption (SVES) for the parameter set specified in
 * the private key blob.
 *
 * The maximum size of the output plaintext may be queried by invoking
 * this function with pt = NULL.  In this case, no decryption is performed,
 * NTRU_OK is returned, and the maximum size the plaintext could be is
 * returned in pt_len.
 * Note that until the decryption is performed successfully, the actual size
 * of the resulting plaintext cannot be known.
 *
 * When pt != NULL, at invocation *pt_len must be the size of the pt buffer.
 * Upon return it is the actual size of the plaintext.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_PARAMETER if an argument pointer
 *  (other than pt) is NULL.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_LENGTH if a length argument
 *  (privkey_blob) is zero, or if ct_len is invalid for the parameter set.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_PRIVATE_KEY if the private-key blob is
 *  invalid (unknown format, corrupt, bad length).
 * Returns NTRU_ERROR_BASE + NTRU_BUFFER_TOO_SMALL if the plaintext buffer
 *  is too small.
 * Returns NTRU_ERROR_BASE + NTRU_NO_MEMORY if memory needed cannot be
 *  allocated from the heap.
 * Returns NTRU_ERROR_BASE + NTRU_FAIL if a decryption error occurs.
 */

uint32_t
ntru_crypto_ntru_decrypt(
    uint16_t privkey_blob_len,   /*     in - no. of octets in private key
                                                 blob */
    uint8_t const *privkey_blob, /*     in - pointer to private key */
    uint16_t ct_len,             /*     in - no. of octets in ciphertext */
    uint8_t const *ct,           /*     in - pointer to ciphertext */
    uint16_t *pt_len,            /* in/out - no. of octets in pt, addr for
                                                 no. of octets in plaintext */
    uint8_t *pt)                 /*    out - address for plaintext */
{
	NTRU_ENCRYPT_PARAM_SET *params = NULL;
	uint8_t const *privkey_packed = NULL;
	uint8_t const *pubkey_packed = NULL;
	uint8_t privkey_pack_type = 0x00;
	uint8_t pubkey_pack_type = 0x00;
	size_t scratch_buf_len;
	uint32_t dF_r;
	uint32_t dF_r1 = 0;
	uint32_t dF_r2 = 0;
	uint32_t dF_r3 = 0;
	uint16_t num_scratch_polys;
	uint16_t pad_deg;
	uint16_t ring_mult_tmp_len;
	uint16_t *scratch_buf = NULL;
	uint16_t *ringel_buf1 = NULL;
	uint16_t *ringel_buf2 = NULL;
	uint16_t *i_buf = NULL;
	uint8_t *m_buf = NULL;
	uint8_t *tmp_buf = NULL;
	uint8_t *Mtrin_buf = NULL;
	uint8_t *M_buf = NULL;
	uint8_t *ptr = NULL;
	NTRU_CRYPTO_HASH_ALGID hash_algid;
	uint8_t md_len;
	uint16_t mod_q_mask;
	uint16_t q_mod_p;
	uint16_t cm_len = 0;
	uint16_t num_zeros;
	uint16_t i;
	bool decryption_ok = TRUE;
	uint32_t result = NTRU_OK;

	/* check for bad parameters */

	if (!privkey_blob || !pt_len) {
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	if (privkey_blob_len == 0) {
		NTRU_RET(NTRU_BAD_LENGTH);
	}

	/* get a pointer to the parameter-set parameters, the packing types for
     * the public and private keys, and pointers to the packed public and
     * private keys
     */

	if (!ntru_crypto_ntru_encrypt_key_parse(FALSE /* privkey */,
	                                        privkey_blob_len,
	                                        privkey_blob, &pubkey_pack_type,
	                                        &privkey_pack_type, &params,
	                                        &pubkey_packed, &privkey_packed)) {
		NTRU_RET(NTRU_BAD_PRIVATE_KEY);
	}

	if (params->q_bits <= 8 || params->q_bits >= 16 || params->N_bits <= 8 || params->N_bits >= 16 || pubkey_pack_type != NTRU_ENCRYPT_KEY_PACKED_COEFFICIENTS || (privkey_pack_type != NTRU_ENCRYPT_KEY_PACKED_TRITS && privkey_pack_type != NTRU_ENCRYPT_KEY_PACKED_INDICES)) {
		NTRU_RET(NTRU_UNSUPPORTED_PARAM_SET);
	}

	/* return the max plaintext size if requested */

	if (!pt) {
		*pt_len = params->m_len_max;
		NTRU_RET(NTRU_OK);
	}

	/* check that a ciphertext was provided */

	if (!ct) {
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	/* cannot check the plaintext buffer size until after the plaintext
     * is derived, if we allow plaintext buffers only as large as the
     * actual plaintext
     */

	/* check the ciphertext length */

	if (ct_len != (params->N * params->q_bits + 7) >> 3) {
		NTRU_RET(NTRU_BAD_LENGTH);
	}

	/* allocate memory for all operations */

	ntru_ring_mult_indices_memreq(params->N, &num_scratch_polys, &pad_deg);

	if (params->is_product_form) {
		dF_r1 = params->dF_r & 0xff;
		dF_r2 = (params->dF_r >> 8) & 0xff;
		dF_r3 = (params->dF_r >> 16) & 0xff;
		dF_r = dF_r1 + dF_r2 + dF_r3;
		num_scratch_polys += 1; /* mult_product_indices needs space for a
                                   mult_indices and one intermediate result */
	} else {
		dF_r = params->dF_r;
	}
	ring_mult_tmp_len = num_scratch_polys * pad_deg;

	scratch_buf_len = (ring_mult_tmp_len << 1) +
	                  /* X-byte temp buf for ring mult and
                                                other intermediate results */
	                  (pad_deg << 2) +   /* 2 2N-byte bufs for ring elements
                                                and overflow from temp buffer */
	                  (dF_r << 2) +      /* buffer for F, r indices */
	                  params->m_len_max; /* buffer for plaintext */

	scratch_buf = MALLOC(scratch_buf_len);
	if (!scratch_buf) {
		NTRU_RET(NTRU_OUT_OF_MEMORY);
	}

	ringel_buf1 = scratch_buf + ring_mult_tmp_len;
	ringel_buf2 = ringel_buf1 + pad_deg;
	i_buf = ringel_buf2 + pad_deg;
	m_buf = (uint8_t *) (i_buf + (dF_r << 1));
	tmp_buf = (uint8_t *) scratch_buf;
	Mtrin_buf = (uint8_t *) ringel_buf1;
	M_buf = Mtrin_buf + params->N;

	/* set hash algorithm and seed length based on security strength */

	if (params->hash_algid == NTRU_CRYPTO_HASH_ALGID_SHA1) {
		hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA1;
		md_len = SHA_1_MD_LEN;
	} else if (params->hash_algid == NTRU_CRYPTO_HASH_ALGID_SHA256) {
		hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA256;
		md_len = SHA_256_MD_LEN;
	} else {
		FREE(scratch_buf);
		NTRU_RET(NTRU_UNSUPPORTED_PARAM_SET);
	}

	/* set constants */

	mod_q_mask = params->q - 1;
	q_mod_p = params->q % 3;

	/* unpack the ciphertext */

	ntru_octets_2_elements(ct_len, ct, params->q_bits, ringel_buf2);

	/* unpack the private key */

	if (privkey_pack_type == NTRU_ENCRYPT_KEY_PACKED_TRITS) {
		ntru_packed_trits_2_indices(privkey_packed, params->N, i_buf,
		                            i_buf + dF_r);

	} else if (privkey_pack_type == NTRU_ENCRYPT_KEY_PACKED_INDICES) {
		ntru_octets_2_elements(
		    (((uint16_t) dF_r << 1) * params->N_bits + 7) >> 3,
		    privkey_packed, params->N_bits, i_buf);
	} else {
		/* Unreachable due to supported parameter set check above */
	}

	/* form cm':
     *  F * e
     *  A = e * (1 + pF) mod q = e + pFe mod q
     *  a = A in the range [-q/2, q/2)
     *  cm' = a mod p
     *
     * first compute F*e w/o reduction mod q and store in ringel_buf1
     */
	if (params->is_product_form) {
		ntru_ring_mult_product_indices(ringel_buf2, (uint16_t) dF_r1,
		                               (uint16_t) dF_r2, (uint16_t) dF_r3,
		                               i_buf, params->N, params->q,
		                               scratch_buf, ringel_buf1);
	} else {
		ntru_ring_mult_indices(ringel_buf2, (uint16_t) dF_r, (uint16_t) dF_r,
		                       i_buf, params->N, params->q,
		                       scratch_buf, ringel_buf1);
	}

	/* then let ringel_buf1 = e + 3*ringel_buf1 (mod q) = e + pFe mod q
     * lift ringel_buf1 elements to integers in the range [-q/2, q/2)
     * let Mtrin_buf = ringel_buf1 (mod 3) = cm'
     */
	for (i = 0; i < params->N; i++) {
		ringel_buf1[i] = (ringel_buf2[i] + 3 * ringel_buf1[i]) & mod_q_mask;

		if (ringel_buf1[i] >= (params->q >> 1)) {
			ringel_buf1[i] = ringel_buf1[i] - q_mod_p;
		}

		Mtrin_buf[i] = (uint8_t)(ringel_buf1[i] % 3);
	}

	/* check that the candidate message representative meets minimum weight
     * requirements
     */
	if (!ntru_poly_check_min_weight(params->N,
	                                Mtrin_buf, params->min_msg_rep_wt)) {
		decryption_ok = FALSE;
	}

	/* form cR = e - cm' mod q */

	for (i = 0; i < params->N; i++) {
		if (Mtrin_buf[i] == 1) {
			ringel_buf2[i] = (ringel_buf2[i] - 1) & mod_q_mask;
		} else if (Mtrin_buf[i] == 2) {
			ringel_buf2[i] = (ringel_buf2[i] + 1) & mod_q_mask;
		} else {
			;
		}
	}

	/* form cR mod 4 */

	ntru_coeffs_mod4_2_octets(params->N, ringel_buf2, tmp_buf);

	/* form mask */

	result = ntru_mgftp1(hash_algid, md_len,
	                     params->min_MGF_hash_calls,
	                     (params->N + 3) / 4, tmp_buf,
	                     tmp_buf + params->N, params->N, tmp_buf);

	if (result == NTRU_OK) {
		/* form cMtrin by subtracting mask from cm', mod p */

		for (i = 0; i < params->N; i++) {
			Mtrin_buf[i] = Mtrin_buf[i] - tmp_buf[i];

			if (Mtrin_buf[i] >= 3) {
				Mtrin_buf[i] += 3;
			}
		}

		/* convert cMtrin to cM (Mtrin to Mbin) */

		if (!ntru_trits_2_bits(Mtrin_buf, params->N, M_buf)) {
			decryption_ok = FALSE;
		}

		/* validate the padded message cM and copy cm to m_buf */

		ptr = M_buf + params->b_len;

		if (params->m_len_len == 2) {
			cm_len = (uint16_t)(*ptr++) << 8;
		}

		cm_len |= (uint16_t)(*ptr++);

		if (cm_len > params->m_len_max) {
			cm_len = params->m_len_max;
			decryption_ok = FALSE;
		}

		memcpy(m_buf, ptr, cm_len);
		ptr += cm_len;
		num_zeros = params->m_len_max - cm_len + 1;

		for (i = 0; i < num_zeros; i++) {
			if (ptr[i] != 0) {
				decryption_ok = FALSE;
			}
		}

		/* form sData (OID || m || b || hTrunc) */

		ptr = tmp_buf;
		memcpy(ptr, params->OID, 3);
		ptr += 3;
		memcpy(ptr, m_buf, cm_len);
		ptr += cm_len;
		memcpy(ptr, M_buf, params->b_len);
		ptr += params->b_len;
		memcpy(ptr, pubkey_packed, params->sec_strength_len);
		ptr += params->sec_strength_len;

		/* generate cr */

		result = ntru_gen_poly(hash_algid, md_len,
		                       params->min_IGF_hash_calls,
		                       (uint16_t)(ptr - tmp_buf),
		                       tmp_buf, tmp_buf,
		                       params->N, params->c_bits,
		                       params->no_bias_limit,
		                       params->is_product_form,
		                       params->dF_r << 1, i_buf);
	}

	if (result == NTRU_OK) {
		/* unpack the public key */

		{
			uint16_t pubkey_packed_len;
			pubkey_packed_len = (params->N * params->q_bits + 7) >> 3;
			ntru_octets_2_elements(pubkey_packed_len, pubkey_packed,
			                       params->q_bits, ringel_buf1);
		}

		/* form cR' = h * cr */

		if (params->is_product_form) {
			ntru_ring_mult_product_indices(ringel_buf1, (uint16_t) dF_r1,
			                               (uint16_t) dF_r2, (uint16_t) dF_r3,
			                               i_buf, params->N, params->q,
			                               scratch_buf, ringel_buf1);
		} else {
			ntru_ring_mult_indices(ringel_buf1, (uint16_t) dF_r, (uint16_t) dF_r,
			                       i_buf, params->N, params->q,
			                       scratch_buf, ringel_buf1);
		}

		/* compare cR' to cR */

		for (i = 0; i < params->N; i++) {
			if (ringel_buf1[i] != ringel_buf2[i]) {
				decryption_ok = FALSE;
			}
		}

		/* output plaintext and plaintext length */

		if (decryption_ok) {
			if (*pt_len < cm_len) {
				memset(scratch_buf, 0, scratch_buf_len);
				FREE(scratch_buf);
				NTRU_RET(NTRU_BUFFER_TOO_SMALL);
			}

			memcpy(pt, m_buf, cm_len);
			*pt_len = cm_len;
		}
	}

	/* cleanup */

	memset(scratch_buf, 0, scratch_buf_len);
	FREE(scratch_buf);

	if (!decryption_ok) {
		NTRU_RET(NTRU_FAIL);
	}

	return result;
}

/* ntru_crypto_ntru_encrypt_keygen
 *
 * Implements key generation for NTRUEncrypt for the parameter set specified.
 *
 * Before invoking this function, a DRBG must be instantiated using
 * ntru_crypto_drbg_instantiate() to obtain a DRBG handle, and in that
 * instantiation the requested security strength must be at least as large
 * as the security strength of the NTRU parameter set being used.
 * Failure to instantiate the DRBG with the proper security strength will
 * result in this function returning DRBG_ERROR_BASE + DRBG_BAD_LENGTH.
 *
 * The required minimum size of the output public-key buffer (pubkey_blob)
 * may be queried by invoking this function with pubkey_blob = NULL.
 * In this case, no key generation is performed, NTRU_OK is returned, and
 * the required minimum size for pubkey_blob is returned in pubkey_blob_len.
 *
 * The required minimum size of the output private-key buffer (privkey_blob)
 * may be queried by invoking this function with privkey_blob = NULL.
 * In this case, no key generation is performed, NTRU_OK is returned, and
 * the required minimum size for privkey_blob is returned in privkey_blob_len.
 *
 * The required minimum sizes of both pubkey_blob and privkey_blob may be
 * queried as described above, in a single invocation of this function.
 *
 * When pubkey_blob != NULL and privkey_blob != NULL, at invocation
 * *pubkey_blob_len must be the size of the pubkey_blob buffer and
 * *privkey_blob_len must be the size of the privkey_blob buffer.
 * Upon return, *pubkey_blob_len is the actual size of the public-key blob
 * and *privkey_blob_len is the actual size of the private-key blob.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_PARAMETER if an argument pointer
 *  (other than pubkey_blob or privkey_blob) is NULL.
 * Returns NTRU_ERROR_BASE + NTRU_INVALID_PARAMETER_SET if the parameter-set
 *  ID is invalid.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_LENGTH if a length argument is invalid.
 * Returns NTRU_ERROR_BASE + NTRU_BUFFER_TOO_SMALL if either the pubkey_blob
 * buffer or the privkey_blob buffer is too small.
 * Returns NTRU_ERROR_BASE + NTRU_NO_MEMORY if memory needed cannot be
 *  allocated from the heap.
 * Returns NTRU_ERROR_BASE + NTRU_FAIL if the polynomial generated for f is
 *  not invertible in (Z/qZ)[X]/(X^N - 1), which is extremely unlikely.
 *  Should this occur, this function should simply be invoked again.
 */

uint32_t
ntru_crypto_ntru_encrypt_keygen(
    DRBG_HANDLE drbg_handle,                /*     in - handle of DRBG */
    NTRU_ENCRYPT_PARAM_SET_ID param_set_id, /*     in - parameter set ID */
    uint16_t *pubkey_blob_len,              /* in/out - no. of octets in
                                                             pubkey_blob, addr
                                                             for no. of octets
                                                             in pubkey_blob */
    uint8_t *pubkey_blob,                   /*    out - address for
                                                             public key blob */
    uint16_t *privkey_blob_len,             /* in/out - no. of octets in
                                                             privkey_blob, addr
                                                             for no. of octets
                                                             in privkey_blob */
    uint8_t *privkey_blob)                  /*    out - address for
                                                             private key blob */
{
	NTRU_ENCRYPT_PARAM_SET *params = NULL;
	uint16_t public_key_blob_len;
	uint16_t private_key_blob_len;
	uint8_t pubkey_pack_type;
	uint8_t privkey_pack_type;
	size_t scratch_buf_len;
	uint32_t dF;
	uint32_t dF1 = 0;
	uint32_t dF2 = 0;
	uint32_t dF3 = 0;
	uint16_t pad_deg;
	uint16_t total_polys;
	uint16_t num_scratch_polys;
	uint16_t *scratch_buf = NULL;
	uint16_t *ringel_buf1 = NULL;
	uint16_t *ringel_buf2 = NULL;
	uint16_t *F_buf = NULL;
	uint8_t *tmp_buf = NULL;
	uint16_t mod_q_mask;
	NTRU_CRYPTO_HASH_ALGID hash_algid;
	uint8_t md_len;
	uint16_t seed_len;
	uint32_t result = NTRU_OK;

	/* get a pointer to the parameter-set parameters */

	if ((params = ntru_encrypt_get_params_with_id(param_set_id)) == NULL) {
		NTRU_RET(NTRU_INVALID_PARAMETER_SET);
	}

	/* check for bad parameters */

	if (!pubkey_blob_len || !privkey_blob_len) {
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	/* get public and private key packing types and blob lengths */

	ntru_crypto_ntru_encrypt_key_get_blob_params(params, &pubkey_pack_type,
	                                             &public_key_blob_len,
	                                             &privkey_pack_type,
	                                             &private_key_blob_len);

	/* return the pubkey_blob size and/or privkey_blob size if requested */

	if (!pubkey_blob || !privkey_blob) {
		if (!pubkey_blob) {
			*pubkey_blob_len = public_key_blob_len;
		}

		if (!privkey_blob) {
			*privkey_blob_len = private_key_blob_len;
		}

		NTRU_RET(NTRU_OK);
	}

	/* check size of output buffers */

	if ((*pubkey_blob_len < public_key_blob_len) ||
	    (*privkey_blob_len < private_key_blob_len)) {
		NTRU_RET(NTRU_BUFFER_TOO_SMALL);
	}

	/* Allocate memory for all operations. We need:
     *  - 2 polynomials for results: ringel_buf1 and ringel_buf2.
     *  - scratch space for ntru_ring_mult_coefficients (which is
     *    implementation dependent) plus one additional polynomial
     *    of the same size for ntru_ring_lift_inv_pow2_x.
     *  - 2*dF coefficients for F
     */
	ntru_ring_mult_coefficients_memreq(params->N, &num_scratch_polys, &pad_deg);
	num_scratch_polys += 1; /* ntru_ring_lift_... */

	total_polys = num_scratch_polys;
	if (params->is_product_form) {
		dF1 = params->dF_r & 0xff;
		dF2 = (params->dF_r >> 8) & 0xff;
		dF3 = (params->dF_r >> 16) & 0xff;
		dF = dF1 + dF2 + dF3;
		/* For product form keys we can overlap ringel_buf1
         * and the scratch space since mult. by f uses F_buf.
         * so only add room for ringel_buf2 */
		num_scratch_polys -= 1;
		total_polys += 1;
	} else {
		dF = params->dF_r;
		total_polys += 2; /* ringel_buf{1,2} */
	}

	scratch_buf_len = ((size_t)(total_polys * pad_deg)) * sizeof(uint16_t);
	scratch_buf_len += 2 * dF * sizeof(uint16_t);
	scratch_buf = MALLOC(scratch_buf_len);
	if (!scratch_buf) {
		NTRU_RET(NTRU_OUT_OF_MEMORY);
	}
	memset(scratch_buf, 0, scratch_buf_len);

	ringel_buf1 = scratch_buf + num_scratch_polys * pad_deg;
	ringel_buf2 = ringel_buf1 + pad_deg;
	F_buf = ringel_buf2 + pad_deg;
	tmp_buf = (uint8_t *) scratch_buf;

	/* set hash algorithm and seed length based on security strength */

	if (params->hash_algid == NTRU_CRYPTO_HASH_ALGID_SHA1) {
		hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA1;
		md_len = SHA_1_MD_LEN;
	} else if (params->hash_algid == NTRU_CRYPTO_HASH_ALGID_SHA256) {
		hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA256;
		md_len = SHA_256_MD_LEN;
	} else {
		FREE(scratch_buf);
		NTRU_RET(NTRU_UNSUPPORTED_PARAM_SET);
	}

	seed_len = 2 * params->sec_strength_len;

	/* set constants */

	mod_q_mask = params->q - 1;

	/* get random bytes for seed for generating trinary F
     * as a list of indices
     */

	result = ntru_crypto_drbg_generate(drbg_handle,
	                                   params->sec_strength_len << 3,
	                                   seed_len, tmp_buf);

	if (result == NTRU_OK) {

		/* generate F */

		result = ntru_gen_poly(hash_algid, md_len,
		                       params->min_IGF_hash_calls,
		                       seed_len, tmp_buf, tmp_buf,
		                       params->N, params->c_bits,
		                       params->no_bias_limit,
		                       params->is_product_form,
		                       params->dF_r << 1, F_buf);
	}

	if (result == NTRU_OK) {
		uint32_t i;

		memset(ringel_buf1, 0, params->N * sizeof(uint16_t));

		/* form F as a ring element */

		if (params->is_product_form) {
			uint32_t dF3_offset = (dF1 + dF2) << 1;

			/* form F1 as a ring element */

			for (i = 0; i < dF1; i++) {
				ringel_buf1[F_buf[i]] = 1;
			}

			for (; i < (dF1 << 1); i++) {
				ringel_buf1[F_buf[i]] = mod_q_mask;
			}

			/* form F1 * F2 */

			ntru_ring_mult_indices(ringel_buf1, (uint16_t) dF2, (uint16_t) dF2,
			                       F_buf + (dF1 << 1), params->N, params->q,
			                       scratch_buf, ringel_buf1);

			/* form (F1 * F2) + F3 */

			for (i = 0; i < dF3; i++) {
				uint16_t index = F_buf[dF3_offset + i];
				ringel_buf1[index] = (ringel_buf1[index] + 1) & mod_q_mask;
			}

			for (; i < (dF3 << 1); i++) {
				uint16_t index = F_buf[dF3_offset + i];
				ringel_buf1[index] = (ringel_buf1[index] - 1) & mod_q_mask;
			}

		} else {
			/* form F as a ring element */

			for (i = 0; i < dF; i++) {
				ringel_buf1[F_buf[i]] = 1;
			}

			for (; i < (dF << 1); i++) {
				ringel_buf1[F_buf[i]] = mod_q_mask;
			}
		}

		/* form f = 1 + pF */

		for (i = 0; i < params->N; i++) {
			ringel_buf1[i] = (ringel_buf1[i] * 3) & mod_q_mask;
		}

		ringel_buf1[0] = (ringel_buf1[0] + 1) & mod_q_mask;

		/* find f^-1 in (Z/2Z)[X]/(X^N - 1) */

		if (!ntru_ring_inv(ringel_buf1, params->N, scratch_buf, ringel_buf2)) {
			result = NTRU_RESULT(NTRU_FAIL);
		}
	}

	if (result == NTRU_OK) {
		/* lift f^-1 in (Z/2Z)[X]/(X^N - 1) to f^-1 in (Z/qZ)[X]/(X^N -1) */
		if (params->is_product_form) {
			result = ntru_ring_lift_inv_pow2_product(ringel_buf2,
			                                         (uint16_t) dF1, (uint16_t) dF2, (uint16_t) dF3,
			                                         F_buf, params->N, params->q, scratch_buf);
		} else {
			result = ntru_ring_lift_inv_pow2_standard(ringel_buf2,
			                                          ringel_buf1, params->N, params->q, scratch_buf);
		}
	}

	if (result == NTRU_OK) {

		/* get random bytes for seed for generating trinary g
         * as a list of indices
         */
		result = ntru_crypto_drbg_generate(drbg_handle,
		                                   params->sec_strength_len << 3,
		                                   seed_len, tmp_buf);
	}

	if (result == NTRU_OK) {
		uint16_t min_IGF_hash_calls =
		    ((((params->dg << 2) + 2) * params->N_bits) + (md_len << 3) - 1) /
		    (md_len << 3);

		/* generate g */

		result = ntru_gen_poly(hash_algid, md_len,
		                       (uint8_t) min_IGF_hash_calls,
		                       seed_len, tmp_buf, tmp_buf,
		                       params->N, params->c_bits,
		                       params->no_bias_limit, FALSE,
		                       (params->dg << 1) + 1, ringel_buf1);
	}

	if (result == NTRU_OK) {
		uint16_t i;

		/* compute h = p * (f^-1 * g) mod q */

		ntru_ring_mult_indices(ringel_buf2, params->dg + 1, params->dg,
		                       ringel_buf1, params->N, params->q, scratch_buf,
		                       ringel_buf2);

		for (i = 0; i < params->N; i++) {
			ringel_buf2[i] = (ringel_buf2[i] * 3) & mod_q_mask;
		}

		/* create public key blob */

		result = ntru_crypto_ntru_encrypt_key_create_pubkey_blob(params,
		                                                         ringel_buf2, pubkey_pack_type, pubkey_blob);
		*pubkey_blob_len = public_key_blob_len;
	}

	if (result == NTRU_OK) {
		/* create private key blob */
		result = ntru_crypto_ntru_encrypt_key_create_privkey_blob(params,
		                                                          ringel_buf2, F_buf, privkey_pack_type, tmp_buf, privkey_blob);
		*privkey_blob_len = private_key_blob_len;
	}

	/* cleanup */

	memset(scratch_buf, 0, scratch_buf_len);
	FREE(scratch_buf);

	return result;
}

/* DER-encoding prefix template for NTRU public keys,
 * with parameter-set-specific fields nomalized
 */

static uint8_t const der_prefix_template[] = {
    0x30, 0x82,
    0x00, 0x25, /* add pubkey length 2 */
    0x30, 0x1a, 0x06, 0x0b, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0xc1, 0x16, 0x01, 0x01, 0x01,
    0x01, /* end of NTRU OID compare */
    0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01,
    0xc1, 0x16, 0x01, 0x01, 0x02,
    0x00, /* set param-set DER id 31 */
    0x03, 0x82,
    0x00, 0x05, /* add pubkey length 34 */
    0x00, 0x04, 0x82,
    0x00, 0x00, /* add pubkey length 39 */
};

/* add_16_to_8s
 *
 * adds a 16-bit value to two bytes
 */

static void
add_16_to_8s(
    uint16_t a,
    uint8_t *b) {
	uint16_t tmp = ((uint16_t) b[0] << 8) + b[1];

	tmp = tmp + a;
	b[0] = (uint8_t)((tmp >> 8) & 0xff);
	b[1] = (uint8_t)(tmp & 0xff);

	return;
}

/* sub_16_from_8s
 *
 * subtracts a 16-bit value from two bytes
 */

static void
sub_16_from_8s(
    uint16_t a,
    uint8_t *b) {
	uint16_t tmp = ((uint16_t) b[0] << 8) + b[1];

	tmp = tmp - a;
	b[0] = (uint8_t)((tmp >> 8) & 0xff);
	b[1] = (uint8_t)(tmp & 0xff);

	return;
}

/* ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo
 *
 * DER-encodes an NTRUEncrypt public-key from a public-key blob into a
 * SubjectPublicKeyInfo field for inclusion in an X.509 certificate.
 *
 * The required minimum size of the output SubjectPublicKeyInfo buffer
 * (encoded_subjectPublicKeyInfo) may be queried by invoking this function
 * with encoded_subjectPublicKeyInfo = NULL.  In this case, no encoding is
 * performed, NTRU_OK is returned, and the required minimum size for
 * encoded_subjectPublicKeyInfo is returned in encoded_subjectPublicKeyInfo_len.
 *
 * When encoded_subjectPublicKeyInfo != NULL, at invocation
 * *encoded_subjectPublicKeyInfo_len must be the size of the
 * encoded_subjectPublicKeyInfo buffer.
 * Upon return, it is the actual size of the encoded public key.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_PARAMETER if an argument pointer
 *  (other than encoded_subjectPublicKeyInfo) is NULL.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_LENGTH if pubkey_blob_len is zero.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_PUBLIC_KEY if the public-key blob is
 *  invalid (unknown format, corrupt, bad length).
 * Returns NTRU_ERROR_BASE + NTRU_BUFFER_TOO_SMALL if the SubjectPublicKeyInfo
 *  buffer is too small.
 */

uint32_t
ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
    uint16_t pubkey_blob_len,   /*     in - no. of octets in public-key
                                                blob */
    uint8_t const *pubkey_blob, /*     in - ptr to public-key blob */
    uint16_t *encoded_subjectPublicKeyInfo_len,
    /* in/out - no. of octets in encoded info,
                                                address for no. of octets in
                                                encoded info */
    uint8_t *encoded_subjectPublicKeyInfo)
/*    out - address for encoded info */
{
	NTRU_ENCRYPT_PARAM_SET *params = NULL;
	uint8_t const *pubkey_packed = NULL;
	uint8_t pubkey_pack_type;
	uint16_t packed_pubkey_len;
	uint16_t encoded_len;

	/* check for bad parameters */

	if (!pubkey_blob || !encoded_subjectPublicKeyInfo_len) {
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	if (pubkey_blob_len == 0) {
		NTRU_RET(NTRU_BAD_LENGTH);
	}

	/* get a pointer to the parameter-set parameters, the packing type for
     * the public key, and a pointer to the packed public key
     */

	if (!ntru_crypto_ntru_encrypt_key_parse(TRUE /* pubkey */, pubkey_blob_len,
	                                        pubkey_blob, &pubkey_pack_type,
	                                        NULL, &params, &pubkey_packed,
	                                        NULL)) {
		NTRU_RET(NTRU_BAD_PUBLIC_KEY);
	}

	/* return the encoded_subjectPublicKeyInfo size if requested */

	packed_pubkey_len = (params->N * params->q_bits + 7) >> 3;
	encoded_len = sizeof(der_prefix_template) + packed_pubkey_len;

	if (!encoded_subjectPublicKeyInfo) {
		*encoded_subjectPublicKeyInfo_len = encoded_len;
		NTRU_RET(NTRU_OK);
	}

	/* check the encoded_subjectPublicKeyInfo buffer size */

	if (*encoded_subjectPublicKeyInfo_len < encoded_len) {
		NTRU_RET(NTRU_BUFFER_TOO_SMALL);
	}

	/* form the encoded subjectPublicKey */

	memcpy(encoded_subjectPublicKeyInfo, der_prefix_template,
	       sizeof(der_prefix_template));

	add_16_to_8s(packed_pubkey_len, encoded_subjectPublicKeyInfo + 2);
	add_16_to_8s(packed_pubkey_len, encoded_subjectPublicKeyInfo + 34);
	add_16_to_8s(packed_pubkey_len, encoded_subjectPublicKeyInfo + 39);
	encoded_subjectPublicKeyInfo[31] = params->der_id;

	memcpy(encoded_subjectPublicKeyInfo + sizeof(der_prefix_template),
	       pubkey_packed, packed_pubkey_len);

	*encoded_subjectPublicKeyInfo_len = encoded_len;

	NTRU_RET(NTRU_OK);
}

/* ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey
 *
 * Decodes a DER-encoded NTRUEncrypt public-key from a
 * SubjectPublicKeyInfo field in an X.509 certificate and returns the
 * public-key blob itself.
 *
 * The required minimum size of the output public-key buffer (pubkey_blob)
 * may be queried by invoking this function with pubkey_blob = NULL.
 * In this case, no decoding is performed, NTRU_OK is returned, and the
 * required minimum size for pubkey_blob is returned in pubkey_blob_len.
 *
 * When pubkey_blob != NULL, at invocation *pubkey_blob_len must be the
 * size of the pubkey_blob buffer.
 * Upon return, it is the actual size of the public-key blob.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_LENGTH if the encoded data buffer
 *  does not contain a full der prefix and public key.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_PARAMETER if an argument pointer
 *  (other than pubkey_blob) is NULL.
 * Returns NTRU_ERROR_BASE + NTRU_BAD_ENCODING if the encoded data is
 *  an invalid encoding of an NTRU public key.
 * Returns NTRU_ERROR_BASE + NTRU_OID_NOT_RECOGNIZED if the
 *  encoded data contains an OID that identifies an object other than
 *  an NTRU public key.
 * Returns NTRU_ERROR_BASE + NTRU_BUFFER_TOO_SMALL if the pubkey_blob buffer
 *  is too small.
 */

uint32_t
ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(
    uint8_t const *encoded_data,  /*     in - ptr to subjectPublicKeyInfo
                                                 in the encoded data */
    uint16_t *pubkey_blob_len,    /* in/out - no. of octets in pubkey blob,
                                                 address for no. of octets in
                                                 pubkey blob */
    uint8_t *pubkey_blob,         /*    out - address for pubkey blob */
    uint8_t **next,               /*    out - address for ptr to encoded
                                                 data following the 
                                                 subjectPublicKeyInfo */
    uint32_t *remaining_data_len) /* in/out - number of bytes remaining in
                                                    buffer *next */
{
	NTRU_ENCRYPT_PARAM_SET *params = NULL;
	uint8_t prefix_buf[41];
	bool der_id_valid;
	uint16_t packed_pubkey_len = 0;
	uint8_t pubkey_pack_type;
	uint16_t public_key_blob_len;
	uint8_t *data_ptr;
	uint32_t data_len;

	/* check for bad parameters */

	if (!encoded_data || !pubkey_blob_len || !next || !remaining_data_len) {
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	data_len = *remaining_data_len;
	if (data_len < sizeof(prefix_buf)) {
		NTRU_RET(NTRU_BAD_LENGTH);
	}

	/* determine if data to be decoded is a valid encoding of an NTRU
     * public key
     */

	data_ptr = (uint8_t *) encoded_data;
	memcpy(prefix_buf, data_ptr, sizeof(prefix_buf));

	/* get a pointer to the parameter-set parameters */

	if ((params = ntru_encrypt_get_params_with_DER_id(data_ptr[31])) == NULL) {
		der_id_valid = FALSE;

		/* normalize the prefix-buffer data used in an NTRU OID comparison */

		prefix_buf[2] = der_prefix_template[2];
		prefix_buf[3] = der_prefix_template[3];

	} else {
		der_id_valid = TRUE;

		/* normalize the prefix-buffer data for the specific parameter set */

		packed_pubkey_len = (params->N * params->q_bits + 7) >> 3;
		sub_16_from_8s(packed_pubkey_len, prefix_buf + 2);
		sub_16_from_8s(packed_pubkey_len, prefix_buf + 34);
		sub_16_from_8s(packed_pubkey_len, prefix_buf + 39);
		prefix_buf[31] = 0;
		/*prefix_buf[40] = 0; */
	}

	/* validate the DER prefix encoding */

	if (!der_id_valid || memcmp(prefix_buf, der_prefix_template,
	                            sizeof(der_prefix_template))) {

		/* bad DER prefix, so determine if this is a bad NTRU encoding or an
         * unknown OID by comparing the first 18 octets
         */

		if (memcmp(prefix_buf, der_prefix_template, 18) == 0) {
			NTRU_RET(NTRU_OID_NOT_RECOGNIZED);
		} else {
			NTRU_RET(NTRU_BAD_ENCODING);
		}
	}

	/* done with prefix */

	data_ptr += sizeof(prefix_buf);
	data_len -= sizeof(prefix_buf);

	/* get public key packing type and blob length */

	ntru_crypto_ntru_encrypt_key_get_blob_params(params, &pubkey_pack_type,
	                                             &public_key_blob_len, NULL,
	                                             NULL);

	/* return the pubkey_blob size if requested */

	if (!pubkey_blob) {
		*pubkey_blob_len = public_key_blob_len;
		NTRU_RET(NTRU_OK);
	}

	/* check size of output buffer */

	if (*pubkey_blob_len < public_key_blob_len) {
		NTRU_RET(NTRU_BUFFER_TOO_SMALL);
	}

	/* check that blob contains additional data of length packed_pubkey_len */
	if (data_len < packed_pubkey_len) {
		NTRU_RET(NTRU_BAD_LENGTH);
	}

	/* check that the public key pack type is supported */
	if (pubkey_pack_type != NTRU_ENCRYPT_KEY_PACKED_COEFFICIENTS) {
		NTRU_RET(NTRU_BAD_PUBLIC_KEY);
	}

	/* create the public-key blob */
	ntru_crypto_ntru_encrypt_key_recreate_pubkey_blob(params, packed_pubkey_len,
	                                                  data_ptr, pubkey_pack_type, pubkey_blob);
	*pubkey_blob_len = public_key_blob_len;

	data_ptr += packed_pubkey_len;
	data_len -= packed_pubkey_len;

	/* check whether the buffer is empty and update *next */
	if (data_len > 0) {
		*next = data_ptr;
		*remaining_data_len = data_len;
	} else {
		*next = NULL;
		*remaining_data_len = 0;
	}

	NTRU_RET(NTRU_OK);
}
