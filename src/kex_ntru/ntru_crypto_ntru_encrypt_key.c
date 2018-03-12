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
 * File: ntru_crypto_ntru_encrypt_key.c
 *
 * Contents: Routines for exporting and importing public and private keys
 *           for NTRUEncrypt.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_encrypt_key.h"

/* ntru_crypto_ntru_encrypt_key_parse
 *
 * Parses an NTRUEncrypt key blob.
 * If the blob is not corrupt, returns packing types for public and private
 * keys, a pointer to the parameter set, a pointer to the public key, and
 * a pointer to the private key if it exists.
 *
 * Returns TRUE if successful.
 * Returns FALSE if the blob is invalid.
 */

bool ntru_crypto_ntru_encrypt_key_parse(
    bool pubkey_parse,               /*  in - if parsing pubkey
                                                         blob */
    uint16_t key_blob_len,           /*  in - no. octets in key
                                                         blob */
    uint8_t const *key_blob,         /*  in - pointer to key blob */
    uint8_t *pubkey_pack_type,       /* out - addr for pubkey
                                                         packing type */
    uint8_t *privkey_pack_type,      /* out - addr for privkey
                                                         packing type */
    NTRU_ENCRYPT_PARAM_SET **params, /* out - addr for ptr to
                                                         parameter set */
    uint8_t const **pubkey,          /* out - addr for ptr to
                                                         packed pubkey */
    uint8_t const **privkey)         /* out - addr for ptr to
                                                         packed privkey */
{
	uint8_t tag;

	/* parse key blob based on tag */

	tag = key_blob[0];
	switch (tag) {
	case NTRU_ENCRYPT_PUBKEY_TAG:

		if (!pubkey_parse) {
			return FALSE;
		}

		break;

	case NTRU_ENCRYPT_PRIVKEY_DEFAULT_TAG:
	case NTRU_ENCRYPT_PRIVKEY_TRITS_TAG:
	case NTRU_ENCRYPT_PRIVKEY_INDICES_TAG:

		if (pubkey_parse) {
			return FALSE;
		}
		break;

	default:
		return FALSE;
		break;
	}

	switch (tag) {
	case NTRU_ENCRYPT_PUBKEY_TAG:
	case NTRU_ENCRYPT_PRIVKEY_DEFAULT_TAG:
	case NTRU_ENCRYPT_PRIVKEY_TRITS_TAG:
	case NTRU_ENCRYPT_PRIVKEY_INDICES_TAG:

		/* Version 0:
             *  byte  0:   tag
             *  byte  1:   no. of octets in OID
             *  bytes 2-4: OID
             *  bytes 5- : packed pubkey
             *             [packed privkey]
             */

		{
			NTRU_ENCRYPT_PARAM_SET *p = NULL;
			uint16_t pubkey_packed_len;

			/* check OID length and minimum blob length for tag and OID */

			if ((key_blob_len < 5) || (key_blob[1] != 3)) {
				return FALSE;
			}

			/* get a pointer to the parameter set corresponding to the OID */

			if ((p = ntru_encrypt_get_params_with_OID(key_blob + 2)) == NULL) {
				return FALSE;
			}

			/* check blob length and assign pointers to blob fields */

			pubkey_packed_len = (p->N * p->q_bits + 7) / 8;

			if (pubkey_parse) /* public-key parsing */
			{
				if (key_blob_len != 5 + pubkey_packed_len) {
					return FALSE;
				}

				*pubkey = key_blob + 5;

			} else /* private-key parsing */
			{
				uint16_t privkey_packed_len;
				uint16_t privkey_packed_trits_len = (p->N + 4) / 5;
				uint16_t privkey_packed_indices_len;
				uint16_t dF;

				/* check packing type for product-form private keys */

				if (p->is_product_form &&
				    (tag == NTRU_ENCRYPT_PRIVKEY_TRITS_TAG)) {
					return FALSE;
				}

				/* set packed-key length for packed indices */

				if (p->is_product_form) {
					dF = (uint16_t)((p->dF_r & 0xff) +         /* df1 */
					                ((p->dF_r >> 8) & 0xff) +  /* df2 */
					                ((p->dF_r >> 16) & 0xff)); /* df3 */
				} else {
					dF = (uint16_t) p->dF_r;
				}

				privkey_packed_indices_len = ((dF << 1) * p->N_bits + 7) >> 3;

				/* set private-key packing type if defaulted */

				if (tag == NTRU_ENCRYPT_PRIVKEY_DEFAULT_TAG) {
					if (p->is_product_form ||
					    (privkey_packed_indices_len <=
					     privkey_packed_trits_len)) {
						tag = NTRU_ENCRYPT_PRIVKEY_INDICES_TAG;
					} else {
						tag = NTRU_ENCRYPT_PRIVKEY_TRITS_TAG;
					}
				}

				if (tag == NTRU_ENCRYPT_PRIVKEY_TRITS_TAG) {
					privkey_packed_len = privkey_packed_trits_len;
				} else {
					privkey_packed_len = privkey_packed_indices_len;
				}

				if (key_blob_len != 5 + pubkey_packed_len + privkey_packed_len) {
					return FALSE;
				}

				*pubkey = key_blob + 5;
				*privkey = *pubkey + pubkey_packed_len;
				*privkey_pack_type = (tag == NTRU_ENCRYPT_PRIVKEY_TRITS_TAG) ? NTRU_ENCRYPT_KEY_PACKED_TRITS : NTRU_ENCRYPT_KEY_PACKED_INDICES;
			}

			/* return parameter set pointer */

			*pubkey_pack_type = NTRU_ENCRYPT_KEY_PACKED_COEFFICIENTS;
			*params = p;
		}

	default:
		break; /* can't get here */
	}

	return TRUE;
}

/* ntru_crypto_ntru_encrypt_key_get_blob_params
 *
 * Returns public and private key packing types and blob lengths given
 * a packing format.  For now, only a default packing format exists.
 *
 * Only public-key params may be returned by setting privkey_pack_type
 * and privkey_blob_len to NULL.
 */

void ntru_crypto_ntru_encrypt_key_get_blob_params(
    NTRU_ENCRYPT_PARAM_SET const *params, /*  in - pointer to
                                                               param set
                                                               parameters */
    uint8_t *pubkey_pack_type,            /* out - addr for pubkey
                                                               packing type */
    uint16_t *pubkey_blob_len,            /* out - addr for no. of
                                                               bytes in
                                                               pubkey blob */
    uint8_t *privkey_pack_type,           /* out - addr for privkey
                                                               packing type */
    uint16_t *privkey_blob_len)           /* out - addr for no. of
                                                               bytes in
                                                               privkey blob */
{
	uint16_t pubkey_packed_len = (params->N * params->q_bits + 7) >> 3;

	*pubkey_pack_type = NTRU_ENCRYPT_KEY_PACKED_COEFFICIENTS;
	*pubkey_blob_len = 5 + pubkey_packed_len;

	if (privkey_pack_type && privkey_blob_len) {
		uint16_t privkey_packed_trits_len = (params->N + 4) / 5;
		uint16_t privkey_packed_indices_len;
		uint16_t dF;

		if (params->is_product_form) {
			dF = (uint16_t)((params->dF_r & 0xff) +         /* df1 */
			                ((params->dF_r >> 8) & 0xff) +  /* df2 */
			                ((params->dF_r >> 16) & 0xff)); /* df3 */
		} else {
			dF = (uint16_t) params->dF_r;
		}

		privkey_packed_indices_len = ((dF << 1) * params->N_bits + 7) >> 3;

		if (params->is_product_form ||
		    (privkey_packed_indices_len <= privkey_packed_trits_len)) {
			*privkey_pack_type = NTRU_ENCRYPT_KEY_PACKED_INDICES;
			*privkey_blob_len =
			    5 + pubkey_packed_len + privkey_packed_indices_len;
		} else {
			*privkey_pack_type = NTRU_ENCRYPT_KEY_PACKED_TRITS;
			*privkey_blob_len =
			    5 + pubkey_packed_len + privkey_packed_trits_len;
		}
	}

	return;
}

/* ntru_crypto_ntru_encrypt_key_create_pubkey_blob
 *
 * Returns a public key blob, packed according to the packing type provided.
 */

uint32_t
ntru_crypto_ntru_encrypt_key_create_pubkey_blob(
    NTRU_ENCRYPT_PARAM_SET const *params, /*  in - pointer to
                                                               param set
                                                               parameters */
    uint16_t const *pubkey,               /*  in - pointer to the
                                                               coefficients
                                                               of the pubkey */
    uint8_t pubkey_pack_type,             /* out - pubkey packing
                                                               type */
    uint8_t *pubkey_blob)                 /* out - addr for the
                                                               pubkey blob */
{

	switch (pubkey_pack_type) {
	case NTRU_ENCRYPT_KEY_PACKED_COEFFICIENTS:
		*pubkey_blob++ = NTRU_ENCRYPT_PUBKEY_TAG;
		*pubkey_blob++ = (uint8_t) sizeof(params->OID);
		memcpy(pubkey_blob, params->OID, sizeof(params->OID));
		pubkey_blob += sizeof(params->OID);
		ntru_elements_2_octets(params->N, pubkey, params->q_bits,
		                       pubkey_blob);
		break;

	default:
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	NTRU_RET(NTRU_OK);
}

/* ntru_crypto_ntru_encrypt_key_recreate_pubkey_blob
 *
 * Returns a public key blob, recreated from an already-packed public key.
 */

uint32_t
ntru_crypto_ntru_encrypt_key_recreate_pubkey_blob(
    NTRU_ENCRYPT_PARAM_SET const *params, /*  in - pointer to
                                                               param set
                                                               parameters */
    uint16_t packed_pubkey_len,           /*  in - no. octets in
                                                               packed pubkey */
    uint8_t const *packed_pubkey,         /*  in - pointer to the
                                                               packed pubkey */
    uint8_t pubkey_pack_type,             /* out - pubkey packing
                                                               type */
    uint8_t *pubkey_blob)                 /* out - addr for the
                                                               pubkey blob */
{

	switch (pubkey_pack_type) {
	case NTRU_ENCRYPT_KEY_PACKED_COEFFICIENTS:
		*pubkey_blob++ = NTRU_ENCRYPT_PUBKEY_TAG;
		*pubkey_blob++ = (uint8_t) sizeof(params->OID);
		memcpy(pubkey_blob, params->OID, sizeof(params->OID));
		pubkey_blob += sizeof(params->OID);
		memcpy(pubkey_blob, packed_pubkey, packed_pubkey_len);
		break;

	default:
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	NTRU_RET(NTRU_OK);
}

/* ntru_crypto_ntru_encrypt_key_create_privkey_blob
 *
 * Returns a private key blob, packed according to the packing type provided.
 */

uint32_t
ntru_crypto_ntru_encrypt_key_create_privkey_blob(
    NTRU_ENCRYPT_PARAM_SET const *params, /*  in - pointer to
                                                               param set
                                                               parameters */
    uint16_t const *pubkey,               /*  in - pointer to the
                                                               coefficients
                                                               of the pubkey */
    uint16_t const *privkey,              /*  in - pointer to the
                                                               indices of the
                                                               privkey */
    uint8_t privkey_pack_type,            /*  in - privkey packing
                                                               type */
    uint8_t *buf,                         /*  in - temp, N bytes */
    uint8_t *privkey_blob)                /* out - addr for the
                                                               privkey blob */
{
	switch (privkey_pack_type) {
	case NTRU_ENCRYPT_KEY_PACKED_TRITS:
	case NTRU_ENCRYPT_KEY_PACKED_INDICES:

		/* format header and packed public key */

		*privkey_blob++ = NTRU_ENCRYPT_PRIVKEY_DEFAULT_TAG;
		*privkey_blob++ = (uint8_t) sizeof(params->OID);
		memcpy(privkey_blob, params->OID, sizeof(params->OID));
		privkey_blob += sizeof(params->OID);
		ntru_elements_2_octets(params->N, pubkey, params->q_bits,
		                       privkey_blob);
		privkey_blob += (params->N * params->q_bits + 7) >> 3;

		/* add packed private key */

		if (privkey_pack_type == NTRU_ENCRYPT_KEY_PACKED_TRITS) {
			ntru_indices_2_packed_trits(privkey, (uint16_t) params->dF_r,
			                            (uint16_t) params->dF_r,
			                            params->N, buf, privkey_blob);
		} else {
			uint32_t dF;

			if (params->is_product_form) {
				dF = (params->dF_r & 0xff) +
				     ((params->dF_r >> 8) & 0xff) +
				     ((params->dF_r >> 16) & 0xff);
			} else {
				dF = params->dF_r;
			}

			ntru_elements_2_octets((uint16_t) dF << 1, privkey,
			                       params->N_bits, privkey_blob);
		}
		break;

	default:
		NTRU_RET(NTRU_BAD_PARAMETER);
	}

	NTRU_RET(NTRU_OK);
}
