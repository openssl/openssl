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
 * File:  ntru_crypto_drbg.c
 *
 * Contents: Implementation of a SHA-256 HMAC-based deterministic random byte
 *           generator (HMAC_DRBG) as defined in ANSI X9.82, Part 3 - 2007.
 *
 * This implementation:
 *   - allows for MAX_INSTANTIATIONS simultaneous drbg instantiations
 *     (may be overridden on compiler command line)
 *   - has a maximum security strength of 256 bits
 *   - automatically uses SHA-256 for all security strengths
 *   - allows a personalization string of length up to
 *     HMAC_DRBG_MAX_PERS_STR_BYTES bytes
 *   - implments reseeding
 *   - does not implement additional input for reseeding or generation
 *   - does not implement predictive resistance
 *   - limits the number of bytes requested in one invocation of generate to
 *     MAX_BYTES_PER_REQUEST
 *   - uses a callback function to allow the caller to supply the
 *     Get_entropy_input routine (entropy function)
 *   - limits the number of bytes returned from the entropy function to
 *     MAX_ENTROPY_NONCE_BYTES
 *   - gets the nonce bytes along with the entropy input from the entropy
 *     function
 *   - automatically reseeds an instantitation after MAX_REQUESTS calls to
 *     generate
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_drbg.h"
#include "ntru_crypto_hmac.h"

/************************
 * HMAC_DRBG parameters *
 ************************/

/* Note: Combined entropy input and nonce are a total of 2 * sec_strength_bits
 * of randomness to provide quantum resistance */
#define HMAC_DRBG_MAX_MIN_ENTROPY_NONCE_BYTES \
	(2 * DRBG_MAX_SEC_STRENGTH_BITS) / 8
#define HMAC_DRBG_MAX_ENTROPY_NONCE_BYTES \
	HMAC_DRBG_MAX_MIN_ENTROPY_NONCE_BYTES *DRBG_MAX_BYTES_PER_BYTE_OF_ENTROPY
#define HMAC_DRBG_MAX_REQUESTS 0xffffffff

/*******************
 * DRBG structures *
 *******************/

/* SHA256_HMAC_DRBG state structure */

typedef struct {
	uint32_t sec_strength;          /* security strength in bits */
	uint32_t requests_left;         /* generation requests remaining
                                            before reseeding */
	ENTROPY_FN entropy_fn;          /* pointer to entropy function */
	NTRU_CRYPTO_HMAC_CTX *hmac_ctx; /* pointer to HMAC context */
	uint8_t V[33];                  /* md_len size internal state + 1 */
} SHA256_HMAC_DRBG_STATE;

/* External DRBG state structure */

typedef struct {
	RANDOM_BYTES_FN randombytesfn;
} EXTERNAL_DRBG_STATE;

/* DRBG state structure */

typedef struct {
	uint32_t handle;
	DRBG_TYPE type;
	void *state;
} DRBG_STATE;

/*************
 * DRBG DATA *
 *************/

/* array of drbg states */

static DRBG_STATE drbg_state[DRBG_MAX_INSTANTIATIONS];

/******************************
 * SHA256 HMAC_DRBG functions *
 ******************************/

/* sha256_hmac_drbg_update
 *
 * This routine is the SHA-256 HMAC_DRBG derivation function for
 * instantiation, and reseeding, and it is used in generation as well.
 * It updates the internal state.
 *
 * For instantiation, provided_data1 holds the entropy input and nonce;
 * provided_data2 holds the optional personalization string.  Combined, this
 * is the seed material.
 *
 * For reseeding, provided_data1 holds the entropy input;
 * provided_data2 is NULL (because this implementation does not support
 * additional input).
 *
 * For byte generation, both provided_data1 and provided_data2 are NULL.
 *
 * Returns DRBG_OK if successful.
 * Returns HMAC errors if they occur.
 */

static uint32_t
sha256_hmac_drbg_update(
    SHA256_HMAC_DRBG_STATE *s,
    uint8_t *key, /* md_len size array */
    uint32_t md_len,
    uint8_t const *provided_data1,
    uint32_t provided_data1_bytes,
    uint8_t const *provided_data2,
    uint32_t provided_data2_bytes) {
	uint32_t result;

	/* new key = HMAC(K, V || 0x00 [|| provided data1 [|| provided data2]] */

	if ((result = ntru_crypto_hmac_init(s->hmac_ctx)) != NTRU_CRYPTO_HMAC_OK) {
		return result;
	}

	s->V[md_len] = 0x00;

	if ((result = ntru_crypto_hmac_update(s->hmac_ctx, s->V, md_len + 1)) !=
	    NTRU_CRYPTO_HMAC_OK) {
		return result;
	}

	if (provided_data1) {
		if ((result = ntru_crypto_hmac_update(s->hmac_ctx, provided_data1,
		                                      provided_data1_bytes)) != NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		if (provided_data2) {
			if ((result = ntru_crypto_hmac_update(s->hmac_ctx, provided_data2,
			                                      provided_data2_bytes)) != NTRU_CRYPTO_HMAC_OK) {
				return result;
			}
		}
	}

	if ((result = ntru_crypto_hmac_final(s->hmac_ctx, key)) !=
	    NTRU_CRYPTO_HMAC_OK) {
		return result;
	}

	if ((result = ntru_crypto_hmac_set_key(s->hmac_ctx, key)) !=
	    NTRU_CRYPTO_HMAC_OK) {
		return result;
	}

	/* new V = HMAC(K, V) */

	if ((result = ntru_crypto_hmac_init(s->hmac_ctx)) != NTRU_CRYPTO_HMAC_OK) {
		return result;
	}

	if ((result = ntru_crypto_hmac_update(s->hmac_ctx, s->V, md_len)) !=
	    NTRU_CRYPTO_HMAC_OK) {
		return result;
	}

	if ((result = ntru_crypto_hmac_final(s->hmac_ctx, s->V)) !=
	    NTRU_CRYPTO_HMAC_OK) {
		return result;
	}

	/* if provided data exists, update K and V again */

	if (provided_data1) {
		/* new key = HMAC(K, V || 0x01 || provided data1 [|| provided data2] */

		if ((result = ntru_crypto_hmac_init(s->hmac_ctx)) !=
		    NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		s->V[md_len] = 0x01;

		if ((result = ntru_crypto_hmac_update(s->hmac_ctx, s->V, md_len + 1)) !=
		    NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		if ((result = ntru_crypto_hmac_update(s->hmac_ctx, provided_data1,
		                                      provided_data1_bytes)) != NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		if (provided_data2) {
			if ((result = ntru_crypto_hmac_update(s->hmac_ctx, provided_data2,
			                                      provided_data2_bytes)) != NTRU_CRYPTO_HMAC_OK) {
				return result;
			}
		}

		if ((result = ntru_crypto_hmac_final(s->hmac_ctx, key)) !=
		    NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		if ((result = ntru_crypto_hmac_set_key(s->hmac_ctx, key)) !=
		    NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		/* new V = HMAC(K, V) */

		if ((result = ntru_crypto_hmac_init(s->hmac_ctx)) !=
		    NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		if ((result = ntru_crypto_hmac_update(s->hmac_ctx, s->V, md_len)) !=
		    NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		if ((result = ntru_crypto_hmac_final(s->hmac_ctx, s->V)) !=
		    NTRU_CRYPTO_HMAC_OK) {
			return result;
		}
	}

	memset(key, 0, md_len);
	DRBG_RET(DRBG_OK);
}

/* sha256_hmac_drbg_instantiate
 *
 * This routine allocates and initializes a SHA-256 HMAC_DRBG internal state. 
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_BAD_LENGTH if the personalization string is too long.
 * Returns DRBG_OUT_OF_MEMORY if the internal state cannot be allocated.
 * Returns errors from HASH or SHA256 if those errors occur.
 */

static uint32_t
sha256_hmac_drbg_instantiate(
    uint32_t sec_strength_bits, /* strength to instantiate */
    uint8_t const *pers_str,
    uint32_t pers_str_bytes,
    ENTROPY_FN entropy_fn,
    SHA256_HMAC_DRBG_STATE **state) {
	uint8_t entropy_nonce[HMAC_DRBG_MAX_ENTROPY_NONCE_BYTES];
	uint32_t entropy_nonce_bytes;
	uint32_t min_bytes_of_entropy;
	uint8_t num_bytes_per_byte_of_entropy;
	uint8_t key[32]; /* array of md_len size */
	SHA256_HMAC_DRBG_STATE *s;
	uint32_t result;
	uint32_t i;

	/* check arguments */

	if (pers_str_bytes > HMAC_DRBG_MAX_PERS_STR_BYTES) {
		DRBG_RET(DRBG_BAD_LENGTH);
	}

	/* calculate number of bytes needed for the entropy input and nonce
     * for a SHA256_HMAC_DRBG, and get them from the entropy source
     */

	if (entropy_fn(GET_NUM_BYTES_PER_BYTE_OF_ENTROPY,
	               &num_bytes_per_byte_of_entropy) == 0) {
		DRBG_RET(DRBG_ENTROPY_FAIL);
	}

	if ((num_bytes_per_byte_of_entropy == 0) ||
	    (num_bytes_per_byte_of_entropy >
	     DRBG_MAX_BYTES_PER_BYTE_OF_ENTROPY)) {
		DRBG_RET(DRBG_ENTROPY_FAIL);
	}

	min_bytes_of_entropy = (2 * sec_strength_bits) / 8;
	entropy_nonce_bytes = min_bytes_of_entropy * num_bytes_per_byte_of_entropy;

	for (i = 0; i < entropy_nonce_bytes; i++) {
		if (entropy_fn(GET_BYTE_OF_ENTROPY, entropy_nonce + i) == 0) {
			DRBG_RET(DRBG_ENTROPY_FAIL);
		}
	}

	/* allocate SHA256_HMAC_DRBG state */
	s = (SHA256_HMAC_DRBG_STATE *) MALLOC(sizeof(SHA256_HMAC_DRBG_STATE));
	if (s == NULL) {
		DRBG_RET(DRBG_OUT_OF_MEMORY);
	}

	/* allocate HMAC context */

	memset(key, 0, sizeof(key));
	if ((result = ntru_crypto_hmac_create_ctx(NTRU_CRYPTO_HASH_ALGID_SHA256,
	                                          key, sizeof(key), &s->hmac_ctx)) != NTRU_CRYPTO_HMAC_OK) {
		FREE(s);
		return result;
	}

	/* init and update internal state */

	memset(s->V, 0x01, sizeof(s->V));
	if ((result = sha256_hmac_drbg_update(s, key, sizeof(key),
	                                      entropy_nonce, entropy_nonce_bytes,
	                                      pers_str, pers_str_bytes)) != DRBG_OK) {
		(void) ntru_crypto_hmac_destroy_ctx(s->hmac_ctx);
		memset(s->V, 0, sizeof(s->V));
		FREE(s);
		memset(entropy_nonce, 0, sizeof(entropy_nonce));
		return result;
	}

	memset(entropy_nonce, 0, sizeof(entropy_nonce));

	/* init instantiation parameters */

	s->sec_strength = sec_strength_bits;
	s->requests_left = HMAC_DRBG_MAX_REQUESTS;
	s->entropy_fn = entropy_fn;
	*state = s;

	return result;
}

/* sha256_hmac_drbg_free
 *
 * This routine frees a SHA-256 HMAC_DRBG internal state.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_BAD_PARAMETER if inappropriate NULL pointers are passed.
 */

static void
sha256_hmac_drbg_free(
    SHA256_HMAC_DRBG_STATE *s) {
	if (s->hmac_ctx) {
		(void) ntru_crypto_hmac_destroy_ctx(s->hmac_ctx);
	}

	memset(s->V, 0, sizeof(s->V));
	s->sec_strength = 0;
	s->requests_left = 0;
	s->entropy_fn = NULL;
	FREE(s);
}

/* sha256_hmac_drbg_reseed
 *
 * This function reseeds an instantiated SHA256_HMAC DRBG.
 *
 * Returns DRBG_OK if successful.
 * Returns HMAC errors if they occur.
 */

static uint32_t
sha256_hmac_drbg_reseed(
    SHA256_HMAC_DRBG_STATE *s) {
	uint8_t entropy[HMAC_DRBG_MAX_ENTROPY_NONCE_BYTES];
	uint32_t entropy_bytes;
	uint32_t min_bytes_of_entropy;
	uint8_t num_bytes_per_byte_of_entropy;
	uint8_t key[32]; /* array of md_len size for sha256_hmac_drbg_update() */
	uint32_t result;
	uint32_t i;

	/* calculate number of bytes needed for the entropy input
     * for a SHA256_HMAC_DRBG, and get them from the entropy source
     */

	if (s->entropy_fn(GET_NUM_BYTES_PER_BYTE_OF_ENTROPY,
	                  &num_bytes_per_byte_of_entropy) == 0) {
		DRBG_RET(DRBG_ENTROPY_FAIL);
	}

	if ((num_bytes_per_byte_of_entropy == 0) ||
	    (num_bytes_per_byte_of_entropy >
	     DRBG_MAX_BYTES_PER_BYTE_OF_ENTROPY)) {
		DRBG_RET(DRBG_ENTROPY_FAIL);
	}

	/* note: factor of 2 here is probably unnecessary, but ensures quantum
     * resistance even if internal state is leaked prior to reseed */
	min_bytes_of_entropy = (2 * s->sec_strength) / 8;
	entropy_bytes = min_bytes_of_entropy * num_bytes_per_byte_of_entropy;

	for (i = 0; i < entropy_bytes; i++) {
		if (s->entropy_fn(GET_BYTE_OF_ENTROPY, entropy + i) == 0) {
			DRBG_RET(DRBG_ENTROPY_FAIL);
		}
	}

	/* update internal state */

	if ((result = sha256_hmac_drbg_update(s, key, sizeof(key),
	                                      entropy, entropy_bytes, NULL, 0)) != DRBG_OK) {
		return result;
	}

	/* reset request counter */

	s->requests_left = HMAC_DRBG_MAX_REQUESTS;
	DRBG_RET(DRBG_OK);
}

/* sha256_hmac_drbg_generate
 *
 * This routine generates pseudorandom bytes from a SHA256_HMAC DRBG.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_BAD_LENGTH if too many bytes are requested or the requested
 *  security strength is too large.
 * Returns HMAC errors if they occur.
 */

static uint32_t
sha256_hmac_drbg_generate(
    SHA256_HMAC_DRBG_STATE *s,
    uint32_t sec_strength_bits,
    uint32_t num_bytes,
    uint8_t *out) {
	uint8_t key[32]; /* array of md_len size for sha256_hmac_drbg_update() */
	uint32_t result;

	/* check if number of bytes requested exceeds the maximum allowed */

	if (num_bytes > HMAC_DRBG_MAX_BYTES_PER_REQUEST) {
		DRBG_RET(DRBG_BAD_LENGTH);
	}

	/* check if drbg has adequate security strength */

	if (sec_strength_bits > s->sec_strength) {
		DRBG_RET(DRBG_BAD_LENGTH);
	}

	/* check if max requests have been exceeded */

	if (s->requests_left == 0) {
		if ((result = sha256_hmac_drbg_reseed(s)) != DRBG_OK) {
			return result;
		}
	}

	/* generate pseudorandom bytes */

	while (num_bytes > 0) {
		/* generate md_len bytes = V = HMAC(K, V) */

		if ((result = ntru_crypto_hmac_init(s->hmac_ctx)) !=
		    NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		if ((result = ntru_crypto_hmac_update(s->hmac_ctx, s->V,
		                                      sizeof(key))) != NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		if ((result = ntru_crypto_hmac_final(s->hmac_ctx, s->V)) !=
		    NTRU_CRYPTO_HMAC_OK) {
			return result;
		}

		/* copy generated bytes to output buffer */

		if (num_bytes < sizeof(key)) {
			memcpy(out, s->V, num_bytes);
			num_bytes = 0;
		} else {
			memcpy(out, s->V, sizeof(key));
			out += sizeof(key);
			num_bytes -= sizeof(key);
		}
	}

	/* update internal state */

	if ((result = sha256_hmac_drbg_update(s, key, sizeof(key),
	                                      NULL, 0, NULL, 0)) != DRBG_OK) {
		return result;
	}

	s->requests_left--;

	DRBG_RET(DRBG_OK);
}

/******************
 * DRBG functions *
 ******************/

/* drbg_get_new_drbg
 *
 * This routine finds an uninstantiated drbg state and returns a pointer to it.
 *
 * Returns a pointer to an uninstantiated drbg state if found.
 * Returns NULL if all drbg states are instantiated.
 */

static DRBG_STATE *
drbg_get_new_drbg() {
	int i;

	for (i = 0; i < DRBG_MAX_INSTANTIATIONS; i++) {
		if (drbg_state[i].state == NULL) {
			return drbg_state + i;
		}
	}

	return NULL;
}

/* drbg_get_drbg
 *
 * This routine finds an instantiated drbg state given its handle, and returns
 * a pointer to it.
 *
 * Returns a pointer to the drbg state if found.
 * Returns NULL if the drbg state is not found.
 */

static DRBG_STATE *
drbg_get_drbg(
    DRBG_HANDLE handle) /* in/out - drbg handle */
{
	int i;

	for (i = 0; i < DRBG_MAX_INSTANTIATIONS; i++) {
		if ((drbg_state[i].handle == handle) && drbg_state[i].state) {
			return drbg_state + i;
		}
	}

	return NULL;
}

/* drbg_get_new_handle
 *
 * This routine gets a new, unique 32-bit handle.
 *
 * Returns the new DRBG handle.
 */

static DRBG_HANDLE
drbg_get_new_handle(void) {
	DRBG_HANDLE h = 0;

	/* ensure the new handle is unique:
     *  if it already exists, increment it
     */

	while (drbg_get_drbg(h) != NULL) {
		++h;
	}

	return h;
}

/********************
 * Public functions *
 ********************/

/* ntru_crypto_drbg_instantiate
 *
 * This routine instantiates a drbg with the requested security strength.
 * See ANS X9.82: Part 3-2007. This routine currently returns an instance
 * of SHA-256 HMAC_DRBG for all requested security strengths.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_PARAMETER if an argument pointer is NULL.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_LENGTH if the security strength requested
 *  or the personalization string is too large.
 * Returns DRBG_ERROR_BASE + DRBG_NOT_AVAILABLE if there are no instantiation
 *  slots available
 * Returns DRBG_ERROR_BASE + DRBG_OUT_OF_MEMORY if the internal state cannot be
 *  allocated from the heap.
 */

uint32_t
ntru_crypto_drbg_instantiate(
    uint32_t sec_strength_bits, /*  in - requested sec strength in bits */
    uint8_t const *pers_str,    /*  in - ptr to personalization string */
    uint32_t pers_str_bytes,    /*  in - no. personalization str bytes */
    ENTROPY_FN entropy_fn,      /*  in - pointer to entropy function */
    DRBG_HANDLE *handle)        /* out - address for drbg handle */
{
	DRBG_STATE *drbg = NULL;
	SHA256_HMAC_DRBG_STATE *state = NULL;
	uint32_t result;

	/* check arguments */

	if ((!pers_str && pers_str_bytes) || !entropy_fn || !handle) {
		DRBG_RET(DRBG_BAD_PARAMETER);
	}

	if (sec_strength_bits > DRBG_MAX_SEC_STRENGTH_BITS) {
		DRBG_RET(DRBG_BAD_LENGTH);
	}

	if (pers_str && (pers_str_bytes == 0)) {
		pers_str = NULL;
	}

	/* set security strength */

	if (sec_strength_bits <= 112) {
		sec_strength_bits = 112;
	} else if (sec_strength_bits <= 128) {
		sec_strength_bits = 128;
	} else if (sec_strength_bits <= 192) {
		sec_strength_bits = 192;
	} else {
		sec_strength_bits = 256;
	}

	/* get an uninstantiated drbg */

	if ((drbg = drbg_get_new_drbg()) == NULL) {
		DRBG_RET(DRBG_NOT_AVAILABLE);
	}

	/* init entropy function */

	if (entropy_fn(INIT, NULL) == 0) {
		DRBG_RET(DRBG_ENTROPY_FAIL);
	}

	/* instantiate a SHA-256 HMAC_DRBG */

	if ((result = sha256_hmac_drbg_instantiate(sec_strength_bits,
	                                           pers_str, pers_str_bytes,
	                                           entropy_fn,
	                                           &state)) != DRBG_OK) {
		return result;
	}

	/* init drbg state */

	drbg->handle = drbg_get_new_handle();
	drbg->type = SHA256_HMAC_DRBG;
	drbg->state = state;

	/* return drbg handle */

	*handle = drbg->handle;
	DRBG_RET(DRBG_OK);
}

/* ntru_crypto_drbg_external_instantiate
 *
 * This routine instruments an external DRBG so that ntru_crypto routines
 * can call it. randombytesfn must be of type
 * uint32_t (randombytesfn*)(unsigned char *out, unsigned long long num_bytes);
 * and should return DRBG_OK on success.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_NOT_AVAILABLE if there are no instantiation
 *  slots available
 * Returns DRBG_ERROR_BASE + DRBG_OUT_OF_MEMORY if the internal state cannot be
 *  allocated from the heap.
 */

uint32_t
ntru_crypto_drbg_external_instantiate(
    RANDOM_BYTES_FN randombytesfn, /*  in - pointer to random bytes function */
    DRBG_HANDLE *handle)           /* out - address for drbg handle */
{
	DRBG_STATE *drbg = NULL;
	EXTERNAL_DRBG_STATE *state = NULL;

	if (!randombytesfn || !handle) {
		DRBG_RET(DRBG_BAD_PARAMETER);
	}

	/* get an uninstantiated drbg */

	if ((drbg = drbg_get_new_drbg()) == NULL) {
		DRBG_RET(DRBG_NOT_AVAILABLE);
	}

	/* instantiate an External DRBG */

	state = (EXTERNAL_DRBG_STATE *) MALLOC(sizeof(EXTERNAL_DRBG_STATE));
	if (state == NULL) {
		DRBG_RET(DRBG_OUT_OF_MEMORY);
	}

	state->randombytesfn = randombytesfn;

	/* init drbg state */

	drbg->handle = drbg_get_new_handle();
	drbg->type = EXTERNAL_DRBG;
	drbg->state = state;

	/* return drbg handle */

	*handle = drbg->handle;

	DRBG_RET(DRBG_OK);
}

/* ntru_crypto_drbg_uninstantiate
 *
 * This routine frees a drbg given its handle.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_PARAMETER if handle is not valid.
 */

uint32_t
ntru_crypto_drbg_uninstantiate(
    DRBG_HANDLE handle) /* in - drbg handle */
{
	DRBG_STATE *drbg = NULL;

	/* find the instantiated drbg */

	if ((drbg = drbg_get_drbg(handle)) == NULL) {
		DRBG_RET(DRBG_BAD_PARAMETER);
	}

	/* zero and free drbg state */

	if (drbg->state) {
		switch (drbg->type) {
		case EXTERNAL_DRBG:
			FREE(drbg->state);
			break;
		case SHA256_HMAC_DRBG:
			sha256_hmac_drbg_free((SHA256_HMAC_DRBG_STATE *) drbg->state);
			break;
		}
		drbg->state = NULL;
	}

	drbg->handle = 0;
	DRBG_RET(DRBG_OK);
}

/* ntru_crypto_drbg_reseed
 *
 * This routine reseeds an instantiated drbg.
 * See ANS X9.82: Part 3-2007.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_PARAMETER if handle is not valid.
 * Returns HMAC errors if they occur.
 */

uint32_t
ntru_crypto_drbg_reseed(
    DRBG_HANDLE handle) /* in - drbg handle */
{
	DRBG_STATE *drbg = NULL;

	/* find the instantiated drbg */

	if ((drbg = drbg_get_drbg(handle)) == NULL) {
		DRBG_RET(DRBG_BAD_PARAMETER);
	}

	if (drbg->type == EXTERNAL_DRBG) {
		DRBG_RET(DRBG_BAD_PARAMETER);
	}

	/* reseed the SHA-256 HMAC_DRBG */

	return sha256_hmac_drbg_reseed((SHA256_HMAC_DRBG_STATE *) drbg->state);
}

/* ntru_crypto_drbg_generate
 *
 * This routine generates pseudorandom bytes using an instantiated drbg.
 * If the maximum number of requests has been reached, reseeding will occur.
 * See ANS X9.82: Part 3-2007.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_PARAMETER if handle is not valid or if
 *  an argument pointer is NULL.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_LENGTH if the security strength requested
 *  is too large or the number of bytes requested is zero or too large.
 * Returns HMAC errors if they occur.
 */

uint32_t
ntru_crypto_drbg_generate(
    DRBG_HANDLE handle,         /*  in - drbg handle */
    uint32_t sec_strength_bits, /*  in - requested sec strength in bits */
    uint32_t num_bytes,         /*  in - number of octets to generate */
    uint8_t *out)               /* out - address for generated octets */
{
	DRBG_STATE *drbg = NULL;

	/* find the instantiated drbg */

	if ((drbg = drbg_get_drbg(handle)) == NULL) {
		DRBG_RET(DRBG_BAD_PARAMETER);
	}

	/* check arguments */

	if (!out) {
		DRBG_RET(DRBG_BAD_PARAMETER);
	}

	if (num_bytes == 0) {
		DRBG_RET(DRBG_BAD_LENGTH);
	}

	/* generate pseudorandom output from the SHA256_HMAC_DRBG */

	switch (drbg->type) {
	case EXTERNAL_DRBG:
		return ((EXTERNAL_DRBG_STATE *) drbg->state)->randombytesfn(out, num_bytes);
	case SHA256_HMAC_DRBG:
		return sha256_hmac_drbg_generate(
		    (SHA256_HMAC_DRBG_STATE *) drbg->state,
		    sec_strength_bits, num_bytes, out);
	default:
		DRBG_RET(DRBG_BAD_PARAMETER);
	}
}
