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
 * File: ntru_crypto_hmac.c
 *
 * Contents: Routines implementing the HMAC hash calculation.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_hmac.h"

/* HMAC context */

struct _NTRU_CRYPTO_HMAC_CTX {
	NTRU_CRYPTO_HASH_CTX hash_ctx;
	uint8_t *k0;
	uint16_t blk_len;
	uint16_t md_len;
};

/* ntru_crypto_hmac_create_ctx
 *
 * This routine creates an HMAC context, setting the hash algorithm and
 * the key to be used.
 *
 * Returns NTRU_CRYPTO_HMAC_OK if successful.
 * Returns NTRU_CRYPTO_HMAC_BAD_ALG if the specified algorithm is not supported.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HMAC_OUT_OF_MEMORY if memory cannot be allocated.
 */

uint32_t
ntru_crypto_hmac_create_ctx(
    NTRU_CRYPTO_HASH_ALGID algid, /*  in - the hash algorithm to be used */
    uint8_t const *key,           /*  in - pointer to the HMAC key */
    uint32_t key_len,             /*  in - number of bytes in HMAC key */
    NTRU_CRYPTO_HMAC_CTX **c)     /* out - address for pointer to HMAC
                                               context */
{
	NTRU_CRYPTO_HMAC_CTX *ctx = NULL;
	uint32_t result;

	/* check parameters */

	if (!c || !key) {
		HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);
	}

	*c = NULL;

	/* allocate memory for an HMAC context */
	if (NULL == (ctx = (NTRU_CRYPTO_HMAC_CTX *) MALLOC(sizeof(NTRU_CRYPTO_HMAC_CTX)))) {
		HMAC_RET(NTRU_CRYPTO_HMAC_OUT_OF_MEMORY);
	}

	/* set the algorithm */

	if ((result = ntru_crypto_hash_set_alg(algid, &ctx->hash_ctx))) {
		FREE(ctx);
		HMAC_RET(NTRU_CRYPTO_HMAC_BAD_ALG);
	}

	/* set block length and digest length */

	if ((result = ntru_crypto_hash_block_length(&ctx->hash_ctx,
	                                            &ctx->blk_len)) ||
	    (result = ntru_crypto_hash_digest_length(&ctx->hash_ctx,
	                                             &ctx->md_len))) {
		FREE(ctx);
		return result;
	}

	/* allocate memory for K0 */
	if ((ctx->k0 = (uint8_t *) MALLOC(ctx->blk_len)) == NULL) {
		FREE(ctx);
		HMAC_RET(NTRU_CRYPTO_HMAC_OUT_OF_MEMORY);
	}

	/* calculate K0 and store in HMAC context */

	memset(ctx->k0, 0, ctx->blk_len);

	/* check if key is too large */

	if (key_len > ctx->blk_len) {
		if ((result = ntru_crypto_hash_digest(algid, key, key_len, ctx->k0))) {
			memset(ctx->k0, 0, ctx->blk_len);
			FREE(ctx->k0);
			FREE(ctx);
			return result;
		}
	} else {
		memcpy(ctx->k0, key, key_len);
	}

	/* return pointer to HMAC context */

	*c = ctx;
	HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}

/* ntru_crypto_hmac_destroy_ctx
 *
 * Destroys an HMAC context.
 *
 * Returns NTRU_CRYPTO_HMAC_OK if successful.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_destroy_ctx(
    NTRU_CRYPTO_HMAC_CTX *c) /* in/out - pointer to HMAC context */
{
	if (!c || !c->k0) {
		HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);
	}

	/* clear key and release memory */

	memset(c->k0, 0, c->blk_len);
	FREE(c->k0);
	FREE(c);

	HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}

/* ntru_crypto_hmac_get_md_len
 *
 * This routine gets the digest length of the HMAC.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_get_md_len(
    NTRU_CRYPTO_HMAC_CTX const *c, /*  in - pointer to HMAC context */
    uint16_t *md_len)              /* out - address for digest length */
{
	/* check parameters */

	if (!c || !md_len) {
		HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);
	}

	/* get digest length */

	*md_len = c->md_len;
	HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}

/* ntru_crypto_hmac_set_key
 *
 * This routine sets a digest-length key into the HMAC context.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_set_key(
    NTRU_CRYPTO_HMAC_CTX *c, /*  in - pointer to HMAC context */
    uint8_t const *key)      /*  in - pointer to new HMAC key */
{
	/* check parameters */

	if (!c || !key) {
		HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);
	}

	/* copy key */

	memcpy(c->k0, key, c->md_len);
	HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}

/* ntru_crypto_hmac_init
 *
 * This routine performs standard initialization of the HMAC state.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_init(
    NTRU_CRYPTO_HMAC_CTX *c) /* in/out - pointer to HMAC context */
{
	uint32_t result;
	int i;

	/* check parameters */

	if (!c) {
		HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);
	}

	/* init hash context and compute H(K0 ^ ipad) */

	for (i = 0; i < c->blk_len; i++) {
		c->k0[i] ^= 0x36; /* K0 ^ ipad */
	}

	if ((result = ntru_crypto_hash_init(&c->hash_ctx)) ||
	    (result = ntru_crypto_hash_update(&c->hash_ctx, c->k0, c->blk_len))) {
		return result;
	}

	HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}

/* ntru_crypto_hmac_update
 *
 * This routine processes input data and updates the HMAC hash calculation.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_OVERFLOW if more than bytes are hashed than the
 *         underlying hash algorithm can handle.
 */

uint32_t
ntru_crypto_hmac_update(
    NTRU_CRYPTO_HMAC_CTX *c, /* in/out - pointer to HMAC context */
    const uint8_t *data,     /*     in - pointer to input data */
    uint32_t data_len)       /*     in - no. of bytes of input data */
{
	uint32_t result;

	/* check parameters */

	if (!c || (data_len && !data)) {
		HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);
	}

	if ((result = ntru_crypto_hash_update(&c->hash_ctx, data, data_len))) {
		return result;
	}

	HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}

/* ntru_crypto_hmac_final
 *
 * This routine completes the HMAC hash calculation and returns the
 * message digest.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_final(
    NTRU_CRYPTO_HMAC_CTX *c, /* in/out - pointer to HMAC context */
    uint8_t *md)             /*   out - address for message digest */
{
	uint32_t result = NTRU_CRYPTO_HMAC_OK;
	int i;

	/* check parameters */

	if (!c || !md) {
		HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);
	}

	/* form K0 ^ opad
     * complete md = H((K0 ^ ipad) || data)
     * compute  md = H((K0 ^ opad) || md)
     * re-form K0
     */

	for (i = 0; i < c->blk_len; i++) {
		c->k0[i] ^= (0x36 ^ 0x5c);
	}

	if ((result = ntru_crypto_hash_final(&c->hash_ctx, md)) ||
	    (result = ntru_crypto_hash_init(&c->hash_ctx)) ||
	    (result = ntru_crypto_hash_update(&c->hash_ctx, c->k0, c->blk_len)) ||
	    (result = ntru_crypto_hash_update(&c->hash_ctx, md, c->md_len)) ||
	    (result = ntru_crypto_hash_final(&c->hash_ctx, md))) {
	}

	for (i = 0; i < c->blk_len; i++) {
		c->k0[i] ^= 0x5c;
	}

	return result;
}
