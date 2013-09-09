/* ====================================================================
 * Copyright (c) 2013 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <stdint.h>
#include <string.h>
#include <openssl/opensslconf.h>

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)

#include <openssl/chacha.h>
#include <openssl/poly1305.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "evp_locl.h"

#define POLY1305_TAG_LEN 16
#define CHACHA20_NONCE_LEN 8

struct aead_chacha20_poly1305_ctx
	{
	unsigned char key[32];
	unsigned char tag_len;
	};

static int aead_chacha20_poly1305_init(EVP_AEAD_CTX *ctx, const unsigned char *key, size_t key_len, size_t tag_len)
	{
	struct aead_chacha20_poly1305_ctx *c20_ctx;

	if (tag_len == 0)
		tag_len = POLY1305_TAG_LEN;

	if (tag_len > POLY1305_TAG_LEN)
		{
		EVPerr(EVP_F_AEAD_CHACHA20_POLY1305_INIT, EVP_R_TOO_LARGE);
		return 0;
		}

	if (key_len != sizeof(c20_ctx->key))
		return 0;  /* internal error - EVP_AEAD_CTX_init should catch this. */

	c20_ctx = OPENSSL_malloc(sizeof(struct aead_chacha20_poly1305_ctx));
	if (c20_ctx == NULL)
		return 0;

	memcpy(&c20_ctx->key[0], key, key_len);
	c20_ctx->tag_len = tag_len;
	ctx->aead_state = c20_ctx;

	return 1;
	}

static void aead_chacha20_poly1305_cleanup(EVP_AEAD_CTX *ctx)
	{
	struct aead_chacha20_poly1305_ctx *c20_ctx = ctx->aead_state;
	OPENSSL_cleanse(c20_ctx->key, sizeof(c20_ctx->key));
	OPENSSL_free(c20_ctx);
	}

static void poly1305_update_with_length(poly1305_state *poly1305,
	const unsigned char *data, size_t data_len)
	{
	size_t j = data_len;
	unsigned char length_bytes[8];
	unsigned i;

	for (i = 0; i < sizeof(length_bytes); i++)
		{
		length_bytes[i] = j;
		j >>= 8;
		}

	CRYPTO_poly1305_update(poly1305, length_bytes, sizeof(length_bytes));
	CRYPTO_poly1305_update(poly1305, data, data_len);
}

static ssize_t aead_chacha20_poly1305_seal(const EVP_AEAD_CTX *ctx,
	unsigned char *out, size_t max_out_len,
	const unsigned char *nonce, size_t nonce_len,
	const unsigned char *in, size_t in_len,
	const unsigned char *ad, size_t ad_len)
	{
	const struct aead_chacha20_poly1305_ctx *c20_ctx = ctx->aead_state;
	unsigned char poly1305_key[32];
	poly1305_state poly1305;
	const uint64_t in_len_64 = in_len;

	/* The underlying ChaCha implementation may not overflow the block
	 * counter into the second counter word. Therefore we disallow
	 * individual operations that work on more than 2TB at a time.
	 * |in_len_64| is needed because, on 32-bit platforms, size_t is only
	 * 32-bits and this produces a warning because it's always false.
	 * Casting to uint64_t inside the conditional is not sufficient to stop
	 * the warning. */
	if (in_len_64 >= (1ull << 32)*64-64)
		{
		EVPerr(EVP_F_AEAD_CHACHA20_POLY1305_SEAL, EVP_R_TOO_LARGE);
		return -1;
		}

	if (max_out_len < in_len + c20_ctx->tag_len)
		{
		EVPerr(EVP_F_AEAD_CHACHA20_POLY1305_SEAL, EVP_R_BUFFER_TOO_SMALL);
		return -1;
		}

	if (nonce_len != CHACHA20_NONCE_LEN)
		{
		EVPerr(EVP_F_AEAD_CHACHA20_POLY1305_SEAL, EVP_R_IV_TOO_LARGE);
		return -1;
		}

	memset(poly1305_key, 0, sizeof(poly1305_key));
	CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key), c20_ctx->key, nonce, 0);

	CRYPTO_poly1305_init(&poly1305, poly1305_key);
	poly1305_update_with_length(&poly1305, ad, ad_len);
	CRYPTO_chacha_20(out, in, in_len, c20_ctx->key, nonce, 1);
	poly1305_update_with_length(&poly1305, out, in_len);

	if (c20_ctx->tag_len != POLY1305_TAG_LEN)
		{
		unsigned char tag[POLY1305_TAG_LEN];
		CRYPTO_poly1305_finish(&poly1305, tag);
		memcpy(out + in_len, tag, c20_ctx->tag_len);
		return in_len + c20_ctx->tag_len;
		}

	CRYPTO_poly1305_finish(&poly1305, out + in_len);
	return in_len + POLY1305_TAG_LEN;
	}

static ssize_t aead_chacha20_poly1305_open(const EVP_AEAD_CTX *ctx,
	unsigned char *out, size_t max_out_len,
	const unsigned char *nonce, size_t nonce_len,
	const unsigned char *in, size_t in_len,
	const unsigned char *ad, size_t ad_len)
	{
	const struct aead_chacha20_poly1305_ctx *c20_ctx = ctx->aead_state;
	unsigned char mac[POLY1305_TAG_LEN];
	unsigned char poly1305_key[32];
	size_t out_len;
	poly1305_state poly1305;
	const uint64_t in_len_64 = in_len;

	if (in_len < c20_ctx->tag_len)
		{
		EVPerr(EVP_F_AEAD_CHACHA20_POLY1305_OPEN, EVP_R_BAD_DECRYPT);
		return -1;
		}

	/* The underlying ChaCha implementation may not overflow the block
	 * counter into the second counter word. Therefore we disallow
	 * individual operations that work on more than 2TB at a time.
	 * |in_len_64| is needed because, on 32-bit platforms, size_t is only
	 * 32-bits and this produces a warning because it's always false.
	 * Casting to uint64_t inside the conditional is not sufficient to stop
	 * the warning. */
	if (in_len_64 >= (1ull << 32)*64-64)
		{
		EVPerr(EVP_F_AEAD_CHACHA20_POLY1305_OPEN, EVP_R_TOO_LARGE);
		return -1;
		}

	if (nonce_len != CHACHA20_NONCE_LEN)
		{
		EVPerr(EVP_F_AEAD_CHACHA20_POLY1305_OPEN, EVP_R_IV_TOO_LARGE);
		return -1;
		}

	out_len = in_len - c20_ctx->tag_len;

	if (max_out_len < out_len)
		{
		EVPerr(EVP_F_AEAD_CHACHA20_POLY1305_OPEN, EVP_R_BUFFER_TOO_SMALL);
		return -1;
		}

	memset(poly1305_key, 0, sizeof(poly1305_key));
	CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key), c20_ctx->key, nonce, 0);

	CRYPTO_poly1305_init(&poly1305, poly1305_key);
	poly1305_update_with_length(&poly1305, ad, ad_len);
	poly1305_update_with_length(&poly1305, in, out_len);
	CRYPTO_poly1305_finish(&poly1305, mac);

	if (CRYPTO_memcmp(mac, in + out_len, c20_ctx->tag_len) != 0)
		{
		EVPerr(EVP_F_AEAD_CHACHA20_POLY1305_OPEN, EVP_R_BAD_DECRYPT);
		return -1;
		}

	CRYPTO_chacha_20(out, in, out_len, c20_ctx->key, nonce, 1);
	return out_len;
	}

static const EVP_AEAD aead_chacha20_poly1305 =
	{
	32,  /* key len */
	CHACHA20_NONCE_LEN,   /* nonce len */
	POLY1305_TAG_LEN,  /* overhead */
	POLY1305_TAG_LEN,  /* max tag length */

	aead_chacha20_poly1305_init,
	aead_chacha20_poly1305_cleanup,
	aead_chacha20_poly1305_seal,
	aead_chacha20_poly1305_open,
	};

const EVP_AEAD *EVP_aead_chacha20_poly1305()
	{
	return &aead_chacha20_poly1305;
	}

#endif  /* !OPENSSL_NO_CHACHA && !OPENSSL_NO_POLY1305 */
