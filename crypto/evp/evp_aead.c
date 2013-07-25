/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <limits.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "evp_locl.h"

size_t EVP_AEAD_key_length(const EVP_AEAD *aead)
	{
	return aead->key_len;
	}

size_t EVP_AEAD_nonce_length(const EVP_AEAD *aead)
	{
	return aead->nonce_len;
	}

size_t EVP_AEAD_max_overhead(const EVP_AEAD *aead)
	{
	return aead->overhead;
	}

size_t EVP_AEAD_max_tag_len(const EVP_AEAD *aead)
	{
	return aead->max_tag_len;
	}

int EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const EVP_AEAD *aead,
		      const unsigned char *key, size_t key_len,
		      size_t tag_len, ENGINE *impl)
	{
	ctx->aead = aead;
	if (key_len != aead->key_len)
		{
		EVPerr(EVP_F_EVP_AEAD_CTX_INIT,EVP_R_UNSUPPORTED_KEY_SIZE);
		return 0;
		}
	return aead->init(ctx, key, key_len, tag_len);
	}

void EVP_AEAD_CTX_cleanup(EVP_AEAD_CTX *ctx)
	{
	if (ctx->aead == NULL)
		return;
	ctx->aead->cleanup(ctx);
	ctx->aead = NULL;
	}

/* check_alias returns 0 if |out| points within the buffer determined by |in|
 * and |in_len| and 1 otherwise.
 *
 * When processing, there's only an issue if |out| points within in[:in_len]
 * and isn't equal to |in|. If that's the case then writing the output will
 * stomp input that hasn't been read yet.
 *
 * This function checks for that case. */
static int check_alias(const unsigned char *in, size_t in_len,
		       const unsigned char *out)
	{
	if (out <= in)
		return 1;
	if (in + in_len < out)
		return 1;
	return 0;
	}

ssize_t EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *ctx,
			  unsigned char *out, size_t max_out_len,
			  const unsigned char *nonce, size_t nonce_len,
			  const unsigned char *in, size_t in_len,
			  const unsigned char *ad, size_t ad_len)
	{
	size_t possible_out_len = in_len + ctx->aead->overhead;
	ssize_t r;

	if (possible_out_len < in_len /* overflow */ ||
	    possible_out_len > SSIZE_MAX /* return value cannot be
					    represented */)
		{
		EVPerr(EVP_F_EVP_AEAD_CTX_SEAL, EVP_R_TOO_LARGE);
		goto error;
		}

	if (!check_alias(in, in_len, out))
		{
		EVPerr(EVP_F_EVP_AEAD_CTX_SEAL, EVP_R_OUTPUT_ALIASES_INPUT);
		goto error;
		}

	r = ctx->aead->seal(ctx, out, max_out_len, nonce, nonce_len,
			    in, in_len, ad, ad_len);
	if (r >= 0)
		return r;

error:
	/* In the event of an error, clear the output buffer so that a caller
	 * that doesn't check the return value doesn't send raw data. */
	memset(out, 0, max_out_len);
	return -1;
	}

ssize_t EVP_AEAD_CTX_open(const EVP_AEAD_CTX *ctx,
			 unsigned char *out, size_t max_out_len,
			 const unsigned char *nonce, size_t nonce_len,
			 const unsigned char *in, size_t in_len,
			 const unsigned char *ad, size_t ad_len)
	{
	ssize_t r;

	if (in_len > SSIZE_MAX)
		{
		EVPerr(EVP_F_EVP_AEAD_CTX_OPEN, EVP_R_TOO_LARGE);
		goto error;  /* may not be able to represent return value. */
		}

	if (!check_alias(in, in_len, out))
		{
		EVPerr(EVP_F_EVP_AEAD_CTX_OPEN, EVP_R_OUTPUT_ALIASES_INPUT);
		goto error;
		}

	r = ctx->aead->open(ctx, out, max_out_len, nonce, nonce_len,
			    in, in_len, ad, ad_len);

	if (r >= 0)
		return r;

error:
	/* In the event of an error, clear the output buffer so that a caller
	 * that doesn't check the return value doesn't try and process bad
	 * data. */
	memset(out, 0, max_out_len);
	return -1;
	}
