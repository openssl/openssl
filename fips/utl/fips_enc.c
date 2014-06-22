/* fipe/evp/fips_enc.c */
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

#define OPENSSL_FIPSAPI

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/fips.h>

void FIPS_cipher_ctx_init(EVP_CIPHER_CTX *ctx)
	{
	memset(ctx,0,sizeof(EVP_CIPHER_CTX));
	/* ctx->cipher=NULL; */
	}

EVP_CIPHER_CTX *FIPS_cipher_ctx_new(void)
	{
	EVP_CIPHER_CTX *ctx=OPENSSL_malloc(sizeof *ctx);
	if (ctx)
		FIPS_cipher_ctx_init(ctx);
	return ctx;
	}

/* The purpose of these is to trap programs that attempt to use non FIPS
 * algorithms in FIPS mode and ignore the errors.
 */

static int bad_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		    const unsigned char *iv, int enc)
	{ FIPS_ERROR_IGNORED("Cipher init"); return 0;}

static int bad_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			 const unsigned char *in, size_t inl)
	{ FIPS_ERROR_IGNORED("Cipher update"); return 0;}

/* NB: no cleanup because it is allowed after failed init */

static int bad_set_asn1(EVP_CIPHER_CTX *ctx, ASN1_TYPE *typ)
	{ FIPS_ERROR_IGNORED("Cipher set_asn1"); return 0;}
static int bad_get_asn1(EVP_CIPHER_CTX *ctx, ASN1_TYPE *typ)
	{ FIPS_ERROR_IGNORED("Cipher get_asn1"); return 0;}
static int bad_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
	{ FIPS_ERROR_IGNORED("Cipher ctrl"); return 0;}

static const EVP_CIPHER bad_cipher =
	{
	0,
	1,
	0,
	0,
	0,
	bad_init,
	bad_do_cipher,
	NULL,
	0,
	bad_set_asn1,
	bad_get_asn1,
	bad_ctrl,
	NULL
	};

int FIPS_cipherinit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
	     const unsigned char *key, const unsigned char *iv, int enc)
	{
	if(FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_CIPHERINIT,FIPS_R_FIPS_SELFTEST_FAILED);
		ctx->cipher = &bad_cipher;
		return 0;
		}
	if (enc == -1)
		enc = ctx->encrypt;
	else
		{
		if (enc)
			enc = 1;
		ctx->encrypt = enc;
		}
	if (cipher)
		{
		/* Only FIPS ciphers allowed */
		if (FIPS_module_mode() && !(cipher->flags & EVP_CIPH_FLAG_FIPS) &&
			!(ctx->flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW))
			{
			EVPerr(EVP_F_FIPS_CIPHERINIT, EVP_R_DISABLED_FOR_FIPS);
			ctx->cipher = &bad_cipher;
			return 0;
			}
		/* Ensure a context left lying around from last time is cleared
		 * (the previous check attempted to avoid this if the same
		 * ENGINE and EVP_CIPHER could be used). */
		FIPS_cipher_ctx_cleanup(ctx);

		/* Restore encrypt field: it is zeroed by cleanup */
		ctx->encrypt = enc;

		ctx->cipher=cipher;
		if (ctx->cipher->ctx_size)
			{
			ctx->cipher_data=OPENSSL_malloc(ctx->cipher->ctx_size);
			if (!ctx->cipher_data)
				{
				EVPerr(EVP_F_FIPS_CIPHERINIT, ERR_R_MALLOC_FAILURE);
				return 0;
				}
			}
		else
			{
			ctx->cipher_data = NULL;
			}
		ctx->key_len = cipher->key_len;
		ctx->flags = 0;
		if(ctx->cipher->flags & EVP_CIPH_CTRL_INIT)
			{
			if(!FIPS_cipher_ctx_ctrl(ctx, EVP_CTRL_INIT, 0, NULL))
				{
				EVPerr(EVP_F_FIPS_CIPHERINIT, EVP_R_INITIALIZATION_ERROR);
				return 0;
				}
			}
		}
	else if(!ctx->cipher)
		{
		EVPerr(EVP_F_FIPS_CIPHERINIT, EVP_R_NO_CIPHER_SET);
		return 0;
		}
	/* we assume block size is a power of 2 in *cryptUpdate */
	OPENSSL_assert(ctx->cipher->block_size == 1
	    || ctx->cipher->block_size == 8
	    || ctx->cipher->block_size == 16);

	if(!(M_EVP_CIPHER_CTX_flags(ctx) & EVP_CIPH_CUSTOM_IV)) {
		switch(M_EVP_CIPHER_CTX_mode(ctx)) {

			case EVP_CIPH_STREAM_CIPHER:
			case EVP_CIPH_ECB_MODE:
			break;

			case EVP_CIPH_CFB_MODE:
			case EVP_CIPH_OFB_MODE:

			ctx->num = 0;
			/* fall-through */

			case EVP_CIPH_CBC_MODE:

			OPENSSL_assert(M_EVP_CIPHER_CTX_iv_length(ctx) <=
					(int)sizeof(ctx->iv));
			if(iv) memcpy(ctx->oiv, iv, M_EVP_CIPHER_CTX_iv_length(ctx));
			memcpy(ctx->iv, ctx->oiv, M_EVP_CIPHER_CTX_iv_length(ctx));
			break;

			case EVP_CIPH_CTR_MODE:
			/* Don't reuse IV for CTR mode */
			if(iv)
				memcpy(ctx->iv, iv, M_EVP_CIPHER_CTX_iv_length(ctx));
			break;

			default:
			return 0;
			break;
		}
	}

	if(key || (ctx->cipher->flags & EVP_CIPH_ALWAYS_CALL_INIT)) {
		if(!ctx->cipher->init(ctx,key,iv,enc)) return 0;
	}
	ctx->buf_len=0;
	ctx->final_used=0;
	ctx->block_mask=ctx->cipher->block_size-1;
	return 1;
	}

void FIPS_cipher_ctx_free(EVP_CIPHER_CTX *ctx)
	{
	if (ctx)
		{
		FIPS_cipher_ctx_cleanup(ctx);
		OPENSSL_free(ctx);
		}
	}

int FIPS_cipher_ctx_cleanup(EVP_CIPHER_CTX *c)
	{
	if (c->cipher != NULL)
		{
		if(c->cipher->cleanup && !c->cipher->cleanup(c))
			return 0;
		/* Cleanse cipher context data */
		if (c->cipher_data)
			OPENSSL_cleanse(c->cipher_data, c->cipher->ctx_size);
		}
	if (c->cipher_data)
		OPENSSL_free(c->cipher_data);
	memset(c,0,sizeof(EVP_CIPHER_CTX));
	return 1;
	}

int FIPS_cipher_ctx_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	int ret;
	if (FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_CIPHER_CTX_CTRL, FIPS_R_SELFTEST_FAILED);
		return 0;
		}
	if(!ctx->cipher) {
		EVPerr(EVP_F_FIPS_CIPHER_CTX_CTRL, EVP_R_NO_CIPHER_SET);
		return 0;
	}

	if(!ctx->cipher->ctrl) {
		EVPerr(EVP_F_FIPS_CIPHER_CTX_CTRL, EVP_R_CTRL_NOT_IMPLEMENTED);
		return 0;
	}

	ret = ctx->cipher->ctrl(ctx, type, arg, ptr);
	if(ret == -1) {
		EVPerr(EVP_F_FIPS_CIPHER_CTX_CTRL, EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED);
		return 0;
	}
	return ret;
}

int FIPS_cipher_ctx_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in)
	{
	if ((in == NULL) || (in->cipher == NULL))
		{
		EVPerr(EVP_F_FIPS_CIPHER_CTX_COPY,EVP_R_INPUT_NOT_INITIALIZED);
		return 0;
		}

	/* Only FIPS ciphers allowed */
	if (FIPS_module_mode() && !(in->cipher->flags & EVP_CIPH_FLAG_FIPS) &&
		!(out->flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW))
		{
		EVPerr(EVP_F_FIPS_CIPHER_CTX_COPY, EVP_R_DISABLED_FOR_FIPS);
		out->cipher = &bad_cipher;
		return 0;
		}

	FIPS_cipher_ctx_cleanup(out);
	memcpy(out,in,sizeof *out);

	if (in->cipher_data && in->cipher->ctx_size)
		{
		out->cipher_data=OPENSSL_malloc(in->cipher->ctx_size);
		if (!out->cipher_data)
			{
			EVPerr(EVP_F_FIPS_CIPHER_CTX_COPY,ERR_R_MALLOC_FAILURE);
			return 0;
			}
		memcpy(out->cipher_data,in->cipher_data,in->cipher->ctx_size);
		}

	if (in->cipher->flags & EVP_CIPH_CUSTOM_COPY)
		return in->cipher->ctrl((EVP_CIPHER_CTX *)in, EVP_CTRL_COPY, 0, out);
	return 1;
	}

/* You can't really set the key length with FIPS, so just check that the
   caller sets the length the context already has. */
int FIPS_cipher_ctx_set_key_length(EVP_CIPHER_CTX *ctx, int keylen)
	{
	if (ctx->key_len == keylen)
		return 1;

	EVPerr(EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH,EVP_R_INVALID_KEY_LENGTH);
	return 0;
	}



int FIPS_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			const unsigned char *in, unsigned int inl)
	{
	if (FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_CIPHER, FIPS_R_SELFTEST_FAILED);
		return -1;
		}
	return ctx->cipher->do_cipher(ctx,out,in,inl);
	}

const EVP_CIPHER *FIPS_get_cipherbynid(int nid)
	{
	switch (nid)
		{
		case NID_aes_128_cbc:
		return FIPS_evp_aes_128_cbc();

		case NID_aes_128_ccm:
		return FIPS_evp_aes_128_ccm();

		case NID_aes_128_cfb1:
		return FIPS_evp_aes_128_cfb1();

		case NID_aes_128_cfb128:
		return FIPS_evp_aes_128_cfb128();

		case NID_aes_128_cfb8:
		return FIPS_evp_aes_128_cfb8();

		case NID_aes_128_ctr:
		return FIPS_evp_aes_128_ctr();

		case NID_aes_128_ecb:
		return FIPS_evp_aes_128_ecb();

		case NID_aes_128_gcm:
		return FIPS_evp_aes_128_gcm();

		case NID_aes_128_ofb128:
		return FIPS_evp_aes_128_ofb();

		case NID_aes_128_xts:
		return FIPS_evp_aes_128_xts();

		case NID_aes_192_cbc:
		return FIPS_evp_aes_192_cbc();

		case NID_aes_192_ccm:
		return FIPS_evp_aes_192_ccm();

		case NID_aes_192_cfb1:
		return FIPS_evp_aes_192_cfb1();

		case NID_aes_192_cfb128:
		return FIPS_evp_aes_192_cfb128();

		case NID_aes_192_cfb8:
		return FIPS_evp_aes_192_cfb8();

		case NID_aes_192_ctr:
		return FIPS_evp_aes_192_ctr();

		case NID_aes_192_ecb:
		return FIPS_evp_aes_192_ecb();

		case NID_aes_192_gcm:
		return FIPS_evp_aes_192_gcm();

		case NID_aes_192_ofb128:
		return FIPS_evp_aes_192_ofb();

		case NID_aes_256_cbc:
		return FIPS_evp_aes_256_cbc();

		case NID_aes_256_ccm:
		return FIPS_evp_aes_256_ccm();

		case NID_aes_256_cfb1:
		return FIPS_evp_aes_256_cfb1();

		case NID_aes_256_cfb128:
		return FIPS_evp_aes_256_cfb128();

		case NID_aes_256_cfb8:
		return FIPS_evp_aes_256_cfb8();

		case NID_aes_256_ctr:
		return FIPS_evp_aes_256_ctr();

		case NID_aes_256_ecb:
		return FIPS_evp_aes_256_ecb();

		case NID_aes_256_gcm:
		return FIPS_evp_aes_256_gcm();

		case NID_aes_256_ofb128:
		return FIPS_evp_aes_256_ofb();

		case NID_aes_256_xts:
		return FIPS_evp_aes_256_xts();

		case NID_des_ede_ecb:
		return FIPS_evp_des_ede();

		case NID_des_ede3_ecb:
		return FIPS_evp_des_ede3();

		case NID_des_ede3_cbc:
		return FIPS_evp_des_ede3_cbc();

		case NID_des_ede3_cfb1:
		return FIPS_evp_des_ede3_cfb1();

		case NID_des_ede3_cfb64:
		return FIPS_evp_des_ede3_cfb64();

		case NID_des_ede3_cfb8:
		return FIPS_evp_des_ede3_cfb8();

		case NID_des_ede3_ofb64:
		return FIPS_evp_des_ede3_ofb();

		case NID_des_ede_cbc:
		return FIPS_evp_des_ede_cbc();

		case NID_des_ede_cfb64:
		return FIPS_evp_des_ede_cfb64();

		case NID_des_ede_ofb64:
		return FIPS_evp_des_ede_ofb();

		default:
		return NULL;

		}
	}

