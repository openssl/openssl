/* fips/evp/fips_md.c */
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
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Minimal standalone FIPS versions of Digest operations */

#define OPENSSL_FIPSAPI

#include <stdio.h>
#include <string.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/fips.h>

void FIPS_md_ctx_init(EVP_MD_CTX *ctx)
	{
	memset(ctx,'\0',sizeof *ctx);
	}

EVP_MD_CTX *FIPS_md_ctx_create(void)
	{
	EVP_MD_CTX *ctx=OPENSSL_malloc(sizeof *ctx);

	if (ctx)
		FIPS_md_ctx_init(ctx);

	return ctx;
	}

/* The purpose of these is to trap programs that attempt to use non FIPS
 * algorithms in FIPS mode and ignore the errors.
 */

static int bad_init(EVP_MD_CTX *ctx)
	{ FIPS_ERROR_IGNORED("Digest init"); return 0;}

static int bad_update(EVP_MD_CTX *ctx,const void *data,size_t count)
	{ FIPS_ERROR_IGNORED("Digest update"); return 0;}

static int bad_final(EVP_MD_CTX *ctx,unsigned char *md)
	{ FIPS_ERROR_IGNORED("Digest Final"); return 0;}

static const EVP_MD bad_md =
	{
	0,
	0,
	0,
	0,
	bad_init,
	bad_update,
	bad_final,
	NULL,
	NULL,
	NULL,
	0,
	{0,0,0,0},
	};

int FIPS_digestinit(EVP_MD_CTX *ctx, const EVP_MD *type)
	{
	M_EVP_MD_CTX_clear_flags(ctx,EVP_MD_CTX_FLAG_CLEANED);
	if(FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_DIGESTINIT,FIPS_R_FIPS_SELFTEST_FAILED);
		ctx->digest = &bad_md;
		ctx->update = bad_update;
		return 0;
		}
	if(FIPS_module_mode() && !(type->flags & EVP_MD_FLAG_FIPS) &&
		!(ctx->flags & EVP_MD_CTX_FLAG_NON_FIPS_ALLOW))
		{
		EVPerr(EVP_F_FIPS_DIGESTINIT, EVP_R_DISABLED_FOR_FIPS);
		ctx->digest = &bad_md;
		ctx->update = bad_update;
		return 0;
		}
	if (ctx->digest != type)
		{
		if (ctx->digest && ctx->digest->ctx_size)
			OPENSSL_free(ctx->md_data);
		ctx->digest=type;
		if (!(ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) && type->ctx_size)
			{
			ctx->update = type->update;
			ctx->md_data=OPENSSL_malloc(type->ctx_size);
			if (ctx->md_data == NULL)
				{
				EVPerr(EVP_F_FIPS_DIGESTINIT,
							ERR_R_MALLOC_FAILURE);
				return 0;
				}
			}
		}
	if (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT)
		return 1;
	return ctx->digest->init(ctx);
	}

int FIPS_digestupdate(EVP_MD_CTX *ctx, const void *data, size_t count)
	{
	if (FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_DIGESTUPDATE, FIPS_R_SELFTEST_FAILED);
		return 0;
		}
	return ctx->update(ctx,data,count);
	}

/* The caller can assume that this removes any secret data from the context */
int FIPS_digestfinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
	{
	int ret;

	if (FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_DIGESTFINAL, FIPS_R_SELFTEST_FAILED);
		return 0;
		}

	OPENSSL_assert(ctx->digest->md_size <= EVP_MAX_MD_SIZE);
	ret=ctx->digest->final(ctx,md);
	if (size != NULL)
		*size=ctx->digest->md_size;
	if (ctx->digest->cleanup)
		{
		ctx->digest->cleanup(ctx);
		M_EVP_MD_CTX_set_flags(ctx,EVP_MD_CTX_FLAG_CLEANED);
		}
	memset(ctx->md_data,0,ctx->digest->ctx_size);
	return ret;
	}

int FIPS_digest(const void *data, size_t count,
		unsigned char *md, unsigned int *size, const EVP_MD *type)
	{
	EVP_MD_CTX ctx;
	int ret;

	FIPS_md_ctx_init(&ctx);
	M_EVP_MD_CTX_set_flags(&ctx,EVP_MD_CTX_FLAG_ONESHOT);
	ret=FIPS_digestinit(&ctx, type)
	  && FIPS_digestupdate(&ctx, data, count)
	  && FIPS_digestfinal(&ctx, md, size);
	FIPS_md_ctx_cleanup(&ctx);

	return ret;
	}

void FIPS_md_ctx_destroy(EVP_MD_CTX *ctx)
	{
	FIPS_md_ctx_cleanup(ctx);
	OPENSSL_free(ctx);
	}

/* This call frees resources associated with the context */
int FIPS_md_ctx_cleanup(EVP_MD_CTX *ctx)
	{
	/* Don't assume ctx->md_data was cleaned in FIPS_digest_Final,
	 * because sometimes only copies of the context are ever finalised.
	 */
	if (ctx->digest && ctx->digest->cleanup
	    && !M_EVP_MD_CTX_test_flags(ctx,EVP_MD_CTX_FLAG_CLEANED))
		ctx->digest->cleanup(ctx);
	if (ctx->digest && ctx->digest->ctx_size && ctx->md_data
	    && !M_EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE))
		{
		OPENSSL_cleanse(ctx->md_data,ctx->digest->ctx_size);
		OPENSSL_free(ctx->md_data);
		}
	memset(ctx,'\0',sizeof *ctx);

	return 1;
	}

int FIPS_md_ctx_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
	{
	unsigned char *tmp_buf;
	if ((in == NULL) || (in->digest == NULL))
		{
		EVPerr(EVP_F_FIPS_MD_CTX_COPY,EVP_R_INPUT_NOT_INITIALIZED);
		return 0;
		}

	if (out->digest == in->digest)
		{
		tmp_buf = out->md_data;
	    	M_EVP_MD_CTX_set_flags(out,EVP_MD_CTX_FLAG_REUSE);
		}
	else tmp_buf = NULL;
	FIPS_md_ctx_cleanup(out);
	memcpy(out,in,sizeof *out);

	if (in->md_data && out->digest->ctx_size)
		{
		if (tmp_buf)
			out->md_data = tmp_buf;
		else
			{
			out->md_data=OPENSSL_malloc(out->digest->ctx_size);
			if (!out->md_data)
				{
				EVPerr(EVP_F_FIPS_MD_CTX_COPY,ERR_R_MALLOC_FAILURE);
				return 0;
				}
			}
		memcpy(out->md_data,in->md_data,out->digest->ctx_size);
		}

	out->update = in->update;

	if (out->digest->copy)
		return out->digest->copy(out,in);
	
	return 1;
	}

const EVP_MD *FIPS_get_digestbynid(int nid)
	{
	switch (nid)
		{
		case NID_sha1:
		return EVP_sha1();

		case NID_sha224:
		return EVP_sha224();

		case NID_sha256:
		return EVP_sha256();

		case NID_sha384:
		return EVP_sha384();

		case NID_sha512:
		return EVP_sha512();

		default:
		return NULL;
		}
	}
