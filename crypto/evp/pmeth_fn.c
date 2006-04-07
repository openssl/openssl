/* pmeth_fn.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <stdio.h>
#include <stdlib.h>
#include <openssl/objects.h>
#include "cryptlib.h"
#include <openssl/evp.h>
#include "evp_locl.h"

int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx)
	{
	int ret;
	if (!ctx || !ctx->pmeth || !ctx->pmeth->sign)
		{
		EVPerr(EVP_F_EVP_PKEY_SIGN_INIT,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	ctx->operation = EVP_PKEY_OP_SIGN;
	if (!ctx->pmeth->sign_init)
		return 1;
	ret = ctx->pmeth->sign_init(ctx);
	if (ret <= 0)
		ctx->operation = EVP_PKEY_OP_UNDEFINED;
	return ret;
	}

int EVP_PKEY_sign(EVP_PKEY_CTX *ctx,
			unsigned char *sig, int *siglen,
			unsigned char *tbs, int tbslen)
	{
	if (!ctx || !ctx->pmeth || !ctx->pmeth->sign)
		{
		EVPerr(EVP_F_EVP_PKEY_SIGN,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	if (ctx->operation != EVP_PKEY_OP_SIGN)
		{
		EVPerr(EVP_F_EVP_PKEY_SIGN, EVP_R_OPERATON_NOT_INITIALIZED);
		return -1;
		}
	return ctx->pmeth->sign(ctx, sig, siglen, tbs, tbslen);
	}

int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx)
	{
	int ret;
	if (!ctx || !ctx->pmeth || !ctx->pmeth->verify)
		{
		EVPerr(EVP_F_EVP_PKEY_VERIFY_INIT,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	ctx->operation = EVP_PKEY_OP_VERIFY;
	if (!ctx->pmeth->verify_init)
		return 1;
	ret = ctx->pmeth->verify_init(ctx);
	if (ret <= 0)
		ctx->operation = EVP_PKEY_OP_UNDEFINED;
	return ret;
	}

int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
			unsigned char *sig, int siglen,
			unsigned char *tbs, int tbslen)
	{
	if (!ctx || !ctx->pmeth || !ctx->pmeth->verify)
		{
		EVPerr(EVP_F_EVP_PKEY_VERIFY,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	if (ctx->operation != EVP_PKEY_OP_VERIFY)
		{
		EVPerr(EVP_F_EVP_PKEY_VERIFY, EVP_R_OPERATON_NOT_INITIALIZED);
		return -1;
		}
	return ctx->pmeth->verify(ctx, sig, siglen, tbs, tbslen);
	}

int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx)
	{
	int ret;
	if (!ctx || !ctx->pmeth || !ctx->pmeth->verify_recover)
		{
		EVPerr(EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	ctx->operation = EVP_PKEY_OP_VERIFYRECOVER;
	if (!ctx->pmeth->verify_recover_init)
		return 1;
	ret = ctx->pmeth->verify_recover_init(ctx);
	if (ret <= 0)
		ctx->operation = EVP_PKEY_OP_UNDEFINED;
	return ret;
	}

int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,
			unsigned char *rout, int *routlen,
			unsigned char *sig, int siglen)
	{
	if (!ctx || !ctx->pmeth || !ctx->pmeth->verify_recover)
		{
		EVPerr(EVP_F_EVP_PKEY_VERIFY_RECOVER,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	if (ctx->operation != EVP_PKEY_OP_VERIFYRECOVER)
		{
		EVPerr(EVP_F_EVP_PKEY_VERIFY_RECOVER, EVP_R_OPERATON_NOT_INITIALIZED);
		return -1;
		}
	return ctx->pmeth->verify_recover(ctx, rout, routlen, sig, siglen);
	}

int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx)
	{
	int ret;
	if (!ctx || !ctx->pmeth || !ctx->pmeth->encrypt)
		{
		EVPerr(EVP_F_EVP_PKEY_ENCRYPT_INIT,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	ctx->operation = EVP_PKEY_OP_ENCRYPT;
	if (!ctx->pmeth->encrypt_init)
		return 1;
	ret = ctx->pmeth->encrypt_init(ctx);
	if (ret <= 0)
		ctx->operation = EVP_PKEY_OP_UNDEFINED;
	return ret;
	}

int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
			unsigned char *out, int *outlen,
			unsigned char *in, int inlen)
	{
	if (!ctx || !ctx->pmeth || !ctx->pmeth->encrypt)
		{
		EVPerr(EVP_F_EVP_PKEY_ENCRYPT,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	if (ctx->operation != EVP_PKEY_OP_ENCRYPT)
		{
		EVPerr(EVP_F_EVP_PKEY_ENCRYPT, EVP_R_OPERATON_NOT_INITIALIZED);
		return -1;
		}
	return ctx->pmeth->encrypt(ctx, out, outlen, in, inlen);
	}

int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx)
	{
	int ret;
	if (!ctx || !ctx->pmeth || !ctx->pmeth->decrypt)
		{
		EVPerr(EVP_F_EVP_PKEY_DECRYPT_INIT,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	ctx->operation = EVP_PKEY_OP_DECRYPT;
	if (!ctx->pmeth->decrypt_init)
		return 1;
	ret = ctx->pmeth->decrypt_init(ctx);
	if (ret <= 0)
		ctx->operation = EVP_PKEY_OP_UNDEFINED;
	return ret;
	}

int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
			unsigned char *out, int *outlen,
			unsigned char *in, int inlen)
	{
	if (!ctx || !ctx->pmeth || !ctx->pmeth->decrypt)
		{
		EVPerr(EVP_F_EVP_PKEY_DECRYPT,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
		}
	if (ctx->operation != EVP_PKEY_OP_DECRYPT)
		{
		EVPerr(EVP_F_EVP_PKEY_DECRYPT, EVP_R_OPERATON_NOT_INITIALIZED);
		return -1;
		}
	return ctx->pmeth->decrypt(ctx, out, outlen, in, inlen);
	}

