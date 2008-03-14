/* crypto/cms/cms_enc.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/rand.h>
#include "cms_lcl.h"
#include "asn1_locl.h"

/* CMS EncryptedData Utilities */

/* Set up EncryptedContentInfo based on supplied cipher bio */

int cms_bio_to_EncryptedContent(CMS_EncryptedContentInfo *ec,
					const unsigned char *key, int keylen,
					BIO *b)
	{
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char iv[EVP_MAX_IV_LENGTH], *piv;
	int ivlen;

	BIO_get_cipher_ctx(b, &ctx);

	/* If necessary set key length */

	if (keylen != EVP_CIPHER_CTX_key_length(ctx))
		{
		if (EVP_CIPHER_CTX_set_key_length(ctx, keylen) <= 0)
			{
			CMSerr(CMS_F_CMS_BIO_TO_ENCRYPTEDCONTENT,
				CMS_R_INVALID_KEY_LENGTH);
			return 0;
			}
		}

	/* Generate a random IV if we need one */

	ivlen = EVP_CIPHER_CTX_iv_length(ctx);
	if (ivlen > 0)
		{
		if (RAND_pseudo_bytes(iv, ivlen) <= 0)
			return 0;
		piv = iv;
		}
	else
		piv = NULL;

	if (EVP_CipherInit_ex(ctx, NULL, NULL, key, piv, 1) <= 0)
		{
		CMSerr(CMS_F_CMS_BIO_TO_ENCRYPTEDCONTENT,
				CMS_R_CIPHER_INITIALISATION_ERROR);
		return 0;
		}

	ec->contentEncryptionAlgorithm->algorithm =
			OBJ_nid2obj(EVP_CIPHER_CTX_type(ctx));

	if (piv)
		{
		ec->contentEncryptionAlgorithm->parameter = ASN1_TYPE_new();
		if (!ec->contentEncryptionAlgorithm->parameter)
			{
			CMSerr(CMS_F_CMS_BIO_TO_ENCRYPTEDCONTENT,
							ERR_R_MALLOC_FAILURE);
			return 0;
			}
		if (EVP_CIPHER_param_to_asn1(ctx, 
			ec->contentEncryptionAlgorithm->parameter) <= 0)
			{
			CMSerr(CMS_F_CMS_BIO_TO_ENCRYPTEDCONTENT,
				CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
			return 0;
			}
		}

	return 1;
	}

/* Return BIO based on EncryptedContentInfo and key */

int cms_EncryptedContent_to_bio(BIO *b, CMS_EncryptedContentInfo *ec,
					const unsigned char *key, int keylen)
	{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *ciph;
	BIO_get_cipher_ctx(b, &ctx);

	ciph = EVP_get_cipherbyobj(ec->contentEncryptionAlgorithm->algorithm);

	if (!ciph)
		{
		CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_TO_BIO, CMS_R_UNKNOWN_CIPHER);
		goto err;
		}

	if (EVP_CipherInit_ex(ctx, ciph, NULL, NULL, NULL, 0) <= 0)
		{
		CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_TO_BIO,
				CMS_R_CIPHER_INITIALISATION_ERROR);
		goto err;
		}

	/* If necessary set key length */

	if (keylen != EVP_CIPHER_CTX_key_length(ctx))
		{
		if (EVP_CIPHER_CTX_set_key_length(ctx, keylen) <= 0)
			{
			CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_TO_BIO,
				CMS_R_INVALID_KEY_LENGTH);
			goto err;
			}
		}

	if (EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, 0) <= 0)
		{
		CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_TO_BIO,
				CMS_R_CIPHER_INITIALISATION_ERROR);
		goto err;
		}

	if (EVP_CIPHER_asn1_to_param(ctx, 
			ec->contentEncryptionAlgorithm->parameter) <= 0)
			{
			CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_TO_BIO,
				CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
			goto err;
			}
	return 1;

	err:
	return 0;
	}

int CMS_EncryptedData_set1_key(BIO *b, CMS_ContentInfo *cms,
				const unsigned char *key, size_t keylen)
	{
	CMS_EncryptedContentInfo *ec;
	if (OBJ_obj2nid(cms->contentType) != NID_pkcs7_encrypted)
		return 0;
	ec = cms->d.encryptedData->encryptedContentInfo;
	return cms_EncryptedContent_to_bio(b, ec, key, keylen);
	}
