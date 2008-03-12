/* crypto/cms/cms_env.c */
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
#include "cms_lcl.h"
#include "asn1_locl.h"

/* CMS EnvelopedData Utilities */

DECLARE_ASN1_ITEM(CMS_EnvelopedData)
DECLARE_ASN1_ITEM(CMS_RecipientInfo)
DECLARE_ASN1_ITEM(CMS_KeyTransRecipientInfo)

#if 0
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(CMS_EnvelopedData)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(CMS_RecipientInfo)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(CMS_KeyTransRecipientInfo)
#endif

DECLARE_STACK_OF(CMS_RecipientInfo)

static CMS_EnvelopedData *cms_get0_enveloped(CMS_ContentInfo *cms)
	{
	if (OBJ_obj2nid(cms->contentType) != NID_pkcs7_enveloped)
		{
		CMSerr(CMS_F_CMS_GET0_ENVELOPED,
				CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA);
		return NULL;
		}
	return cms->d.envelopedData;
	}

static CMS_EnvelopedData *cms_enveloped_data_init(CMS_ContentInfo *cms)
	{
	if (cms->d.other == NULL)
		{
		cms->d.envelopedData = M_ASN1_new_of(CMS_EnvelopedData);
		if (!cms->d.envelopedData)
			{
			CMSerr(CMS_F_CMS_ENVELOPED_DATA_INIT,
							ERR_R_MALLOC_FAILURE);
			return NULL;
			}
		cms->d.envelopedData->version = 0;
		cms->d.envelopedData->encryptedContentInfo->contentType =
						OBJ_nid2obj(NID_pkcs7_data);
		ASN1_OBJECT_free(cms->contentType);
		cms->contentType = OBJ_nid2obj(NID_pkcs7_enveloped);
		return cms->d.envelopedData;
		}
	return cms_get0_enveloped(cms);
	}

/* Add a recipient certificate. For now only handle key transport.
 * If we ever handle key agreement will need updating.
 */

CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms,
					X509 *recip, unsigned int flags)
	{
	CMS_RecipientInfo *ri = NULL;
	CMS_KeyTransRecipientInfo *ktri;
	CMS_EnvelopedData *env;
	EVP_PKEY *pk = NULL;
	int i, type;
	/* Init enveloped data */
	env = cms_enveloped_data_init(cms);
	if (!env)
		goto err;

	/* Initialized recipient info */
	ri = M_ASN1_new_of(CMS_RecipientInfo);
	if (!ri)
		goto merr;

	/* Initialize and add key transrport recipient info */

	ri->d.ktri = M_ASN1_new_of(CMS_KeyTransRecipientInfo);
	if (!ri->d.ktri)
		goto merr;
	ri->type = CMS_RECIPINFO_TRANS;

	ktri = ri->d.ktri;

	X509_check_purpose(recip, -1, -1);
	pk = X509_get_pubkey(recip);
	if (!pk)
		{
		CMSerr(CMS_F_CMS_ADD1_RECIPIENT_CERT,
				CMS_R_ERROR_GETTING_PUBLIC_KEY);
		goto err;
		}
	CRYPTO_add(&recip->references, 1, CRYPTO_LOCK_X509);
	CRYPTO_add(&pk->references, 1, CRYPTO_LOCK_EVP_PKEY);
	ktri->pkey = pk;
	ktri->recip = recip;

	if (flags & CMS_USE_KEYID)
		{
		ktri->version = 2;
		type = CMS_RECIPINFO_KEYIDENTIFIER;
		}
	else
		{
		ktri->version = 0;
		type = CMS_RECIPINFO_ISSUER_SERIAL;
		}

	/* Not a typo: RecipientIdentifier and SignerIdentifier are the
	 * same structure.
	 */

	if (!cms_set1_SignerIdentifier(ktri->rid, recip, type))
		goto err;

	if (pk->ameth && pk->ameth->pkey_ctrl)
		{
		i = pk->ameth->pkey_ctrl(pk, ASN1_PKEY_CTRL_CMS_ENVELOPE,
						0, ri);
		if (i == -2)
			{
			CMSerr(CMS_F_CMS_ADD1_RECIPIENT_CERT,
				CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
			goto err;
			}
		if (i <= 0)
			{
			CMSerr(CMS_F_CMS_ADD1_RECIPIENT_CERT,
				CMS_R_CTRL_FAILURE);
			goto err;
			}
		}

	if (!sk_CMS_RecipientInfo_push(env->recipientInfos, ri))
		goto merr;

	return ri;

	merr:
	CMSerr(CMS_F_CMS_ADD1_RECIPIENT_CERT, ERR_R_MALLOC_FAILURE);
	err:
	if (ri)
		M_ASN1_free_of(ri, CMS_RecipientInfo);
	return NULL;

	}

int CMS_RecipientInfo_ktri_get0_algs(CMS_RecipientInfo *ri,
					EVP_PKEY **pk, X509 **recip,
					X509_ALGOR **palg)
	{
	CMS_KeyTransRecipientInfo *ktri;
	if (ri->type != CMS_RECIPINFO_TRANS)
		{
		CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_ALGS,
			CMS_R_NOT_KEY_TRANSPORT);
		return 0;
		}

	ktri = ri->d.ktri;

	if (pk)
		*pk = ktri->pkey;
	if (recip)
		*recip = ktri->recip;
	if (palg)
		*palg = ktri->keyEncryptionAlgorithm;
	return 1;
	}

int CMS_RecipientInfo_ktri_get0_signer_id(CMS_RecipientInfo *ri,
					ASN1_OCTET_STRING **keyid,
					X509_NAME **issuer, ASN1_INTEGER **sno)
	{
	CMS_KeyTransRecipientInfo *ktri;
	if (ri->type != CMS_RECIPINFO_TRANS)
		{
		CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_SIGNER_ID,
			CMS_R_NOT_KEY_TRANSPORT);
		return 0;
		}

	return cms_SignerIdentifier_get0_signer_id(ktri->rid,
							keyid, issuer, sno);
	}

int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert)
	{
	CMS_KeyTransRecipientInfo *ktri;
	if (ri->type != CMS_RECIPINFO_TRANS)
		{
		CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_CERT_CMP,
			CMS_R_NOT_KEY_TRANSPORT);
		return 0;
		}

	return cms_SignerIdentifier_cert_cmp(ktri->rid, cert);
	}
