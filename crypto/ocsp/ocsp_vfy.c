/* ocsp_vfy.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <openssl/ocsp.h>
#include <openssl/err.h>

static X509 *ocsp_find_signer(OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
				X509_STORE *st, unsigned long flags);
static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id);

/* Verify a basic response message */

int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
				X509_STORE *st, unsigned long flags)
	{
	X509 *signer;
	int ret;
	signer = ocsp_find_signer(bs, certs, st, flags);
	if (!signer)
		{
		OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND);
		return 0;
		}
	if(!(flags & OCSP_NOSIGS))
		{
		EVP_PKEY *skey;
		skey = X509_get_pubkey(signer);
		ret = OCSP_BASICRESP_verify(bs, skey, 0);
		EVP_PKEY_free(skey);
		if(ret <= 0)
			{
			OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_SIGNATURE_FAILURE);
			return 0;
			}
		}
	return 1;
	}


static X509 *ocsp_find_signer(OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
				X509_STORE *st, unsigned long flags)
	{
	X509 *signer;
	OCSP_RESPID *rid = bs->tbsResponseData->responderId;
	if ((signer = ocsp_find_signer_sk(certs, rid)))
		return signer;
	if(!(flags & OCSP_NOINTERN) &&
	    (signer = ocsp_find_signer_sk(bs->certs, rid)))
		return signer;
	/* Maybe lookup from store if by subject name */

	return NULL;
	}


static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id)
	{
	int i;
	unsigned char tmphash[SHA_DIGEST_LENGTH], *keyhash;
	ASN1_BIT_STRING *key;
	EVP_MD_CTX ctx;
	X509 *x;

	/* Easy if lookup by name */
	if(id->type == V_OCSP_RESPID_NAME)
		return X509_find_by_subject(certs, id->value.byName);

	/* Lookup by key hash */

	/* If key hash isn't SHA1 length then forget it */
	if(id->value.byKey->length != SHA_DIGEST_LENGTH) return NULL;
	keyhash = id->value.byKey->data;
	/* Calculate hash of each key and compare */
	for(i = 0; i < sk_X509_num(certs); i++)
		{
		x = sk_X509_value(certs, i);
		key = x->cert_info->key->public_key;
		EVP_DigestInit(&ctx,EVP_sha1());
		EVP_DigestUpdate(&ctx,key->data, key->length);
		EVP_DigestFinal(&ctx,tmphash,NULL);
		if(!memcmp(keyhash, tmphash, SHA_DIGEST_LENGTH))
			return x;
		}
	return NULL;
	}


