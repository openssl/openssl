/* ocsp_cid.c */
/* Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project. */

/* History:
   This file was originally part of ocsp.c and was transfered to Richard
   Levitte from CertCo by Kathy Weinhold in mid-spring 2000 to be included
   in OpenSSL or released as a patch kit. */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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

#include <openssl/bio.h>
#include <openssl/asn1_mac.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>

/* Make sure we work well with older variants of OpenSSL */
#ifndef OPENSSL_malloc
#define OPENSSL_malloc Malloc
#endif
#ifndef OPENSSL_realloc
#define OPENSSL_realloc Realloc
#endif
#ifndef OPENSSL_free
#define OPENSSL_free Free
#endif

OCSP_CERTID *OCSP_CERTID_new(void)
	{
	ASN1_CTX c;
	OCSP_CERTID *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_CERTID);
	M_ASN1_New(ret->hashAlgorithm, X509_ALGOR_new);
	M_ASN1_New(ret->issuerNameHash, ASN1_OCTET_STRING_new);
	M_ASN1_New(ret->issuerKeyHash, ASN1_OCTET_STRING_new);
	M_ASN1_New(ret->serialNumber, ASN1_INTEGER_new);
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_CERTID_NEW);
	}
	
void OCSP_CERTID_free(OCSP_CERTID *a)
	{
	if (a == NULL) return;
	X509_ALGOR_free(a->hashAlgorithm);
	ASN1_OCTET_STRING_free(a->issuerNameHash);
	ASN1_OCTET_STRING_free(a->issuerKeyHash);
	ASN1_INTEGER_free(a->serialNumber);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_CERTID(OCSP_CERTID *a,
		    unsigned char **pp)
	{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->hashAlgorithm, i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->issuerNameHash, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_len(a->issuerKeyHash, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_len(a->serialNumber, i2d_ASN1_INTEGER);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->hashAlgorithm, i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->issuerNameHash, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_put(a->issuerKeyHash, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_put(a->serialNumber, i2d_ASN1_INTEGER);
	M_ASN1_I2D_finish();
	}

OCSP_CERTID *d2i_OCSP_CERTID(OCSP_CERTID **a,
			     unsigned char **pp,
			     long length)
	{
	M_ASN1_D2I_vars(a,OCSP_CERTID *,OCSP_CERTID_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->hashAlgorithm, d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->issuerNameHash, d2i_ASN1_OCTET_STRING);
	M_ASN1_D2I_get(ret->issuerKeyHash, d2i_ASN1_OCTET_STRING);
	M_ASN1_D2I_get(ret->serialNumber, d2i_ASN1_INTEGER);

	/* protect against malformed CERTID's */
	if (ASN1_STRING_length(ret->issuerNameHash) == 0 ||
		ASN1_STRING_length(ret->issuerKeyHash) == 0 ||
		ASN1_STRING_length(ret->serialNumber) == 0)
		goto err;

	M_ASN1_D2I_Finish(a,OCSP_CERTID_free,ASN1_F_D2I_OCSP_CERTID);
	}

int i2a_OCSP_CERTID(BIO *bp,
		    OCSP_CERTID* a)
        {
#ifdef UNDEF
	/* XXX this guy isn't implemented. */
	i2a_X509_ALGOR(bp, a->hashAlgorithm);
#else   /* instead, just show OID, not param */
	i2a_ASN1_OBJECT(bp, a->hashAlgorithm->algorithm);
#endif
	i2a_ASN1_STRING(bp, a->issuerNameHash, V_ASN1_OCTET_STRING);
	i2a_ASN1_STRING(bp, a->issuerKeyHash, V_ASN1_OCTET_STRING);
	i2a_ASN1_INTEGER(bp, a->serialNumber);
	return 4;
	}
