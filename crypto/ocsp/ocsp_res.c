/* ocsp_req.c */
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

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int i2a_OCSP_RESPBYTES(BIO *bp,
		       OCSP_RESPBYTES* a)
        {
	i2a_ASN1_OBJECT(bp, a->responseType);
	i2a_ASN1_STRING(bp, a->response, V_ASN1_OCTET_STRING);
	return 2;
	}

int i2a_OCSP_RESPONSE(BIO *bp, OCSP_RESPONSE* a)
        {
	i2a_ASN1_STRING(bp, a->responseStatus, V_ASN1_ENUMERATED);
	i2a_OCSP_RESPBYTES(bp, a->responseBytes);
	return a->responseBytes ? 2 : 1;
	}

int i2a_OCSP_RESPID(BIO *bp, OCSP_RESPID* a)
        {
	switch (a->type)
		{
		case V_OCSP_RESPID_NAME:
		        X509_NAME_print(bp, a->value.byName, 16);
		        break;
		case V_OCSP_RESPID_KEY:
		        i2a_ASN1_STRING(bp, a->value.byKey, V_ASN1_OCTET_STRING);
		        break;
		}

	return 1;
	}

int i2a_OCSP_RESPDATA(BIO *bp, OCSP_RESPDATA* a)
        {
	int i, j=2;
	if (a->version == NULL) BIO_puts(bp, "0");
	else i2a_ASN1_INTEGER(bp, a->version);
	i2a_OCSP_RESPID(bp, a->responderId);
	if (!ASN1_GENERALIZEDTIME_print(bp, a->producedAt)) return 0;
	if (a->responses != NULL)
		{
		for (i=0; i<sk_OCSP_SINGLERESP_num(a->responses); i++)
			if (sk_OCSP_SINGLERESP_value(a->responses,i) != NULL)
				i2a_OCSP_SINGLERESP(bp, 
				      sk_OCSP_SINGLERESP_value(a->responses,i));
		j+=sk_OCSP_SINGLERESP_num(a->responses);
		}
#ifdef UNDEF
	/* XXX need generic extension print method or need to register
	 * ocsp extensions with existing extension handler mechanism,
	 * invoke i2a callbacks.
	 */
	if (a->responseExtensions != NULL)
		{
		for (i=0; i<sk_X509_EXTENSION_num(a->responseExtensions); i++)
			if (sk_X509_EXTENSION_value(a->responseExtensions,i) != NULL)
				i2a_X509_EXTENSION(bp, 
				   sk_X509_EXTENSION_value(a->responseExtensions,i));
		j+=sk_X509_EXTENSION_num(a->responseExtensions);
		}
#endif
	return j;
	}

int i2a_OCSP_BASICRESP(BIO *bp, OCSP_BASICRESP* a)
        {
	int i, j=3;
	i2a_OCSP_RESPDATA(bp, a->tbsResponseData);
#ifdef UNDEF
	/* XXX this guy isn't implemented. */
	i2a_X509_ALGOR(bp, a->signatureAlgorithm);
#else   /* instead, just show OID, not param */
	i2a_ASN1_OBJECT(bp, a->signatureAlgorithm->algorithm);
#endif
	i2a_ASN1_STRING(bp, a->signature, V_ASN1_BIT_STRING);
	if (a->certs != NULL)
		{
		for (i=0; i<sk_X509_num(a->certs); i++)
			if (sk_X509_value(a->certs,i) != NULL)
				X509_print(bp, sk_X509_value(a->certs,i));
		j+=sk_X509_num(a->certs);
		}
	return j;
	}

int i2a_OCSP_REVOKEDINFO(BIO *bp, OCSP_REVOKEDINFO* a)
        {
	int i=0; 
	if (!ASN1_GENERALIZEDTIME_print(bp, a->revocationTime)) return 0;
	if (a->revocationReason)
		{
                i2a_ASN1_STRING(bp, a->revocationReason, V_ASN1_ENUMERATED);
		i++;
		}
	return i;
	}

int i2a_OCSP_CERTSTATUS(BIO *bp, OCSP_CERTSTATUS* a)
        {
	switch (a->type)
		{
		case V_OCSP_CERTSTATUS_GOOD:
			BIO_puts(bp, "CertStatus: good");
		        break;
		case V_OCSP_CERTSTATUS_REVOKED:
			BIO_puts(bp, "CertStatus: revoked");
			i2a_OCSP_REVOKEDINFO(bp, a->value.revoked);
		        break;
		case V_OCSP_CERTSTATUS_UNKNOWN:
			BIO_puts(bp, "CertStatus: unknown");
		        break;
		}
	return 1;
	}

int i2a_OCSP_SINGLERESP(BIO *bp, OCSP_SINGLERESP* a)
        {
	int /* XXX i, */ j=3;
	i2a_OCSP_CERTID(bp, a->certId);
	i2a_OCSP_CERTSTATUS(bp, a->certStatus);
	if (!ASN1_GENERALIZEDTIME_print(bp, a->thisUpdate)) return 0;
	if (a->nextUpdate) 
	        {
		if (!ASN1_GENERALIZEDTIME_print(bp, a->nextUpdate)) return 0;
		j++;
		}
#ifdef UNDEF
	/* XXX need generic extension print method or need to register
	 * ocsp extensions with existing extension handler mechanism,
	 * invoke i2a callbacks.
	 */
	if (a->singleExtensions != NULL)
		{
		for (i=0; i<sk_X509_EXTENSION_num(a->singleExtensions); i++)
			if (sk_X509_EXTENSION_value(a->singleExtensions,i) != NULL)
				i2a_X509_EXTENSION(bp, 
				  sk_X509_EXTENSION_value(a->singleExtensions,i));
		j+=sk_X509_EXTENSION_num(a->singleExtensions);
		}
#endif
	return j;
	}

int i2a_OCSP_CRLID(BIO *bp, OCSP_CRLID* a)
        {
	int i = 0;
	char buf[1024];
	if (a->crlUrl && ASN1_STRING_print(bp, (ASN1_STRING*)a->crlUrl)) i++;
	if (a->crlNum && a2i_ASN1_INTEGER(bp, a->crlNum, buf, sizeof buf)) i++;
	if (a->crlTime && ASN1_GENERALIZEDTIME_print(bp, a->crlTime)) i++;
	return i;
	}

int i2a_OCSP_SERVICELOC(BIO *bp,
			OCSP_SERVICELOC* a)
        {
	int i;
	X509_NAME_print(bp, a->issuer, 16);
	if (!a->locator) return 1;
	for (i=0; i<sk_ACCESS_DESCRIPTION_num(a->locator); i++)
		i2a_ACCESS_DESCRIPTION(bp,
			     sk_ACCESS_DESCRIPTION_value(a->locator,i));
	return i+2;
	}
