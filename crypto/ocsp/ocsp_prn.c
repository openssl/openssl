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
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>

int OCSP_CERTID_print(BIO *bp, OCSP_CERTID* a, int indent)
        {
	BIO_printf(bp, "%*sCertificate ID:\n", indent, "");
	indent += 2;
	BIO_printf(bp, "%*sHash Algorithm: ", indent, "");
	i2a_ASN1_OBJECT(bp, a->hashAlgorithm->algorithm);
	BIO_printf(bp, "\n%*sIssuer Name Hash: ", indent, "");
	i2a_ASN1_STRING(bp, a->issuerNameHash, V_ASN1_OCTET_STRING);
	BIO_printf(bp, "\n%*sIssuer Key Hash: ", indent, "");
	i2a_ASN1_STRING(bp, a->issuerKeyHash, V_ASN1_OCTET_STRING);
	BIO_printf(bp, "\n%*sSerial Number: ", indent, "");
	i2a_ASN1_INTEGER(bp, a->serialNumber);
	BIO_printf(bp, "\n");
	return 1;
	}

int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST* o, unsigned long flags)
        {
	int i;
	long l;
	OCSP_CERTID* cid = NULL;
	OCSP_ONEREQ *one = NULL;
	OCSP_REQINFO *inf = o->tbsRequest;
	OCSP_SIGNATURE *sig = o->optionalSignature;

	if (BIO_write(bp,"OCSP Request Data:\n",19) <= 0) goto err;
	l=ASN1_INTEGER_get(inf->version);
	if (BIO_printf(bp,"%4sVersion: %lu (0x%lx)","",l+1,l) <= 0) goto err;
	if (inf->requestorName != NULL)
	        {
		if (BIO_write(bp,"\n    Requestor Name: ",21) <= 0) 
		        goto err;
		GENERAL_NAME_print(bp, inf->requestorName);
		}
	if (BIO_write(bp,"\n    Requestor List:\n",21) <= 0) goto err;
	for (i = 0; i < sk_OCSP_ONEREQ_num(inf->requestList); i++)
	        {
		if (!sk_OCSP_ONEREQ_value(inf->requestList, i)) continue;
		one = sk_OCSP_ONEREQ_value(inf->requestList, i);
		cid = one->reqCert;
		OCSP_CERTID_print(bp, cid, 8);
		if (!X509V3_extensions_print(bp,
					"OCSP Request Single Extensions",
					one->singleRequestExtensions, flags, 4))
							goto err;
		}
	if (!X509V3_extensions_print(bp, "OCSP Request Extensions",
			inf->requestExtensions, flags, 4))
							goto err;
	if (sig)
	        {
		X509_signature_print(bp, sig->signatureAlgorithm, sig->signature);
		}
	return 1;
err:
	return 0;
	}
