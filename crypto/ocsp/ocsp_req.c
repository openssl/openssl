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

#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

int i2a_OCSP_REQINFO(BIO *bp,
		     OCSP_REQINFO* a)
        {
	int i, j=1;
	if (a->version == NULL) BIO_puts(bp, "0");
	else i2a_ASN1_INTEGER(bp, a->version);
	if (a->requestorName != NULL) 
		{
		j++;
#ifdef UNDEF
		i2a_GENERAL_NAME(bp, a->requestorName); /* does not exist */
#endif
		}
	if (a->requestList != NULL)
		{
		for (i=0; i<sk_OCSP_ONEREQ_num(a->requestList); i++)
			if (sk_OCSP_ONEREQ_value(a->requestList,i) != NULL)
				i2a_OCSP_ONEREQ(bp, 
				      sk_OCSP_ONEREQ_value(a->requestList,i));
		j+=sk_OCSP_ONEREQ_num(a->requestList);
		}
	j+=OCSP_extensions_print(bp, a->requestExtensions,
				 "Request Extensions");
	return j;
	}

int i2a_OCSP_REQUEST(BIO *bp,
		     OCSP_REQUEST* a)
        {
	i2a_OCSP_REQINFO(bp, a->tbsRequest);
	i2a_OCSP_SIGNATURE(bp, a->optionalSignature);
	return a->optionalSignature ? 2 : 1;
	}

int i2a_OCSP_ONEREQ(BIO *bp,
		    OCSP_ONEREQ* a)
        {
	i2a_OCSP_CERTID(bp, a->reqCert);
#ifdef UNDEF
	/* XXX need generic extension print method or need to register
	 * ocsp extensions with existing extension handler mechanism,
	 * invoke i2a callbacks.
	 */
	if (a->singleRequestExtensions != NULL)
		{
		for (i=0; i<sk_X509_EXTENSION_num(a->singleRequestExtensions); i++)
			if (sk_X509_EXTENSION_value(a->singleRequestExtensions,i) != NULL)
			  i2a_X509_EXTENSION(bp, 
				     sk_X509_EXTENSION_value(
				        a->singleRequestExtensions, i));
		j+=sk_X509_EXTENSION_num(a->singleRequestExtensions);
		}
#endif
	return 1;
	}
