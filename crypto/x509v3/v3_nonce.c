/* v3_nonce.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

/* OCSP nonce. This is needs special treatment because it doesn't have
 * an ASN1 encoding at all: it just contains arbitrary data.
 */

static void *ocsp_nonce_new(void);
static int i2d_ocsp_nonce(void *a, unsigned char **pp);
static void *d2i_ocsp_nonce(void *a, unsigned char **pp, long length);
static void ocsp_nonce_free(void *a);
static int i2r_ocsp_nonce(X509V3_EXT_METHOD *method, void *nonce, BIO *out, int indent);

X509V3_EXT_METHOD v3_ocsp_nonce = {
	NID_id_pkix_OCSP_Nonce, 0, NULL,
	ocsp_nonce_new,
	ocsp_nonce_free,
	d2i_ocsp_nonce,
	i2d_ocsp_nonce,
	0,0,
	0,0,
	i2r_ocsp_nonce,0,
	NULL
};

static void *ocsp_nonce_new(void)
{
	return ASN1_OCTET_STRING_new();
}

static int i2d_ocsp_nonce(void *a, unsigned char **pp)
{
	ASN1_OCTET_STRING *os = a;
	if(*pp) {
		memcpy(*pp, os->data, os->length);
		*pp += os->length;
	}
	return os->length;
}

static void *d2i_ocsp_nonce(void *a, unsigned char **pp, long length)
{
	ASN1_OCTET_STRING *os, **pos;
	pos = a;
	if(!pos || !*pos) os = ASN1_OCTET_STRING_new();
	else os = *pos;
	if(!ASN1_OCTET_STRING_set(os, *pp, length)) goto err;

	*pp += length;

	if(pos) *pos = os;
	return os;

	err:
	if(os && (!pos || (*pos != os))) M_ASN1_OCTET_STRING_free(os);
	OCSPerr(OCSP_F_D2I_OCSP_NONCE, ERR_R_MALLOC_FAILURE);
	return NULL;
}

static void ocsp_nonce_free(void *a)
{
	M_ASN1_OCTET_STRING_free(a);
}

static int i2r_ocsp_nonce(X509V3_EXT_METHOD *method, void *nonce, BIO *out, int indent)
{
	if(BIO_printf(out, "%*s", indent, "") <= 0) return 0;
	if(i2a_ASN1_STRING(out, nonce, V_ASN1_OCTET_STRING) <= 0) return 0;
	return 1;
}
