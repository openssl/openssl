/* ocsp_sig.c */
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

OCSP_SIGNATURE *OCSP_SIGNATURE_new(void)
	{
	ASN1_CTX c;
	OCSP_SIGNATURE *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_SIGNATURE);
	M_ASN1_New(ret->signatureAlgorithm, X509_ALGOR_new);
	M_ASN1_New(ret->signature, ASN1_BIT_STRING_new);
	ret->certs = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_SIGNATURE_NEW);
	}
	
void OCSP_SIGNATURE_free(OCSP_SIGNATURE *a)
	{
	if (a == NULL) return;
	X509_ALGOR_free(a->signatureAlgorithm);
	ASN1_BIT_STRING_free(a->signature);
	if (a->certs) sk_X509_pop_free(a->certs, X509_free);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_SIGNATURE(OCSP_SIGNATURE *a,
		       unsigned char **pp)
	{
	int v=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->signatureAlgorithm, i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->signature, i2d_ASN1_BIT_STRING);
	M_ASN1_I2D_len_EXP_SEQUENCE_opt_type(X509, a->certs, i2d_X509,
			     0,	V_ASN1_SEQUENCE, v);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->signatureAlgorithm, i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->signature, i2d_ASN1_BIT_STRING);
	M_ASN1_I2D_put_EXP_SEQUENCE_opt_type(X509, a->certs, i2d_X509, 0,
					V_ASN1_SEQUENCE, v);
	M_ASN1_I2D_finish();
	}

OCSP_SIGNATURE *d2i_OCSP_SIGNATURE(OCSP_SIGNATURE **a,
				   unsigned char **pp,
				   long length)
	{
	M_ASN1_D2I_vars(a,OCSP_SIGNATURE *,OCSP_SIGNATURE_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->signatureAlgorithm, d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->signature, d2i_ASN1_BIT_STRING);
	/* there is no M_ASN1_D2I_get_EXP_seq* code, so
	   we're using the set version */
	M_ASN1_D2I_get_EXP_set_opt_type(X509, ret->certs, d2i_X509,
				   X509_free, 0, V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a,OCSP_SIGNATURE_free,ASN1_F_D2I_OCSP_SIGNATURE);
	}

int i2a_OCSP_SIGNATURE(BIO *bp,
		       OCSP_SIGNATURE* a)
        {
	int i, j=2;
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
