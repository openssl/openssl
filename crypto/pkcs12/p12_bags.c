/* p12_bags.c */
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
#include <openssl/asn1_mac.h>
#include <openssl/pkcs12.h>

int i2d_PKCS12_BAGS(PKCS12_BAGS *a, unsigned char **pp)
{
	int bagnid, v = 0;
	M_ASN1_I2D_vars(a);
	bagnid = OBJ_obj2nid (a->type);
	M_ASN1_I2D_len (a->type, i2d_ASN1_OBJECT);
	
	switch (bagnid) {

		case NID_x509Certificate:
			M_ASN1_I2D_len_EXP_opt (a->value.x509cert,
						 i2d_ASN1_OCTET_STRING, 0, v);
		break;

		case NID_x509Crl:
			M_ASN1_I2D_len_EXP_opt (a->value.x509crl,
						 i2d_ASN1_OCTET_STRING, 0, v);
		break;

		case NID_sdsiCertificate:
			M_ASN1_I2D_len_EXP_opt (a->value.sdsicert,
						 i2d_ASN1_IA5STRING, 0, v);
		break;

		default:
			M_ASN1_I2D_len_EXP_opt (a->value.other,
						 i2d_ASN1_TYPE, 0, v);
		break;
	}

	M_ASN1_I2D_seq_total ();
	
	M_ASN1_I2D_put (a->type, i2d_ASN1_OBJECT);
	
	switch (bagnid) {

		case NID_x509Certificate:
			M_ASN1_I2D_put_EXP_opt (a->value.x509cert,
						 i2d_ASN1_OCTET_STRING, 0, v);
		break;

		case NID_x509Crl:
			M_ASN1_I2D_put_EXP_opt (a->value.x509crl,
						 i2d_ASN1_OCTET_STRING, 0, v);
		break;

		case NID_sdsiCertificate:
			M_ASN1_I2D_put_EXP_opt (a->value.sdsicert,
						 i2d_ASN1_IA5STRING, 0, v);
		break;

		default:
		M_ASN1_I2D_put_EXP_opt (a->value.other, i2d_ASN1_TYPE, 0, v);
		break;
	}
	M_ASN1_I2D_finish();
}

PKCS12_BAGS *PKCS12_BAGS_new(void)
{
	PKCS12_BAGS *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, PKCS12_BAGS);
	ret->type=NULL;
	ret->value.other=NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_PKCS12_BAGS_NEW);
}

PKCS12_BAGS *d2i_PKCS12_BAGS(PKCS12_BAGS **a, unsigned char **pp,
	     long length)
{
	int bagnid;
	M_ASN1_D2I_vars(a,PKCS12_BAGS *,PKCS12_BAGS_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get (ret->type, d2i_ASN1_OBJECT);
	bagnid = OBJ_obj2nid (ret->type);
	switch (bagnid) {

		case NID_x509Certificate:
			M_ASN1_D2I_get_EXP_opt (ret->value.x509cert,
						 d2i_ASN1_OCTET_STRING, 0);
		break;

		case NID_x509Crl:
			M_ASN1_D2I_get_EXP_opt (ret->value.x509crl,
						 d2i_ASN1_OCTET_STRING, 0);
		break;

		case NID_sdsiCertificate:
			M_ASN1_D2I_get_EXP_opt (ret->value.sdsicert,
						 d2i_ASN1_IA5STRING, 0);
		break;

		default:
			M_ASN1_D2I_get_EXP_opt (ret->value.other,
							 d2i_ASN1_TYPE, 0);
		break;
	}

	M_ASN1_D2I_Finish(a, PKCS12_BAGS_free, ASN1_F_D2I_PKCS12_BAGS);
}

void PKCS12_BAGS_free (PKCS12_BAGS *a)
{
	if (a == NULL) return;
	switch (OBJ_obj2nid(a->type)) {

		case NID_x509Certificate:
			M_ASN1_OCTET_STRING_free (a->value.x509cert);
		break;

		case NID_x509Crl:
			M_ASN1_OCTET_STRING_free (a->value.x509crl);
		break;

		case NID_sdsiCertificate:
			M_ASN1_IA5STRING_free (a->value.sdsicert);
		break;

		default:
			ASN1_TYPE_free (a->value.other);
		break;
	}

	ASN1_OBJECT_free (a->type);
	OPENSSL_free (a);
}
