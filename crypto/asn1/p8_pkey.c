/* p8_pkey.c */
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
#include <openssl/x509.h>

int i2d_PKCS8_PRIV_KEY_INFO (PKCS8_PRIV_KEY_INFO *a, unsigned char **pp)
{

	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len (a->version, i2d_ASN1_INTEGER);
	M_ASN1_I2D_len (a->pkeyalg, i2d_X509_ALGOR);
	M_ASN1_I2D_len (a->pkey, i2d_ASN1_TYPE);
	M_ASN1_I2D_len_IMP_SET_opt_type (X509_ATTRIBUTE, a->attributes,
					 i2d_X509_ATTRIBUTE, 0);
	
	M_ASN1_I2D_seq_total ();

	M_ASN1_I2D_put (a->version, i2d_ASN1_INTEGER);
	M_ASN1_I2D_put (a->pkeyalg, i2d_X509_ALGOR);
	M_ASN1_I2D_put (a->pkey, i2d_ASN1_TYPE);
	M_ASN1_I2D_put_IMP_SET_opt_type (X509_ATTRIBUTE, a->attributes,
					 i2d_X509_ATTRIBUTE, 0);

	M_ASN1_I2D_finish();
}

PKCS8_PRIV_KEY_INFO *PKCS8_PRIV_KEY_INFO_new(void)
{
	PKCS8_PRIV_KEY_INFO *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, PKCS8_PRIV_KEY_INFO);
	M_ASN1_New (ret->version, ASN1_INTEGER_new);
	M_ASN1_New (ret->pkeyalg, X509_ALGOR_new);
	M_ASN1_New (ret->pkey, ASN1_TYPE_new);
	ret->attributes = NULL;
	ret->broken = PKCS8_OK;
	return (ret);
	M_ASN1_New_Error(ASN1_F_PKCS8_PRIV_KEY_INFO_NEW);
}

PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO **a,
	     unsigned char **pp, long length)
{
	M_ASN1_D2I_vars(a,PKCS8_PRIV_KEY_INFO *,PKCS8_PRIV_KEY_INFO_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get (ret->version, d2i_ASN1_INTEGER);
	M_ASN1_D2I_get (ret->pkeyalg, d2i_X509_ALGOR);
	M_ASN1_D2I_get (ret->pkey, d2i_ASN1_TYPE);
	M_ASN1_D2I_get_IMP_set_opt_type(X509_ATTRIBUTE, ret->attributes,
					d2i_X509_ATTRIBUTE,
					X509_ATTRIBUTE_free, 0);
	if (ASN1_TYPE_get(ret->pkey) == V_ASN1_SEQUENCE) 
						ret->broken = PKCS8_NO_OCTET;
	M_ASN1_D2I_Finish(a, PKCS8_PRIV_KEY_INFO_free, ASN1_F_D2I_PKCS8_PRIV_KEY_INFO);
}

void PKCS8_PRIV_KEY_INFO_free (PKCS8_PRIV_KEY_INFO *a)
{
	if (a == NULL) return;
	ASN1_INTEGER_free (a->version);
	X509_ALGOR_free(a->pkeyalg);
	/* Clear sensitive data */
	if (a->pkey->value.octet_string)
		memset (a->pkey->value.octet_string->data,
				 0, a->pkey->value.octet_string->length);
	ASN1_TYPE_free (a->pkey);
	sk_X509_ATTRIBUTE_pop_free (a->attributes, X509_ATTRIBUTE_free);
	Free (a);
}
