/* v3_akey.c */
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
#include <stdlib.h>
#include <pem.h>
#include <asn1_mac.h>
#include <err.h>
#include <objects.h>
#include <conf.h>
#include "x509v3.h"

#ifndef NOPROTO
static STACK *i2v_AUTHORITY_KEYID(X509V3_EXT_METHOD *method, AUTHORITY_KEYID *akeyid, STACK *extlist);
static AUTHORITY_KEYID *v2i_AUTHORITY_KEYID(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK *values);

#else

static STACK *i2v_AUTHORITY_KEYID();
static AUTHORITY_KEYID *v2i_AUTHORITY_KEYID();

#endif

X509V3_EXT_METHOD v3_akey_id = {
NID_authority_key_identifier, 0,
(X509V3_EXT_NEW)AUTHORITY_KEYID_new,
AUTHORITY_KEYID_free,
(X509V3_EXT_D2I)d2i_AUTHORITY_KEYID,
i2d_AUTHORITY_KEYID,
NULL, NULL,
(X509V3_EXT_I2V)i2v_AUTHORITY_KEYID,
(X509V3_EXT_V2I)v2i_AUTHORITY_KEYID,
NULL,
NULL
};


/*
 * ASN1err(ASN1_F_AUTHORITY_KEYID_NEW,ERR_R_MALLOC_FAILURE);
 * ASN1err(ASN1_F_D2I_AUTHORITY_KEYID,ERR_R_MALLOC_FAILURE);
 */

int i2d_AUTHORITY_KEYID(a,pp)
AUTHORITY_KEYID *a;
unsigned char **pp;
{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len_IMP_opt (a->keyid, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_len_IMP_opt (a->issuer, i2d_GENERAL_NAMES);
	M_ASN1_I2D_len_IMP_opt (a->serial, i2d_ASN1_INTEGER);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put_IMP_opt (a->keyid, i2d_ASN1_OCTET_STRING, 0);
	M_ASN1_I2D_put_IMP_opt (a->issuer, i2d_GENERAL_NAMES, 1);
	M_ASN1_I2D_put_IMP_opt (a->serial, i2d_ASN1_INTEGER, 2);

	M_ASN1_I2D_finish();
}

AUTHORITY_KEYID *AUTHORITY_KEYID_new()
{
	AUTHORITY_KEYID *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, AUTHORITY_KEYID);
	ret->keyid = NULL;
	ret->issuer = NULL;
	ret->serial = NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_AUTHORITY_KEYID_NEW);
}

AUTHORITY_KEYID *d2i_AUTHORITY_KEYID(a,pp,length)
AUTHORITY_KEYID **a;
unsigned char **pp;
long length;
{
	M_ASN1_D2I_vars(a,AUTHORITY_KEYID *,AUTHORITY_KEYID_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get_IMP_opt (ret->keyid, d2i_ASN1_OCTET_STRING, 0,
							V_ASN1_OCTET_STRING);
	M_ASN1_D2I_get_IMP_opt (ret->issuer, d2i_GENERAL_NAMES, 1,
							V_ASN1_SEQUENCE);
	M_ASN1_D2I_get_IMP_opt (ret->serial, d2i_ASN1_INTEGER, 2,
							V_ASN1_INTEGER);
	M_ASN1_D2I_Finish(a, AUTHORITY_KEYID_free, ASN1_F_D2I_AUTHORITY_KEYID);
}

void AUTHORITY_KEYID_free(a)
AUTHORITY_KEYID *a;
{
	if (a == NULL) return;
	ASN1_OCTET_STRING_free(a->keyid);
	sk_pop_free(a->issuer, GENERAL_NAME_free);
	ASN1_INTEGER_free (a->serial);
	Free ((char *)a);
}

static STACK *i2v_AUTHORITY_KEYID(method, akeyid, extlist)
X509V3_EXT_METHOD *method;
AUTHORITY_KEYID *akeyid;
STACK *extlist;
{
	char *tmp;
	if(akeyid->keyid) {
		tmp = hex_to_string(akeyid->keyid->data, akeyid->keyid->length);
		X509V3_add_value("keyid", tmp, &extlist);
		Free(tmp);
	}
	if(akeyid->issuer) 
		extlist = i2v_GENERAL_NAMES(NULL, akeyid->issuer, extlist);
	if(akeyid->serial) {
		tmp = hex_to_string(akeyid->serial->data,
						 akeyid->serial->length);
		X509V3_add_value("serial", tmp, &extlist);
		Free(tmp);
	}
	return extlist;
}

static AUTHORITY_KEYID *v2i_AUTHORITY_KEYID(method, ctx, values)
X509V3_EXT_METHOD *method;
X509V3_CTX *ctx;
STACK *values;
{
return NULL;
}

