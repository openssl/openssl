/* v3_bcons.c */
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
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

static STACK_OF(CONF_VALUE) *i2v_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method, BASIC_CONSTRAINTS *bcons, STACK_OF(CONF_VALUE) *extlist);
static BASIC_CONSTRAINTS *v2i_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values);

X509V3_EXT_METHOD v3_bcons = {
NID_basic_constraints, 0,
(X509V3_EXT_NEW)BASIC_CONSTRAINTS_new,
(X509V3_EXT_FREE)BASIC_CONSTRAINTS_free,
(X509V3_EXT_D2I)d2i_BASIC_CONSTRAINTS,
(X509V3_EXT_I2D)i2d_BASIC_CONSTRAINTS,
NULL, NULL,
(X509V3_EXT_I2V)i2v_BASIC_CONSTRAINTS,
(X509V3_EXT_V2I)v2i_BASIC_CONSTRAINTS,
NULL,NULL,
NULL
};


int i2d_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS *a, unsigned char **pp)
{
	M_ASN1_I2D_vars(a);
	if(a->ca) M_ASN1_I2D_len (a->ca, i2d_ASN1_BOOLEAN);
	M_ASN1_I2D_len (a->pathlen, i2d_ASN1_INTEGER);

	M_ASN1_I2D_seq_total();

	if (a->ca) M_ASN1_I2D_put (a->ca, i2d_ASN1_BOOLEAN);
	M_ASN1_I2D_put (a->pathlen, i2d_ASN1_INTEGER);
	M_ASN1_I2D_finish();
}

BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new(void)
{
	BASIC_CONSTRAINTS *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, BASIC_CONSTRAINTS);
	ret->ca = 0;
	ret->pathlen = NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_BASIC_CONSTRAINTS_NEW);
}

BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a,
	     unsigned char **pp, long length)
{
	M_ASN1_D2I_vars(a,BASIC_CONSTRAINTS *,BASIC_CONSTRAINTS_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	if((M_ASN1_next & (~V_ASN1_CONSTRUCTED)) ==
		 (V_ASN1_UNIVERSAL|V_ASN1_BOOLEAN) ) {
			M_ASN1_D2I_get_int (ret->ca, d2i_ASN1_BOOLEAN);
	}
	M_ASN1_D2I_get_opt (ret->pathlen, d2i_ASN1_INTEGER, V_ASN1_INTEGER);
	M_ASN1_D2I_Finish(a, BASIC_CONSTRAINTS_free, ASN1_F_D2I_BASIC_CONSTRAINTS);
}

void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a)
{
	if (a == NULL) return;
	M_ASN1_INTEGER_free (a->pathlen);
	Free (a);
}

static STACK_OF(CONF_VALUE) *i2v_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method,
	     BASIC_CONSTRAINTS *bcons, STACK_OF(CONF_VALUE) *extlist)
{
	X509V3_add_value_bool("CA", bcons->ca, &extlist);
	X509V3_add_value_int("pathlen", bcons->pathlen, &extlist);
	return extlist;
}

static BASIC_CONSTRAINTS *v2i_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method,
	     X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values)
{
	BASIC_CONSTRAINTS *bcons=NULL;
	CONF_VALUE *val;
	int i;
	if(!(bcons = BASIC_CONSTRAINTS_new())) {
		X509V3err(X509V3_F_V2I_BASIC_CONSTRAINTS, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	for(i = 0; i < sk_CONF_VALUE_num(values); i++) {
		val = sk_CONF_VALUE_value(values, i);
		if(!strcmp(val->name, "CA")) {
			if(!X509V3_get_value_bool(val, &bcons->ca)) goto err;
		} else if(!strcmp(val->name, "pathlen")) {
			if(!X509V3_get_value_int(val, &bcons->pathlen)) goto err;
		} else {
			X509V3err(X509V3_F_V2I_BASIC_CONSTRAINTS, X509V3_R_INVALID_NAME);
			X509V3_conf_err(val);
			goto err;
		}
	}
	return bcons;
	err:
	BASIC_CONSTRAINTS_free(bcons);
	return NULL;
}

