/* v3_info.c */
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
#include <openssl/asn1_mac.h>
#include <openssl/x509v3.h>

static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
				STACK_OF(ACCESS_DESCRIPTION) *ainfo,
						STACK_OF(CONF_VALUE) *ret);
static STACK_OF(ACCESS_DESCRIPTION) *v2i_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
				 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);

X509V3_EXT_METHOD v3_info =
{ NID_info_access, X509V3_EXT_MULTILINE,
(X509V3_EXT_NEW)AUTHORITY_INFO_ACCESS_new,
(X509V3_EXT_FREE)AUTHORITY_INFO_ACCESS_free,
(X509V3_EXT_D2I)d2i_AUTHORITY_INFO_ACCESS,
(X509V3_EXT_I2D)i2d_AUTHORITY_INFO_ACCESS,
NULL, NULL,
(X509V3_EXT_I2V)i2v_AUTHORITY_INFO_ACCESS,
(X509V3_EXT_V2I)v2i_AUTHORITY_INFO_ACCESS,
NULL, NULL, NULL};

static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
				STACK_OF(ACCESS_DESCRIPTION) *ainfo,
						STACK_OF(CONF_VALUE) *ret)
{
	ACCESS_DESCRIPTION *desc;
	int i;
	char objtmp[80], *ntmp;
	CONF_VALUE *vtmp;
	for(i = 0; i < sk_ACCESS_DESCRIPTION_num(ainfo); i++) {
		desc = sk_ACCESS_DESCRIPTION_value(ainfo, i);
		ret = i2v_GENERAL_NAME(method, desc->location, ret);
		if(!ret) break;
		vtmp = sk_CONF_VALUE_value(ret, i);
		i2t_ASN1_OBJECT(objtmp, 80, desc->method);
		ntmp = Malloc(strlen(objtmp) + strlen(vtmp->name) + 5);
		if(!ntmp) {
			X509V3err(X509V3_F_I2V_AUTHORITY_INFO_ACCESS,
					ERR_R_MALLOC_FAILURE);
			return NULL;
		}
		strcpy(ntmp, objtmp);
		strcat(ntmp, " - ");
		strcat(ntmp, vtmp->name);
		Free(vtmp->name);
		vtmp->name = ntmp;
		
	}
	if(!ret) return sk_CONF_VALUE_new_null();
	return ret;
}

static STACK_OF(ACCESS_DESCRIPTION) *v2i_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
				 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
	STACK_OF(ACCESS_DESCRIPTION) *ainfo = NULL;
	CONF_VALUE *cnf, ctmp;
	ACCESS_DESCRIPTION *acc;
	int i, objlen;
	char *objtmp, *ptmp;
	if(!(ainfo = sk_ACCESS_DESCRIPTION_new(NULL))) {
		X509V3err(X509V3_F_V2I_ACCESS_DESCRIPTION,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	for(i = 0; i < sk_CONF_VALUE_num(nval); i++) {
		cnf = sk_CONF_VALUE_value(nval, i);
		if(!(acc = ACCESS_DESCRIPTION_new())
			|| !sk_ACCESS_DESCRIPTION_push(ainfo, acc)) {
			X509V3err(X509V3_F_V2I_ACCESS_DESCRIPTION,ERR_R_MALLOC_FAILURE);
			goto err;
		}
		ptmp = strchr(cnf->name, ';');
		if(!ptmp) {
			X509V3err(X509V3_F_V2I_ACCESS_DESCRIPTION,X509V3_R_INVALID_SYNTAX);
			goto err;
		}
		objlen = ptmp - cnf->name;
		ctmp.name = ptmp + 1;
		ctmp.value = cnf->value;
		if(!(acc->location = v2i_GENERAL_NAME(method, ctx, &ctmp)))
								 goto err; 
		if(!(objtmp = Malloc(objlen + 1))) {
			X509V3err(X509V3_F_V2I_ACCESS_DESCRIPTION,ERR_R_MALLOC_FAILURE);
			goto err;
		}
		strncpy(objtmp, cnf->name, objlen);
		objtmp[objlen] = 0;
		acc->method = OBJ_txt2obj(objtmp, 0);
		if(!acc->method) {
			X509V3err(X509V3_F_V2I_ACCESS_DESCRIPTION,X509V3_R_BAD_OBJECT);
			ERR_add_error_data(2, "value=", objtmp);
			Free(objtmp);
			goto err;
		}
		Free(objtmp);

	}
	return ainfo;
	err:
	sk_ACCESS_DESCRIPTION_pop_free(ainfo, ACCESS_DESCRIPTION_free);
	return NULL;
}

int i2d_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION *a, unsigned char **pp)
{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->method, i2d_ASN1_OBJECT);
	M_ASN1_I2D_len(a->location, i2d_GENERAL_NAME);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(a->method, i2d_ASN1_OBJECT);
	M_ASN1_I2D_put(a->location, i2d_GENERAL_NAME);

	M_ASN1_I2D_finish();
}

ACCESS_DESCRIPTION *ACCESS_DESCRIPTION_new(void)
{
	ACCESS_DESCRIPTION *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, ACCESS_DESCRIPTION);
	ret->method = OBJ_nid2obj(NID_undef);
	ret->location = NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_ACCESS_DESCRIPTION_NEW);
}

ACCESS_DESCRIPTION *d2i_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION **a, unsigned char **pp,
	     long length)
{
	M_ASN1_D2I_vars(a,ACCESS_DESCRIPTION *,ACCESS_DESCRIPTION_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->method, d2i_ASN1_OBJECT);
	M_ASN1_D2I_get(ret->location, d2i_GENERAL_NAME);
	M_ASN1_D2I_Finish(a, ACCESS_DESCRIPTION_free, ASN1_F_D2I_ACCESS_DESCRIPTION);
}

void ACCESS_DESCRIPTION_free(ACCESS_DESCRIPTION *a)
{
	if (a == NULL) return;
	ASN1_OBJECT_free(a->method);
	GENERAL_NAME_free(a->location);
	Free (a);
}

STACK_OF(ACCESS_DESCRIPTION) *AUTHORITY_INFO_ACCESS_new(void)
{
	return sk_ACCESS_DESCRIPTION_new(NULL);
}

void AUTHORITY_INFO_ACCESS_free(STACK_OF(ACCESS_DESCRIPTION) *a)
{
	sk_ACCESS_DESCRIPTION_pop_free(a, ACCESS_DESCRIPTION_free);
}

STACK_OF(ACCESS_DESCRIPTION) *d2i_AUTHORITY_INFO_ACCESS(STACK_OF(ACCESS_DESCRIPTION) **a,
					 unsigned char **pp, long length)
{
return d2i_ASN1_SET_OF_ACCESS_DESCRIPTION(a, pp, length, d2i_ACCESS_DESCRIPTION,
			 ACCESS_DESCRIPTION_free, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
}

int i2d_AUTHORITY_INFO_ACCESS(STACK_OF(ACCESS_DESCRIPTION) *a, unsigned char **pp)
{
return i2d_ASN1_SET_OF_ACCESS_DESCRIPTION(a, pp, i2d_ACCESS_DESCRIPTION, V_ASN1_SEQUENCE,
						 V_ASN1_UNIVERSAL, IS_SEQUENCE);
}

IMPLEMENT_STACK_OF(ACCESS_DESCRIPTION)
IMPLEMENT_ASN1_SET_OF(ACCESS_DESCRIPTION)


