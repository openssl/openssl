/* v3_extku.c */
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
#include <openssl/conf.h>
#include <openssl/x509v3.h>

static STACK_OF(ASN1_OBJECT) *v2i_ext_ku(X509V3_EXT_METHOD *method,
				X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);
static STACK_OF(CONF_VALUE) *i2v_ext_ku(X509V3_EXT_METHOD *method,
		STACK_OF(ASN1_OBJECT) *eku, STACK_OF(CONF_VALUE) *extlist);
X509V3_EXT_METHOD v3_ext_ku = {
NID_ext_key_usage, 0,
(X509V3_EXT_NEW)ext_ku_new,
(X509V3_EXT_FREE)ext_ku_free,
(X509V3_EXT_D2I)d2i_ext_ku,
(X509V3_EXT_I2D)i2d_ext_ku,
NULL, NULL,
(X509V3_EXT_I2V)i2v_ext_ku,
(X509V3_EXT_V2I)v2i_ext_ku,
NULL,NULL,
NULL
};

STACK_OF(ASN1_OBJECT) *ext_ku_new(void)
{
	return sk_ASN1_OBJECT_new_null();
}

void ext_ku_free(STACK_OF(ASN1_OBJECT) *eku)
{
	sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
	return;
}

int i2d_ext_ku(STACK_OF(ASN1_OBJECT) *a, unsigned char **pp)
{
	return i2d_ASN1_SET_OF_ASN1_OBJECT(a, pp, i2d_ASN1_OBJECT,
				V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, IS_SEQUENCE);
}

STACK_OF(ASN1_OBJECT) *d2i_ext_ku(STACK_OF(ASN1_OBJECT) **a,
					unsigned char **pp, long length)
{
	return d2i_ASN1_SET_OF_ASN1_OBJECT(a, pp, length, d2i_ASN1_OBJECT,
			 ASN1_OBJECT_free, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
}



static STACK_OF(CONF_VALUE) *i2v_ext_ku(X509V3_EXT_METHOD *method,
		STACK_OF(ASN1_OBJECT) *eku, STACK_OF(CONF_VALUE) *ext_list)
{
int i;
ASN1_OBJECT *obj;
char obj_tmp[80];
for(i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
	obj = sk_ASN1_OBJECT_value(eku, i);
	i2t_ASN1_OBJECT(obj_tmp, 80, obj);
	X509V3_add_value(NULL, obj_tmp, &ext_list);
}
return ext_list;
}

static STACK_OF(ASN1_OBJECT) *v2i_ext_ku(X509V3_EXT_METHOD *method,
				X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
STACK_OF(ASN1_OBJECT) *extku;
char *extval;
ASN1_OBJECT *objtmp;
CONF_VALUE *val;
int i;

if(!(extku = sk_ASN1_OBJECT_new(NULL))) {
	X509V3err(X509V3_F_V2I_EXT_KU,ERR_R_MALLOC_FAILURE);
	return NULL;
}

for(i = 0; i < sk_CONF_VALUE_num(nval); i++) {
	val = sk_CONF_VALUE_value(nval, i);
	if(val->value) extval = val->value;
	else extval = val->name;
	if(!(objtmp = OBJ_txt2obj(extval, 0))) {
		sk_ASN1_OBJECT_pop_free(extku, ASN1_OBJECT_free);
		X509V3err(X509V3_F_V2I_EXT_KU,X509V3_R_INVALID_OBJECT_IDENTIFIER);
		X509V3_conf_err(val);
		return NULL;
	}
	sk_ASN1_OBJECT_push(extku, objtmp);
}
return extku;
}
