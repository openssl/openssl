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
#include "asn1.h"
#include "conf.h"
#include "x509v3.h"

#ifndef NOPROTO
static STACK *v2i_ext_ku(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK *nval);
static STACK *i2v_ext_ku(X509V3_EXT_METHOD *method, STACK *eku, STACK *extlist);
#else
static STACK *v2i_ext_ku();
static STACK *i2v_ext_ku();
#endif

X509V3_EXT_METHOD v3_ext_ku = {
NID_ext_key_usage, 0,
(X509V3_EXT_NEW)ext_ku_new,
ext_ku_free,
(X509V3_EXT_D2I)d2i_ext_ku,
i2d_ext_ku,
NULL, NULL,
(X509V3_EXT_I2V)i2v_ext_ku,
(X509V3_EXT_V2I)v2i_ext_ku,
NULL,NULL,
NULL
};

STACK *ext_ku_new()
{
	return sk_new_null();
}

void ext_ku_free(eku)
STACK *eku;
{
	sk_pop_free(eku, ASN1_OBJECT_free);
	return;
}

int i2d_ext_ku(a,pp)
STACK *a;
unsigned char **pp;
{
	return i2d_ASN1_SET(a, pp, i2d_ASN1_OBJECT, V_ASN1_SEQUENCE,
						 V_ASN1_UNIVERSAL, IS_SEQUENCE);
}

STACK *d2i_ext_ku(a,pp,length)
STACK **a;
unsigned char **pp;
long length;
{
	return d2i_ASN1_SET(a, pp, length, (char *(*)())(d2i_ASN1_OBJECT),
			 ASN1_OBJECT_free, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
}



static STACK *i2v_ext_ku(method, eku, ext_list)
X509V3_EXT_METHOD *method;
STACK  *eku;
STACK *ext_list;
{
int i;
ASN1_OBJECT *obj;
char obj_tmp[80];
for(i = 0; i < sk_num(eku); i++) {
	obj = (ASN1_OBJECT *)sk_value(eku, i);
	i2t_ASN1_OBJECT(obj_tmp, 80, obj);
	X509V3_add_value(NULL, obj_tmp, &ext_list);
}
return ext_list;
}

static STACK *v2i_ext_ku(method, ctx, nval)
X509V3_EXT_METHOD *method;
X509V3_CTX *ctx;
STACK *nval;
{
STACK *extku;
char *extval;
ASN1_OBJECT *objtmp;
CONF_VALUE *val;
int i;

if(!(extku = sk_new(NULL))) {
	X509V3err(X509V3_F_V2I_EXT_KU,ERR_R_MALLOC_FAILURE);
	return NULL;
}

for(i = 0; i < sk_num(nval); i++) {
	val = (CONF_VALUE *)sk_value(nval, i);
	if(val->value) extval = val->value;
	else extval = val->name;
	if(!(objtmp = OBJ_txt2obj(extval, 0))) {
		sk_pop_free(extku, ASN1_OBJECT_free);
		X509V3err(X509V3_F_V2I_EXT_KU,X509V3_R_INVALID_OBJECT_IDENTIFIER);
		X509V3_conf_err(val);
		return NULL;
	}
	sk_push(extku, (char *)objtmp);
}
return extku;
}
