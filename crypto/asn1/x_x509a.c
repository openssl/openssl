/* a_x509a.c */
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
#include <openssl/evp.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>

/* X509_CERT_AUX routines. These are used to encode additional
 * user modifiable data about a certificate. This data is
 * appended to the X509 encoding when the *_X509_AUX routines
 * are used. This means that the "traditional" X509 routines
 * will simply ignore the extra data. 
 */

static X509_CERT_AUX *aux_get(X509 *x);

X509_CERT_AUX *d2i_X509_CERT_AUX(X509_CERT_AUX **a, unsigned char **pp, long length)
{
	M_ASN1_D2I_vars(a, X509_CERT_AUX *, X509_CERT_AUX_new);
	
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();

	M_ASN1_D2I_get_seq_opt_type(ASN1_OBJECT, ret->trust,
					d2i_ASN1_OBJECT, ASN1_OBJECT_free);
	M_ASN1_D2I_get_IMP_set_opt_type(ASN1_OBJECT, ret->reject,
					d2i_ASN1_OBJECT, ASN1_OBJECT_free, 0);
	M_ASN1_D2I_get_opt(ret->alias, d2i_ASN1_UTF8STRING, V_ASN1_UTF8STRING);
	M_ASN1_D2I_get_opt(ret->keyid, d2i_ASN1_OCTET_STRING, V_ASN1_OCTET_STRING);
	M_ASN1_D2I_get_IMP_set_opt_type(X509_ALGOR, ret->other,
					d2i_X509_ALGOR, X509_ALGOR_free, 1);

	M_ASN1_D2I_Finish(a, X509_CERT_AUX_free, ASN1_F_D2I_X509_CERT_AUX);
}

X509_CERT_AUX *X509_CERT_AUX_new()
{
	X509_CERT_AUX *ret = NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, X509_CERT_AUX);
	ret->trust = NULL;
	ret->reject = NULL;
	ret->alias = NULL;
	ret->keyid = NULL;
	ret->other = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_X509_CERT_AUX_NEW);
}

void X509_CERT_AUX_free(X509_CERT_AUX *a)
{
	if(a == NULL) return;
	sk_ASN1_OBJECT_pop_free(a->trust, ASN1_OBJECT_free);
	sk_ASN1_OBJECT_pop_free(a->reject, ASN1_OBJECT_free);
	ASN1_UTF8STRING_free(a->alias);
	ASN1_OCTET_STRING_free(a->keyid);
	sk_X509_ALGOR_pop_free(a->other, X509_ALGOR_free);
	OPENSSL_free(a);
}

int i2d_X509_CERT_AUX(X509_CERT_AUX *a, unsigned char **pp)
{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len_SEQUENCE_opt_type(ASN1_OBJECT, a->trust, i2d_ASN1_OBJECT);
	M_ASN1_I2D_len_IMP_SEQUENCE_opt_type(ASN1_OBJECT, a->reject, i2d_ASN1_OBJECT, 0);

	M_ASN1_I2D_len(a->alias, i2d_ASN1_UTF8STRING);
	M_ASN1_I2D_len(a->keyid, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_len_IMP_SEQUENCE_opt_type(X509_ALGOR, a->other, i2d_X509_ALGOR, 1);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put_SEQUENCE_opt_type(ASN1_OBJECT, a->trust, i2d_ASN1_OBJECT);
	M_ASN1_I2D_put_IMP_SEQUENCE_opt_type(ASN1_OBJECT, a->reject, i2d_ASN1_OBJECT, 0);

	M_ASN1_I2D_put(a->alias, i2d_ASN1_UTF8STRING);
	M_ASN1_I2D_put(a->keyid, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_put_IMP_SEQUENCE_opt_type(X509_ALGOR, a->other, i2d_X509_ALGOR, 1);

	M_ASN1_I2D_finish();
}

static X509_CERT_AUX *aux_get(X509 *x)
{
	if(!x) return NULL;
	if(!x->aux && !(x->aux = X509_CERT_AUX_new())) return NULL;
	return x->aux;
}

int X509_alias_set1(X509 *x, unsigned char *name, int len)
{
	X509_CERT_AUX *aux;
	if(!(aux = aux_get(x))) return 0;
	if(!aux->alias && !(aux->alias = ASN1_UTF8STRING_new())) return 0;
	return ASN1_STRING_set(aux->alias, name, len);
}

int X509_keyid_set1(X509 *x, unsigned char *id, int len)
{
	X509_CERT_AUX *aux;
	if(!(aux = aux_get(x))) return 0;
	if(!aux->keyid && !(aux->keyid = ASN1_OCTET_STRING_new())) return 0;
	return ASN1_STRING_set(aux->keyid, id, len);
}

unsigned char *X509_alias_get0(X509 *x, int *len)
{
	if(!x->aux || !x->aux->alias) return NULL;
	if(len) *len = x->aux->alias->length;
	return x->aux->alias->data;
}

int X509_add1_trust_object(X509 *x, ASN1_OBJECT *obj)
{
	X509_CERT_AUX *aux;
	ASN1_OBJECT *objtmp;
	if(!(objtmp = OBJ_dup(obj))) return 0;
	if(!(aux = aux_get(x))) return 0;
	if(!aux->trust
		&& !(aux->trust = sk_ASN1_OBJECT_new_null())) return 0;
	return sk_ASN1_OBJECT_push(aux->trust, objtmp);
}

int X509_add1_reject_object(X509 *x, ASN1_OBJECT *obj)
{
	X509_CERT_AUX *aux;
	ASN1_OBJECT *objtmp;
	if(!(objtmp = OBJ_dup(obj))) return 0;
	if(!(aux = aux_get(x))) return 0;
	if(!aux->reject
		&& !(aux->reject = sk_ASN1_OBJECT_new_null())) return 0;
	return sk_ASN1_OBJECT_push(aux->reject, objtmp);
}

void X509_trust_clear(X509 *x)
{
	if(x->aux && x->aux->trust) {
		sk_ASN1_OBJECT_pop_free(x->aux->trust, ASN1_OBJECT_free);
		x->aux->trust = NULL;
	}
}

void X509_reject_clear(X509 *x)
{
	if(x->aux && x->aux->reject) {
		sk_ASN1_OBJECT_pop_free(x->aux->reject, ASN1_OBJECT_free);
		x->aux->reject = NULL;
	}
}

