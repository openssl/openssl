/* v3_crld.c */
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

static STACK_OF(CONF_VALUE) *i2v_crld(X509V3_EXT_METHOD *method,
		STACK_OF(DIST_POINT) *crld, STACK_OF(CONF_VALUE) *extlist);
static STACK_OF(DIST_POINT) *v2i_crld(X509V3_EXT_METHOD *method,
				X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);

X509V3_EXT_METHOD v3_crld = {
NID_crl_distribution_points, X509V3_EXT_MULTILINE,
(X509V3_EXT_NEW)CRL_DIST_POINTS_new,
(X509V3_EXT_FREE)CRL_DIST_POINTS_free,
(X509V3_EXT_D2I)d2i_CRL_DIST_POINTS,
(X509V3_EXT_I2D)i2d_CRL_DIST_POINTS,
NULL, NULL,
(X509V3_EXT_I2V)i2v_crld,
(X509V3_EXT_V2I)v2i_crld,
NULL, NULL, NULL
};

static STACK_OF(CONF_VALUE) *i2v_crld(X509V3_EXT_METHOD *method,
			STACK_OF(DIST_POINT) *crld, STACK_OF(CONF_VALUE) *exts)
{
	DIST_POINT *point;
	int i;
	for(i = 0; i < sk_DIST_POINT_num(crld); i++) {
		point = sk_DIST_POINT_value(crld, i);
		if(point->distpoint->fullname) {
			exts = i2v_GENERAL_NAMES(NULL,
					 point->distpoint->fullname, exts);
		}
		if(point->reasons) 
			X509V3_add_value("reasons","<UNSUPPORTED>", &exts);
		if(point->CRLissuer)
			X509V3_add_value("CRLissuer","<UNSUPPORTED>", &exts);
		if(point->distpoint->relativename)
		        X509V3_add_value("RelativeName","<UNSUPPORTED>", &exts);
	}
	return exts;
}

static STACK_OF(DIST_POINT) *v2i_crld(X509V3_EXT_METHOD *method,
				X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
	STACK_OF(DIST_POINT) *crld = NULL;
	STACK_OF(GENERAL_NAME) *gens = NULL;
	GENERAL_NAME *gen = NULL;
	CONF_VALUE *cnf;
	int i;
	if(!(crld = sk_DIST_POINT_new(NULL))) goto merr;
	for(i = 0; i < sk_CONF_VALUE_num(nval); i++) {
		DIST_POINT *point;
		cnf = sk_CONF_VALUE_value(nval, i);
		if(!(gen = v2i_GENERAL_NAME(method, ctx, cnf))) goto err; 
		if(!(gens = GENERAL_NAMES_new())) goto merr;
		if(!sk_GENERAL_NAME_push(gens, gen)) goto merr;
		gen = NULL;
		if(!(point = DIST_POINT_new())) goto merr;
		if(!sk_DIST_POINT_push(crld, point)) {
			DIST_POINT_free(point);
			goto merr;
		}
		if(!(point->distpoint = DIST_POINT_NAME_new())) goto merr;
		point->distpoint->fullname = gens;
		gens = NULL;
	}
	return crld;

	merr:
	X509V3err(X509V3_F_V2I_CRLD,ERR_R_MALLOC_FAILURE);
	err:
	GENERAL_NAME_free(gen);
	GENERAL_NAMES_free(gens);
	sk_DIST_POINT_pop_free(crld, DIST_POINT_free);
	return NULL;
}

int i2d_CRL_DIST_POINTS(STACK_OF(DIST_POINT) *a, unsigned char **pp)
{

return i2d_ASN1_SET_OF_DIST_POINT(a, pp, i2d_DIST_POINT, V_ASN1_SEQUENCE,
                                                 V_ASN1_UNIVERSAL, IS_SEQUENCE);}

STACK_OF(DIST_POINT) *CRL_DIST_POINTS_new(void)
{
	return sk_DIST_POINT_new_null();
}

void CRL_DIST_POINTS_free(STACK_OF(DIST_POINT) *a)
{
	sk_DIST_POINT_pop_free(a, DIST_POINT_free);
}

STACK_OF(DIST_POINT) *d2i_CRL_DIST_POINTS(STACK_OF(DIST_POINT) **a,
		unsigned char **pp,long length)
{
return d2i_ASN1_SET_OF_DIST_POINT(a, pp, length, d2i_DIST_POINT,
                         DIST_POINT_free, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

}

IMPLEMENT_STACK_OF(DIST_POINT)
IMPLEMENT_ASN1_SET_OF(DIST_POINT)

int i2d_DIST_POINT(DIST_POINT *a, unsigned char **pp)
{
	int v = 0;
	M_ASN1_I2D_vars(a);
	/* NB: underlying type is a CHOICE so need EXPLICIT tagging */
	M_ASN1_I2D_len_EXP_opt (a->distpoint, i2d_DIST_POINT_NAME, 0, v);
	M_ASN1_I2D_len_IMP_opt (a->reasons, i2d_ASN1_BIT_STRING);
	M_ASN1_I2D_len_IMP_opt (a->CRLissuer, i2d_GENERAL_NAMES);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put_EXP_opt (a->distpoint, i2d_DIST_POINT_NAME, 0, v);
	M_ASN1_I2D_put_IMP_opt (a->reasons, i2d_ASN1_BIT_STRING, 1);
	M_ASN1_I2D_put_IMP_opt (a->CRLissuer, i2d_GENERAL_NAMES, 2);

	M_ASN1_I2D_finish();
}

DIST_POINT *DIST_POINT_new(void)
{
	DIST_POINT *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, DIST_POINT);
	ret->distpoint = NULL;
	ret->reasons = NULL;
	ret->CRLissuer = NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_DIST_POINT_NEW);
}

DIST_POINT *d2i_DIST_POINT(DIST_POINT **a, unsigned char **pp, long length)
{
	M_ASN1_D2I_vars(a,DIST_POINT *,DIST_POINT_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get_EXP_opt (ret->distpoint, d2i_DIST_POINT_NAME, 0);
	M_ASN1_D2I_get_IMP_opt (ret->reasons, d2i_ASN1_BIT_STRING, 1,
							V_ASN1_BIT_STRING);
	M_ASN1_D2I_get_IMP_opt (ret->CRLissuer, d2i_GENERAL_NAMES, 2,
							V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a, DIST_POINT_free, ASN1_F_D2I_DIST_POINT);
}

void DIST_POINT_free(DIST_POINT *a)
{
	if (a == NULL) return;
	DIST_POINT_NAME_free(a->distpoint);
	ASN1_BIT_STRING_free(a->reasons);
	sk_GENERAL_NAME_pop_free(a->CRLissuer, GENERAL_NAME_free);
	Free ((char *)a);
}

int i2d_DIST_POINT_NAME(DIST_POINT_NAME *a, unsigned char **pp)
{
	int v = 0;
	M_ASN1_I2D_vars(a);

	if(a->fullname) {
		M_ASN1_I2D_len_IMP_opt (a->fullname, i2d_GENERAL_NAMES);
	} else {
		M_ASN1_I2D_len_EXP_opt (a->relativename, i2d_X509_NAME, 1, v);
	}

	/* Don't want a SEQUENCE so... */
	if(pp == NULL) return ret;
	p = *pp;

	if(a->fullname) {
		M_ASN1_I2D_put_IMP_opt (a->fullname, i2d_GENERAL_NAMES, 0);
	} else {
		M_ASN1_I2D_put_EXP_opt (a->relativename, i2d_X509_NAME, 1, v);
	}
	M_ASN1_I2D_finish();
}

DIST_POINT_NAME *DIST_POINT_NAME_new(void)
{
	DIST_POINT_NAME *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, DIST_POINT_NAME);
	ret->fullname = NULL;
	ret->relativename = NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_DIST_POINT_NAME_NEW);
}

void DIST_POINT_NAME_free(DIST_POINT_NAME *a)
{
	if (a == NULL) return;
	X509_NAME_free(a->relativename);
	sk_GENERAL_NAME_pop_free(a->fullname, GENERAL_NAME_free);
	Free ((char *)a);
}

DIST_POINT_NAME *d2i_DIST_POINT_NAME(DIST_POINT_NAME **a, unsigned char **pp,
	     long length)
{
        unsigned char _tmp, tag;
        M_ASN1_D2I_vars(a,DIST_POINT_NAME *,DIST_POINT_NAME_new);
        M_ASN1_D2I_Init();
        c.slen = length;

        _tmp = M_ASN1_next;
        tag = _tmp & ~V_ASN1_CONSTRUCTED;
	
	if(tag == (0|V_ASN1_CONTEXT_SPECIFIC)) {
		M_ASN1_D2I_get_imp(ret->fullname, d2i_GENERAL_NAMES,
							V_ASN1_SEQUENCE);
	} else if (tag == (1|V_ASN1_CONTEXT_SPECIFIC)) {
		M_ASN1_D2I_get_EXP_opt (ret->relativename, d2i_X509_NAME, 1);
	} else {
		c.error = ASN1_R_BAD_TAG;
		goto err;
	}

	M_ASN1_D2I_Finish(a, DIST_POINT_NAME_free, ASN1_F_D2I_DIST_POINT_NAME);
}
