/* v3_alt.c */
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
#include <openssl/x509v3.h>

static STACK_OF(GENERAL_NAME) *v2i_subject_alt(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);
static STACK_OF(GENERAL_NAME) *v2i_issuer_alt(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);
static int copy_email(X509V3_CTX *ctx, STACK_OF(GENERAL_NAME) *gens);
static int copy_issuer(X509V3_CTX *ctx, STACK_OF(GENERAL_NAME) *gens);
X509V3_EXT_METHOD v3_alt[] = {
{ NID_subject_alt_name, 0,
(X509V3_EXT_NEW)GENERAL_NAMES_new,
(X509V3_EXT_FREE)GENERAL_NAMES_free,
(X509V3_EXT_D2I)d2i_GENERAL_NAMES,
(X509V3_EXT_I2D)i2d_GENERAL_NAMES,
NULL, NULL,
(X509V3_EXT_I2V)i2v_GENERAL_NAMES,
(X509V3_EXT_V2I)v2i_subject_alt,
NULL, NULL, NULL},
{ NID_issuer_alt_name, 0,
(X509V3_EXT_NEW)GENERAL_NAMES_new,
(X509V3_EXT_FREE)GENERAL_NAMES_free,
(X509V3_EXT_D2I)d2i_GENERAL_NAMES,
(X509V3_EXT_I2D)i2d_GENERAL_NAMES,
NULL, NULL,
(X509V3_EXT_I2V)i2v_GENERAL_NAMES,
(X509V3_EXT_V2I)v2i_issuer_alt,
NULL, NULL, NULL},
};

STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method,
		STACK_OF(GENERAL_NAME) *gens, STACK_OF(CONF_VALUE) *ret)
{
	int i;
	GENERAL_NAME *gen;
	for(i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
		gen = sk_GENERAL_NAME_value(gens, i);
		ret = i2v_GENERAL_NAME(method, gen, ret);
	}
	if(!ret) return sk_CONF_VALUE_new_null();
	return ret;
}

STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method,
				GENERAL_NAME *gen, STACK_OF(CONF_VALUE) *ret)
{
	char oline[256];
	unsigned char *p;
	switch (gen->type)
	{
		case GEN_OTHERNAME:
		X509V3_add_value("othername","<unsupported>", &ret);
		break;

		case GEN_X400:
		X509V3_add_value("X400Name","<unsupported>", &ret);
		break;

		case GEN_EDIPARTY:
		X509V3_add_value("EdiPartyName","<unsupported>", &ret);
		break;

		case GEN_EMAIL:
		X509V3_add_value_uchar("email",gen->d.ia5->data, &ret);
		break;

		case GEN_DNS:
		X509V3_add_value_uchar("DNS",gen->d.ia5->data, &ret);
		break;

		case GEN_URI:
		X509V3_add_value_uchar("URI",gen->d.ia5->data, &ret);
		break;

		case GEN_DIRNAME:
		X509_NAME_oneline(gen->d.dirn, oline, 256);
		X509V3_add_value("DirName",oline, &ret);
		break;

		case GEN_IPADD:
		p = gen->d.ip->data;
		/* BUG: doesn't support IPV6 */
		if(gen->d.ip->length != 4) {
			X509V3_add_value("IP Address","<invalid>", &ret);
			break;
		}
		sprintf(oline, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
		X509V3_add_value("IP Address",oline, &ret);
		break;

		case GEN_RID:
		i2t_ASN1_OBJECT(oline, 256, gen->d.rid);
		X509V3_add_value("Registered ID",oline, &ret);
		break;
	}
	return ret;
}

static STACK_OF(GENERAL_NAME) *v2i_issuer_alt(X509V3_EXT_METHOD *method,
				 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
	STACK_OF(GENERAL_NAME) *gens = NULL;
	CONF_VALUE *cnf;
	int i;
	if(!(gens = sk_GENERAL_NAME_new(NULL))) {
		X509V3err(X509V3_F_V2I_GENERAL_NAMES,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	for(i = 0; i < sk_CONF_VALUE_num(nval); i++) {
		cnf = sk_CONF_VALUE_value(nval, i);
		if(!name_cmp(cnf->name, "issuer") && cnf->value &&
						!strcmp(cnf->value, "copy")) {
			if(!copy_issuer(ctx, gens)) goto err;
		} else {
			GENERAL_NAME *gen;
			if(!(gen = v2i_GENERAL_NAME(method, ctx, cnf)))
								 goto err; 
			sk_GENERAL_NAME_push(gens, gen);
		}
	}
	return gens;
	err:
	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	return NULL;
}

/* Append subject altname of issuer to issuer alt name of subject */

static int copy_issuer(X509V3_CTX *ctx, STACK_OF(GENERAL_NAME) *gens)
{
	STACK_OF(GENERAL_NAME) *ialt;
	GENERAL_NAME *gen;
	X509_EXTENSION *ext;
	int i;
	if(ctx && (ctx->flags == CTX_TEST)) return 1;
	if(!ctx || !ctx->issuer_cert) {
		X509V3err(X509V3_F_COPY_ISSUER,X509V3_R_NO_ISSUER_DETAILS);
		goto err;
	}
        i = X509_get_ext_by_NID(ctx->issuer_cert, NID_subject_alt_name, -1);
	if(i < 0) return 1;
        if(!(ext = X509_get_ext(ctx->issuer_cert, i)) ||
                        !(ialt = X509V3_EXT_d2i(ext)) ) {
		X509V3err(X509V3_F_COPY_ISSUER,X509V3_R_ISSUER_DECODE_ERROR);
		goto err;
	}

	for(i = 0; i < sk_GENERAL_NAME_num(ialt); i++) {
		gen = sk_GENERAL_NAME_value(ialt, i);
		if(!sk_GENERAL_NAME_push(gens, gen)) {
			X509V3err(X509V3_F_COPY_ISSUER,ERR_R_MALLOC_FAILURE);
			goto err;
		}
	}
	sk_GENERAL_NAME_free(ialt);

	return 1;
		
	err:
	return 0;
	
}

static STACK_OF(GENERAL_NAME) *v2i_subject_alt(X509V3_EXT_METHOD *method,
				 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
	STACK_OF(GENERAL_NAME) *gens = NULL;
	CONF_VALUE *cnf;
	int i;
	if(!(gens = sk_GENERAL_NAME_new(NULL))) {
		X509V3err(X509V3_F_V2I_GENERAL_NAMES,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	for(i = 0; i < sk_CONF_VALUE_num(nval); i++) {
		cnf = sk_CONF_VALUE_value(nval, i);
		if(!name_cmp(cnf->name, "email") && cnf->value &&
						!strcmp(cnf->value, "copy")) {
			if(!copy_email(ctx, gens)) goto err;
		} else {
			GENERAL_NAME *gen;
			if(!(gen = v2i_GENERAL_NAME(method, ctx, cnf)))
								 goto err; 
			sk_GENERAL_NAME_push(gens, gen);
		}
	}
	return gens;
	err:
	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	return NULL;
}

/* Copy any email addresses in a certificate or request to 
 * GENERAL_NAMES
 */

static int copy_email(X509V3_CTX *ctx, STACK_OF(GENERAL_NAME) *gens)
{
	X509_NAME *nm;
	ASN1_IA5STRING *email = NULL;
	X509_NAME_ENTRY *ne;
	GENERAL_NAME *gen = NULL;
	int i;
	if(ctx->flags == CTX_TEST) return 1;
	if(!ctx || (!ctx->subject_cert && !ctx->subject_req)) {
		X509V3err(X509V3_F_COPY_EMAIL,X509V3_R_NO_SUBJECT_DETAILS);
		goto err;
	}
	/* Find the subject name */
	if(ctx->subject_cert) nm = X509_get_subject_name(ctx->subject_cert);
	else nm = X509_REQ_get_subject_name(ctx->subject_req);

	/* Now add any email address(es) to STACK */
	i = -1;
	while((i = X509_NAME_get_index_by_NID(nm,
					 NID_pkcs9_emailAddress, i)) > 0) {
		ne = X509_NAME_get_entry(nm, i);
		email = M_ASN1_IA5STRING_dup(X509_NAME_ENTRY_get_data(ne));
		if(!email || !(gen = GENERAL_NAME_new())) {
			X509V3err(X509V3_F_COPY_EMAIL,ERR_R_MALLOC_FAILURE);
			goto err;
		}
		gen->d.ia5 = email;
		email = NULL;
		gen->type = GEN_EMAIL;
		if(!sk_GENERAL_NAME_push(gens, gen)) {
			X509V3err(X509V3_F_COPY_EMAIL,ERR_R_MALLOC_FAILURE);
			goto err;
		}
		gen = NULL;
	}

	
	return 1;
		
	err:
	GENERAL_NAME_free(gen);
	M_ASN1_IA5STRING_free(email);
	return 0;
	
}

STACK_OF(GENERAL_NAME) *v2i_GENERAL_NAMES(X509V3_EXT_METHOD *method,
				X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
	GENERAL_NAME *gen;
	STACK_OF(GENERAL_NAME) *gens = NULL;
	CONF_VALUE *cnf;
	int i;
	if(!(gens = sk_GENERAL_NAME_new(NULL))) {
		X509V3err(X509V3_F_V2I_GENERAL_NAMES,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	for(i = 0; i < sk_CONF_VALUE_num(nval); i++) {
		cnf = sk_CONF_VALUE_value(nval, i);
		if(!(gen = v2i_GENERAL_NAME(method, ctx, cnf))) goto err; 
		sk_GENERAL_NAME_push(gens, gen);
	}
	return gens;
	err:
	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	return NULL;
}

GENERAL_NAME *v2i_GENERAL_NAME(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
							 CONF_VALUE *cnf)
{
char is_string = 0;
int type;
GENERAL_NAME *gen = NULL;

char *name, *value;

name = cnf->name;
value = cnf->value;

if(!value) {
	X509V3err(X509V3_F_V2I_GENERAL_NAME,X509V3_R_MISSING_VALUE);
	return NULL;
}

if(!(gen = GENERAL_NAME_new())) {
	X509V3err(X509V3_F_V2I_GENERAL_NAME,ERR_R_MALLOC_FAILURE);
	return NULL;
}

if(!name_cmp(name, "email")) {
	is_string = 1;
	type = GEN_EMAIL;
} else if(!name_cmp(name, "URI")) {
	is_string = 1;
	type = GEN_URI;
} else if(!name_cmp(name, "DNS")) {
	is_string = 1;
	type = GEN_DNS;
} else if(!name_cmp(name, "RID")) {
	ASN1_OBJECT *obj;
	if(!(obj = OBJ_txt2obj(value,0))) {
		X509V3err(X509V3_F_V2I_GENERAL_NAME,X509V3_R_BAD_OBJECT);
		ERR_add_error_data(2, "value=", value);
		goto err;
	}
	gen->d.rid = obj;
	type = GEN_RID;
} else if(!name_cmp(name, "IP")) {
	int i1,i2,i3,i4;
	unsigned char ip[4];
	if((sscanf(value, "%d.%d.%d.%d",&i1,&i2,&i3,&i4) != 4) ||
	    (i1 < 0) || (i1 > 255) || (i2 < 0) || (i2 > 255) ||
	    (i3 < 0) || (i3 > 255) || (i4 < 0) || (i4 > 255) ) {
		X509V3err(X509V3_F_V2I_GENERAL_NAME,X509V3_R_BAD_IP_ADDRESS);
		ERR_add_error_data(2, "value=", value);
		goto err;
	}
	ip[0] = i1; ip[1] = i2 ; ip[2] = i3 ; ip[3] = i4;
	if(!(gen->d.ip = M_ASN1_OCTET_STRING_new()) ||
		!ASN1_STRING_set(gen->d.ip, ip, 4)) {
			X509V3err(X509V3_F_V2I_GENERAL_NAME,ERR_R_MALLOC_FAILURE);
			goto err;
	}
	type = GEN_IPADD;
} else {
	X509V3err(X509V3_F_V2I_GENERAL_NAME,X509V3_R_UNSUPPORTED_OPTION);
	ERR_add_error_data(2, "name=", name);
	goto err;
}

if(is_string) {
	if(!(gen->d.ia5 = M_ASN1_IA5STRING_new()) ||
		      !ASN1_STRING_set(gen->d.ia5, (unsigned char*)value,
				       strlen(value))) {
		X509V3err(X509V3_F_V2I_GENERAL_NAME,ERR_R_MALLOC_FAILURE);
		goto err;
	}
}

gen->type = type;

return gen;

err:
GENERAL_NAME_free(gen);
return NULL;
}
