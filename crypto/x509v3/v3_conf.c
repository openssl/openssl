/* v3_conf.c */
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
/* config file utilities */

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <pem.h>
#include <conf.h>
#include <err.h>
#include "x509v3.h"

X509_EXTENSION *X509V3_EXT_conf(conf, ctx, name, value)
LHASH *conf;	/* Config file */
X509V3_CTX *ctx;
char *name;	/* Name */
char *value;	/* Value */
{
	return X509V3_EXT_conf_nid(conf, ctx, OBJ_sn2nid(name), value);
}


X509_EXTENSION *X509V3_EXT_conf_nid(conf, ctx, ext_nid, value)
LHASH *conf;	/* Config file */
X509V3_CTX *ctx;
int ext_nid;
char *value;	/* Value */
{
	X509_EXTENSION *ext = NULL;
	X509V3_EXT_METHOD *method;
	STACK *nval;
	char *ext_struc;
	char *ext_der, *p;
	int ext_len;
	int crit = 0;
	ASN1_OCTET_STRING *ext_oct;
	if(ext_nid == NID_undef) return NULL;
	if(!(method = X509V3_EXT_get_nid(ext_nid))) {
		/* Add generic extension support here */
		return NULL;
	}
	/* Check for critical */
	if((strlen(value) >= 9) && !strncmp(value, "critical,", 9)) {
		crit = 1;
		value+=9;
	}
	/* Skip over spaces */
	while(isspace(*value)) value++;
	/* Now get internal extension representation based on type */
	if(method->v2i) {
		if(*value == '@') nval = CONF_get_section(conf, value + 1);
		else nval = X509V3_parse_list(value);
		if(!nval) {
			X509V3err(X509V3_F_X509V3_EXT_CONF,X509V3_R_INVALID_EXTENSION_STRING);
			ERR_add_error_data(4, "name=", OBJ_nid2sn(ext_nid), ",section=", value);
			return NULL;
		}
		ext_struc = method->v2i(method, ctx, nval);
		if(*value != '@') sk_pop_free(nval, X509V3_conf_free);
		if(!ext_struc) return NULL;
	} else if(method->s2i) {
		if(!(ext_struc = method->s2i(method, ctx, value))) return NULL;
	} else {
		X509V3err(X509V3_F_X509V3_EXT_CONF,X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED);
		ERR_add_error_data(2, "name=", OBJ_nid2sn(ext_nid));
		return NULL;
	}

	/* We've now got the internal representation: convert to DER */
	ext_len = method->i2d(ext_struc, NULL);
	ext_der = Malloc(ext_len);
	p = ext_der;
	method->i2d(ext_struc, &p);
	method->ext_free(ext_struc);
	ext_oct = ASN1_OCTET_STRING_new();
	ext_oct->data = ext_der;
	ext_oct->length = ext_len;
	
	ext = X509_EXTENSION_create_by_NID(NULL, ext_nid, crit, ext_oct);
	ASN1_OCTET_STRING_free(ext_oct);

	return ext;

}

/* This is the main function: add a bunch of extensions based on a config file
 * section
 */

int X509V3_EXT_add_conf(conf, ctx, section, cert)
LHASH *conf;
X509V3_CTX *ctx;
char *section;
X509 *cert;
{
	X509_EXTENSION *ext;
	STACK *nval;
	CONF_VALUE *val;	
	int i;
	if(!(nval = CONF_get_section(conf, section))) return 0;
	for(i = 0; i < sk_num(nval); i++) {
		val = (CONF_VALUE *)sk_value(nval, i);
		if(!(ext = X509V3_EXT_conf(conf, ctx, val->name, val->value)))
								return 0;
		if(cert) X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	}
	return 1;
}

