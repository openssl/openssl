/* p12_attr.c */
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
#include <openssl/pkcs12.h>

/* Add a local keyid to a safebag */

int PKCS12_add_localkeyid (PKCS12_SAFEBAG *bag, unsigned char *name,
	     int namelen)
{
	X509_ATTRIBUTE *attrib;
	ASN1_BMPSTRING *oct;
	ASN1_TYPE *keyid;
	if (!(keyid = ASN1_TYPE_new ())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_LOCALKEYID, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	keyid->type = V_ASN1_OCTET_STRING;
	if (!(oct = M_ASN1_OCTET_STRING_new())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_LOCALKEYID, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if (!M_ASN1_OCTET_STRING_set(oct, name, namelen)) {
		PKCS12err(PKCS12_F_PKCS12_ADD_LOCALKEYID, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	keyid->value.octet_string = oct;
	if (!(attrib = X509_ATTRIBUTE_new ())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_LOCALKEYID, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	attrib->object = OBJ_nid2obj(NID_localKeyID);
	if (!(attrib->value.set = sk_ASN1_TYPE_new_null())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_LOCALKEYID, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	sk_ASN1_TYPE_push (attrib->value.set,keyid);
	attrib->set = 1;
	if (!bag->attrib && !(bag->attrib = sk_X509_ATTRIBUTE_new_null ())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_LOCALKEYID, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	sk_X509_ATTRIBUTE_push (bag->attrib, attrib);
	return 1;
}

/* Add key usage to PKCS#8 structure */

int PKCS8_add_keyusage (PKCS8_PRIV_KEY_INFO *p8, int usage)
{
	X509_ATTRIBUTE *attrib;
	ASN1_BIT_STRING *bstr;
	ASN1_TYPE *keyid;
	unsigned char us_val;
	us_val = (unsigned char) usage;
	if (!(keyid = ASN1_TYPE_new ())) {
		PKCS12err(PKCS12_F_PKCS8_ADD_KEYUSAGE, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	keyid->type = V_ASN1_BIT_STRING;
	if (!(bstr = M_ASN1_BIT_STRING_new())) {
		PKCS12err(PKCS12_F_PKCS8_ADD_KEYUSAGE, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if (!M_ASN1_BIT_STRING_set(bstr, &us_val, 1)) {
		PKCS12err(PKCS12_F_PKCS8_ADD_KEYUSAGE, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	keyid->value.bit_string = bstr;
	if (!(attrib = X509_ATTRIBUTE_new ())) {
		PKCS12err(PKCS12_F_PKCS8_ADD_KEYUSAGE, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	attrib->object = OBJ_nid2obj(NID_key_usage);
	if (!(attrib->value.set = sk_ASN1_TYPE_new_null())) {
		PKCS12err(PKCS12_F_PKCS8_ADD_KEYUSAGE, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	sk_ASN1_TYPE_push (attrib->value.set,keyid);
	attrib->set = 1;
	if (!p8->attributes
	    && !(p8->attributes = sk_X509_ATTRIBUTE_new_null ())) {
		PKCS12err(PKCS12_F_PKCS8_ADD_KEYUSAGE, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	sk_X509_ATTRIBUTE_push (p8->attributes, attrib);
	return 1;
}

/* Add a friendlyname to a safebag */

int PKCS12_add_friendlyname_asc (PKCS12_SAFEBAG *bag, const char *name,
				 int namelen)
{
	unsigned char *uniname;
	int ret, unilen;
	if (!asc2uni(name, &uniname, &unilen)) {
		PKCS12err(PKCS12_F_PKCS12_ADD_FRIENDLYNAME_ASC,
							ERR_R_MALLOC_FAILURE);
		return 0;
	}
	ret = PKCS12_add_friendlyname_uni (bag, uniname, unilen);
	OPENSSL_free(uniname);
	return ret;
}
	

int PKCS12_add_friendlyname_uni (PKCS12_SAFEBAG *bag,
				 const unsigned char *name, int namelen)
{
	X509_ATTRIBUTE *attrib;
	ASN1_BMPSTRING *bmp;
	ASN1_TYPE *fname;
	/* Zap ending double null if included */
	if(!name[namelen - 1] && !name[namelen - 2]) namelen -= 2;
	if (!(fname = ASN1_TYPE_new ())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_FRIENDLYNAME_UNI,
							ERR_R_MALLOC_FAILURE);
		return 0;
	}
	fname->type = V_ASN1_BMPSTRING;
	if (!(bmp = M_ASN1_BMPSTRING_new())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_FRIENDLYNAME_UNI,
							ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if (!(bmp->data = OPENSSL_malloc (namelen))) {
		PKCS12err(PKCS12_F_PKCS12_ADD_FRIENDLYNAME_UNI,
							ERR_R_MALLOC_FAILURE);
		return 0;
	}
	memcpy (bmp->data, name, namelen);
	bmp->length = namelen;
	fname->value.bmpstring = bmp;
	if (!(attrib = X509_ATTRIBUTE_new ())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_FRIENDLYNAME_UNI,
							ERR_R_MALLOC_FAILURE);
		return 0;
	}
	attrib->object = OBJ_nid2obj(NID_friendlyName);
	if (!(attrib->value.set = sk_ASN1_TYPE_new_null())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_FRIENDLYNAME,
							ERR_R_MALLOC_FAILURE);
		return 0;
	}
	sk_ASN1_TYPE_push (attrib->value.set,fname);
	attrib->set = 1;
	if (!bag->attrib && !(bag->attrib = sk_X509_ATTRIBUTE_new_null ())) {
		PKCS12err(PKCS12_F_PKCS12_ADD_FRIENDLYNAME_UNI,
							ERR_R_MALLOC_FAILURE);
		return 0;
	}
	sk_X509_ATTRIBUTE_push (bag->attrib, attrib);
	return PKCS12_OK;
}

ASN1_TYPE *PKCS12_get_attr_gen (STACK_OF(X509_ATTRIBUTE) *attrs, int attr_nid)
{
	X509_ATTRIBUTE *attrib;
	int i;
	if (!attrs) return NULL;
	for (i = 0; i < sk_X509_ATTRIBUTE_num (attrs); i++) {
		attrib = sk_X509_ATTRIBUTE_value (attrs, i);
		if (OBJ_obj2nid (attrib->object) == attr_nid) {
			if (sk_ASN1_TYPE_num (attrib->value.set))
			    return sk_ASN1_TYPE_value(attrib->value.set, 0);
			else return NULL;
		}
	}
	return NULL;
}

char *PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag)
{
	ASN1_TYPE *atype;
	if (!(atype = PKCS12_get_attr(bag, NID_friendlyName))) return NULL;
	if (atype->type != V_ASN1_BMPSTRING) return NULL;
	return uni2asc(atype->value.bmpstring->data,
				 atype->value.bmpstring->length);
}

