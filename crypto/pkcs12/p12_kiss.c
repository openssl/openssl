/* p12_kiss.c */
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

/* Simplified PKCS#12 routines */

static int parse_pk12( PKCS12 *p12, const char *pass, int passlen, EVP_PKEY **pkey, X509 **cert, STACK **ca);
static int parse_bags( STACK *bags, const char *pass, int passlen, EVP_PKEY **pkey, X509 **cert, STACK **ca, ASN1_OCTET_STRING **keyid, char *keymatch);
static int parse_bag( PKCS12_SAFEBAG *bag, const char *pass, int passlen, EVP_PKEY **pkey, X509 **cert, STACK **ca, ASN1_OCTET_STRING **keyid, char *keymatch);
/* Parse and decrypt a PKCS#12 structure returning user key, user cert
 * and other (CA) certs. Note either ca should be NULL, *ca should be NULL,
 * or it should point to a valid STACK structure. pkey and cert can be
 * passed unitialised.
 */

int PKCS12_parse (PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert,
	     STACK **ca)
{

/* Check for NULL PKCS12 structure */

if(!p12) {
	PKCS12err(PKCS12_F_PKCS12_PARSE,PKCS12_R_INVALID_NULL_PKCS12_POINTER);
	return 0;
}

/* Allocate stack for ca certificates if needed */
if ((ca != NULL) && (*ca == NULL)) {
	if (!(*ca = sk_new(NULL))) {
		PKCS12err(PKCS12_F_PKCS12_PARSE,ERR_R_MALLOC_FAILURE);
		return 0;
	}
}

if(pkey) *pkey = NULL;
if(cert) *cert = NULL;

/* Check the mac */

if (!PKCS12_verify_mac (p12, pass, -1)) {
	PKCS12err(PKCS12_F_PKCS12_PARSE,PKCS12_R_MAC_VERIFY_FAILURE);
	goto err;
}

if (!parse_pk12 (p12, pass, -1, pkey, cert, ca)) {
	PKCS12err(PKCS12_F_PKCS12_PARSE,PKCS12_R_PARSE_ERROR);
	goto err;
}

return 1;

err:

if (pkey && *pkey) EVP_PKEY_free (*pkey);
if (cert && *cert) X509_free (*cert);
if (ca) sk_pop_free (*ca, X509_free);
return 0;

}

/* Parse the outer PKCS#12 structure */

static int parse_pk12 (PKCS12 *p12, const char *pass, int passlen,
	     EVP_PKEY **pkey, X509 **cert, STACK **ca)
{
	STACK *asafes, *bags;
	int i, bagnid;
	PKCS7 *p7;
	ASN1_OCTET_STRING *keyid = NULL;
	char keymatch = 0;
	if (!( asafes = M_PKCS12_unpack_authsafes (p12))) return 0;
	for (i = 0; i < sk_num (asafes); i++) {
		p7 = (PKCS7 *) sk_value (asafes, i);
		bagnid = OBJ_obj2nid (p7->type);
		if (bagnid == NID_pkcs7_data) {
			bags = M_PKCS12_unpack_p7data (p7);
		} else if (bagnid == NID_pkcs7_encrypted) {
			bags = M_PKCS12_unpack_p7encdata (p7, pass, passlen);
		} else continue;
		if (!bags) {
			sk_pop_free (asafes, PKCS7_free);
			return 0;
		}
	    	if (!parse_bags(bags, pass, passlen, pkey, cert, ca,
							 &keyid, &keymatch)) {
			sk_pop_free(bags, PKCS12_SAFEBAG_free);
			sk_pop_free(asafes, PKCS7_free);
			return 0;
		}
		sk_pop_free(bags, PKCS12_SAFEBAG_free);
	}
	sk_pop_free(asafes, PKCS7_free);
	if (keyid) M_ASN1_OCTET_STRING_free(keyid);
	return 1;
}


static int parse_bags (STACK *bags, const char *pass, int passlen,
		       EVP_PKEY **pkey, X509 **cert, STACK **ca,
		       ASN1_OCTET_STRING **keyid, char *keymatch)
{
	int i;
	for (i = 0; i < sk_num(bags); i++) {
		if (!parse_bag((PKCS12_SAFEBAG *)sk_value (bags, i),
			 pass, passlen, pkey, cert, ca, keyid,
							 keymatch)) return 0;
	}
	return 1;
}

#define MATCH_KEY  0x1
#define MATCH_CERT 0x2
#define MATCH_ALL  0x3

static int parse_bag(PKCS12_SAFEBAG *bag, const char *pass, int passlen,
		      EVP_PKEY **pkey, X509 **cert, STACK **ca,
		      ASN1_OCTET_STRING **keyid,
	     char *keymatch)
{
	PKCS8_PRIV_KEY_INFO *p8;
	X509 *x509;
	ASN1_OCTET_STRING *lkey = NULL;
	ASN1_TYPE *attrib;


	if ((attrib = PKCS12_get_attr (bag, NID_localKeyID)))
		    			    lkey = attrib->value.octet_string;

	/* Check for any local key id matching (if needed) */
	if (lkey && ((*keymatch & MATCH_ALL) != MATCH_ALL)) {
		if (*keyid) {
			if (M_ASN1_OCTET_STRING_cmp(*keyid, lkey)) lkey = NULL;
		} else {
			if (!(*keyid = M_ASN1_OCTET_STRING_dup(lkey))) {
				PKCS12err(PKCS12_F_PARSE_BAGS,ERR_R_MALLOC_FAILURE);
				return 0;
		    }
		}
	}
	
	switch (M_PKCS12_bag_type(bag))
	{
	case NID_keyBag:
		if (!lkey || !pkey) return 1;	
		if (!(*pkey = EVP_PKCS82PKEY(bag->value.keybag))) return 0;
		*keymatch |= MATCH_KEY;
	break;

	case NID_pkcs8ShroudedKeyBag:
		if (!lkey || !pkey) return 1;	
		if (!(p8 = M_PKCS12_decrypt_skey(bag, pass, passlen)))
				return 0;
		*pkey = EVP_PKCS82PKEY(p8);
		PKCS8_PRIV_KEY_INFO_free(p8);
		if (!(*pkey)) return 0;
		*keymatch |= MATCH_KEY;
	break;

	case NID_certBag:
		if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate )
								 return 1;
		if (!(x509 = M_PKCS12_certbag2x509(bag))) return 0;
		if (lkey) {
			*keymatch |= MATCH_CERT;
			if (cert) *cert = x509;
		} else if (ca) sk_push (*ca, (char *)x509);
	break;

	case NID_safeContentsBag:
		return parse_bags(bag->value.safes, pass, passlen,
			 		pkey, cert, ca, keyid, keymatch);
	break;

	default:
		return 1;
	break;
	}
	return 1;
}

