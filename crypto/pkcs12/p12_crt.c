/* p12_crt.c */
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

PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert,
	     STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter, int mac_iter,
	     int keytype)
{
	PKCS12 *p12;
	STACK *bags, *safes;
	PKCS12_SAFEBAG *bag;
	PKCS8_PRIV_KEY_INFO *p8;
	PKCS7 *authsafe;
	X509 *tcert;
	int i;
	unsigned char keyid[EVP_MAX_MD_SIZE];
	unsigned int keyidlen;

	/* Set defaults */
	if(!nid_cert) nid_cert = NID_pbe_WithSHA1And40BitRC2_CBC;
	if(!nid_key) nid_key = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
	if(!iter) iter = PKCS12_DEFAULT_ITER;
	if(!mac_iter) mac_iter = 1;

	if(!pkey || !cert) {
		PKCS12err(PKCS12_F_PKCS12_CREATE,PKCS12_R_INVALID_NULL_ARGUMENT);
		return NULL;
	}

	if(!(bags = sk_new (NULL))) {
		PKCS12err(PKCS12_F_PKCS12_CREATE,ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	/* Add user certificate */
	if(!(bag = M_PKCS12_x5092certbag(cert))) return NULL;
	if(name && !PKCS12_add_friendlyname(bag, name, -1)) return NULL;
	X509_digest(cert, EVP_sha1(), keyid, &keyidlen);
	if(!PKCS12_add_localkeyid(bag, keyid, keyidlen)) return NULL;

	if(!sk_push(bags, (char *)bag)) {
		PKCS12err(PKCS12_F_PKCS12_CREATE,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	
	/* Add all other certificates */
	if(ca) {
		for(i = 0; i < sk_X509_num(ca); i++) {
			tcert = sk_X509_value(ca, i);
			if(!(bag = M_PKCS12_x5092certbag(tcert))) return NULL;
			if(!sk_push(bags, (char *)bag)) {
				PKCS12err(PKCS12_F_PKCS12_CREATE,ERR_R_MALLOC_FAILURE);
				return NULL;
			}
		}
	}

	/* Turn certbags into encrypted authsafe */
	authsafe = PKCS12_pack_p7encdata (nid_cert, pass, -1, NULL, 0,
					  iter, bags);
	sk_pop_free(bags, PKCS12_SAFEBAG_free);

	if (!authsafe) return NULL;

	if(!(safes = sk_new (NULL)) || !sk_push(safes, (char *)authsafe)) {
		PKCS12err(PKCS12_F_PKCS12_CREATE,ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	/* Make a shrouded key bag */
	if(!(p8 = EVP_PKEY2PKCS8 (pkey))) return NULL;
	if(keytype && !PKCS8_add_keyusage(p8, keytype)) return NULL;
	bag = PKCS12_MAKE_SHKEYBAG (nid_key, pass, -1, NULL, 0, iter, p8);
	if(!bag) return NULL;
	PKCS8_PRIV_KEY_INFO_free(p8);
        if (name && !PKCS12_add_friendlyname (bag, name, -1)) return NULL;
	if(!PKCS12_add_localkeyid (bag, keyid, keyidlen)) return NULL;
	if(!(bags = sk_new(NULL)) || !sk_push (bags, (char *)bag)) {
		PKCS12err(PKCS12_F_PKCS12_CREATE,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	/* Turn it into unencrypted safe bag */
	if(!(authsafe = PKCS12_pack_p7data (bags))) return NULL;
	sk_pop_free(bags, PKCS12_SAFEBAG_free);
	if(!sk_push(safes, (char *)authsafe)) {
		PKCS12err(PKCS12_F_PKCS12_CREATE,ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if(!(p12 = PKCS12_init (NID_pkcs7_data))) return NULL;

	if(!M_PKCS12_pack_authsafes (p12, safes)) return NULL;

	sk_pop_free(safes, PKCS7_free);

	if(!PKCS12_set_mac (p12, pass, -1, NULL, 0, mac_iter, NULL))
	    return NULL;

	return p12;

}
