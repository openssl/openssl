/* p12_add.c */
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

/* Pack an object into an OCTET STRING and turn into a safebag */

PKCS12_SAFEBAG *PKCS12_pack_safebag (char *obj, int (*i2d)(), int nid1,
	     int nid2)
{
	PKCS12_BAGS *bag;
	PKCS12_SAFEBAG *safebag;
	if (!(bag = PKCS12_BAGS_new ())) {
		PKCS12err(PKCS12_F_PKCS12_PACK_SAFEBAG, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	bag->type = OBJ_nid2obj(nid1);
	if (!ASN1_pack_string(obj, i2d, &bag->value.octet)) {
		PKCS12err(PKCS12_F_PKCS12_PACK_SAFEBAG, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	if (!(safebag = PKCS12_SAFEBAG_new ())) {
		PKCS12err(PKCS12_F_PKCS12_PACK_SAFEBAG, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	safebag->value.bag = bag;
	safebag->type = OBJ_nid2obj(nid2);
	return safebag;
}

/* Turn PKCS8 object into a keybag */

PKCS12_SAFEBAG *PKCS12_MAKE_KEYBAG (PKCS8_PRIV_KEY_INFO *p8)
{
	PKCS12_SAFEBAG *bag;
	if (!(bag = PKCS12_SAFEBAG_new())) {
		PKCS12err(PKCS12_F_PKCS12_MAKE_KEYBAG,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	bag->type = OBJ_nid2obj(NID_keyBag);
	bag->value.keybag = p8;
	return bag;
}

/* Turn PKCS8 object into a shrouded keybag */

PKCS12_SAFEBAG *PKCS12_MAKE_SHKEYBAG (int pbe_nid, const char *pass,
	     int passlen, unsigned char *salt, int saltlen, int iter,
	     PKCS8_PRIV_KEY_INFO *p8)
{
	PKCS12_SAFEBAG *bag;

	/* Set up the safe bag */
	if (!(bag = PKCS12_SAFEBAG_new ())) {
		PKCS12err(PKCS12_F_PKCS12_MAKE_SHKEYBAG, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	bag->type = OBJ_nid2obj(NID_pkcs8ShroudedKeyBag);
	if (!(bag->value.shkeybag = 
	  PKCS8_encrypt(pbe_nid, NULL, pass, passlen, salt, saltlen, iter,
									 p8))) {
		PKCS12err(PKCS12_F_PKCS12_MAKE_SHKEYBAG, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	return bag;
}

/* Turn a stack of SAFEBAGS into a PKCS#7 data Contentinfo */
PKCS7 *PKCS12_pack_p7data (STACK *sk)
{
	PKCS7 *p7;
	if (!(p7 = PKCS7_new())) {
		PKCS12err(PKCS12_F_PKCS12_PACK_P7DATA, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	p7->type = OBJ_nid2obj(NID_pkcs7_data);
	if (!(p7->d.data = M_ASN1_OCTET_STRING_new())) {
		PKCS12err(PKCS12_F_PKCS12_PACK_P7DATA, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	
	if (!ASN1_seq_pack(sk, i2d_PKCS12_SAFEBAG, &p7->d.data->data,
					&p7->d.data->length)) {
		PKCS12err(PKCS12_F_PKCS12_PACK_P7DATA, PKCS12_R_CANT_PACK_STRUCTURE);
		return NULL;
	}
	return p7;
}

/* Turn a stack of SAFEBAGS into a PKCS#7 encrypted data ContentInfo */

PKCS7 *PKCS12_pack_p7encdata (int pbe_nid, const char *pass, int passlen,
	     unsigned char *salt, int saltlen, int iter, STACK *bags)
{
	PKCS7 *p7;
	X509_ALGOR *pbe;
	if (!(p7 = PKCS7_new())) {
		PKCS12err(PKCS12_F_PKCS12_PACK_P7ENCDATA, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	if(!PKCS7_set_type(p7, NID_pkcs7_encrypted)) {
		PKCS12err(PKCS12_F_PKCS12_PACK_P7ENCDATA,
				PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE);
		return NULL;
	}
	if (!(pbe = PKCS5_pbe_set (pbe_nid, iter, salt, saltlen))) {
		PKCS12err(PKCS12_F_PKCS12_PACK_P7ENCDATA, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	X509_ALGOR_free(p7->d.encrypted->enc_data->algorithm);
	p7->d.encrypted->enc_data->algorithm = pbe;
	M_ASN1_OCTET_STRING_free(p7->d.encrypted->enc_data->enc_data);
	if (!(p7->d.encrypted->enc_data->enc_data =
	PKCS12_i2d_encrypt (pbe, i2d_PKCS12_SAFEBAG, pass, passlen,
				 (char *)bags, 1))) {
		PKCS12err(PKCS12_F_PKCS12_PACK_P7ENCDATA, PKCS12_R_ENCRYPT_ERROR);
		return NULL;
	}

	return p7;
}

X509_SIG *PKCS8_encrypt(int pbe_nid, const EVP_CIPHER *cipher,
			 const char *pass, int passlen,
			 unsigned char *salt, int saltlen, int iter,
						PKCS8_PRIV_KEY_INFO *p8inf)
{
	X509_SIG *p8;
	X509_ALGOR *pbe;

	if (!(p8 = X509_SIG_new())) {
		PKCS12err(PKCS12_F_PKCS8_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if(pbe_nid == -1) pbe = PKCS5_pbe2_set(cipher, iter, salt, saltlen);
	else pbe = PKCS5_pbe_set(pbe_nid, iter, salt, saltlen);
	if(!pbe) {
		PKCS12err(PKCS12_F_PKCS8_ENCRYPT, ERR_R_ASN1_LIB);
		goto err;
	}
	X509_ALGOR_free(p8->algor);
	p8->algor = pbe;
	M_ASN1_OCTET_STRING_free(p8->digest);
	if (!(p8->digest = 
	PKCS12_i2d_encrypt (pbe, i2d_PKCS8_PRIV_KEY_INFO, pass, passlen,
						 (char *)p8inf, 0))) {
		PKCS12err(PKCS12_F_PKCS8_ENCRYPT, PKCS12_R_ENCRYPT_ERROR);
		goto err;
	}

	return p8;

	err:
	X509_SIG_free(p8);
	return NULL;
}
