/* evp_pkey.c */
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
#include <stdlib.h>
#include "cryptlib.h"
#include <openssl/x509.h>
#include <openssl/rand.h>

/* Extract a private key from a PKCS8 structure */

EVP_PKEY *EVP_PKCS82PKEY (PKCS8_PRIV_KEY_INFO *p8)
{
	EVP_PKEY *pkey;
#ifndef NO_RSA
	RSA *rsa;
#endif
#ifndef NO_DSA
	DSA *dsa;
	ASN1_INTEGER *dsapriv;
	STACK *ndsa;
	BN_CTX *ctx;
	int plen;
#endif
	X509_ALGOR *a;
	unsigned char *p;
	int pkeylen;
	char obj_tmp[80];

	switch (p8->broken) {
		case PKCS8_OK:
		p = p8->pkey->value.octet_string->data;
		pkeylen = p8->pkey->value.octet_string->length;
		break;

		case PKCS8_NO_OCTET:
		p = p8->pkey->value.sequence->data;
		pkeylen = p8->pkey->value.sequence->length;
		break;

		default:
		EVPerr(EVP_F_EVP_PKCS82PKEY,EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE);
		return NULL;
		break;
	}
	if (!(pkey = EVP_PKEY_new())) {
		EVPerr(EVP_F_EVP_PKCS82PKEY,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	a = p8->pkeyalg;
	switch (OBJ_obj2nid(a->algorithm))
	{
#ifndef NO_RSA
		case NID_rsaEncryption:
		if (!(rsa = d2i_RSAPrivateKey (NULL, &p, pkeylen))) {
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
			return NULL;
		}
		EVP_PKEY_assign_RSA (pkey, rsa);
		break;
#endif
#ifndef NO_DSA
		case NID_dsa:
		/* PKCS#8 DSA is weird: you just get a private key integer
	         * and parameters in the AlgorithmIdentifier the pubkey must
		 * be recalculated.
		 */
	
		/* Check for broken Netscape Database DSA PKCS#8, UGH! */
		if(*p == (V_ASN1_SEQUENCE|V_ASN1_CONSTRUCTED)) {
		    if(!(ndsa = ASN1_seq_unpack(p, pkeylen, 
					(char *(*)())d2i_ASN1_INTEGER,
							 ASN1_STRING_free))) {
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
			return NULL;
		    }
		    if(sk_num(ndsa) != 2 ) {
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
			sk_pop_free(ndsa, ASN1_STRING_free);
			return NULL;
		    }
		    dsapriv = (ASN1_INTEGER *) sk_pop(ndsa);
		    sk_pop_free(ndsa, ASN1_STRING_free);
		} else if (!(dsapriv=d2i_ASN1_INTEGER (NULL, &p, pkeylen))) {
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
			return NULL;
		}
		/* Retrieve parameters */
		if (a->parameter->type != V_ASN1_SEQUENCE) {
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_NO_DSA_PARAMETERS);
			return NULL;
		}
		p = a->parameter->value.sequence->data;
		plen = a->parameter->value.sequence->length;
		if (!(dsa = d2i_DSAparams (NULL, &p, plen))) {
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
			return NULL;
		}
		/* We have parameters now set private key */
		if (!(dsa->priv_key = ASN1_INTEGER_to_BN(dsapriv, NULL))) {
			EVPerr(EVP_F_EVP_PKCS82PKEY,EVP_R_BN_DECODE_ERROR);
			DSA_free (dsa);
			return NULL;
		}
		/* Calculate public key (ouch!) */
		if (!(dsa->pub_key = BN_new())) {
			EVPerr(EVP_F_EVP_PKCS82PKEY,ERR_R_MALLOC_FAILURE);
			DSA_free (dsa);
			return NULL;
		}
		if (!(ctx = BN_CTX_new())) {
			EVPerr(EVP_F_EVP_PKCS82PKEY,ERR_R_MALLOC_FAILURE);
			DSA_free (dsa);
			return NULL;
		}
			
		if (!BN_mod_exp(dsa->pub_key, dsa->g,
						 dsa->priv_key, dsa->p, ctx)) {
			
			EVPerr(EVP_F_EVP_PKCS82PKEY,EVP_R_BN_PUBKEY_ERROR);
			BN_CTX_free (ctx);
			DSA_free (dsa);
			return NULL;
		}

		EVP_PKEY_assign_DSA (pkey, dsa);
		BN_CTX_free (ctx);
		break;
#endif
		default:
		EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
		if (!a->algorithm) strcpy (obj_tmp, "NULL");
		else i2t_ASN1_OBJECT(obj_tmp, 80, a->algorithm);
		ERR_add_error_data(2, "TYPE=", obj_tmp);
		EVP_PKEY_free (pkey);
		return NULL;
	}
	return pkey;
}

/* Turn a private key into a PKCS8 structure */

PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey)
{
	PKCS8_PRIV_KEY_INFO *p8;
#ifndef NO_DSA
	ASN1_INTEGER *dpkey;
	unsigned char *p, *q;
	int len;
#endif
	if (!(p8 = PKCS8_PRIV_KEY_INFO_new())) {	
		EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	ASN1_INTEGER_set (p8->version, 0);
	if (!(p8->pkeyalg->parameter = ASN1_TYPE_new ())) {
		EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
		PKCS8_PRIV_KEY_INFO_free (p8);
		return NULL;
	}
	switch (EVP_PKEY_type(pkey->type)) {
#ifndef NO_RSA
		case EVP_PKEY_RSA:

		p8->pkeyalg->algorithm = OBJ_nid2obj(NID_rsaEncryption);
		p8->pkeyalg->parameter->type = V_ASN1_NULL;
		if (!ASN1_pack_string ((char *)pkey, i2d_PrivateKey,
					 &p8->pkey->value.octet_string)) {
			EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
			PKCS8_PRIV_KEY_INFO_free (p8);
			return NULL;
		}
		break;
#endif
#ifndef NO_DSA
		case EVP_PKEY_DSA:
		p8->pkeyalg->algorithm = OBJ_nid2obj(NID_dsa);

		/* get paramaters and place in AlgorithmIdentifier */
		len = i2d_DSAparams (pkey->pkey.dsa, NULL);
		if (!(p = Malloc(len))) {
			EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
			PKCS8_PRIV_KEY_INFO_free (p8);
			return NULL;
		}
		q = p;
		i2d_DSAparams (pkey->pkey.dsa, &q);
		p8->pkeyalg->parameter->type = V_ASN1_SEQUENCE;
		p8->pkeyalg->parameter->value.sequence = ASN1_STRING_new();
		ASN1_STRING_set(p8->pkeyalg->parameter->value.sequence, p, len);
		Free(p);
		/* Get private key into an integer and pack */
		if (!(dpkey = BN_to_ASN1_INTEGER (pkey->pkey.dsa->priv_key, NULL))) {
			EVPerr(EVP_F_EVP_PKEY2PKCS8,EVP_R_ENCODE_ERROR);
			PKCS8_PRIV_KEY_INFO_free (p8);
			return NULL;
		}
		
		if (!ASN1_pack_string((char *)dpkey, i2d_ASN1_INTEGER,
					 &p8->pkey->value.octet_string)) {
			EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
			ASN1_INTEGER_free (dpkey);
			PKCS8_PRIV_KEY_INFO_free (p8);
			return NULL;
		}
		ASN1_INTEGER_free (dpkey);
		break;
#endif
		default:
		EVPerr(EVP_F_EVP_PKEY2PKCS8, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
		PKCS8_PRIV_KEY_INFO_free (p8);
		return NULL;
	}
	p8->pkey->type = V_ASN1_OCTET_STRING;
	RAND_seed (p8->pkey->value.octet_string->data,
					 p8->pkey->value.octet_string->length);
	return p8;
}

PKCS8_PRIV_KEY_INFO *PKCS8_set_broken(PKCS8_PRIV_KEY_INFO *p8, int broken)
{
	switch (broken) {

		case PKCS8_OK:
		p8->broken = PKCS8_OK;
		return p8;
		break;

		case PKCS8_NO_OCTET:
		p8->broken = PKCS8_NO_OCTET;
		p8->pkey->type = V_ASN1_SEQUENCE;
		return p8;
		break;

		default:
		EVPerr(EVP_F_EVP_PKCS8_SET_BROKEN,EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE);
		return NULL;
		break;
		
	}
}


