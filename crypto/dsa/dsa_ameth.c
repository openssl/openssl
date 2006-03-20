/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/dsa.h>

static int dsa_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
	{
	const unsigned char *p, *pm;
	int pklen, pmlen;
	int ptype;
	void *pval;
	ASN1_STRING *pstr;
	X509_ALGOR *palg;
	ASN1_INTEGER *public_key = NULL;

	DSA *dsa = NULL;

	if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
		return 0;
	X509_ALGOR_get0(NULL, &ptype, &pval, palg);

	if (ptype != V_ASN1_SEQUENCE)
		{
		DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_PARAMETER_ENCODING_ERROR);
		goto err;
		}

	pstr = pval;	
	pm = pstr->data;
	pmlen = pstr->length;

	if (!(dsa = d2i_DSAparams(NULL, &pm, pmlen)))
		{
		DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_DECODE_ERROR);
		goto err;
		}

	if (!(public_key=d2i_ASN1_INTEGER(NULL, &p, pklen)))
		{
		DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_DECODE_ERROR);
		goto err;
		}

	/* We have parameters now set public key */
	if (!(dsa->pub_key = ASN1_INTEGER_to_BN(public_key, NULL)))
		{
		DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_BN_DECODE_ERROR);
		goto err;
		}

	ASN1_INTEGER_free(public_key);

	return 1;

	err:
	if (pubkey)
		ASN1_INTEGER_free(public_key);
	if (dsa)
		DSA_free(dsa);
	return 0;

	}

static int dsa_pub_encode(X509_PUBKEY *pk, EVP_PKEY *pkey)
	{
	DSA *dsa;
	void *pval;
	int ptype;
	unsigned char *penc = NULL;
	int penclen;

	dsa=pkey->pkey.dsa;
	if (pkey->save_parameters)
		{
		ASN1_STRING *str;
		str = ASN1_STRING_new();
		str->length = i2d_DSAparams(dsa, &str->data);
		if (str->length <= 0)
			{
			DSAerr(DSA_F_DSA_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
			goto err;
			}
		ptype = V_ASN1_SEQUENCE;
		}
	else
		{
		ptype = V_ASN1_UNDEF;
		pval = NULL;
		}
	dsa->write_params=0;

	penclen = i2d_DSAPublicKey(dsa, &penc);

	if (penclen <= 0)
		{
		DSAerr(DSA_F_DSA_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_DSA),
				ptype, pval, penc, penclen))
		return 1;

	err:
	if (penc)
		OPENSSL_free(penc);
	if (pval)
		ASN1_STRING_free(pval);

	return 0;
	}

/* In PKCS#8 DSA: you just get a private key integer and parameters in the
 * AlgorithmIdentifier the pubkey must be recalculated.
 */
	
static int dsa_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
	{
	const unsigned char *p, *pm;
	int pklen, pmlen;
	int ptype;
	void *pval;
	ASN1_STRING *pstr;
	X509_ALGOR *palg;
	ASN1_INTEGER *privkey = NULL;
	BN_CTX *ctx = NULL;

	STACK_OF(ASN1_TYPE) *ndsa = NULL;
	DSA *dsa = NULL;

	if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
		return 0;
	X509_ALGOR_get0(NULL, &ptype, &pval, palg);

	/* Check for broken DSA PKCS#8, UGH! */
	if (*p == (V_ASN1_SEQUENCE|V_ASN1_CONSTRUCTED))
		{
		ASN1_TYPE *t1, *t2;
	    	if(!(ndsa = ASN1_seq_unpack_ASN1_TYPE(p, pklen, 
							  d2i_ASN1_TYPE,
							  ASN1_TYPE_free)))
			goto decerr;
		if (sk_ASN1_TYPE_num(ndsa) != 2)
			goto decerr;
		/* Handle Two broken types:
	    	 * SEQUENCE {parameters, priv_key}
		 * SEQUENCE {pub_key, priv_key}
		 */

		t1 = sk_ASN1_TYPE_value(ndsa, 0);
		t2 = sk_ASN1_TYPE_value(ndsa, 1);
		if (t1->type == V_ASN1_SEQUENCE)
			{
			p8->broken = PKCS8_EMBEDDED_PARAM;
			pval = t1->value.ptr;
			}
		else if (ptype == V_ASN1_SEQUENCE)
			p8->broken = PKCS8_NS_DB;
		else
			goto decerr;

		if (t2->type != V_ASN1_INTEGER)
			goto decerr;

		privkey = t2->value.integer;
		}
	else
		{
		if (!(privkey=d2i_ASN1_INTEGER(NULL, &p, pklen)))
			goto decerr;
		if (ptype != V_ASN1_SEQUENCE)
			goto decerr;
		}

	pstr = pval;	
	pm = pstr->data;
	pmlen = pstr->length;
	if (!(dsa = d2i_DSAparams(NULL, &pm, pmlen)))
		goto decerr;
	/* We have parameters now set private key */
	if (!(dsa->priv_key = ASN1_INTEGER_to_BN(privkey, NULL)))
		{
		DSAerr(DSA_F_DSA_PRIV_DECODE,DSA_R_BN_ERROR);
		goto dsaerr;
		}
	/* Calculate public key */
	if (!(dsa->pub_key = BN_new()))
		{
		DSAerr(DSA_F_DSA_PRIV_DECODE, ERR_R_MALLOC_FAILURE);
		goto dsaerr;
		}
	if (!(ctx = BN_CTX_new()))
		{
		DSAerr(DSA_F_DSA_PRIV_DECODE, ERR_R_MALLOC_FAILURE);
		goto dsaerr;
		}
			
	if (!BN_mod_exp(dsa->pub_key, dsa->g, dsa->priv_key, dsa->p, ctx))
		{
		DSAerr(DSA_F_DSA_PRIV_DECODE,DSA_R_BN_ERROR);
		goto dsaerr;
		}

	EVP_PKEY_assign_DSA(pkey, dsa);
	BN_CTX_free (ctx);
	if(ndsa)
		sk_ASN1_TYPE_pop_free(ndsa, ASN1_TYPE_free);
	else
		ASN1_INTEGER_free(privkey);

	return 1;

	decerr:
	DSAerr(DSA_F_DSA_PRIV_DECODE, EVP_R_DECODE_ERROR);
	dsaerr:
	BN_CTX_free (ctx);
	sk_ASN1_TYPE_pop_free(ndsa, ASN1_TYPE_free);
	DSA_free(dsa);
	EVP_PKEY_free(pkey);
	return 0;
	}

static int dsa_priv_encode(PKCS8_PRIV_KEY_INFO *p8, EVP_PKEY *pkey)
{
	ASN1_STRING *params = NULL;
	ASN1_INTEGER *prkey = NULL;
	unsigned char *dp = NULL;
	int dplen;

	params = ASN1_STRING_new();

	if (!params)
		{
		DSAerr(DSA_F_DSA_PRIV_ENCODE,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	params->length = i2d_DSAparams(pkey->pkey.dsa, &params->data);
	if (params->length <= 0)
		{
		DSAerr(DSA_F_DSA_PRIV_ENCODE,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	params->type = V_ASN1_SEQUENCE;

	/* Get private key into integer */
	prkey = BN_to_ASN1_INTEGER(pkey->pkey.dsa->priv_key, NULL);

	if (!prkey)
		{
		DSAerr(DSA_F_DSA_PRIV_ENCODE,DSA_R_BN_ERROR);
		goto err;
		}

	dplen = i2d_ASN1_INTEGER(prkey, &dp);

	ASN1_INTEGER_free(prkey);

	if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_dsa), 0,
				V_ASN1_SEQUENCE, params, dp, dplen))
		goto err;

	return 1;

err:
	if (dp != NULL)
		OPENSSL_free(dp);
	if (params != NULL)
		ASN1_STRING_free(params);
	if (prkey != NULL)
		ASN1_INTEGER_free(prkey);
	return 0;
}

/* NB these are sorted in pkey_id order, lowest first */

const EVP_PKEY_ASN1_METHOD dsa_asn1_meths[] = 
	{

		{
		EVP_PKEY_DSA2,
		EVP_PKEY_DSA,
		ASN1_PKEY_ALIAS
		},

		{
		EVP_PKEY_DSA1,
		EVP_PKEY_DSA,
		ASN1_PKEY_ALIAS
		},

		{
		EVP_PKEY_DSA4,
		EVP_PKEY_DSA,
		ASN1_PKEY_ALIAS
		},

		{
		EVP_PKEY_DSA3,
		EVP_PKEY_DSA,
		ASN1_PKEY_ALIAS
		},

		{
		EVP_PKEY_DSA,
		EVP_PKEY_DSA,
		0,
		dsa_pub_decode,
		dsa_pub_encode,
		0,
		dsa_priv_decode,
		dsa_priv_encode,
		0,
		0,
		0
		}
	};

