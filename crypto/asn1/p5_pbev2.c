/* p5_pbev2.c */
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
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

/* PKCS#5 v2.0 password based encryption structures */

int i2d_PBE2PARAM(PBE2PARAM *a, unsigned char **pp)
{
	M_ASN1_I2D_vars(a);
	M_ASN1_I2D_len (a->keyfunc, i2d_X509_ALGOR);
	M_ASN1_I2D_len (a->encryption, i2d_X509_ALGOR);

	M_ASN1_I2D_seq_total ();

	M_ASN1_I2D_put (a->keyfunc, i2d_X509_ALGOR);
	M_ASN1_I2D_put (a->encryption, i2d_X509_ALGOR);

	M_ASN1_I2D_finish();
}

PBE2PARAM *PBE2PARAM_new(void)
{
	PBE2PARAM *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, PBE2PARAM);
	M_ASN1_New(ret->keyfunc,X509_ALGOR_new);
	M_ASN1_New(ret->encryption,X509_ALGOR_new);
	return (ret);
	M_ASN1_New_Error(ASN1_F_PBE2PARAM_NEW);
}

PBE2PARAM *d2i_PBE2PARAM(PBE2PARAM **a, unsigned char **pp, long length)
{
	M_ASN1_D2I_vars(a,PBE2PARAM *,PBE2PARAM_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get (ret->keyfunc, d2i_X509_ALGOR);
	M_ASN1_D2I_get (ret->encryption, d2i_X509_ALGOR);
	M_ASN1_D2I_Finish(a, PBE2PARAM_free, ASN1_F_D2I_PBE2PARAM);
}

void PBE2PARAM_free (PBE2PARAM *a)
{
	if(a==NULL) return;
	X509_ALGOR_free(a->keyfunc);
	X509_ALGOR_free(a->encryption);
	Free ((char *)a);
}

int i2d_PBKDF2PARAM(PBKDF2PARAM *a, unsigned char **pp)
{
	M_ASN1_I2D_vars(a);
	M_ASN1_I2D_len (a->salt, i2d_ASN1_TYPE);
	M_ASN1_I2D_len (a->iter, i2d_ASN1_INTEGER);
	M_ASN1_I2D_len (a->keylength, i2d_ASN1_INTEGER);
	M_ASN1_I2D_len (a->prf, i2d_X509_ALGOR);

	M_ASN1_I2D_seq_total ();

	M_ASN1_I2D_put (a->salt, i2d_ASN1_TYPE);
	M_ASN1_I2D_put (a->iter, i2d_ASN1_INTEGER);
	M_ASN1_I2D_put (a->keylength, i2d_ASN1_INTEGER);
	M_ASN1_I2D_put (a->prf, i2d_X509_ALGOR);

	M_ASN1_I2D_finish();
}

PBKDF2PARAM *PBKDF2PARAM_new(void)
{
	PBKDF2PARAM *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, PBKDF2PARAM);
	M_ASN1_New(ret->salt, ASN1_TYPE_new);
	M_ASN1_New(ret->iter, ASN1_INTEGER_new);
	ret->keylength = NULL;
	ret->prf = NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_PBKDF2PARAM_NEW);
}

PBKDF2PARAM *d2i_PBKDF2PARAM(PBKDF2PARAM **a, unsigned char **pp,
	     long length)
{
	M_ASN1_D2I_vars(a,PBKDF2PARAM *,PBKDF2PARAM_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get (ret->salt, d2i_ASN1_TYPE);
	M_ASN1_D2I_get (ret->iter, d2i_ASN1_INTEGER);
	M_ASN1_D2I_get_opt (ret->keylength, d2i_ASN1_INTEGER, V_ASN1_INTEGER);
	M_ASN1_D2I_get_opt (ret->prf, d2i_X509_ALGOR, V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a, PBKDF2PARAM_free, ASN1_F_D2I_PBKDF2PARAM);
}

void PBKDF2PARAM_free (PBKDF2PARAM *a)
{
	if(a==NULL) return;
	ASN1_TYPE_free(a->salt);
	ASN1_INTEGER_free(a->iter);
	ASN1_INTEGER_free(a->keylength);
	X509_ALGOR_free(a->prf);
	Free ((char *)a);
}

/* Return an algorithm identifier for a PKCS#5 v2.0 PBE algorithm:
 * yes I know this is horrible!
 */

X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
				 unsigned char *salt, int saltlen)
{
	X509_ALGOR *scheme = NULL, *kalg = NULL, *ret = NULL;
	int alg_nid;
	EVP_CIPHER_CTX ctx;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	PBKDF2PARAM *kdf = NULL;
	PBE2PARAM *pbe2 = NULL;
	ASN1_OCTET_STRING *osalt = NULL;

	if(!(pbe2 = PBE2PARAM_new())) goto merr;

	/* Setup the AlgorithmIdentifier for the encryption scheme */
	scheme = pbe2->encryption;

	alg_nid = EVP_CIPHER_type(cipher);

	scheme->algorithm = OBJ_nid2obj(alg_nid);
	if(!(scheme->parameter = ASN1_TYPE_new())) goto merr;

	/* Create random IV */
	RAND_bytes(iv, EVP_CIPHER_iv_length(cipher));

	/* Dummy cipherinit to just setup the IV */
	EVP_CipherInit(&ctx, cipher, NULL, iv, 0);
	if(EVP_CIPHER_param_to_asn1(&ctx, scheme->parameter) < 0) {
		ASN1err(ASN1_F_PKCS5_PBE2_SET,
					ASN1_R_ERROR_SETTING_CIPHER_PARAMS);
		goto err;
	}
	EVP_CIPHER_CTX_cleanup(&ctx);

	if(!(kdf = PBKDF2PARAM_new())) goto merr;
	if(!(osalt = ASN1_OCTET_STRING_new())) goto merr;

	if (!saltlen) saltlen = PKCS5_SALT_LEN;
	if (!(osalt->data = Malloc (saltlen))) goto merr;
	osalt->length = saltlen;
	if (salt) memcpy (osalt->data, salt, saltlen);
	else RAND_bytes (osalt->data, saltlen);

	if(iter <= 0) iter = PKCS5_DEFAULT_ITER;
	if(!ASN1_INTEGER_set(kdf->iter, iter)) goto merr;

	/* Now include salt in kdf structure */
	kdf->salt->value.octet_string = osalt;
	kdf->salt->type = V_ASN1_OCTET_STRING;
	osalt = NULL;

	/* If its RC2 then we'd better setup the key length */

	if(alg_nid == NID_rc2_cbc) {
		if(!(kdf->keylength = ASN1_INTEGER_new())) goto merr;
		if(!ASN1_INTEGER_set (kdf->keylength,
				 EVP_CIPHER_key_length(cipher))) goto merr;
	}

	/* prf can stay NULL because we are using hmacWithSHA1 */

	/* Now setup the PBE2PARAM keyfunc structure */

	pbe2->keyfunc->algorithm = OBJ_nid2obj(NID_id_pbkdf2);

	/* Encode PBKDF2PARAM into parameter of pbe2 */

	if(!(pbe2->keyfunc->parameter = ASN1_TYPE_new())) goto merr;

	if(!ASN1_pack_string(kdf, i2d_PBKDF2PARAM,
			 &pbe2->keyfunc->parameter->value.sequence)) goto merr;
	pbe2->keyfunc->parameter->type = V_ASN1_SEQUENCE;

	PBKDF2PARAM_free(kdf);
	kdf = NULL;

	/* Now set up top level AlgorithmIdentifier */

	if(!(ret = X509_ALGOR_new())) goto merr;
	if(!(ret->parameter = ASN1_TYPE_new())) goto merr;

	ret->algorithm = OBJ_nid2obj(NID_pbes2);

	/* Encode PBE2PARAM into parameter */

	if(!ASN1_pack_string(pbe2, i2d_PBE2PARAM,
				 &ret->parameter->value.sequence)) goto merr;
	ret->parameter->type = V_ASN1_SEQUENCE;

	PBE2PARAM_free(pbe2);
	pbe2 = NULL;

	return ret;

	merr:
	ASN1err(ASN1_F_PKCS5_PBE2_SET,ERR_R_MALLOC_FAILURE);

	err:
	PBE2PARAM_free(pbe2);
	/* Note 'scheme' is freed as part of pbe2 */
	ASN1_OCTET_STRING_free(osalt);
	PBKDF2PARAM_free(kdf);
	X509_ALGOR_free(kalg);
	X509_ALGOR_free(ret);

	return NULL;

}
