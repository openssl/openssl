/* evp_pbe.c */
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
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "cryptlib.h"

/* Password based encryption (PBE) functions */

static STACK *pbe_algs;

/* Setup a cipher context from a PBE algorithm */

typedef struct {
int pbe_nid;
EVP_CIPHER *cipher;
EVP_MD *md;
EVP_PBE_KEYGEN *keygen;
} EVP_PBE_CTL;

int EVP_PBE_CipherInit (ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
	     unsigned char *salt, int saltlen, int iter, EVP_CIPHER_CTX *ctx,
	     int en_de)
{

	EVP_PBE_CTL *pbetmp, pbelu;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	int i;
	pbelu.pbe_nid = OBJ_obj2nid(pbe_obj);
	if (pbelu.pbe_nid != NID_undef) i = sk_find(pbe_algs, (char *)&pbelu);
	else i = -1;

	if (i == -1) {
		char obj_tmp[80];
		EVPerr(EVP_F_EVP_PBE_CIPHERINIT,EVP_R_UNKNOWN_PBE_ALGORITHM);
		if (!pbe_obj) strcpy (obj_tmp, "NULL");
		else i2t_ASN1_OBJECT(obj_tmp, 80, pbe_obj);
		ERR_add_error_data(2, "TYPE=", obj_tmp);
		return 0;
	}
	if (passlen == -1) passlen = strlen(pass);
	pbetmp = (EVP_PBE_CTL *)sk_value (pbe_algs, i);
	i = (*pbetmp->keygen)(pass, passlen, salt, saltlen, iter,
					 pbetmp->cipher, pbetmp->md, key, iv);
	if (!i) {
		EVPerr(EVP_F_EVP_PBE_CIPHERINIT,EVP_R_KEYGEN_FAILURE);
		return 0;
	}
	EVP_CipherInit (ctx, pbetmp->cipher, key, iv, en_de);
	return 1;	
}

/* Setup a PBE algorithm but take most parameters from AlgorithmIdentifier */

int EVP_PBE_ALGOR_CipherInit (X509_ALGOR *algor, const char *pass,
			      int passlen, EVP_CIPHER_CTX *ctx, int en_de)
{
	PBEPARAM *pbe;
	int saltlen, iter;
	unsigned char *salt, *pbuf;

	/* Extract useful info from algor */
	pbuf = algor->parameter->value.sequence->data;
	if (!(pbe = d2i_PBEPARAM (NULL, &pbuf,
			 algor->parameter->value.sequence->length))) {
		EVPerr(EVP_F_EVP_PBE_ALGOR_CIPHERINIT,EVP_R_DECODE_ERROR);
		return 0;
	}

	if (!pbe->iter) iter = 1;
	else iter = ASN1_INTEGER_get (pbe->iter);
	salt = pbe->salt->data;
	saltlen = pbe->salt->length;

	if (!(EVP_PBE_CipherInit (algor->algorithm, pass, passlen, salt,
 						saltlen, iter, ctx, en_de))) {
		EVPerr(EVP_F_EVP_PBE_ALGOR_CIPHERINIT,EVP_R_EVP_PBE_CIPHERINIT_ERROR);
		PBEPARAM_free(pbe);
		return 0;
	}
	PBEPARAM_free(pbe);
	return 1;
}


static int pbe_cmp (EVP_PBE_CTL **pbe1, EVP_PBE_CTL **pbe2)
{
	return ((*pbe1)->pbe_nid - (*pbe2)->pbe_nid);
}

/* Add a PBE algorithm */

int EVP_PBE_alg_add (int nid, EVP_CIPHER *cipher, EVP_MD *md,
	     EVP_PBE_KEYGEN *keygen)
{
	EVP_PBE_CTL *pbe_tmp;
	if (!pbe_algs) pbe_algs = sk_new (pbe_cmp);
	if (!(pbe_tmp = (EVP_PBE_CTL*) Malloc (sizeof(EVP_PBE_CTL)))) {
		EVPerr(EVP_F_EVP_PBE_ALG_ADD,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	pbe_tmp->pbe_nid = nid;
	pbe_tmp->cipher = cipher;
	pbe_tmp->md = md;
	pbe_tmp->keygen = keygen;
	sk_push (pbe_algs, (char *)pbe_tmp);
	return 1;
}

void EVP_PBE_cleanup(void)
{
	sk_pop_free(pbe_algs, FreeFunc);
	pbe_algs = NULL;
}
