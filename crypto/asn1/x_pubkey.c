/* crypto/asn1/x_pubkey.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "cryptlib.h"
#include "asn1_mac.h"

/*
 * ASN1err(ASN1_F_D2I_X509_PUBKEY,ASN1_R_LENGTH_MISMATCH);
 * ASN1err(ASN1_F_X509_PUBKEY_NEW,ASN1_R_LENGTH_MISMATCH);
 */

int i2d_X509_PUBKEY(a,pp)
X509_PUBKEY *a;
unsigned char **pp;
	{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->algor,	i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->public_key,	i2d_ASN1_BIT_STRING);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(a->algor,	i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->public_key,	i2d_ASN1_BIT_STRING);

	M_ASN1_I2D_finish();
	}

X509_PUBKEY *d2i_X509_PUBKEY(a,pp,length)
X509_PUBKEY **a;
unsigned char **pp;
long length;
	{
	M_ASN1_D2I_vars(a,X509_PUBKEY *,X509_PUBKEY_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->algor,d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->public_key,d2i_ASN1_BIT_STRING);
	if (ret->pkey != NULL)
		{
		EVP_PKEY_free(ret->pkey);
		ret->pkey=NULL;
		}
	M_ASN1_D2I_Finish(a,X509_PUBKEY_free,ASN1_F_D2I_X509_PUBKEY);
	}

X509_PUBKEY *X509_PUBKEY_new()
	{
	X509_PUBKEY *ret=NULL;

	M_ASN1_New_Malloc(ret,X509_PUBKEY);
	M_ASN1_New(ret->algor,X509_ALGOR_new);
	M_ASN1_New(ret->public_key,ASN1_BIT_STRING_new);
	ret->pkey=NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_X509_PUBKEY_NEW);
	}

void X509_PUBKEY_free(a)
X509_PUBKEY *a;
	{
	if (a == NULL) return;
	X509_ALGOR_free(a->algor);
	ASN1_BIT_STRING_free(a->public_key);
	if (a->pkey != NULL) EVP_PKEY_free(a->pkey);
	Free((char *)a);
	}

int X509_PUBKEY_set(x,pkey)
X509_PUBKEY **x;
EVP_PKEY *pkey;
	{
	int ok=0;
	X509_PUBKEY *pk;
	X509_ALGOR *a;
	ASN1_OBJECT *o;
	unsigned char *s,*p;
	int i;

	if (x == NULL) return(0);

	if ((pk=X509_PUBKEY_new()) == NULL) goto err;
	a=pk->algor;

	/* set the algorithm id */
	if ((o=OBJ_nid2obj(pkey->type)) == NULL) goto err;
	ASN1_OBJECT_free(a->algorithm);
	a->algorithm=o;

	/* Set the parameter list */
	if (!pkey->save_parameters || (pkey->type == EVP_PKEY_RSA))
		{
		if ((a->parameter == NULL) ||
			(a->parameter->type != V_ASN1_NULL))
			{
			ASN1_TYPE_free(a->parameter);
			a->parameter=ASN1_TYPE_new();
			a->parameter->type=V_ASN1_NULL;
			}
		}
	else
#ifndef NO_DSA
		if (pkey->type == EVP_PKEY_DSA)
		{
		unsigned char *pp;
		DSA *dsa;

		dsa=pkey->pkey.dsa;
		dsa->write_params=0;
		ASN1_TYPE_free(a->parameter);
		i=i2d_DSAparams(dsa,NULL);
		p=(unsigned char *)Malloc(i);
		pp=p;
		i2d_DSAparams(dsa,&pp);
		a->parameter=ASN1_TYPE_new();
		a->parameter->type=V_ASN1_SEQUENCE;
		a->parameter->value.sequence=ASN1_STRING_new();
		ASN1_STRING_set(a->parameter->value.sequence,p,i);
		Free(p);
		}
	else
#endif
		{
		X509err(X509_F_X509_PUBKEY_SET,X509_R_UNSUPPORTED_ALGORITHM);
		goto err;
		}

	i=i2d_PublicKey(pkey,NULL);
	if ((s=(unsigned char *)Malloc(i+1)) == NULL) goto err;
	p=s;
	i2d_PublicKey(pkey,&p);
	if (!ASN1_BIT_STRING_set(pk->public_key,s,i)) goto err;
	Free(s);

	CRYPTO_add(&pkey->references,1,CRYPTO_LOCK_EVP_PKEY);
	pk->pkey=pkey;

	if (*x != NULL)
		X509_PUBKEY_free(*x);

	*x=pk;
	pk=NULL;

	ok=1;
err:
	if (pk != NULL) X509_PUBKEY_free(pk);
	return(ok);
	}

EVP_PKEY *X509_PUBKEY_get(key)
X509_PUBKEY *key;
	{
	EVP_PKEY *ret=NULL;
	long j;
	int type;
	unsigned char *p;
#ifndef NO_DSA
	X509_ALGOR *a;
#endif

	if (key == NULL) goto err;

	if (key->pkey != NULL) return(key->pkey);

	if (key->public_key == NULL) goto err;

	type=OBJ_obj2nid(key->algor->algorithm);
	p=key->public_key->data;
        j=key->public_key->length;
        if ((ret=d2i_PublicKey(type,NULL,&p,(long)j)) == NULL)
		{
		X509err(X509_F_X509_PUBKEY_GET,X509_R_ERR_ASN1_LIB);
		goto err;
		}
	ret->save_parameters=0;

#ifndef NO_DSA
	a=key->algor;
	if (ret->type == EVP_PKEY_DSA)
		{
		if (a->parameter->type == V_ASN1_SEQUENCE)
			{
			ret->pkey.dsa->write_params=0;
			p=a->parameter->value.sequence->data;
			j=a->parameter->value.sequence->length;
			if (!d2i_DSAparams(&ret->pkey.dsa,&p,(long)j))
				goto err;
			}
		ret->save_parameters=1;
		}
#endif
	key->pkey=ret;
	return(ret);
err:
	if (ret != NULL)
		EVP_PKEY_free(ret);
	return(NULL);
	}

