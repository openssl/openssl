/* crypto/asn1/x_crl.c */
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
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>

static int X509_REVOKED_cmp(const X509_REVOKED * const *a,
				const X509_REVOKED * const *b);
static int X509_REVOKED_seq_cmp(const X509_REVOKED * const *a,
				const X509_REVOKED * const *b);
int i2d_X509_REVOKED(X509_REVOKED *a, unsigned char **pp)
	{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->serialNumber,i2d_ASN1_INTEGER);
	M_ASN1_I2D_len(a->revocationDate,i2d_ASN1_TIME);
	M_ASN1_I2D_len_SEQUENCE_opt_type(X509_EXTENSION,a->extensions,
					 i2d_X509_EXTENSION);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(a->serialNumber,i2d_ASN1_INTEGER);
	M_ASN1_I2D_put(a->revocationDate,i2d_ASN1_TIME);
	M_ASN1_I2D_put_SEQUENCE_opt_type(X509_EXTENSION,a->extensions,
					 i2d_X509_EXTENSION);

	M_ASN1_I2D_finish();
	}

X509_REVOKED *d2i_X509_REVOKED(X509_REVOKED **a, unsigned char **pp,
	     long length)
	{
	M_ASN1_D2I_vars(a,X509_REVOKED *,X509_REVOKED_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->serialNumber,d2i_ASN1_INTEGER);
	M_ASN1_D2I_get(ret->revocationDate,d2i_ASN1_TIME);
	M_ASN1_D2I_get_seq_opt_type(X509_EXTENSION,ret->extensions,
				    d2i_X509_EXTENSION,X509_EXTENSION_free);
	M_ASN1_D2I_Finish(a,X509_REVOKED_free,ASN1_F_D2I_X509_REVOKED);
	}

int i2d_X509_CRL_INFO(X509_CRL_INFO *a, unsigned char **pp)
	{
	int v1=0;
	long l=0;
	int (*old_cmp)(const X509_REVOKED * const *,
			const X509_REVOKED * const *);
	M_ASN1_I2D_vars(a);
	
	old_cmp=sk_X509_REVOKED_set_cmp_func(a->revoked,X509_REVOKED_seq_cmp);
	sk_X509_REVOKED_sort(a->revoked);
	sk_X509_REVOKED_set_cmp_func(a->revoked,old_cmp);

	if ((a->version != NULL) && ((l=ASN1_INTEGER_get(a->version)) != 0))
		{
		M_ASN1_I2D_len(a->version,i2d_ASN1_INTEGER);
		}
	M_ASN1_I2D_len(a->sig_alg,i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->issuer,i2d_X509_NAME);
	M_ASN1_I2D_len(a->lastUpdate,i2d_ASN1_TIME);
	if (a->nextUpdate != NULL)
		{ M_ASN1_I2D_len(a->nextUpdate,i2d_ASN1_TIME); }
	M_ASN1_I2D_len_SEQUENCE_opt_type(X509_REVOKED,a->revoked,
					 i2d_X509_REVOKED);
	M_ASN1_I2D_len_EXP_SEQUENCE_opt_type(X509_EXTENSION,a->extensions,
					     i2d_X509_EXTENSION,0,
					     V_ASN1_SEQUENCE,v1);

	M_ASN1_I2D_seq_total();

	if ((a->version != NULL) && (l != 0))
		{
		M_ASN1_I2D_put(a->version,i2d_ASN1_INTEGER);
		}
	M_ASN1_I2D_put(a->sig_alg,i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->issuer,i2d_X509_NAME);
	M_ASN1_I2D_put(a->lastUpdate,i2d_ASN1_TIME);
	if (a->nextUpdate != NULL)
		{ M_ASN1_I2D_put(a->nextUpdate,i2d_ASN1_TIME); }
	M_ASN1_I2D_put_SEQUENCE_opt_type(X509_REVOKED,a->revoked,
					 i2d_X509_REVOKED);
	M_ASN1_I2D_put_EXP_SEQUENCE_opt_type(X509_EXTENSION,a->extensions,
					     i2d_X509_EXTENSION,0,
					     V_ASN1_SEQUENCE,v1);

	M_ASN1_I2D_finish();
	}

X509_CRL_INFO *d2i_X509_CRL_INFO(X509_CRL_INFO **a, unsigned char **pp,
	     long length)
	{
	int i,ver=0;
	M_ASN1_D2I_vars(a,X509_CRL_INFO *,X509_CRL_INFO_new);


	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get_opt(ret->version,d2i_ASN1_INTEGER,V_ASN1_INTEGER);
	if (ret->version != NULL)
		ver=ret->version->data[0];
	
	if ((ver == 0) && (ret->version != NULL))
		{
		M_ASN1_INTEGER_free(ret->version);
		ret->version=NULL;
		}
	M_ASN1_D2I_get(ret->sig_alg,d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->issuer,d2i_X509_NAME);
	M_ASN1_D2I_get(ret->lastUpdate,d2i_ASN1_TIME);
	/* Manually handle the OPTIONAL ASN1_TIME stuff */
	/* First try UTCTime */
	M_ASN1_D2I_get_opt(ret->nextUpdate,d2i_ASN1_UTCTIME, V_ASN1_UTCTIME);
	/* If that doesn't work try GeneralizedTime */
	if(!ret->nextUpdate) 
		M_ASN1_D2I_get_opt(ret->nextUpdate,d2i_ASN1_GENERALIZEDTIME,
							V_ASN1_GENERALIZEDTIME);
	if (ret->revoked != NULL)
		{
		while (sk_X509_REVOKED_num(ret->revoked))
			X509_REVOKED_free(sk_X509_REVOKED_pop(ret->revoked));
		}
	M_ASN1_D2I_get_seq_opt_type(X509_REVOKED,ret->revoked,d2i_X509_REVOKED,
				    X509_REVOKED_free);

	if (ret->revoked != NULL)
		{
		for (i=0; i<sk_X509_REVOKED_num(ret->revoked); i++)
			{
			sk_X509_REVOKED_value(ret->revoked,i)->sequence=i;
			}
		}

	if (ret->extensions != NULL)
		{
		while (sk_X509_EXTENSION_num(ret->extensions))
			X509_EXTENSION_free(
			sk_X509_EXTENSION_pop(ret->extensions));
		}
		
	M_ASN1_D2I_get_EXP_set_opt_type(X509_EXTENSION,ret->extensions,
					d2i_X509_EXTENSION,
					X509_EXTENSION_free,0,
					V_ASN1_SEQUENCE);

	M_ASN1_D2I_Finish(a,X509_CRL_INFO_free,ASN1_F_D2I_X509_CRL_INFO);
	}

int i2d_X509_CRL(X509_CRL *a, unsigned char **pp)
	{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->crl,i2d_X509_CRL_INFO);
	M_ASN1_I2D_len(a->sig_alg,i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->signature,i2d_ASN1_BIT_STRING);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(a->crl,i2d_X509_CRL_INFO);
	M_ASN1_I2D_put(a->sig_alg,i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->signature,i2d_ASN1_BIT_STRING);

	M_ASN1_I2D_finish();
	}

X509_CRL *d2i_X509_CRL(X509_CRL **a, unsigned char **pp, long length)
	{
	M_ASN1_D2I_vars(a,X509_CRL *,X509_CRL_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->crl,d2i_X509_CRL_INFO);
	M_ASN1_D2I_get(ret->sig_alg,d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->signature,d2i_ASN1_BIT_STRING);

	M_ASN1_D2I_Finish(a,X509_CRL_free,ASN1_F_D2I_X509_CRL);
	}


X509_REVOKED *X509_REVOKED_new(void)
	{
	X509_REVOKED *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,X509_REVOKED);
	M_ASN1_New(ret->serialNumber,M_ASN1_INTEGER_new);
	M_ASN1_New(ret->revocationDate,M_ASN1_UTCTIME_new);
	ret->extensions=NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_X509_REVOKED_NEW);
	}

X509_CRL_INFO *X509_CRL_INFO_new(void)
	{
	X509_CRL_INFO *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,X509_CRL_INFO);
	ret->version=NULL;
	M_ASN1_New(ret->sig_alg,X509_ALGOR_new);
	M_ASN1_New(ret->issuer,X509_NAME_new);
	M_ASN1_New(ret->lastUpdate,M_ASN1_UTCTIME_new);
	ret->nextUpdate=NULL;
	M_ASN1_New(ret->revoked,sk_X509_REVOKED_new_null);
	M_ASN1_New(ret->extensions,sk_X509_EXTENSION_new_null);
	sk_X509_REVOKED_set_cmp_func(ret->revoked,X509_REVOKED_cmp);
	return(ret);
	M_ASN1_New_Error(ASN1_F_X509_CRL_INFO_NEW);
	}

X509_CRL *X509_CRL_new(void)
	{
	X509_CRL *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,X509_CRL);
	ret->references=1;
	M_ASN1_New(ret->crl,X509_CRL_INFO_new);
	M_ASN1_New(ret->sig_alg,X509_ALGOR_new);
	M_ASN1_New(ret->signature,M_ASN1_BIT_STRING_new);
	return(ret);
	M_ASN1_New_Error(ASN1_F_X509_CRL_NEW);
	}

void X509_REVOKED_free(X509_REVOKED *a)
	{
	if (a == NULL) return;
	M_ASN1_INTEGER_free(a->serialNumber);
	M_ASN1_UTCTIME_free(a->revocationDate);
	sk_X509_EXTENSION_pop_free(a->extensions,X509_EXTENSION_free);
	OPENSSL_free(a);
	}

void X509_CRL_INFO_free(X509_CRL_INFO *a)
	{
	if (a == NULL) return;
	M_ASN1_INTEGER_free(a->version);
	X509_ALGOR_free(a->sig_alg);
	X509_NAME_free(a->issuer);
	M_ASN1_UTCTIME_free(a->lastUpdate);
	if (a->nextUpdate)
		M_ASN1_UTCTIME_free(a->nextUpdate);
	sk_X509_REVOKED_pop_free(a->revoked,X509_REVOKED_free);
	sk_X509_EXTENSION_pop_free(a->extensions,X509_EXTENSION_free);
	OPENSSL_free(a);
	}

void X509_CRL_free(X509_CRL *a)
	{
	int i;

	if (a == NULL) return;

	i=CRYPTO_add(&a->references,-1,CRYPTO_LOCK_X509_CRL);
#ifdef REF_PRINT
	REF_PRINT("X509_CRL",a);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"X509_CRL_free, bad reference count\n");
		abort();
		}
#endif

	X509_CRL_INFO_free(a->crl);
	X509_ALGOR_free(a->sig_alg);
	M_ASN1_BIT_STRING_free(a->signature);
	OPENSSL_free(a);
	}

static int X509_REVOKED_cmp(const X509_REVOKED * const *a,
			const X509_REVOKED * const *b)
	{
	return(ASN1_STRING_cmp(
		(ASN1_STRING *)(*a)->serialNumber,
		(ASN1_STRING *)(*b)->serialNumber));
	}

static int X509_REVOKED_seq_cmp(const X509_REVOKED * const *a,
				const X509_REVOKED * const *b)
	{
	return((*a)->sequence-(*b)->sequence);
	}

IMPLEMENT_STACK_OF(X509_REVOKED)
IMPLEMENT_ASN1_SET_OF(X509_REVOKED)
IMPLEMENT_STACK_OF(X509_CRL)
IMPLEMENT_ASN1_SET_OF(X509_CRL)
