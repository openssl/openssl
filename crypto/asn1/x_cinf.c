/* crypto/asn1/x_cinf.c */
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

int i2d_X509_CINF(X509_CINF *a, unsigned char **pp)
	{
	int v1=0,v2=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len_EXP_opt(a->version,i2d_ASN1_INTEGER,0,v1);
	M_ASN1_I2D_len(a->serialNumber,		i2d_ASN1_INTEGER);
	M_ASN1_I2D_len(a->signature,		i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->issuer,		i2d_X509_NAME);
	M_ASN1_I2D_len(a->validity,		i2d_X509_VAL);
	M_ASN1_I2D_len(a->subject,		i2d_X509_NAME);
	M_ASN1_I2D_len(a->key,			i2d_X509_PUBKEY);
	M_ASN1_I2D_len_IMP_opt(a->issuerUID,	i2d_ASN1_BIT_STRING);
	M_ASN1_I2D_len_IMP_opt(a->subjectUID,	i2d_ASN1_BIT_STRING);
	M_ASN1_I2D_len_EXP_SEQUENCE_opt_type(X509_EXTENSION,a->extensions,
					     i2d_X509_EXTENSION,3,
					     V_ASN1_SEQUENCE,v2);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put_EXP_opt(a->version,i2d_ASN1_INTEGER,0,v1);
	M_ASN1_I2D_put(a->serialNumber,		i2d_ASN1_INTEGER);
	M_ASN1_I2D_put(a->signature,		i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->issuer,		i2d_X509_NAME);
	M_ASN1_I2D_put(a->validity,		i2d_X509_VAL);
	M_ASN1_I2D_put(a->subject,		i2d_X509_NAME);
	M_ASN1_I2D_put(a->key,			i2d_X509_PUBKEY);
	M_ASN1_I2D_put_IMP_opt(a->issuerUID,	i2d_ASN1_BIT_STRING,1);
	M_ASN1_I2D_put_IMP_opt(a->subjectUID,	i2d_ASN1_BIT_STRING,2);
	M_ASN1_I2D_put_EXP_SEQUENCE_opt_type(X509_EXTENSION,a->extensions,
					     i2d_X509_EXTENSION,3,
					     V_ASN1_SEQUENCE,v2);

	M_ASN1_I2D_finish();
	}

X509_CINF *d2i_X509_CINF(X509_CINF **a, unsigned char **pp, long length)
	{
	int ver=0;
	M_ASN1_D2I_vars(a,X509_CINF *,X509_CINF_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	/* we have the optional version field */
	if (M_ASN1_next == (V_ASN1_CONTEXT_SPECIFIC | V_ASN1_CONSTRUCTED | 0))
		{
		M_ASN1_D2I_get_EXP_opt(ret->version,d2i_ASN1_INTEGER,0);
		if (ret->version->data != NULL)
			ver=ret->version->data[0];
		}
	else
		{
		if (ret->version != NULL)
			{
			ASN1_INTEGER_free(ret->version);
			ret->version=NULL;
			}
		}
	M_ASN1_D2I_get(ret->serialNumber,d2i_ASN1_INTEGER);
	M_ASN1_D2I_get(ret->signature,d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->issuer,d2i_X509_NAME);
	M_ASN1_D2I_get(ret->validity,d2i_X509_VAL);
	M_ASN1_D2I_get(ret->subject,d2i_X509_NAME);
	M_ASN1_D2I_get(ret->key,d2i_X509_PUBKEY);
	if (ver >= 1) /* version 2 extensions */
		{
		if (ret->issuerUID != NULL)
			{
			ASN1_BIT_STRING_free(ret->issuerUID);
			ret->issuerUID=NULL;
			}
		if (ret->subjectUID != NULL)
			{
			ASN1_BIT_STRING_free(ret->subjectUID);
			ret->subjectUID=NULL;
			}
		M_ASN1_D2I_get_IMP_opt(ret->issuerUID,d2i_ASN1_BIT_STRING,  1,
			V_ASN1_BIT_STRING);
		M_ASN1_D2I_get_IMP_opt(ret->subjectUID,d2i_ASN1_BIT_STRING, 2,
			V_ASN1_BIT_STRING);
		}
/* Note: some broken certificates include extensions but don't set
 * the version number properly. By bypassing this check they can
 * be parsed.
 */

#ifdef VERSION_EXT_CHECK
	if (ver >= 2) /* version 3 extensions */
#endif
		{
		if (ret->extensions != NULL)
			while (sk_X509_EXTENSION_num(ret->extensions))
				X509_EXTENSION_free(
				      sk_X509_EXTENSION_pop(ret->extensions));
		M_ASN1_D2I_get_EXP_set_opt_type(X509_EXTENSION,ret->extensions,
						d2i_X509_EXTENSION,
						X509_EXTENSION_free,3,
						V_ASN1_SEQUENCE);
		}
	M_ASN1_D2I_Finish(a,X509_CINF_free,ASN1_F_D2I_X509_CINF);
	}

X509_CINF *X509_CINF_new(void)
	{
	X509_CINF *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,X509_CINF);
	ret->version=NULL;
	M_ASN1_New(ret->serialNumber,ASN1_INTEGER_new);
	M_ASN1_New(ret->signature,X509_ALGOR_new);
	M_ASN1_New(ret->issuer,X509_NAME_new);
	M_ASN1_New(ret->validity,X509_VAL_new);
	M_ASN1_New(ret->subject,X509_NAME_new);
	M_ASN1_New(ret->key,X509_PUBKEY_new);
	ret->issuerUID=NULL;
	ret->subjectUID=NULL;
	ret->extensions=NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_X509_CINF_NEW);
	}

void X509_CINF_free(X509_CINF *a)
	{
	if (a == NULL) return;
	ASN1_INTEGER_free(a->version);
	ASN1_INTEGER_free(a->serialNumber);
	X509_ALGOR_free(a->signature);
	X509_NAME_free(a->issuer);
	X509_VAL_free(a->validity);
	X509_NAME_free(a->subject);
	X509_PUBKEY_free(a->key);
	ASN1_BIT_STRING_free(a->issuerUID);
	ASN1_BIT_STRING_free(a->subjectUID);
	sk_X509_EXTENSION_pop_free(a->extensions,X509_EXTENSION_free);
	Free(a);
	}

