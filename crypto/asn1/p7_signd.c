/* crypto/asn1/p7_signd.c */
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
#include "x509.h"

/*
 * ASN1err(ASN1_F_PKCS7_SIGNED_NEW,ASN1_R_LENGTH_MISMATCH);
 * ASN1err(ASN1_F_D2I_PKCS7_SIGNED,ASN1_R_LENGTH_MISMATCH);
 */

int i2d_PKCS7_SIGNED(a,pp)
PKCS7_SIGNED *a;
unsigned char **pp;
	{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->version,i2d_ASN1_INTEGER);
	M_ASN1_I2D_len_SET(a->md_algs,i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->contents,i2d_PKCS7);
	M_ASN1_I2D_len_IMP_set_opt(a->cert,i2d_X509,0);
	M_ASN1_I2D_len_IMP_set_opt(a->crl,i2d_X509_CRL,1);
	M_ASN1_I2D_len_SET(a->signer_info,i2d_PKCS7_SIGNER_INFO);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(a->version,i2d_ASN1_INTEGER);
	M_ASN1_I2D_put_SET(a->md_algs,i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->contents,i2d_PKCS7);
	M_ASN1_I2D_put_IMP_set_opt(a->cert,i2d_X509,0);
	M_ASN1_I2D_put_IMP_set_opt(a->crl,i2d_X509_CRL,1);
	M_ASN1_I2D_put_SET(a->signer_info,i2d_PKCS7_SIGNER_INFO);

	M_ASN1_I2D_finish();
	}

PKCS7_SIGNED *d2i_PKCS7_SIGNED(a,pp,length)
PKCS7_SIGNED **a;
unsigned char **pp;
long length;
	{
	M_ASN1_D2I_vars(a,PKCS7_SIGNED *,PKCS7_SIGNED_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->version,d2i_ASN1_INTEGER);
	M_ASN1_D2I_get_set(ret->md_algs,d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->contents,d2i_PKCS7);
	M_ASN1_D2I_get_IMP_set_opt(ret->cert,d2i_X509,0);
	M_ASN1_D2I_get_IMP_set_opt(ret->crl,d2i_X509_CRL,1);
	M_ASN1_D2I_get_set(ret->signer_info,d2i_PKCS7_SIGNER_INFO);

	M_ASN1_D2I_Finish(a,PKCS7_SIGNED_free,ASN1_F_D2I_PKCS7_SIGNED);
	}

PKCS7_SIGNED *PKCS7_SIGNED_new()
	{
	PKCS7_SIGNED *ret=NULL;

	M_ASN1_New_Malloc(ret,PKCS7_SIGNED);
	M_ASN1_New(ret->version,ASN1_INTEGER_new);
	M_ASN1_New(ret->md_algs,sk_new_null);
	M_ASN1_New(ret->contents,PKCS7_new);
	ret->cert=NULL;
	ret->crl=NULL;
	M_ASN1_New(ret->signer_info,sk_new_null);
	return(ret);
	M_ASN1_New_Error(ASN1_F_PKCS7_SIGNED_NEW);
	}

void PKCS7_SIGNED_free(a)
PKCS7_SIGNED *a;
	{
	if (a == NULL) return;
	ASN1_INTEGER_free(a->version);
	sk_pop_free(a->md_algs,X509_ALGOR_free);
	PKCS7_free(a->contents);
	sk_pop_free(a->cert,X509_free);
	sk_pop_free(a->crl,X509_CRL_free);
	sk_pop_free(a->signer_info,PKCS7_SIGNER_INFO_free);
	Free((char *)a);
	}

