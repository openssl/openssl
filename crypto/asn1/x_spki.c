/* crypto/asn1/x_spki.c */
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

 /* This module was send to me my Pat Richards <patr@x509.com> who
  * wrote it.  It is under my Copyright with his permission
  */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/x509.h>
#include <openssl/asn1_mac.h>

int i2d_NETSCAPE_SPKAC(NETSCAPE_SPKAC *a, unsigned char **pp)
	{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->pubkey,	i2d_X509_PUBKEY);
	M_ASN1_I2D_len(a->challenge,	i2d_ASN1_IA5STRING);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(a->pubkey,	i2d_X509_PUBKEY);
	M_ASN1_I2D_put(a->challenge,	i2d_ASN1_IA5STRING);

	M_ASN1_I2D_finish();
	}

NETSCAPE_SPKAC *d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC **a, unsigned char **pp,
	     long length)
	{
	M_ASN1_D2I_vars(a,NETSCAPE_SPKAC *,NETSCAPE_SPKAC_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->pubkey,d2i_X509_PUBKEY);
	M_ASN1_D2I_get(ret->challenge,d2i_ASN1_IA5STRING);
	M_ASN1_D2I_Finish(a,NETSCAPE_SPKAC_free,ASN1_F_D2I_NETSCAPE_SPKAC);
	}

NETSCAPE_SPKAC *NETSCAPE_SPKAC_new(void)
	{
	NETSCAPE_SPKAC *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,NETSCAPE_SPKAC);
	M_ASN1_New(ret->pubkey,X509_PUBKEY_new);
	M_ASN1_New(ret->challenge,M_ASN1_IA5STRING_new);
	return(ret);
	M_ASN1_New_Error(ASN1_F_NETSCAPE_SPKAC_NEW);
	}

void NETSCAPE_SPKAC_free(NETSCAPE_SPKAC *a)
	{
	if (a == NULL) return;
	X509_PUBKEY_free(a->pubkey);
	M_ASN1_IA5STRING_free(a->challenge);
	Free(a);
	}

int i2d_NETSCAPE_SPKI(NETSCAPE_SPKI *a, unsigned char **pp)
	{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->spkac,	i2d_NETSCAPE_SPKAC);
	M_ASN1_I2D_len(a->sig_algor,	i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->signature,	i2d_ASN1_BIT_STRING);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(a->spkac,	i2d_NETSCAPE_SPKAC);
	M_ASN1_I2D_put(a->sig_algor,	i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->signature,	i2d_ASN1_BIT_STRING);

	M_ASN1_I2D_finish();
	}

NETSCAPE_SPKI *d2i_NETSCAPE_SPKI(NETSCAPE_SPKI **a, unsigned char **pp,
	     long length)
	{
	M_ASN1_D2I_vars(a,NETSCAPE_SPKI *,NETSCAPE_SPKI_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->spkac,d2i_NETSCAPE_SPKAC);
	M_ASN1_D2I_get(ret->sig_algor,d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->signature,d2i_ASN1_BIT_STRING);
	M_ASN1_D2I_Finish(a,NETSCAPE_SPKI_free,ASN1_F_D2I_NETSCAPE_SPKI);
	}

NETSCAPE_SPKI *NETSCAPE_SPKI_new(void)
	{
	NETSCAPE_SPKI *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,NETSCAPE_SPKI);
	M_ASN1_New(ret->spkac,NETSCAPE_SPKAC_new);
	M_ASN1_New(ret->sig_algor,X509_ALGOR_new);
	M_ASN1_New(ret->signature,M_ASN1_BIT_STRING_new);
	return(ret);
	M_ASN1_New_Error(ASN1_F_NETSCAPE_SPKI_NEW);
	}

void NETSCAPE_SPKI_free(NETSCAPE_SPKI *a)
	{
	if (a == NULL) return;
	NETSCAPE_SPKAC_free(a->spkac);
	X509_ALGOR_free(a->sig_algor);
	M_ASN1_BIT_STRING_free(a->signature);
	Free(a);
	}

