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
	M_ASN1_I2D_len (a->salt, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_len (a->iter, i2d_ASN1_INTEGER);
	M_ASN1_I2D_len (a->keylength, i2d_ASN1_INTEGER);
	M_ASN1_I2D_len (a->prf, i2d_X509_ALGOR);

	M_ASN1_I2D_seq_total ();

	M_ASN1_I2D_put (a->salt, i2d_ASN1_OCTET_STRING);
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
	M_ASN1_New(ret->salt, ASN1_OCTET_STRING_new);
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
	M_ASN1_D2I_get (ret->salt, d2i_ASN1_OCTET_STRING);
	M_ASN1_D2I_get (ret->iter, d2i_ASN1_INTEGER);
	M_ASN1_D2I_get_opt (ret->keylength, d2i_ASN1_INTEGER, V_ASN1_INTEGER);
	M_ASN1_D2I_get_opt (ret->prf, d2i_X509_ALGOR, V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a, PBKDF2PARAM_free, ASN1_F_D2I_PBKDF2PARAM);
}

void PBKDF2PARAM_free (PBKDF2PARAM *a)
{
	if(a==NULL) return;
	ASN1_OCTET_STRING_free(a->salt);
	ASN1_INTEGER_free(a->iter);
	ASN1_INTEGER_free(a->keylength);
	X509_ALGOR_free(a->prf);
	Free ((char *)a);
}

