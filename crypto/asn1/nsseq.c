/* nsseq.c */
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
#include <openssl/asn1_mac.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/objects.h>

/* Netscape certificate sequence structure */

int i2d_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE *a, unsigned char **pp)
{
	int v = 0;
	M_ASN1_I2D_vars(a);
	M_ASN1_I2D_len (a->type, i2d_ASN1_OBJECT);
	M_ASN1_I2D_len_EXP_SEQUENCE_opt_type(X509,a->certs,i2d_X509,0,
					     V_ASN1_SEQUENCE,v);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put (a->type, i2d_ASN1_OBJECT);
	M_ASN1_I2D_put_EXP_SEQUENCE_opt_type(X509,a->certs,i2d_X509,0,
					     V_ASN1_SEQUENCE,v);

	M_ASN1_I2D_finish();
}

NETSCAPE_CERT_SEQUENCE *NETSCAPE_CERT_SEQUENCE_new(void)
{
	NETSCAPE_CERT_SEQUENCE *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, NETSCAPE_CERT_SEQUENCE);
	/* Note hardcoded object type */
	ret->type = OBJ_nid2obj(NID_netscape_cert_sequence);
	ret->certs = NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_NETSCAPE_CERT_SEQUENCE_NEW);
}

NETSCAPE_CERT_SEQUENCE *d2i_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE **a,
	     unsigned char **pp, long length)
{
	M_ASN1_D2I_vars(a,NETSCAPE_CERT_SEQUENCE *,
					NETSCAPE_CERT_SEQUENCE_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get (ret->type, d2i_ASN1_OBJECT);
	M_ASN1_D2I_get_EXP_set_opt_type(X509,ret->certs,d2i_X509,X509_free,0,
					V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a, NETSCAPE_CERT_SEQUENCE_free,
			  ASN1_F_D2I_NETSCAPE_CERT_SEQUENCE);
}

void NETSCAPE_CERT_SEQUENCE_free (NETSCAPE_CERT_SEQUENCE *a)
{
	if (a == NULL) return;
	ASN1_OBJECT_free(a->type);
	if(a->certs)
	    sk_X509_pop_free(a->certs, X509_free);
	OPENSSL_free (a);
}
