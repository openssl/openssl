/* v3_sxnet.c */
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
#include "conf.h"
#include "asn1.h"
#include "asn1_mac.h"
#include "x509v3.h"

/* Support for Thawte strong extranet extension */

#ifndef NOPROTO
static int sxnet_i2r(X509V3_EXT_METHOD *method, SXNET *sx, BIO *out, int indent);
#else
static int sxnet_i2r();
#endif

X509V3_EXT_METHOD v3_sxnet = {
NID_sxnet, X509V3_EXT_MULTILINE,
(X509V3_EXT_NEW)SXNET_new,
SXNET_free,
(X509V3_EXT_D2I)d2i_SXNET,
i2d_SXNET,
NULL, NULL,
NULL, NULL,
(X509V3_EXT_I2R)sxnet_i2r,
NULL,
NULL
};


/*
 * ASN1err(ASN1_F_SXNET_NEW,ERR_R_MALLOC_FAILURE);
 * ASN1err(ASN1_F_D2I_SXNET,ERR_R_MALLOC_FAILURE);
 * ASN1err(ASN1_F_SXNETID_NEW,ERR_R_MALLOC_FAILURE);
 * ASN1err(ASN1_F_D2I_SXNETID,ERR_R_MALLOC_FAILURE);
 */

int i2d_SXNET(a,pp)
SXNET *a;
unsigned char **pp;
{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len (a->version, i2d_ASN1_INTEGER);
	M_ASN1_I2D_len_SEQUENCE (a->ids, i2d_SXNETID);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put (a->version, i2d_ASN1_INTEGER);
	M_ASN1_I2D_put_SEQUENCE (a->ids, i2d_SXNETID);

	M_ASN1_I2D_finish();
}

SXNET *SXNET_new()
{
	SXNET *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, SXNET);
	ret->version = NULL;
	ret->ids = NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_SXNET_NEW);
}

SXNET *d2i_SXNET(a,pp,length)
SXNET **a;
unsigned char **pp;
long length;
{
	M_ASN1_D2I_vars(a,SXNET *,SXNET_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get (ret->version, d2i_ASN1_INTEGER);
	M_ASN1_D2I_get_seq (ret->ids, d2i_SXNETID, SXNETID_free);
	M_ASN1_D2I_Finish(a, SXNET_free, ASN1_F_D2I_SXNET);
}

void SXNET_free(a)
SXNET *a;
{
	if (a == NULL) return;
	ASN1_INTEGER_free(a->version);
	sk_pop_free(a->ids, SXNETID_free);
	Free ((char *)a);
}



int i2d_SXNETID(a,pp)
SXNETID *a;
unsigned char **pp;
{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len (a->zone, i2d_ASN1_INTEGER);
	M_ASN1_I2D_len (a->user, i2d_ASN1_OCTET_STRING);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put (a->zone, i2d_ASN1_INTEGER);
	M_ASN1_I2D_put (a->user, i2d_ASN1_OCTET_STRING);

	M_ASN1_I2D_finish();
}

SXNETID *SXNETID_new()
{
	SXNETID *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, SXNETID);
	ret->zone = NULL;
	M_ASN1_New(ret->user,ASN1_OCTET_STRING_new);
	return (ret);
	M_ASN1_New_Error(ASN1_F_SXNETID_NEW);
}

SXNETID *d2i_SXNETID(a,pp,length)
SXNETID **a;
unsigned char **pp;
long length;
{
	M_ASN1_D2I_vars(a,SXNETID *,SXNETID_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->zone, d2i_ASN1_INTEGER);
	M_ASN1_D2I_get(ret->user, d2i_ASN1_OCTET_STRING);
	M_ASN1_D2I_Finish(a, SXNETID_free, ASN1_F_D2I_SXNETID);
}

void SXNETID_free(a)
SXNETID *a;
{
	if (a == NULL) return;
	ASN1_INTEGER_free(a->zone);
	ASN1_OCTET_STRING_free(a->user);
	Free ((char *)a);
}

static int sxnet_i2r(method, sx, out, indent)
X509V3_EXT_METHOD *method;
SXNET *sx;
BIO *out;
int indent;
{
	long v;
	char *tmp;
	SXNETID *id;
	int i;
	v = ASN1_INTEGER_get(sx->version);
	BIO_printf(out, "%*sVersion: %d (0x%X)", indent, "", v + 1, v);
	for(i = 0; i < sk_num(sx->ids); i++) {
		id = (SXNETID *)sk_value(sx->ids, i);
		tmp = i2s_ASN1_INTEGER(NULL, id->zone);
		BIO_printf(out, "\n%*sZone: %s, User: ", indent, "", tmp);
		Free(tmp);
		ASN1_OCTET_STRING_print(out, id->user);
	}
	return 1;
}
