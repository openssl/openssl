/* v3_pku.c */
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
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509v3.h>

static int i2r_PKEY_USAGE_PERIOD(X509V3_EXT_METHOD *method, PKEY_USAGE_PERIOD *usage, BIO *out, int indent);
/*
static PKEY_USAGE_PERIOD *v2i_PKEY_USAGE_PERIOD(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values);
*/
X509V3_EXT_METHOD v3_pkey_usage_period = {
NID_private_key_usage_period, 0,
(X509V3_EXT_NEW)PKEY_USAGE_PERIOD_new,
(X509V3_EXT_FREE)PKEY_USAGE_PERIOD_free,
(X509V3_EXT_D2I)d2i_PKEY_USAGE_PERIOD,
(X509V3_EXT_I2D)i2d_PKEY_USAGE_PERIOD,
NULL, NULL, NULL, NULL,
(X509V3_EXT_I2R)i2r_PKEY_USAGE_PERIOD, NULL,
NULL
};

int i2d_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD *a, unsigned char **pp)
{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len_IMP_opt (a->notBefore, i2d_ASN1_GENERALIZEDTIME);
	M_ASN1_I2D_len_IMP_opt (a->notAfter, i2d_ASN1_GENERALIZEDTIME);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put_IMP_opt (a->notBefore, i2d_ASN1_GENERALIZEDTIME, 0);
	M_ASN1_I2D_put_IMP_opt (a->notAfter, i2d_ASN1_GENERALIZEDTIME, 1);

	M_ASN1_I2D_finish();
}

PKEY_USAGE_PERIOD *PKEY_USAGE_PERIOD_new(void)
{
	PKEY_USAGE_PERIOD *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, PKEY_USAGE_PERIOD);
	ret->notBefore = NULL;
	ret->notAfter = NULL;
	return (ret);
	M_ASN1_New_Error(ASN1_F_PKEY_USAGE_PERIOD_NEW);
}

PKEY_USAGE_PERIOD *d2i_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD **a,
	     unsigned char **pp, long length)
{
	M_ASN1_D2I_vars(a,PKEY_USAGE_PERIOD *,PKEY_USAGE_PERIOD_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get_IMP_opt (ret->notBefore, d2i_ASN1_GENERALIZEDTIME, 0,
							V_ASN1_GENERALIZEDTIME);
	M_ASN1_D2I_get_IMP_opt (ret->notAfter, d2i_ASN1_GENERALIZEDTIME, 1,
							V_ASN1_GENERALIZEDTIME);
	M_ASN1_D2I_Finish(a, PKEY_USAGE_PERIOD_free, ASN1_F_D2I_PKEY_USAGE_PERIOD);
}

void PKEY_USAGE_PERIOD_free(PKEY_USAGE_PERIOD *a)
{
	if (a == NULL) return;
	ASN1_GENERALIZEDTIME_free(a->notBefore);
	ASN1_GENERALIZEDTIME_free(a->notAfter);
	Free ((char *)a);
}

static int i2r_PKEY_USAGE_PERIOD(X509V3_EXT_METHOD *method,
	     PKEY_USAGE_PERIOD *usage, BIO *out, int indent)
{
	BIO_printf(out, "%*s", indent, "");
	if(usage->notBefore) {
		BIO_write(out, "Not Before: ", 12);
		ASN1_GENERALIZEDTIME_print(out, usage->notBefore);
		if(usage->notAfter) BIO_write(out, ", ", 2);
	}
	if(usage->notAfter) {
		BIO_write(out, "Not After: ", 11);
		ASN1_GENERALIZEDTIME_print(out, usage->notAfter);
	}
	return 1;
}

/*
static PKEY_USAGE_PERIOD *v2i_PKEY_USAGE_PERIOD(method, ctx, values)
X509V3_EXT_METHOD *method;
X509V3_CTX *ctx;
STACK_OF(CONF_VALUE) *values;
{
return NULL;
}
*/
