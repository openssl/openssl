/* v3_alt.c */
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
#include <pem.h>
#include <asn1_mac.h>
#include <err.h>
#include <objects.h>
#include <conf.h>
#include "x509v3.h"

#ifndef NOPROTO
static STACK *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method, STACK *gen);
/*static STACK *v2i_GENERAL_NAMES(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK *values);*/
#endif

X509V3_EXT_METHOD v3_alt[] = {
{ NID_subject_alt_name, 0,
(X509V3_EXT_NEW)GENERAL_NAMES_new,
GENERAL_NAMES_free,
(X509V3_EXT_D2I)d2i_GENERAL_NAMES,
i2d_GENERAL_NAMES,
NULL, NULL,
(X509V3_EXT_I2V)i2v_GENERAL_NAMES,
(X509V3_EXT_V2I)NULL /*v2i_GENERAL_NAMES*/,
NULL, NULL},
{ NID_issuer_alt_name, 0,
(X509V3_EXT_NEW)GENERAL_NAMES_new,
GENERAL_NAMES_free,
(X509V3_EXT_D2I)d2i_GENERAL_NAMES,
i2d_GENERAL_NAMES,
NULL, NULL,
(X509V3_EXT_I2V)i2v_GENERAL_NAMES,
(X509V3_EXT_V2I)NULL /*v2i_GENERAL_NAMES*/,
NULL, NULL},
EXT_END
};

static STACK *i2v_GENERAL_NAMES(method, gens)
X509V3_EXT_METHOD *method;
STACK *gens;
{
	int i;
	STACK *ret = NULL;
	GENERAL_NAME *gen;
	for(i = 0; i < sk_num(gens); i++) {
		gen = (GENERAL_NAME *)sk_value(gens, i);
		switch (gen->type)
		{
                case GEN_OTHERNAME:
		X509V3_add_value("othername","<unsupported>", &ret);
		break;

                case GEN_X400:
		X509V3_add_value("X400Name","<unsupported>", &ret);
		break;

                case GEN_EDIPARTY:
		X509V3_add_value("EdiPartyName","<unsupported>", &ret);
                break;

                case GEN_EMAIL:
		X509V3_add_value("email",gen->d.ia5->data, &ret);
		break;

                case GEN_DNS:
		X509V3_add_value("DNS",gen->d.ia5->data, &ret);
		break;

                case GEN_URI:
		X509V3_add_value("URI",gen->d.ia5->data, &ret);
                break;

                case GEN_IPADD:
		X509V3_add_value("IP Address","<unsupported>", &ret);
                break;

                case GEN_RID:
		X509V3_add_value("Registered ID","<unsupported>", &ret);
                break;
		}
	}
	return ret;
}

