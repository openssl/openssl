/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include "asn1_locl.h"

extern const EVP_PKEY_ASN1_METHOD rsa_asn1_meths[];
extern const EVP_PKEY_ASN1_METHOD dsa_asn1_meths[];
extern const EVP_PKEY_ASN1_METHOD eckey_asn1_meth;

/* Keep this sorted in type order !! */
const EVP_PKEY_ASN1_METHOD *standard_methods[] = 
	{
	&rsa_asn1_meths[0],
	&rsa_asn1_meths[1],
	&dsa_asn1_meths[0],
	&dsa_asn1_meths[1],
	&dsa_asn1_meths[2],
	&dsa_asn1_meths[3],
	&dsa_asn1_meths[4],
	&eckey_asn1_meth
	};

#ifdef TEST
void main()
	{
	int i;
	for (i = 0;
		i < sizeof(standard_methods)/sizeof(EVP_PKEY_ASN1_METHOD *);
		i++)
		fprintf(stderr, "Number %d id=%d\n", i,
			standard_methods[i]->pkey_id);
	}
#endif

static int ameth_cmp(const EVP_PKEY_ASN1_METHOD * const *a,
                const EVP_PKEY_ASN1_METHOD * const *b)
	{
        return ((*a)->pkey_id - (*b)->pkey_id);
	}

const EVP_PKEY_ASN1_METHOD *EVP_PKEY_ASN1_find(int type)
	{
	EVP_PKEY_ASN1_METHOD tmp, *t = &tmp, **ret;
	tmp.pkey_id = type;
	ret = (EVP_PKEY_ASN1_METHOD **) OBJ_bsearch((char *)&t,
        		(char *)standard_methods,
			sizeof(standard_methods)/sizeof(EVP_PKEY_ASN1_METHOD *),
        		sizeof(EVP_PKEY_ASN1_METHOD *),
			(int (*)(const void *, const void *))ameth_cmp);
	if ((*ret)->pkey_flags & ASN1_PKEY_ALIAS)
		return EVP_PKEY_ASN1_find((*ret)->pkey_base_id);
	return *ret;
	}

