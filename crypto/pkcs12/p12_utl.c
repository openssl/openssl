/* p12_utl.c */
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
#include <openssl/pkcs12.h>

/* Cheap and nasty Unicode stuff */

unsigned char *asc2uni(const char *asc, int asclen, unsigned char **uni, int *unilen)
{
	int ulen, i;
	unsigned char *unitmp;
	if (asclen == -1) asclen = strlen(asc);
	ulen = asclen*2  + 2;
	if (!(unitmp = OPENSSL_malloc(ulen))) return NULL;
	for (i = 0; i < ulen - 2; i+=2) {
		unitmp[i] = 0;
		unitmp[i + 1] = asc[i>>1];
	}
	/* Make result double null terminated */
	unitmp[ulen - 2] = 0;
	unitmp[ulen - 1] = 0;
	if (unilen) *unilen = ulen;
	if (uni) *uni = unitmp;
	return unitmp;
}

char *uni2asc(unsigned char *uni, int unilen)
{
	int asclen, i;
	char *asctmp;
	asclen = unilen / 2;
	/* If no terminating zero allow for one */
	if (!unilen || uni[unilen - 1]) asclen++;
	uni++;
	if (!(asctmp = OPENSSL_malloc(asclen))) return NULL;
	for (i = 0; i < unilen; i+=2) asctmp[i>>1] = uni[i];
	asctmp[asclen - 1] = 0;
	return asctmp;
}

int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12)
{
	return ASN1_i2d_bio((int(*)())i2d_PKCS12, bp, (unsigned char *)p12);
}

#ifndef NO_FP_API
int i2d_PKCS12_fp(FILE *fp, PKCS12 *p12)
{
	return ASN1_i2d_fp((int(*)())i2d_PKCS12, fp, (unsigned char *)p12);
}
#endif

PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12)
{
	return (PKCS12 *)ASN1_d2i_bio((char *(*)())PKCS12_new,
         (char *(*)())d2i_PKCS12, bp, (unsigned char **)p12);
}
#ifndef NO_FP_API
PKCS12 *d2i_PKCS12_fp(FILE *fp, PKCS12 **p12)
{
        return (PKCS12 *)ASN1_d2i_fp((char *(*)())PKCS12_new, 
         (char *(*)())d2i_PKCS12, fp, (unsigned char **)(p12));
}
#endif

