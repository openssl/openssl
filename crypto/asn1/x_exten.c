/* crypto/asn1/x_exten.c */
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
#include <openssl/objects.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>

int i2d_X509_EXTENSION(X509_EXTENSION *a, unsigned char **pp)
	{
	int k=0;
	int r=0,ret=0;
	unsigned char **p=NULL;

	if (a == NULL) return(0);

	p=NULL;
	for (;;)
		{
		if (k)
			{
			r=ASN1_object_size(1,ret,V_ASN1_SEQUENCE);
			if (pp == NULL) return(r);
			p=pp;
			ASN1_put_object(p,1,ret,V_ASN1_SEQUENCE,
				V_ASN1_UNIVERSAL);
			}

		ret+=i2d_ASN1_OBJECT(a->object,p);
		if ((a->critical) || a->netscape_hack)
			ret+=i2d_ASN1_BOOLEAN(a->critical,p);
		ret+=i2d_ASN1_OCTET_STRING(a->value,p);
		if (k++) return(r);
		}
	}

X509_EXTENSION *d2i_X509_EXTENSION(X509_EXTENSION **a, unsigned char **pp,
	     long length)
	{
	int i;
	M_ASN1_D2I_vars(a,X509_EXTENSION *,X509_EXTENSION_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->object,d2i_ASN1_OBJECT);

	ret->netscape_hack=0;
	if ((c.slen != 0) &&
		(M_ASN1_next == (V_ASN1_UNIVERSAL|V_ASN1_BOOLEAN)))
		{
		c.q=c.p;
		if (d2i_ASN1_BOOLEAN(&i,&c.p,c.slen) < 0) goto err;
		ret->critical=i;
		c.slen-=(c.p-c.q);
		if (ret->critical == 0) ret->netscape_hack=1;
		}
	M_ASN1_D2I_get(ret->value,d2i_ASN1_OCTET_STRING);

	M_ASN1_D2I_Finish(a,X509_EXTENSION_free,ASN1_F_D2I_X509_EXTENSION);
	}

X509_EXTENSION *X509_EXTENSION_new(void)
	{
	X509_EXTENSION *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,X509_EXTENSION);
	ret->object=OBJ_nid2obj(NID_undef);
	M_ASN1_New(ret->value,M_ASN1_OCTET_STRING_new);
	ret->critical=0;
	ret->netscape_hack=0;
	return(ret);
	M_ASN1_New_Error(ASN1_F_X509_EXTENSION_NEW);
	}
	
void X509_EXTENSION_free(X509_EXTENSION *a)
	{
	if (a == NULL) return;
	ASN1_OBJECT_free(a->object);
	M_ASN1_OCTET_STRING_free(a->value);
	OPENSSL_free(a);
	}

