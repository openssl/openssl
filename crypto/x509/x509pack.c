/* crypto/x509/x509pack.c */
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
#include "stack.h"
#include "cryptlib.h"
#include "asn1.h"
#include "objects.h"
#include "evp.h"
#include "x509.h"

ASN1_OCTET_STRING *X509v3_pack_string(ex,type,bytes,len)
ASN1_OCTET_STRING **ex;
int type;
unsigned char *bytes;
int len;
	{
	ASN1_OCTET_STRING *os;
	ASN1_STRING str;
	unsigned char *p;
	int i;

	if ((ex == NULL) || (*ex == NULL))
		os=ASN1_OCTET_STRING_new();
	else
		os= *ex;

	if (len < 0) len=strlen((char *)bytes);
	str.length=len;
	str.type=type;
	str.data=bytes;

	/* str now holds the data, we just have to copy it into ->value */

	switch (type)
		{
	case V_ASN1_BIT_STRING:
		i=i2d_ASN1_BIT_STRING((ASN1_BIT_STRING *)&str,NULL);
		if (!ASN1_STRING_set((ASN1_STRING *)os,NULL,i))
			goto err;
		p=(unsigned char *)os->data;
		i2d_ASN1_BIT_STRING((ASN1_BIT_STRING *)&str,&p);
		break;
	case V_ASN1_OCTET_STRING:
		i=i2d_ASN1_OCTET_STRING((ASN1_OCTET_STRING *)&str,NULL);
		if (!ASN1_STRING_set((ASN1_STRING *)os,NULL,i))
			goto err;
		p=(unsigned char *)os->data;
		i2d_ASN1_OCTET_STRING((ASN1_OCTET_STRING *)&str,&p);
		break;
	case V_ASN1_IA5STRING:
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_T61STRING:
		i=i2d_ASN1_bytes(&str,NULL,type,V_ASN1_UNIVERSAL);
		if (!ASN1_STRING_set((ASN1_STRING *)os,NULL,i))
			goto err;
		p=(unsigned char *)os->data;
		i=i2d_ASN1_bytes(&str,&p,type,V_ASN1_UNIVERSAL);
		break;
	default:
		X509err(X509_F_X509V3_PACK_STRING,X509_R_UNKNOWN_STRING_TYPE);
		goto err;
		}
	os->length=i;

	if ((ex != NULL) && (os != *ex))
		*ex=os;
	return(os);
err:
	return(NULL);
	}

ASN1_STRING *X509v3_unpack_string(ex,type,os)
ASN1_STRING **ex;
int type;
ASN1_OCTET_STRING *os;
	{
	unsigned char *p;
	ASN1_STRING *ret=NULL;

	p=os->data;
	switch (type)
		{
	case V_ASN1_BIT_STRING:
		ret=(ASN1_STRING *)d2i_ASN1_BIT_STRING(
			(ASN1_BIT_STRING **)ex,&p,os->length);
		break;
	case V_ASN1_OCTET_STRING:
		ret=(ASN1_STRING *)d2i_ASN1_OCTET_STRING(
			(ASN1_BIT_STRING **)ex,&p,os->length);
		break;
	case V_ASN1_IA5STRING:
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_T61STRING:
		ret=(ASN1_STRING *)d2i_ASN1_PRINTABLE(ex,&p,os->length);
		break;
	default:
		X509err(X509_F_X509V3_UNPACK_STRING,X509_R_UNKNOWN_STRING_TYPE);
		}
	return(ret);
	}

