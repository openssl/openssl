/* crypto/x509/x509_cmp.c */
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
#include <sys/types.h>
#include <sys/stat.h>
#include "cryptlib.h"
#include "asn1.h"
#include "objects.h"
#include "x509.h"

int X509_issuer_and_serial_cmp(a,b)
X509 *a;
X509 *b;
	{
	int i;
	X509_CINF *ai,*bi;

	ai=a->cert_info;
	bi=b->cert_info;
	i=ASN1_INTEGER_cmp(ai->serialNumber,bi->serialNumber);
	if (i) return(i);
	return(X509_NAME_cmp(ai->issuer,bi->issuer));
	}

#ifndef NO_MD5
unsigned long X509_issuer_and_serial_hash(a)
X509 *a;
	{
	unsigned long ret=0;
	MD5_CTX ctx;
	unsigned char md[16];
	char str[256];

	X509_NAME_oneline(a->cert_info->issuer,str,256);
	ret=strlen(str);
	MD5_Init(&ctx);
	MD5_Update(&ctx,(unsigned char *)str,ret);
	MD5_Update(&ctx,(unsigned char *)a->cert_info->serialNumber->data,
		(unsigned long)a->cert_info->serialNumber->length);
	MD5_Final(&(md[0]),&ctx);
	ret=(	((unsigned long)md[0]     )|((unsigned long)md[1]<<8L)|
		((unsigned long)md[2]<<16L)|((unsigned long)md[3]<<24L)
		)&0xffffffffL;
	return(ret);
	}
#endif
	
int X509_issuer_name_cmp(a, b)
X509 *a;
X509 *b;
	{
	return(X509_NAME_cmp(a->cert_info->issuer,b->cert_info->issuer));
	}

int X509_subject_name_cmp(a, b)
X509 *a;
X509 *b;
	{
	return(X509_NAME_cmp(a->cert_info->subject,b->cert_info->subject));
	}

int X509_CRL_cmp(a, b)
X509_CRL *a;
X509_CRL *b;
	{
	return(X509_NAME_cmp(a->crl->issuer,b->crl->issuer));
	}

X509_NAME *X509_get_issuer_name(a)
X509 *a;
	{
	return(a->cert_info->issuer);
	}

unsigned long X509_issuer_name_hash(x)
X509 *x;
	{
	return(X509_NAME_hash(x->cert_info->issuer));
	}

X509_NAME *X509_get_subject_name(a)
X509 *a;
	{
	return(a->cert_info->subject);
	}

ASN1_INTEGER *X509_get_serialNumber(a)
X509 *a;
	{
	return(a->cert_info->serialNumber);
	}

unsigned long X509_subject_name_hash(x)
X509 *x;
	{
	return(X509_NAME_hash(x->cert_info->subject));
	}

int X509_NAME_cmp(a, b)
X509_NAME *a;
X509_NAME *b;
	{
	int i,j;
	X509_NAME_ENTRY *na,*nb;

	if (sk_num(a->entries) != sk_num(b->entries))
		return(sk_num(a->entries)-sk_num(b->entries));
	for (i=sk_num(a->entries)-1; i>=0; i--)
		{
		na=(X509_NAME_ENTRY *)sk_value(a->entries,i);
		nb=(X509_NAME_ENTRY *)sk_value(b->entries,i);
		j=na->value->length-nb->value->length;
		if (j) return(j);
		j=memcmp(na->value->data,nb->value->data,
			na->value->length);
		if (j) return(j);
		j=na->set-nb->set;
		if (j) return(j);
		}

	/* We will check the object types after checking the values
	 * since the values will more often be different than the object
	 * types. */
	for (i=sk_num(a->entries)-1; i>=0; i--)
		{
		na=(X509_NAME_ENTRY *)sk_value(a->entries,i);
		nb=(X509_NAME_ENTRY *)sk_value(b->entries,i);
		j=OBJ_cmp(na->object,nb->object);
		if (j) return(j);
		}
	return(0);
	}

#ifndef NO_MD5
/* I now DER encode the name and hash it.  Since I cache the DER encoding,
 * this is reasonably effiecent. */
unsigned long X509_NAME_hash(x)
X509_NAME *x;
	{
	unsigned long ret=0;
	unsigned char md[16];
	unsigned char str[256],*p,*pp;
	int i;

	i=i2d_X509_NAME(x,NULL);
	if (i > sizeof(str))
		p=Malloc(i);
	else
		p=str;

	pp=p;
	i2d_X509_NAME(x,&pp);
	MD5((unsigned char *)p,i,&(md[0]));
	if (p != str) Free(p);

	ret=(	((unsigned long)md[0]     )|((unsigned long)md[1]<<8L)|
		((unsigned long)md[2]<<16L)|((unsigned long)md[3]<<24L)
		)&0xffffffffL;
	return(ret);
	}
#endif

/* Search a stack of X509 for a match */
X509 *X509_find_by_issuer_and_serial(sk,name,serial)
STACK *sk;
X509_NAME *name;
ASN1_INTEGER *serial;
	{
	int i;
	X509_CINF cinf;
	X509 x,*x509=NULL;

	x.cert_info= &cinf;
	cinf.serialNumber=serial;
	cinf.issuer=name;

	for (i=0; i<sk_num(sk); i++)
		{
		x509=(X509 *)sk_value(sk,i);
		if (X509_issuer_and_serial_cmp(x509,&x) == 0)
			return(x509);
		}
	return(NULL);
	}

X509 *X509_find_by_subject(sk,name)
STACK *sk;
X509_NAME *name;
	{
	X509 *x509;
	int i;

	for (i=0; i<sk_num(sk); i++)
		{
		x509=(X509 *)sk_value(sk,i);
		if (X509_NAME_cmp(X509_get_subject_name(x509),name) == 0)
			return(x509);
		}
	return(NULL);
	}

