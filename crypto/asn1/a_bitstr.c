/* crypto/asn1/a_bitstr.c */
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
#include "asn1.h"

/* ASN1err(ASN1_F_ASN1_STRING_NEW,ASN1_R_STRING_TOO_SHORT);
 * ASN1err(ASN1_F_D2I_ASN1_BIT_STRING,ASN1_R_EXPECTING_A_BIT_STRING);
 */

int i2d_ASN1_BIT_STRING(a,pp)
ASN1_BIT_STRING *a;
unsigned char **pp;
	{
	int ret,j,r,bits;
	unsigned char *p,*d;

	if (a == NULL) return(0);

	/* our bit strings are always a multiple of 8 :-) */
	bits=0;
	ret=1+a->length;
	r=ASN1_object_size(0,ret,V_ASN1_BIT_STRING);
	if (pp == NULL) return(r);
	p= *pp;

	ASN1_put_object(&p,0,ret,V_ASN1_BIT_STRING,V_ASN1_UNIVERSAL);
	if (bits == 0)
		j=0;
	else	j=8-bits;
	*(p++)=(unsigned char)j;
	d=a->data;
	memcpy(p,d,a->length);
	p+=a->length;
	if (a->length > 0) p[-1]&=(0xff<<j);
	*pp=p;
	return(r);
	}

ASN1_BIT_STRING *d2i_ASN1_BIT_STRING(a, pp, length)
ASN1_BIT_STRING **a;
unsigned char **pp;
long length;
	{
	ASN1_BIT_STRING *ret=NULL;
	unsigned char *p,*s;
	long len;
	int inf,tag,xclass;
	int i;

	if ((a == NULL) || ((*a) == NULL))
		{
		if ((ret=ASN1_BIT_STRING_new()) == NULL) return(NULL);
		}
	else
		ret=(*a);

	p= *pp;
	inf=ASN1_get_object(&p,&len,&tag,&xclass,length);
	if (inf & 0x80)
		{
		i=ASN1_R_BAD_OBJECT_HEADER;
		goto err;
		}

	if (tag != V_ASN1_BIT_STRING)
		{
		i=ASN1_R_EXPECTING_A_BIT_STRING;
		goto err;
		}
	if (len < 1) { i=ASN1_R_STRING_TOO_SHORT; goto err; }

	i= *(p++);
	if (len-- > 1) /* using one because of the bits left byte */
		{
		s=(unsigned char *)Malloc((int)len);
		if (s == NULL)
			{
			i=ERR_R_MALLOC_FAILURE;
			goto err;
			}
		memcpy(s,p,(int)len);
		s[len-1]&=(0xff<<i);
		p+=len;
		}
	else
		s=NULL;

	ret->length=(int)len;
	if (ret->data != NULL) Free((char *)ret->data);
	ret->data=s;
	ret->type=V_ASN1_BIT_STRING;
	if (a != NULL) (*a)=ret;
	*pp=p;
	return(ret);
err:
	ASN1err(ASN1_F_D2I_ASN1_BIT_STRING,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		ASN1_BIT_STRING_free(ret);
	return(NULL);
	}

/* These next 2 functions from Goetz Babin-Ebell <babinebell@trustcenter.de>
 */
int ASN1_BIT_STRING_set_bit(a,n,value)
ASN1_BIT_STRING *a;
int n;
int value;
	{
	int w,v,iv;
	unsigned char *c;

	w=n/8;
	v=1<<(7-(n&0x07));
	iv= ~v;

	if (a == NULL) return(0);
	if ((a->length < (w+1)) || (a->data == NULL))
		{
		if (!value) return(1); /* Don't need to set */
		if (a->data == NULL)
			c=(unsigned char *)Malloc(w+1);
		else
			c=(unsigned char *)Realloc(a->data,w+1);
		if (c == NULL) return(0);
		a->data=c;
		a->length=w+1;
		c[w]=0;
		}
	a->data[w]=((a->data[w])&iv)|v;
	while ((a->length > 0) && (a->data[a->length-1] == 0))
		a->length--;
	return(1);
	}

int ASN1_BIT_STRING_get_bit(a,n)
ASN1_BIT_STRING *a;
int n;
	{
	int w,v;

	w=n/8;
	v=1<<(7-(n&0x07));
	if ((a == NULL) || (a->length < (w+1)) || (a->data == NULL))
		return(0);
	return((a->data[w]&v) != 0);
	}

