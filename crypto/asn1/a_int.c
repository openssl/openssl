/* crypto/asn1/a_int.c */
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

/* ASN1err(ASN1_F_D2I_ASN1_INTEGER,ASN1_R_EXPECTING_AN_INTEGER);
 */

int i2d_ASN1_INTEGER(a,pp)
ASN1_INTEGER *a;
unsigned char **pp;
	{
	int pad=0,ret,r,i,t;
	unsigned char *p,*pt,*n,pb=0;

	if ((a == NULL) || (a->data == NULL)) return(0);
	t=a->type;
	if (a->length == 0)
		ret=1;
	else
		{
		ret=a->length;
		i=a->data[0];
		if ((t == V_ASN1_INTEGER) && (i > 127))
			{
			pad=1;
			pb=0;
			}
		else if ((t == V_ASN1_NEG_INTEGER) && (i>128))
			{
			pad=1;
			pb=0xFF;
			}
		ret+=pad;
		}
	r=ASN1_object_size(0,ret,V_ASN1_INTEGER);
	if (pp == NULL) return(r);
	p= *pp;

	ASN1_put_object(&p,0,ret,V_ASN1_INTEGER,V_ASN1_UNIVERSAL);
	if (pad) *(p++)=pb;
	if (a->length == 0)
		*(p++)=0;
	else if (t == V_ASN1_INTEGER)
		{
		memcpy(p,a->data,(unsigned int)a->length);
		p+=a->length;
		}
	else
		{
		n=a->data;
		pt=p;
		for (i=a->length; i>0; i--)
			*(p++)= (*(n++)^0xFF)+1;
		if (!pad) *pt|=0x80;
		}

	*pp=p;
	return(r);
	}

ASN1_INTEGER *d2i_ASN1_INTEGER(a, pp, length)
ASN1_INTEGER **a;
unsigned char **pp;
long length;
	{
	ASN1_INTEGER *ret=NULL;
	unsigned char *p,*to,*s;
	long len;
	int inf,tag,xclass;
	int i;

	if ((a == NULL) || ((*a) == NULL))
		{
		if ((ret=ASN1_INTEGER_new()) == NULL) return(NULL);
		ret->type=V_ASN1_INTEGER;
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

	if (tag != V_ASN1_INTEGER)
		{
		i=ASN1_R_EXPECTING_AN_INTEGER;
		goto err;
		}

	/* We must Malloc stuff, even for 0 bytes otherwise it
	 * signifies a missing NULL parameter. */
	s=(unsigned char *)Malloc((int)len+1);
	if (s == NULL)
		{
		i=ERR_R_MALLOC_FAILURE;
		goto err;
		}
	to=s;
	if (*p & 0x80) /* a negative number */
		{
		ret->type=V_ASN1_NEG_INTEGER;
		if (*p == 0xff)
			{
			p++;
			len--;
			}
		for (i=(int)len; i>0; i--)
			*(to++)= (*(p++)^0xFF)+1;
		}
	else
		{
		ret->type=V_ASN1_INTEGER;
		if ((*p == 0) && (len != 1))
			{
			p++;
			len--;
			}
		memcpy(s,p,(int)len);
		p+=len;
		}

	if (ret->data != NULL) Free((char *)ret->data);
	ret->data=s;
	ret->length=(int)len;
	if (a != NULL) (*a)=ret;
	*pp=p;
	return(ret);
err:
	ASN1err(ASN1_F_D2I_ASN1_INTEGER,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		ASN1_INTEGER_free(ret);
	return(NULL);
	}

int ASN1_INTEGER_set(a,v)
ASN1_INTEGER *a;
long v;
	{
	int i,j,k;
	unsigned char buf[sizeof(long)+1];
	long d;

	a->type=V_ASN1_INTEGER;
	if (a->length < (sizeof(long)+1))
		{
		if (a->data != NULL)
			Free((char *)a->data);
		if ((a->data=(unsigned char *)Malloc(sizeof(long)+1)) != NULL)
			memset((char *)a->data,0,sizeof(long)+1);
		}
	if (a->data == NULL)
		{
		ASN1err(ASN1_F_ASN1_INTEGER_SET,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	d=v;
	if (d < 0)
		{
		d= -d;
		a->type=V_ASN1_NEG_INTEGER;
		}

	for (i=0; i<sizeof(long); i++)
		{
		if (d == 0) break;
		buf[i]=(int)d&0xff;
		d>>=8;
		}
	j=0;
	if (v < 0) a->data[j++]=0;
	for (k=i-1; k >=0; k--)
		a->data[j++]=buf[k];
	a->length=j;
	return(1);
	}

long ASN1_INTEGER_get(a)
ASN1_INTEGER *a;
	{
	int neg=0,i;
	long r=0;

	if (a == NULL) return(0L);
	i=a->type;
	if (i == V_ASN1_NEG_INTEGER)
		neg=1;
	else if (i != V_ASN1_INTEGER)
		return(0);
	
	if (a->length > sizeof(long))
		{
		/* hmm... a bit ugly */
		return(0xffffffffL);
		}
	if (a->data == NULL)
		return(0);

	for (i=0; i<a->length; i++)
		{
		r<<=8;
		r|=(unsigned char)a->data[i];
		}
	if (neg) r= -r;
	return(r);
	}

ASN1_INTEGER *BN_to_ASN1_INTEGER(bn,ai)
BIGNUM *bn;
ASN1_INTEGER *ai;
	{
	ASN1_INTEGER *ret;
	int len,j;

	if (ai == NULL)
		ret=ASN1_INTEGER_new();
	else
		ret=ai;
	if (ret == NULL)
		{
		ASN1err(ASN1_F_BN_TO_ASN1_INTEGER,ASN1_R_ERROR_STACK);
		goto err;
		}
	ret->type=V_ASN1_INTEGER;
	j=BN_num_bits(bn);
	len=((j == 0)?0:((j/8)+1));
	ret->data=(unsigned char *)Malloc(len+4);
	ret->length=BN_bn2bin(bn,ret->data);
	return(ret);
err:
	if (ret != ai) ASN1_INTEGER_free(ret);
	return(NULL);
	}

BIGNUM *ASN1_INTEGER_to_BN(ai,bn)
ASN1_INTEGER *ai;
BIGNUM *bn;
	{
	BIGNUM *ret;

	if ((ret=BN_bin2bn(ai->data,ai->length,bn)) == NULL)
		ASN1err(ASN1_F_ASN1_INTEGER_TO_BN,ASN1_R_BN_LIB);
	return(ret);
	}
