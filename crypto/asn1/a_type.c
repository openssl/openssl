/* crypto/asn1/a_type.c */
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
#include <openssl/asn1_mac.h>

static void ASN1_TYPE_component_free(ASN1_TYPE *a);
int i2d_ASN1_TYPE(ASN1_TYPE *a, unsigned char **pp)
	{
	int r=0;

	if (a == NULL) return(0);

	switch (a->type)
		{
	case V_ASN1_NULL:
		if (pp != NULL)
			ASN1_put_object(pp,0,0,V_ASN1_NULL,V_ASN1_UNIVERSAL);
		r=2;
		break;
	case V_ASN1_INTEGER:
	case V_ASN1_NEG_INTEGER:
		r=i2d_ASN1_INTEGER(a->value.integer,pp);
		break;
	case V_ASN1_ENUMERATED:
	case V_ASN1_NEG_ENUMERATED:
		r=i2d_ASN1_ENUMERATED(a->value.enumerated,pp);
		break;
	case V_ASN1_BIT_STRING:
		r=i2d_ASN1_BIT_STRING(a->value.bit_string,pp);
		break;
	case V_ASN1_OCTET_STRING:
		r=i2d_ASN1_OCTET_STRING(a->value.octet_string,pp);
		break;
	case V_ASN1_OBJECT:
		r=i2d_ASN1_OBJECT(a->value.object,pp);
		break;
	case V_ASN1_PRINTABLESTRING:
		r=M_i2d_ASN1_PRINTABLESTRING(a->value.printablestring,pp);
		break;
	case V_ASN1_T61STRING:
		r=M_i2d_ASN1_T61STRING(a->value.t61string,pp);
		break;
	case V_ASN1_IA5STRING:
		r=M_i2d_ASN1_IA5STRING(a->value.ia5string,pp);
		break;
	case V_ASN1_GENERALSTRING:
		r=M_i2d_ASN1_GENERALSTRING(a->value.generalstring,pp);
		break;
	case V_ASN1_UNIVERSALSTRING:
		r=M_i2d_ASN1_UNIVERSALSTRING(a->value.universalstring,pp);
		break;
	case V_ASN1_UTF8STRING:
		r=M_i2d_ASN1_UTF8STRING(a->value.utf8string,pp);
		break;
	case V_ASN1_VISIBLESTRING:
		r=M_i2d_ASN1_VISIBLESTRING(a->value.visiblestring,pp);
		break;
	case V_ASN1_BMPSTRING:
		r=M_i2d_ASN1_BMPSTRING(a->value.bmpstring,pp);
		break;
	case V_ASN1_UTCTIME:
		r=i2d_ASN1_UTCTIME(a->value.utctime,pp);
		break;
	case V_ASN1_GENERALIZEDTIME:
		r=i2d_ASN1_GENERALIZEDTIME(a->value.generalizedtime,pp);
		break;
	case V_ASN1_SET:
	case V_ASN1_SEQUENCE:
	case V_ASN1_OTHER:
	default:
		if (a->value.set == NULL)
			r=0;
		else
			{
			r=a->value.set->length;
			if (pp != NULL)
				{
				memcpy(*pp,a->value.set->data,r);
				*pp+=r;
				}
			}
		break;
		}
	return(r);
	}

ASN1_TYPE *d2i_ASN1_TYPE(ASN1_TYPE **a, unsigned char **pp, long length)
	{
	ASN1_TYPE *ret=NULL;
	unsigned char *q,*p,*max;
	int inf,tag,xclass;
	long len;

	if ((a == NULL) || ((*a) == NULL))
		{
		if ((ret=ASN1_TYPE_new()) == NULL) goto err;
		}
	else
		ret=(*a);

	p= *pp;
	q=p;
	max=(p+length);

	inf=ASN1_get_object(&q,&len,&tag,&xclass,length);
	if (inf & 0x80) goto err;
	/* If not universal tag we've no idea what it is */
	if(xclass != V_ASN1_UNIVERSAL) tag = V_ASN1_OTHER;
	
	ASN1_TYPE_component_free(ret);

	switch (tag)
		{
	case V_ASN1_NULL:
		p=q;
		ret->value.ptr=NULL;
		break;
	case V_ASN1_INTEGER:
		if ((ret->value.integer=
			d2i_ASN1_INTEGER(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_ENUMERATED:
		if ((ret->value.enumerated=
			d2i_ASN1_ENUMERATED(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_BIT_STRING:
		if ((ret->value.bit_string=
			d2i_ASN1_BIT_STRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_OCTET_STRING:
		if ((ret->value.octet_string=
			d2i_ASN1_OCTET_STRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_VISIBLESTRING:
		if ((ret->value.visiblestring=
			d2i_ASN1_VISIBLESTRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_UTF8STRING:
		if ((ret->value.utf8string=
			d2i_ASN1_UTF8STRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_OBJECT:
		if ((ret->value.object=
			d2i_ASN1_OBJECT(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_PRINTABLESTRING:
		if ((ret->value.printablestring=
			d2i_ASN1_PRINTABLESTRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_T61STRING:
		if ((ret->value.t61string=
			M_d2i_ASN1_T61STRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_IA5STRING:
		if ((ret->value.ia5string=
			M_d2i_ASN1_IA5STRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_GENERALSTRING:
		if ((ret->value.generalstring=
			M_d2i_ASN1_GENERALSTRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_UNIVERSALSTRING:
		if ((ret->value.universalstring=
			M_d2i_ASN1_UNIVERSALSTRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_BMPSTRING:
		if ((ret->value.bmpstring=
			M_d2i_ASN1_BMPSTRING(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_UTCTIME:
		if ((ret->value.utctime=
			d2i_ASN1_UTCTIME(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_GENERALIZEDTIME:
		if ((ret->value.generalizedtime=
			d2i_ASN1_GENERALIZEDTIME(NULL,&p,max-p)) == NULL)
			goto err;
		break;
	case V_ASN1_SET:
	case V_ASN1_SEQUENCE:
	case V_ASN1_OTHER:
	default:
		/* Sets and sequences are left complete */
		if ((ret->value.set=ASN1_STRING_new()) == NULL) goto err;
		ret->value.set->type=tag;
		len+=(q-p);
		if (!ASN1_STRING_set(ret->value.set,p,(int)len)) goto err;
		p+=len;
		break;
		}

	ret->type=tag;
	if (a != NULL) (*a)=ret;
	*pp=p;
	return(ret);
err:
	if ((ret != NULL) && ((a == NULL) || (*a != ret))) ASN1_TYPE_free(ret);
	return(NULL);
	}

ASN1_TYPE *ASN1_TYPE_new(void)
	{
	ASN1_TYPE *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,ASN1_TYPE);
	ret->type= -1;
	ret->value.ptr=NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_ASN1_TYPE_NEW);
	}

void ASN1_TYPE_free(ASN1_TYPE *a)
	{
	if (a == NULL) return;
	ASN1_TYPE_component_free(a);
	OPENSSL_free(a);
	}

int ASN1_TYPE_get(ASN1_TYPE *a)
	{
	if (a->value.ptr != NULL)
		return(a->type);
	else
		return(0);
	}

void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value)
	{
	if (a->value.ptr != NULL)
		ASN1_TYPE_component_free(a);
	a->type=type;
	a->value.ptr=value;
	}

static void ASN1_TYPE_component_free(ASN1_TYPE *a)
	{
	if (a == NULL) return;

	if (a->value.ptr != NULL)
		{
		switch (a->type)
			{
		case V_ASN1_OBJECT:
			ASN1_OBJECT_free(a->value.object);
			break;
		case V_ASN1_NULL:
			break;
		case V_ASN1_INTEGER:
		case V_ASN1_NEG_INTEGER:
		case V_ASN1_ENUMERATED:
		case V_ASN1_NEG_ENUMERATED:
		case V_ASN1_BIT_STRING:
		case V_ASN1_OCTET_STRING:
		case V_ASN1_SEQUENCE:
		case V_ASN1_SET:
		case V_ASN1_NUMERICSTRING:
		case V_ASN1_PRINTABLESTRING:
		case V_ASN1_T61STRING:
		case V_ASN1_VIDEOTEXSTRING:
		case V_ASN1_IA5STRING:
		case V_ASN1_UTCTIME:
		case V_ASN1_GENERALIZEDTIME:
		case V_ASN1_GRAPHICSTRING:
		case V_ASN1_VISIBLESTRING:
		case V_ASN1_GENERALSTRING:
		case V_ASN1_UNIVERSALSTRING:
		case V_ASN1_BMPSTRING:
		case V_ASN1_UTF8STRING:
		case V_ASN1_OTHER:
		default:
			ASN1_STRING_free((ASN1_STRING *)a->value.ptr);
			break;
			}
		a->type=0;
		a->value.ptr=NULL;
		}
	}

IMPLEMENT_STACK_OF(ASN1_TYPE)
IMPLEMENT_ASN1_SET_OF(ASN1_TYPE)
