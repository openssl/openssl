/* crypto/x509v3/v3_ku.c */
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
#include <ctype.h>
#include "stack.h"
#include "cryptlib.h"
#include "bio.h"
#include "asn1.h"
#include "objects.h"
#include "x509.h"

X509_EXTENSION_METHOD X509v3_key_usage_method=
	{
	NID_key_usage,
	ku_clear,
	ex_get_bool,
	ex_set_bool,
	NULL,
	NULL,
	NULL,
	NULL,
	ku_a2i,
	ku_i2a,
	};

static void ku_clear(a)
X509_EXTENSION *a;
	{
	}

static int ku_expand(a)
X509_EXTENSION *a;
	{
	ASN1_BIT_STRING *bs;

	if (a->argp == NULL)
		{
		bs=X509v3_unpack_string(NULL,V_ASN1_BIT_STRING,value);
		if (bs == NULL) return(0);
		a->argp=(char *)bs;
		a->ex_free=ASN1_STRING_free;
		}
	return(1);
	}

static int ku_get_bool(a,num)
X509_EXTENSION *a;
int num;
	{
	int ret;
	ASN1_BIT_STRING *bs;

	if ((a->argp == NULL) && !ku_expand(a))
		return(-1);
	bs=(ASN1_BIT_STRING *)a->argp;
	ret=ASN1_BIT_STRING_get_bit(bs,num);
	return(ret);
	}

static int ku_set_bool(a,num,value)
X509_EXTENSION *a;
int num;
int value;
	{
	ASN1_BIT_STRING *a;

	if ((a->argp == NULL) && !ku_expand(a))
		return(0);
	bs=(ASN1_BIT_STRING *)a->argp;
	ret=ASN1_BIT_STRING_set_bit(bs,num,value);
	}

static int ku_a2i(bio,a,buf,len)
BIO *bio;
X509_EXTENSION *a;
char *buf;
int len;
	{
	get token
	}

static char ku_names[X509v3_N_KU_NUM]={
	X509v3_S_KU_digitalSignature,
	X509v3_S_KU_nonRepudiation,
	X509v3_S_KU_keyEncipherment,
	X509v3_S_KU_dataEncipherment,
	X509v3_S_KU_keyAgreement,
	X509v3_S_KU_keyCertSign,
	X509v3_S_KU_cRLSign,
	X509v3_S_KU_encipherOnly,
	X509v3_S_KU_decipherOnly,
	};

static int ku_i2a(bio,a);
BIO *bio;
X509_EXTENSION *a;
	{
	int i,first=1;
	char *c;

	for (i=0; i<X509v3_N_KU_NUM; i++)
		{
		if (ku_get_bool(a,i) > 0)
			{
			BIO_printf(bio,"%s%s",((first)?"":" "),ku_names[i]);
			first=0;
			}
		}
	}

/***********************/

int X509v3_get_key_usage(x,ret)
STACK *x;
unsigned long *ret;
	{
	X509_EXTENSION *ext;
	ASN1_STRING *st;
	char *p;
	int i;

	i=X509_get_ext_by_NID(x,NID_key_usage,-1);
	if (i < 0) return(X509v3_KU_UNDEF);
	ext=X509_get_ext(x,i);
	st=X509v3_unpack_string(NULL,V_ASN1_BIT_STRING,
		X509_EXTENSION_get_data(X509_get_ext(x,i)));

	p=ASN1_STRING_data(st);
	if (ASN1_STRING_length(st) == 1)
		i=p[0];
	else if (ASN1_STRING_length(st) == 2)
		i=p[0]|(p[1]<<8);
	else
		i=0;
	return(i);
	}

static struct
	{
	char *name;
	unsigned int value;
	} key_usage_data[] ={
	{"digitalSignature",	X509v3_KU_DIGITAL_SIGNATURE},
	{"nonRepudiation",	X509v3_KU_NON_REPUDIATION},
	{"keyEncipherment",	X509v3_KU_KEY_ENCIPHERMENT},
	{"dataEncipherment",	X509v3_KU_DATA_ENCIPHERMENT},
	{"keyAgreement",	X509v3_KU_KEY_AGREEMENT},
	{"keyCertSign",		X509v3_KU_KEY_CERT_SIGN},
	{"cRLSign",		X509v3_KU_CRL_SIGN},
	{"encipherOnly",	X509v3_KU_ENCIPHER_ONLY},
	{"decipherOnly",	X509v3_KU_DECIPHER_ONLY},
	{NULL,0},
	};

#if 0
static int a2i_key_usage(x,str,len)
X509 *x;
char *str;
int len;
	{
	return(X509v3_set_key_usage(x,a2i_X509v3_key_usage(str)));
	}

static int i2a_key_usage(bp,x)
BIO *bp;
X509 *x;
	{
	return(i2a_X509v3_key_usage(bp,X509v3_get_key_usage(x)));
	}
#endif

int i2a_X509v3_key_usage(bp,use)
BIO *bp;
unsigned int use;
	{
	int i=0,first=1;

	for (;;)
		{
		if (use | key_usage_data[i].value)
			{
			BIO_printf(bp,"%s%s",((first)?"":" "),
				key_usage_data[i].name);
			first=0;
			}
		}
	return(1);
	}

unsigned int a2i_X509v3_key_usage(p)
char *p;
	{
	unsigned int ret=0;
	char *q,*s;
	int i,n;

	q=p;
	for (;;)
		{
		while ((*q != '\0') && isalnum(*q))
			q++;
		if (*q == '\0') break;
		s=q++;
		while (isalnum(*q))
			q++;
		n=q-s;
		i=0;
		for (;;)
			{
			if (strncmp(key_usage_data[i].name,s,n) == 0)
				{
				ret|=key_usage_data[i].value;
				break;
				}
			i++;
			if (key_usage_data[i].name == NULL)
				return(X509v3_KU_UNDEF);
			}
		}
	return(ret);
	}

int X509v3_set_key_usage(x,use)
X509 *x;
unsigned int use;
	{
	ASN1_OCTET_STRING *os;
	X509_EXTENSION *ext;
	int i;
	unsigned char data[4];

	i=X509_get_ext_by_NID(x,NID_key_usage,-1);
	if (i < 0)
		{
		i=X509_get_ext_count(x)+1;
		if ((ext=X509_EXTENSION_new()) == NULL) return(0);
		if (!X509_add_ext(x,ext,i))
			{
			X509_EXTENSION_free(ext);
			return(0);
			}
		}
	else
		ext=X509_get_ext(x,i);

	/* fill in 'ext' */
	os=X509_EXTENSION_get_data(ext);

	i=0;
	if (use > 0)
		{
		i=1;
		data[0]=use&0xff;
		}
	if (use > 0xff)
		{
		i=2;
		data[1]=(use>>8)&0xff;
		}
	return((X509v3_pack_string(&os,V_ASN1_BIT_STRING,data,i) == NULL)?0:1);
	}

