/* crypto/asn1/t_x509.c */
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
#include <openssl/buffer.h>
#include <openssl/bn.h>
#ifndef NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef NO_DSA
#include <openssl/dsa.h>
#endif
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef NO_FP_API
int X509_print_fp(FILE *fp, X509 *x)
        {
        BIO *b;
        int ret;

        if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		X509err(X509_F_X509_PRINT_FP,ERR_R_BUF_LIB);
                return(0);
		}
        BIO_set_fp(b,fp,BIO_NOCLOSE);
        ret=X509_print(b, x);
        BIO_free(b);
        return(ret);
        }
#endif

int X509_print(BIO *bp, X509 *x)
	{
	long l;
	int ret=0,i,j,n;
	char *m=NULL,*s;
	X509_CINF *ci;
	ASN1_INTEGER *bs;
	EVP_PKEY *pkey=NULL;
	const char *neg;
	X509_EXTENSION *ex;
	ASN1_STRING *str=NULL;

	ci=x->cert_info;
	if (BIO_write(bp,"Certificate:\n",13) <= 0) goto err;
	if (BIO_write(bp,"    Data:\n",10) <= 0) goto err;
	l=X509_get_version(x);
	if (BIO_printf(bp,"%8sVersion: %lu (0x%lx)\n","",l+1,l) <= 0) goto err;
	if (BIO_write(bp,"        Serial Number:",22) <= 0) goto err;

	bs=X509_get_serialNumber(x);
	if (bs->length <= 4)
		{
		l=ASN1_INTEGER_get(bs);
		if (l < 0)
			{
			l= -l;
			neg="-";
			}
		else
			neg="";
		if (BIO_printf(bp," %s%lu (%s0x%lx)\n",neg,l,neg,l) <= 0)
			goto err;
		}
	else
		{
		neg=(bs->type == V_ASN1_NEG_INTEGER)?" (Negative)":"";
		if (BIO_printf(bp,"\n%12s%s","",neg) <= 0) goto err;

		for (i=0; i<bs->length; i++)
			{
			if (BIO_printf(bp,"%02x%c",bs->data[i],
				((i+1 == bs->length)?'\n':':')) <= 0)
				goto err;
			}
		}

	i=OBJ_obj2nid(ci->signature->algorithm);
	if (BIO_printf(bp,"%8sSignature Algorithm: %s\n","",
		(i == NID_undef)?"UNKNOWN":OBJ_nid2ln(i)) <= 0)
		goto err;

	if (BIO_write(bp,"        Issuer: ",16) <= 0) goto err;
	if (!X509_NAME_print(bp,X509_get_issuer_name(x),16)) goto err;
	if (BIO_write(bp,"\n        Validity\n",18) <= 0) goto err;
	if (BIO_write(bp,"            Not Before: ",24) <= 0) goto err;
	if (!ASN1_TIME_print(bp,X509_get_notBefore(x))) goto err;
	if (BIO_write(bp,"\n            Not After : ",25) <= 0) goto err;
	if (!ASN1_TIME_print(bp,X509_get_notAfter(x))) goto err;
	if (BIO_write(bp,"\n        Subject: ",18) <= 0) goto err;
	if (!X509_NAME_print(bp,X509_get_subject_name(x),16)) goto err;
	if (BIO_write(bp,"\n        Subject Public Key Info:\n",34) <= 0)
		goto err;
	i=OBJ_obj2nid(ci->key->algor->algorithm);
	if (BIO_printf(bp,"%12sPublic Key Algorithm: %s\n","",
		(i == NID_undef)?"UNKNOWN":OBJ_nid2ln(i)) <= 0) goto err;

	pkey=X509_get_pubkey(x);
	if (pkey == NULL)
		{
		BIO_printf(bp,"%12sUnable to load Public Key\n","");
		ERR_print_errors(bp);
		}
	else
#ifndef NO_RSA
	if (pkey->type == EVP_PKEY_RSA)
		{
		BIO_printf(bp,"%12sRSA Public Key: (%d bit)\n","",
		BN_num_bits(pkey->pkey.rsa->n));
		RSA_print(bp,pkey->pkey.rsa,16);
		}
	else
#endif
#ifndef NO_DSA
	if (pkey->type == EVP_PKEY_DSA)
		{
		BIO_printf(bp,"%12sDSA Public Key:\n","");
		DSA_print(bp,pkey->pkey.dsa,16);
		}
	else
#endif
		BIO_printf(bp,"%12sUnknown Public Key:\n","");

	EVP_PKEY_free(pkey);

	n=X509_get_ext_count(x);
	if (n > 0)
		{
		BIO_printf(bp,"%8sX509v3 extensions:\n","");
		for (i=0; i<n; i++)
			{
#if 0
			int data_type,pack_type;
#endif
			ASN1_OBJECT *obj;

			ex=X509_get_ext(x,i);
			if (BIO_printf(bp,"%12s","") <= 0) goto err;
			obj=X509_EXTENSION_get_object(ex);
			i2a_ASN1_OBJECT(bp,obj);
			j=X509_EXTENSION_get_critical(ex);
			if (BIO_printf(bp,": %s\n",j?"critical":"","") <= 0)
				goto err;
			if(!X509V3_EXT_print(bp, ex, 0, 16))
				{
				BIO_printf(bp, "%16s", "");
				ASN1_OCTET_STRING_print(bp,ex->value);
				}
			if (BIO_write(bp,"\n",1) <= 0) goto err;
			}
		}

	i=OBJ_obj2nid(x->sig_alg->algorithm);
	if (BIO_printf(bp,"%4sSignature Algorithm: %s","",
		(i == NID_undef)?"UNKNOWN":OBJ_nid2ln(i)) <= 0) goto err;

	n=x->signature->length;
	s=(char *)x->signature->data;
	for (i=0; i<n; i++)
		{
		if ((i%18) == 0)
			if (BIO_write(bp,"\n        ",9) <= 0) goto err;
		if (BIO_printf(bp,"%02x%s",(unsigned char)s[i],
			((i+1) == n)?"":":") <= 0) goto err;
		}
	if (BIO_write(bp,"\n",1) != 1) goto err;
	ret=1;
err:
	if (str != NULL) ASN1_STRING_free(str);
	if (m != NULL) Free((char *)m);
	return(ret);
	}

int ASN1_STRING_print(BIO *bp, ASN1_STRING *v)
	{
	int i,n;
	char buf[80],*p;;

	if (v == NULL) return(0);
	n=0;
	p=(char *)v->data;
	for (i=0; i<v->length; i++)
		{
		if ((p[i] > '~') || ((p[i] < ' ') &&
			(p[i] != '\n') && (p[i] != '\r')))
			buf[n]='.';
		else
			buf[n]=p[i];
		n++;
		if (n >= 80)
			{
			if (BIO_write(bp,buf,n) <= 0)
				return(0);
			n=0;
			}
		}
	if (n > 0)
		if (BIO_write(bp,buf,n) <= 0)
			return(0);
	return(1);
	}

int ASN1_TIME_print(BIO *bp, ASN1_TIME *tm)
{
	if(tm->type == V_ASN1_UTCTIME) return ASN1_UTCTIME_print(bp, tm);
	if(tm->type == V_ASN1_GENERALIZEDTIME)
				return ASN1_GENERALIZEDTIME_print(bp, tm);
	BIO_write(bp,"Bad time value",14);
	return(0);
}

static const char *mon[12]=
    {
    "Jan","Feb","Mar","Apr","May","Jun",
    "Jul","Aug","Sep","Oct","Nov","Dec"
    };

int ASN1_GENERALIZEDTIME_print(BIO *bp, ASN1_GENERALIZEDTIME *tm)
	{
	char *v;
	int gmt=0;
	int i;
	int y=0,M=0,d=0,h=0,m=0,s=0;

	i=tm->length;
	v=(char *)tm->data;

	if (i < 12) goto err;
	if (v[i-1] == 'Z') gmt=1;
	for (i=0; i<12; i++)
		if ((v[i] > '9') || (v[i] < '0')) goto err;
	y= (v[0]-'0')*1000+(v[1]-'0')*100 + (v[2]-'0')*10+(v[3]-'0');
	M= (v[4]-'0')*10+(v[5]-'0');
	if ((M > 12) || (M < 1)) goto err;
	d= (v[6]-'0')*10+(v[7]-'0');
	h= (v[8]-'0')*10+(v[9]-'0');
	m=  (v[10]-'0')*10+(v[11]-'0');
	if (	(v[12] >= '0') && (v[12] <= '9') &&
		(v[13] >= '0') && (v[13] <= '9'))
		s=  (v[12]-'0')*10+(v[13]-'0');

	if (BIO_printf(bp,"%s %2d %02d:%02d:%02d %d%s",
		mon[M-1],d,h,m,s,y,(gmt)?" GMT":"") <= 0)
		return(0);
	else
		return(1);
err:
	BIO_write(bp,"Bad time value",14);
	return(0);
	}

int ASN1_UTCTIME_print(BIO *bp, ASN1_UTCTIME *tm)
	{
	char *v;
	int gmt=0;
	int i;
	int y=0,M=0,d=0,h=0,m=0,s=0;

	i=tm->length;
	v=(char *)tm->data;

	if (i < 10) goto err;
	if (v[i-1] == 'Z') gmt=1;
	for (i=0; i<10; i++)
		if ((v[i] > '9') || (v[i] < '0')) goto err;
	y= (v[0]-'0')*10+(v[1]-'0');
	if (y < 50) y+=100;
	M= (v[2]-'0')*10+(v[3]-'0');
	if ((M > 12) || (M < 1)) goto err;
	d= (v[4]-'0')*10+(v[5]-'0');
	h= (v[6]-'0')*10+(v[7]-'0');
	m=  (v[8]-'0')*10+(v[9]-'0');
	if (	(v[10] >= '0') && (v[10] <= '9') &&
		(v[11] >= '0') && (v[11] <= '9'))
		s=  (v[10]-'0')*10+(v[11]-'0');

	if (BIO_printf(bp,"%s %2d %02d:%02d:%02d %d%s",
		mon[M-1],d,h,m,s,y+1900,(gmt)?" GMT":"") <= 0)
		return(0);
	else
		return(1);
err:
	BIO_write(bp,"Bad time value",14);
	return(0);
	}

int X509_NAME_print(BIO *bp, X509_NAME *name, int obase)
	{
	char *s,*c;
	int ret=0,l,ll,i,first=1;
	char buf[256];

	ll=80-2-obase;

	s=X509_NAME_oneline(name,buf,256);
	s++; /* skip the first slash */

	l=ll;
	c=s;
	for (;;)
		{
#ifndef CHARSET_EBCDIC
		if (	((*s == '/') &&
				((s[1] >= 'A') && (s[1] <= 'Z') && (
					(s[2] == '=') ||
					((s[2] >= 'A') && (s[2] <= 'Z') &&
					(s[3] == '='))
				 ))) ||
			(*s == '\0'))
#else
		if (	((*s == '/') &&
				(isupper(s[1]) && (
					(s[2] == '=') ||
					(isupper(s[2]) &&
					(s[3] == '='))
				 ))) ||
			(*s == '\0'))
#endif
			{
			if ((l <= 0) && !first)
				{
				first=0;
				if (BIO_write(bp,"\n",1) != 1) goto err;
				for (i=0; i<obase; i++)
					{
					if (BIO_write(bp," ",1) != 1) goto err;
					}
				l=ll;
				}
			i=s-c;
			if (BIO_write(bp,c,i) != i) goto err;
			c+=i;
			c++;
			if (*s != '\0')
				{
				if (BIO_write(bp,", ",2) != 2) goto err;
				}
			l--;
			}
		if (*s == '\0') break;
		s++;
		l--;
		}
	
	ret=1;
	if (0)
		{
err:
		X509err(X509_F_X509_NAME_PRINT,ERR_R_BUF_LIB);
		}
	return(ret);
	}

