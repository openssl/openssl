/* crypto/asn1/t_req.c */
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
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef NO_FP_API
int X509_REQ_print_fp(FILE *fp, X509_REQ *x)
        {
        BIO *b;
        int ret;

        if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		X509err(X509_F_X509_REQ_PRINT_FP,ERR_R_BUF_LIB);
                return(0);
		}
        BIO_set_fp(b,fp,BIO_NOCLOSE);
        ret=X509_REQ_print(b, x);
        BIO_free(b);
        return(ret);
        }
#endif

int X509_REQ_print(BIO *bp, X509_REQ *x)
	{
	unsigned long l;
	int i,n;
	char *s;
	const char *neg;
	X509_REQ_INFO *ri;
	EVP_PKEY *pkey;
	STACK_OF(X509_ATTRIBUTE) *sk;
	STACK_OF(X509_EXTENSION) *exts;
	char str[128];

	ri=x->req_info;
	sprintf(str,"Certificate Request:\n");
	if (BIO_puts(bp,str) <= 0) goto err;
	sprintf(str,"%4sData:\n","");
	if (BIO_puts(bp,str) <= 0) goto err;

	neg=(ri->version->type == V_ASN1_NEG_INTEGER)?"-":"";
	l=0;
	for (i=0; i<ri->version->length; i++)
		{ l<<=8; l+=ri->version->data[i]; }
	sprintf(str,"%8sVersion: %s%lu (%s0x%lx)\n","",neg,l,neg,l);
	if (BIO_puts(bp,str) <= 0) goto err;
	sprintf(str,"%8sSubject: ","");
	if (BIO_puts(bp,str) <= 0) goto err;

	X509_NAME_print(bp,ri->subject,16);
	sprintf(str,"\n%8sSubject Public Key Info:\n","");
	if (BIO_puts(bp,str) <= 0) goto err;
	i=OBJ_obj2nid(ri->pubkey->algor->algorithm);
	sprintf(str,"%12sPublic Key Algorithm: %s\n","",
		(i == NID_undef)?"UNKNOWN":OBJ_nid2ln(i));
	if (BIO_puts(bp,str) <= 0) goto err;

	pkey=X509_REQ_get_pubkey(x);
#ifndef NO_RSA
	if (pkey != NULL && pkey->type == EVP_PKEY_RSA)
		{
		BIO_printf(bp,"%12sRSA Public Key: (%d bit)\n","",
			BN_num_bits(pkey->pkey.rsa->n));
		RSA_print(bp,pkey->pkey.rsa,16);
		}
	else 
#endif
#ifndef NO_DSA
		if (pkey != NULL && pkey->type == EVP_PKEY_DSA)
		{
		BIO_printf(bp,"%12sDSA Public Key:\n","");
		DSA_print(bp,pkey->pkey.dsa,16);
		}
	else
#endif
		BIO_printf(bp,"%12sUnknown Public Key:\n","");

	if (pkey != NULL)
	    EVP_PKEY_free(pkey);

	/* may not be */
	sprintf(str,"%8sAttributes:\n","");
	if (BIO_puts(bp,str) <= 0) goto err;

	sk=x->req_info->attributes;
	if ((sk == NULL) || (sk_X509_ATTRIBUTE_num(sk) == 0))
		{
		if (!x->req_info->req_kludge)
			{
			sprintf(str,"%12sa0:00\n","");
			if (BIO_puts(bp,str) <= 0) goto err;
			}
		}
	else
		{
		for (i=0; i<sk_X509_ATTRIBUTE_num(sk); i++)
			{
			ASN1_TYPE *at;
			X509_ATTRIBUTE *a;
			ASN1_BIT_STRING *bs=NULL;
			ASN1_TYPE *t;
			int j,type=0,count=1,ii=0;

			a=sk_X509_ATTRIBUTE_value(sk,i);
			if(X509_REQ_extension_nid(OBJ_obj2nid(a->object)))
								continue;
			sprintf(str,"%12s","");
			if (BIO_puts(bp,str) <= 0) goto err;
			if ((j=i2a_ASN1_OBJECT(bp,a->object)) > 0)
			{
			if (a->set)
				{
				ii=0;
				count=sk_ASN1_TYPE_num(a->value.set);
get_next:
				at=sk_ASN1_TYPE_value(a->value.set,ii);
				type=at->type;
				bs=at->value.asn1_string;
				}
			else
				{
				t=a->value.single;
				type=t->type;
				bs=t->value.bit_string;
				}
			}
			for (j=25-j; j>0; j--)
				if (BIO_write(bp," ",1) != 1) goto err;
			if (BIO_puts(bp,":") <= 0) goto err;
			if (	(type == V_ASN1_PRINTABLESTRING) ||
				(type == V_ASN1_T61STRING) ||
				(type == V_ASN1_IA5STRING))
				{
				if (BIO_write(bp,(char *)bs->data,bs->length)
					!= bs->length)
					goto err;
				BIO_puts(bp,"\n");
				}
			else
				{
				BIO_puts(bp,"unable to print attribute\n");
				}
			if (++ii < count) goto get_next;
			}
		}

	exts = X509_REQ_get_extensions(x);
	if(exts) {
		BIO_printf(bp,"%8sRequested Extensions:\n","");
		for (i=0; i<sk_X509_EXTENSION_num(exts); i++) {
			ASN1_OBJECT *obj;
			X509_EXTENSION *ex;
			int j;
			ex=sk_X509_EXTENSION_value(exts, i);
			if (BIO_printf(bp,"%12s","") <= 0) goto err;
			obj=X509_EXTENSION_get_object(ex);
			i2a_ASN1_OBJECT(bp,obj);
			j=X509_EXTENSION_get_critical(ex);
			if (BIO_printf(bp,": %s\n",j?"critical":"","") <= 0)
				goto err;
			if(!X509V3_EXT_print(bp, ex, 0, 16)) {
				BIO_printf(bp, "%16s", "");
				M_ASN1_OCTET_STRING_print(bp,ex->value);
			}
			if (BIO_write(bp,"\n",1) <= 0) goto err;
		}
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	}

	i=OBJ_obj2nid(x->sig_alg->algorithm);
	sprintf(str,"%4sSignature Algorithm: %s","",
		(i == NID_undef)?"UNKNOWN":OBJ_nid2ln(i));
	if (BIO_puts(bp,str) <= 0) goto err;

	n=x->signature->length;
	s=(char *)x->signature->data;
	for (i=0; i<n; i++)
		{
		if ((i%18) == 0)
			{
			sprintf(str,"\n%8s","");
			if (BIO_puts(bp,str) <= 0) goto err;
			}
		sprintf(str,"%02x%s",(unsigned char)s[i],((i+1) == n)?"":":");
		if (BIO_puts(bp,str) <= 0) goto err;
		}
	if (BIO_puts(bp,"\n") <= 0) goto err;
	return(1);
err:
	X509err(X509_F_X509_REQ_PRINT,ERR_R_BUF_LIB);
	return(0);
	}
