/* crypto/pkcs7/pk7_doit.c */
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
#include "rand.h"
#include "objects.h"
#include "x509.h"

BIO *PKCS7_dataInit(p7,bio)
PKCS7 *p7;
BIO *bio;
	{
	int i,j;
	BIO *out=NULL,*btmp;
	X509_ALGOR *xa;
	EVP_MD *evp_md;
	EVP_CIPHER *evp_cipher=NULL;
	STACK *md_sk=NULL,*rsk=NULL;
	X509_ALGOR *xalg=NULL;
	PKCS7_RECIP_INFO *ri=NULL;
	EVP_PKEY *pkey;

	i=OBJ_obj2nid(p7->type);
	p7->state=PKCS7_S_HEADER;

	switch (i)
		{
	case NID_pkcs7_signed:
		md_sk=p7->d.sign->md_algs;
		break;
	case NID_pkcs7_signedAndEnveloped:
		rsk=p7->d.signed_and_enveloped->recipientinfo;
		md_sk=p7->d.signed_and_enveloped->md_algs;
		evp_cipher=EVP_get_cipherbyname(OBJ_nid2sn(OBJ_obj2nid(p7->d.signed_and_enveloped->enc_data->algorithm->algorithm)));
		if (evp_cipher == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_DATAINIT,PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
			goto err;
			}
		xalg=p7->d.signed_and_enveloped->enc_data->algorithm;
		break;
	default:
		PKCS7err(PKCS7_F_PKCS7_DATAINIT,PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
	        goto err;
		}

	if (md_sk != NULL)
		{
		for (i=0; i<sk_num(md_sk); i++)
			{
			xa=(X509_ALGOR *)sk_value(md_sk,i);
			if ((btmp=BIO_new(BIO_f_md())) == NULL) goto err;

			j=OBJ_obj2nid(xa->algorithm);
			evp_md=EVP_get_digestbyname(OBJ_nid2sn(j));
			if (evp_md == NULL)
				{
				PKCS7err(PKCS7_F_PKCS7_DATAINIT,PKCS7_R_UNKNOWN_DIGEST_TYPE);
				goto err;
				}

			BIO_set_md(btmp,evp_md);
			if (out == NULL)
				out=btmp;
			else
				BIO_push(out,btmp);
			}
		}

	if (evp_cipher != NULL)
		{
		unsigned char key[EVP_MAX_KEY_LENGTH];
		unsigned char iv[EVP_MAX_IV_LENGTH];
		int keylen,ivlen;
		int jj,max;
		unsigned char *tmp;

		if ((btmp=BIO_new(BIO_f_cipher())) == NULL) goto err;
		keylen=EVP_CIPHER_key_length(evp_cipher);
		ivlen=EVP_CIPHER_iv_length(evp_cipher);

		if (ivlen > 0)
			{
			ASN1_OCTET_STRING *os;

			RAND_bytes(iv,ivlen);
			os=ASN1_OCTET_STRING_new();
			ASN1_OCTET_STRING_set(os,iv,ivlen);
		/*	ASN1_TYPE_set(xalg->parameter,V_ASN1_OCTET_STRING,
				(char *)os);
		*/	}
		RAND_bytes(key,keylen);

		/* Lets do the pub key stuff :-) */
		max=0;
		for (i=0; i<sk_num(rsk); i++)
			{
			ri=(PKCS7_RECIP_INFO *)sk_value(rsk,i);
			if (ri->cert == NULL) abort();
			pkey=X509_get_pubkey(ri->cert);
			jj=EVP_PKEY_size(pkey);
			if (max < jj) max=jj;
			}
		if ((tmp=(unsigned char *)Malloc(max)) == NULL) abort();
		for (i=0; i<sk_num(rsk); i++)
			{
			ri=(PKCS7_RECIP_INFO *)sk_value(rsk,i);
			pkey=X509_get_pubkey(ri->cert);
			jj=EVP_PKEY_encrypt(tmp,key,keylen,pkey);
			if (jj <= 0) abort();
			ASN1_OCTET_STRING_set(ri->enc_key,tmp,jj);
			}

		BIO_set_cipher(btmp,evp_cipher,key,iv,1);

		if (out == NULL)
			out=btmp;
		else
			BIO_push(out,btmp);
		}

	if (bio == NULL) /* ??????????? */
		{
		if (p7->detached)
			bio=BIO_new(BIO_s_null());
		else
			{
			bio=BIO_new(BIO_s_mem());
			if (PKCS7_type_is_signed(p7) &&
				PKCS7_type_is_data(p7->d.sign->contents))
				{
				ASN1_OCTET_STRING *os;

				os=p7->d.sign->contents->d.data;
				if (os->length > 0)
					BIO_write(bio,(char *)os->data,
						os->length);
				}
			}
		}
	BIO_push(out,bio);
	return(out);
err:
	return(NULL);
	}

int PKCS7_dataSign(p7,bio)
PKCS7 *p7;
BIO *bio;
	{
	int ret=0;
	int i,j;
	BIO *btmp;
	BUF_MEM *buf_mem=NULL;
	BUF_MEM *buf=NULL;
	PKCS7_SIGNER_INFO *si;
	EVP_MD_CTX *mdc,ctx_tmp;
	STACK *sk,*si_sk=NULL;
	unsigned char *p,*pp=NULL;
	int x;
	ASN1_OCTET_STRING *os=NULL;

	i=OBJ_obj2nid(p7->type);
	p7->state=PKCS7_S_HEADER;

	switch (i)
		{
	case NID_pkcs7_signedAndEnveloped:
		/* XXXXXXXXXXXXXXXX */
		si_sk=p7->d.signed_and_enveloped->signer_info;
		os=ASN1_OCTET_STRING_new();
		p7->d.signed_and_enveloped->enc_data->enc_data=os;
		break;
	case NID_pkcs7_signed:
		si_sk=p7->d.sign->signer_info;
		os=p7->d.sign->contents->d.data;
		break;
		}

	if (si_sk != NULL)
		{
		if ((buf=BUF_MEM_new()) == NULL) goto err;
		for (i=0; i<sk_num(si_sk); i++)
			{
			si=(PKCS7_SIGNER_INFO *)
				sk_value(si_sk,i);
			if (si->pkey == NULL)
				continue;
			j=OBJ_obj2nid(si->digest_enc_alg->algorithm);

			btmp=bio;
			for (;;)
				{
				if ((btmp=BIO_find_type(btmp,BIO_TYPE_MD)) 
					== NULL)
					{
					PKCS7err(PKCS7_F_PKCS7_DATASIGN,PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
					goto err;
					}
				BIO_get_md_ctx(btmp,&mdc);
				if (mdc == NULL)
					{
					PKCS7err(PKCS7_F_PKCS7_DATASIGN,PKCS7_R_INTERNAL_ERROR);
					goto err;
					}
				if (EVP_MD_pkey_type(EVP_MD_CTX_type(mdc)) == j)
					break;
				else
					btmp=btmp->next_bio;
				}
			
			/* We now have the EVP_MD_CTX, lets do the
			 * signing. */
			memcpy(&ctx_tmp,mdc,sizeof(ctx_tmp));
			if (!BUF_MEM_grow(buf,EVP_PKEY_size(si->pkey)))
				goto err;

			sk=si->auth_attr;
			if ((sk != NULL) && (sk_num(sk) != 0))
				{
				x=i2d_ASN1_SET(sk,NULL,i2d_X509_ATTRIBUTE,
					V_ASN1_SET,V_ASN1_UNIVERSAL);
				pp=(unsigned char *)Malloc(i);
				p=pp;
				i2d_ASN1_SET(sk,&p,i2d_X509_ATTRIBUTE,
					V_ASN1_SET,V_ASN1_UNIVERSAL);
				EVP_SignUpdate(&ctx_tmp,pp,x);
				Free(pp);
				}

			if (!EVP_SignFinal(&ctx_tmp,(unsigned char *)buf->data,
				(unsigned int *)&buf->length,si->pkey))
				goto err;
			if (!ASN1_STRING_set(si->enc_digest,
				(unsigned char *)buf->data,buf->length))
				goto err;
			}
		if (p7->detached)
			ASN1_OCTET_STRING_set(os,(unsigned char *)"",0);
		else
			{
			btmp=BIO_find_type(bio,BIO_TYPE_MEM);
			if (btmp == NULL)
				{
				PKCS7err(PKCS7_F_PKCS7_DATASIGN,PKCS7_R_UNABLE_TO_FIND_MEM_BIO);
				goto err;
				}
			BIO_get_mem_ptr(btmp,&buf_mem);
			ASN1_OCTET_STRING_set(os,
				(unsigned char *)buf_mem->data,buf_mem->length);
			}
		if (pp != NULL) Free(pp);
		pp=NULL;
		}

	ret=1;
err:
	if (buf != NULL) BUF_MEM_free(buf);
	return(ret);
	}

int PKCS7_dataVerify(cert_store,ctx,bio,p7,si)
X509_STORE *cert_store;
X509_STORE_CTX *ctx;
BIO *bio;
PKCS7 *p7;
PKCS7_SIGNER_INFO *si;
	{
	PKCS7_SIGNED *s;
	ASN1_OCTET_STRING *os;
	EVP_MD_CTX mdc_tmp,*mdc;
	unsigned char *pp,*p;
	PKCS7_ISSUER_AND_SERIAL *ias;
	int ret=0,md_type,i;
	STACK *sk;
	BIO *btmp;
	X509 *x509;

	if (!PKCS7_type_is_signed(p7)) abort();
	/* XXXXXXXXXXXXXXXXXXXXXXX */
	ias=si->issuer_and_serial;
	s=p7->d.sign;

	x509=X509_find_by_issuer_and_serial(s->cert,ias->issuer,ias->serial);

	/* were we able to find the cert in passed to us */
	if (x509 == NULL)
		{
		PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_UNABLE_TO_FIND_CERTIFICATE);
		goto err;
		}

	/* Lets verify */
	X509_STORE_CTX_init(ctx,cert_store,x509,s->cert);
	i=X509_verify_cert(ctx);
	if (i <= 0) goto err;
	X509_STORE_CTX_cleanup(ctx);

	/* So we like 'x509', lets check the signature. */
	md_type=OBJ_obj2nid(si->digest_alg->algorithm);

	btmp=bio;
	for (;;)
		{
		if ((btmp == NULL) ||
			((btmp=BIO_find_type(btmp,BIO_TYPE_MD)) == NULL))
			{
			PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
			goto err;
			}
		BIO_get_md_ctx(btmp,&mdc);
		if (mdc == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_INTERNAL_ERROR);
			goto err;
			}
		if (EVP_MD_type(EVP_MD_CTX_type(mdc)) == md_type)
			break;
		btmp=btmp->next_bio;	
		}

	/* mdc is the digest ctx that we want */
	memcpy(&mdc_tmp,mdc,sizeof(mdc_tmp));

	sk=si->auth_attr;
	if ((sk != NULL) && (sk_num(sk) != 0))
		{
		i=i2d_ASN1_SET(sk,NULL,i2d_X509_ATTRIBUTE,
			V_ASN1_SET,V_ASN1_UNIVERSAL);
		pp=(unsigned char *)malloc(i);
		p=pp;
		i2d_ASN1_SET(sk,&p,i2d_X509_ATTRIBUTE,
			V_ASN1_SET,V_ASN1_UNIVERSAL);
		EVP_VerifyUpdate(&mdc_tmp,pp,i);
		free(pp);
		}

	os=si->enc_digest;
	i=EVP_VerifyFinal(&mdc_tmp,os->data,os->length,
		X509_get_pubkey(x509));
	if (i <= 0)
		{
		PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_SIGNATURE_FAILURE);
		ret= -1;
		goto err;
		}
	else
		ret=1;
err:
	return(ret);
	}

