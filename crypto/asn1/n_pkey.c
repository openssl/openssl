/* crypto/asn1/n_pkey.c */
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

#ifndef NO_RSA
#include <stdio.h>
#include "cryptlib.h"
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/asn1_mac.h>
#include <openssl/evp.h>
#include <openssl/x509.h>


#ifndef NO_RC4

typedef struct netscape_pkey_st
	{
	ASN1_INTEGER *version;
	X509_ALGOR *algor;
	ASN1_OCTET_STRING *private_key;
	} NETSCAPE_PKEY;

static int i2d_NETSCAPE_PKEY(NETSCAPE_PKEY *a, unsigned char **pp);
static NETSCAPE_PKEY *d2i_NETSCAPE_PKEY(NETSCAPE_PKEY **a,unsigned char **pp, long length);
static NETSCAPE_PKEY *NETSCAPE_PKEY_new(void);
static void NETSCAPE_PKEY_free(NETSCAPE_PKEY *);

int i2d_Netscape_RSA(RSA *a, unsigned char **pp, int (*cb)())
	{
	int i,j,l[6];
	NETSCAPE_PKEY *pkey;
	unsigned char buf[256],*zz;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	EVP_CIPHER_CTX ctx;
	X509_ALGOR *alg=NULL;
	ASN1_OCTET_STRING os,os2;
	M_ASN1_I2D_vars(a);

	if (a == NULL) return(0);

#ifdef WIN32
	r=r; /* shut the damn compiler up :-) */
#endif

	os.data=os2.data=NULL;
	if ((pkey=NETSCAPE_PKEY_new()) == NULL) goto err;
	if (!ASN1_INTEGER_set(pkey->version,0)) goto err;

	if (pkey->algor->algorithm != NULL)
		ASN1_OBJECT_free(pkey->algor->algorithm);
	pkey->algor->algorithm=OBJ_nid2obj(NID_rsaEncryption);
	if ((pkey->algor->parameter=ASN1_TYPE_new()) == NULL) goto err;
	pkey->algor->parameter->type=V_ASN1_NULL;

	l[0]=i2d_RSAPrivateKey(a,NULL);
	pkey->private_key->length=l[0];

	os2.length=i2d_NETSCAPE_PKEY(pkey,NULL);
	l[1]=i2d_ASN1_OCTET_STRING(&os2,NULL);

	if ((alg=X509_ALGOR_new()) == NULL) goto err;
	if (alg->algorithm != NULL)
		ASN1_OBJECT_free(alg->algorithm);
	alg->algorithm=OBJ_nid2obj(NID_rc4);
	if ((alg->parameter=ASN1_TYPE_new()) == NULL) goto err;
	alg->parameter->type=V_ASN1_NULL;

	l[2]=i2d_X509_ALGOR(alg,NULL);
	l[3]=ASN1_object_size(1,l[2]+l[1],V_ASN1_SEQUENCE);

#ifndef CONST_STRICT
	os.data=(unsigned char *)"private-key";
#endif
	os.length=11;
	l[4]=i2d_ASN1_OCTET_STRING(&os,NULL);

	l[5]=ASN1_object_size(1,l[4]+l[3],V_ASN1_SEQUENCE);

	if (pp == NULL)
		{
		if (pkey != NULL) NETSCAPE_PKEY_free(pkey);
		if (alg != NULL) X509_ALGOR_free(alg);
		return(l[5]);
		}

	if (pkey->private_key->data != NULL)
		Free((char *)pkey->private_key->data);
	if ((pkey->private_key->data=(unsigned char *)Malloc(l[0])) == NULL)
		{
		ASN1err(ASN1_F_I2D_NETSCAPE_RSA,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	zz=pkey->private_key->data;
	i2d_RSAPrivateKey(a,&zz);

	if ((os2.data=(unsigned char *)Malloc(os2.length)) == NULL)
		{
		ASN1err(ASN1_F_I2D_NETSCAPE_RSA,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	zz=os2.data;
	i2d_NETSCAPE_PKEY(pkey,&zz);
		
	if (cb == NULL)
		cb=EVP_read_pw_string;
	i=cb(buf,256,"Enter Private Key password:",1);
	if (i != 0)
		{
		ASN1err(ASN1_F_I2D_NETSCAPE_RSA,ASN1_R_BAD_PASSWORD_READ);
		goto err;
		}
	EVP_BytesToKey(EVP_rc4(),EVP_md5(),NULL,buf,
		strlen((char *)buf),1,key,NULL);
	memset(buf,0,256);

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit(&ctx,EVP_rc4(),key,NULL);
	EVP_EncryptUpdate(&ctx,os2.data,&i,os2.data,os2.length);
	EVP_EncryptFinal(&ctx,&(os2.data[i]),&j);
	EVP_CIPHER_CTX_cleanup(&ctx);

	p= *pp;
	ASN1_put_object(&p,1,l[4]+l[3],V_ASN1_SEQUENCE,V_ASN1_UNIVERSAL);
	i2d_ASN1_OCTET_STRING(&os,&p);
	ASN1_put_object(&p,1,l[2]+l[1],V_ASN1_SEQUENCE,V_ASN1_UNIVERSAL);
	i2d_X509_ALGOR(alg,&p);
	i2d_ASN1_OCTET_STRING(&os2,&p);
	ret=l[5];
err:
	if (os2.data != NULL) Free(os2.data);
	if (alg != NULL) X509_ALGOR_free(alg);
	if (pkey != NULL) NETSCAPE_PKEY_free(pkey);
	r=r;
	return(ret);
	}

RSA *d2i_Netscape_RSA(RSA **a, unsigned char **pp, long length, int (*cb)())
	{
	RSA *ret=NULL;
	ASN1_OCTET_STRING *os=NULL;
	ASN1_CTX c;

	c.pp=pp;
	c.error=ASN1_R_DECODING_ERROR;

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(os,d2i_ASN1_OCTET_STRING);
	if ((os->length != 11) || (strncmp("private-key",
		(char *)os->data,os->length) != 0))
		{
		ASN1err(ASN1_F_D2I_NETSCAPE_RSA,ASN1_R_PRIVATE_KEY_HEADER_MISSING);
		ASN1_BIT_STRING_free(os);
		goto err;
		}
	ASN1_BIT_STRING_free(os);
	c.q=c.p;
	if ((ret=d2i_Netscape_RSA_2(a,&c.p,c.slen,cb)) == NULL) goto err;
	c.slen-=(c.p-c.q);

	M_ASN1_D2I_Finish(a,RSA_free,ASN1_F_D2I_NETSCAPE_RSA);
	}

RSA *d2i_Netscape_RSA_2(RSA **a, unsigned char **pp, long length,
	     int (*cb)())
	{
	NETSCAPE_PKEY *pkey=NULL;
	RSA *ret=NULL;
	int i,j;
	unsigned char buf[256],*zz;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	EVP_CIPHER_CTX ctx;
	X509_ALGOR *alg=NULL;
	ASN1_OCTET_STRING *os=NULL;
	ASN1_CTX c;

	c.error=ERR_R_NESTED_ASN1_ERROR;
	c.pp=pp;

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(alg,d2i_X509_ALGOR);
	if (OBJ_obj2nid(alg->algorithm) != NID_rc4)
		{
		ASN1err(ASN1_F_D2I_NETSCAPE_RSA_2,ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM);
		goto err;
		}
	M_ASN1_D2I_get(os,d2i_ASN1_OCTET_STRING);
	if (cb == NULL)
		cb=EVP_read_pw_string;
	i=cb(buf,256,"Enter Private Key password:",0);
	if (i != 0)
		{
		ASN1err(ASN1_F_D2I_NETSCAPE_RSA_2,ASN1_R_BAD_PASSWORD_READ);
		goto err;
		}

	EVP_BytesToKey(EVP_rc4(),EVP_md5(),NULL,buf,
		strlen((char *)buf),1,key,NULL);
	memset(buf,0,256);

	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit(&ctx,EVP_rc4(),key,NULL);
	EVP_DecryptUpdate(&ctx,os->data,&i,os->data,os->length);
	EVP_DecryptFinal(&ctx,&(os->data[i]),&j);
	EVP_CIPHER_CTX_cleanup(&ctx);
	os->length=i+j;

	zz=os->data;

	if ((pkey=d2i_NETSCAPE_PKEY(NULL,&zz,os->length)) == NULL)
		{
		ASN1err(ASN1_F_D2I_NETSCAPE_RSA_2,ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY);
		goto err;
		}
		
	zz=pkey->private_key->data;
	if ((ret=d2i_RSAPrivateKey(a,&zz,pkey->private_key->length)) == NULL)
		{
		ASN1err(ASN1_F_D2I_NETSCAPE_RSA_2,ASN1_R_UNABLE_TO_DECODE_RSA_KEY);
		goto err;
		}
	if (!asn1_Finish(&c)) goto err;
	*pp=c.p;
err:
	if (pkey != NULL) NETSCAPE_PKEY_free(pkey);
	if (os != NULL) ASN1_BIT_STRING_free(os);
	if (alg != NULL) X509_ALGOR_free(alg);
	return(ret);
	}

static int i2d_NETSCAPE_PKEY(NETSCAPE_PKEY *a, unsigned char **pp)
	{
	M_ASN1_I2D_vars(a);


	M_ASN1_I2D_len(a->version,	i2d_ASN1_INTEGER);
	M_ASN1_I2D_len(a->algor,	i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->private_key,	i2d_ASN1_OCTET_STRING);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(a->version,	i2d_ASN1_INTEGER);
	M_ASN1_I2D_put(a->algor,	i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->private_key,	i2d_ASN1_OCTET_STRING);

	M_ASN1_I2D_finish();
	}

static NETSCAPE_PKEY *d2i_NETSCAPE_PKEY(NETSCAPE_PKEY **a, unsigned char **pp,
	     long length)
	{
	M_ASN1_D2I_vars(a,NETSCAPE_PKEY *,NETSCAPE_PKEY_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->version,d2i_ASN1_INTEGER);
	M_ASN1_D2I_get(ret->algor,d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->private_key,d2i_ASN1_OCTET_STRING);
	M_ASN1_D2I_Finish(a,NETSCAPE_PKEY_free,ASN1_F_D2I_NETSCAPE_PKEY);
	}

static NETSCAPE_PKEY *NETSCAPE_PKEY_new(void)
	{
	NETSCAPE_PKEY *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,NETSCAPE_PKEY);
	M_ASN1_New(ret->version,ASN1_INTEGER_new);
	M_ASN1_New(ret->algor,X509_ALGOR_new);
	M_ASN1_New(ret->private_key,ASN1_OCTET_STRING_new);
	return(ret);
	M_ASN1_New_Error(ASN1_F_NETSCAPE_PKEY_NEW);
	}

static void NETSCAPE_PKEY_free(NETSCAPE_PKEY *a)
	{
	if (a == NULL) return;
	ASN1_INTEGER_free(a->version);
	X509_ALGOR_free(a->algor);
	ASN1_OCTET_STRING_free(a->private_key);
	Free((char *)a);
	}

#endif /* NO_RC4 */
#endif
