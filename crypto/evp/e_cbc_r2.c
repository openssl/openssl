/* crypto/evp/e_cbc_r2.c */
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

#ifndef NO_RC2

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>

static void rc2_cbc_init_key(EVP_CIPHER_CTX *ctx, unsigned char *key,
	unsigned char *iv,int enc);
static void rc2_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	unsigned char *in, unsigned int inl);
static int rc2_meth_to_magic(const EVP_CIPHER *e);
static EVP_CIPHER *rc2_magic_to_meth(int i);
static int rc2_set_asn1_type_and_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
static int rc2_get_asn1_type_and_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

#define RC2_40_MAGIC	0xa0
#define RC2_64_MAGIC	0x78
#define RC2_128_MAGIC	0x3a

static EVP_CIPHER r2_cbc_cipher=
	{
	NID_rc2_cbc,
	8,EVP_RC2_KEY_SIZE,8,
	rc2_cbc_init_key,
	rc2_cbc_cipher,
	NULL,
	sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+
		sizeof((((EVP_CIPHER_CTX *)NULL)->c.rc2_ks)),
	rc2_set_asn1_type_and_iv,
	rc2_get_asn1_type_and_iv,
	};

static EVP_CIPHER r2_64_cbc_cipher=
	{
	NID_rc2_64_cbc,
	8,8 /* 64 bit */,8,
	rc2_cbc_init_key,
	rc2_cbc_cipher,
	NULL,
	sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+
		sizeof((((EVP_CIPHER_CTX *)NULL)->c.rc2_ks)),
	rc2_set_asn1_type_and_iv,
	rc2_get_asn1_type_and_iv,
	};

static EVP_CIPHER r2_40_cbc_cipher=
	{
	NID_rc2_40_cbc,
	8,5 /* 40 bit */,8,
	rc2_cbc_init_key,
	rc2_cbc_cipher,
	NULL,
	sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+
		sizeof((((EVP_CIPHER_CTX *)NULL)->c.rc2_ks)),
	rc2_set_asn1_type_and_iv,
	rc2_get_asn1_type_and_iv,
	};

EVP_CIPHER *EVP_rc2_cbc(void)
	{
	return(&r2_cbc_cipher);
	}

EVP_CIPHER *EVP_rc2_64_cbc(void)
	{
	return(&r2_64_cbc_cipher);
	}

EVP_CIPHER *EVP_rc2_40_cbc(void)
	{
	return(&r2_40_cbc_cipher);
	}
	
static void rc2_cbc_init_key(EVP_CIPHER_CTX *ctx, unsigned char *key,
	     unsigned char *iv, int enc)
	{
	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,8);
	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),8);
	if (key != NULL)
		RC2_set_key(&(ctx->c.rc2_ks),EVP_CIPHER_CTX_key_length(ctx),
			key,EVP_CIPHER_CTX_key_length(ctx)*8);
	}

static void rc2_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	     unsigned char *in, unsigned int inl)
	{
	RC2_cbc_encrypt(
		in,out,(long)inl,
		&(ctx->c.rc2_ks),&(ctx->iv[0]),
		ctx->encrypt);
	}

static int rc2_meth_to_magic(const EVP_CIPHER *e)
	{
	int i;

	i=EVP_CIPHER_key_length(e);
	if 	(i == 16) return(RC2_128_MAGIC);
	else if (i == 8)  return(RC2_64_MAGIC);
	else if (i == 5)  return(RC2_40_MAGIC);
	else return(0);
	}

static EVP_CIPHER *rc2_magic_to_meth(int i)
	{
	if      (i == RC2_128_MAGIC) return(EVP_rc2_cbc());
	else if (i == RC2_64_MAGIC)  return(EVP_rc2_64_cbc());
	else if (i == RC2_40_MAGIC)  return(EVP_rc2_40_cbc());
	else
		{
		EVPerr(EVP_F_RC2_MAGIC_TO_METH,EVP_R_UNSUPPORTED_KEY_SIZE);
		return(NULL);
		}
	}

static int rc2_get_asn1_type_and_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
	{
	long num=0;
	int i=0,l;
	EVP_CIPHER *e;

	if (type != NULL)
		{
		l=EVP_CIPHER_CTX_iv_length(c);
		i=ASN1_TYPE_get_int_octetstring(type,&num,c->oiv,l);
		if (i != l)
			return(-1);
		else if (i > 0)
			memcpy(c->iv,c->oiv,l);
		e=rc2_magic_to_meth((int)num);
		if (e == NULL)
			return(-1);
		if (e != EVP_CIPHER_CTX_cipher(c))
			{
			EVP_CIPHER_CTX_cipher(c)=e;
			rc2_cbc_init_key(c,NULL,NULL,1);
			}
		}
	return(i);
	}

static int rc2_set_asn1_type_and_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
	{
	long num;
	int i=0,j;

	if (type != NULL)
		{
		num=rc2_meth_to_magic(EVP_CIPHER_CTX_cipher(c));
		j=EVP_CIPHER_CTX_iv_length(c);
		i=ASN1_TYPE_set_int_octetstring(type,num,c->oiv,j);
		}
	return(i);
	}

#endif
