/* rsaref/rsaref.c */
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
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rsaref.h>
#include <openssl/rand.h>

static int RSAref_bn2bin(BIGNUM * from, unsigned char* to, int max);
#ifdef undef
static BIGNUM* RSAref_bin2bn(unsigned char* from, BIGNUM * to, int max);
#endif
static int RSAref_Public_eay2ref(RSA * from, RSArefPublicKey * to);
static int RSAref_Private_eay2ref(RSA * from, RSArefPrivateKey * to);
int RSA_ref_private_decrypt(int len, unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);
int RSA_ref_private_encrypt(int len, unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);
int RSA_ref_public_encrypt(int len, unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);
int RSA_ref_public_decrypt(int len, unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);
static int BN_ref_mod_exp(BIGNUM *r,BIGNUM *a,const BIGNUM *p,const BIGNUM *m,
			  BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static int RSA_ref_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa);
static RSA_METHOD rsa_pkcs1_ref_meth={
	"RSAref PKCS#1 RSA",
	RSA_ref_public_encrypt,
	RSA_ref_public_decrypt,
	RSA_ref_private_encrypt,
	RSA_ref_private_decrypt,
	RSA_ref_mod_exp,
	BN_ref_mod_exp,
	NULL,
	NULL,
	0,
	NULL,
	};

RSA_METHOD *RSA_PKCS1_RSAref(void)
	{
	return(&rsa_pkcs1_ref_meth);
	}

static int RSA_ref_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa)
	{
	RSAREFerr(RSAREF_F_RSA_REF_MOD_EXP,ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
	return(0);
	}

static int BN_ref_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			  const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	RSAREFerr(RSAREF_F_BN_REF_MOD_EXP,ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
	return(0);
	}

/* unsigned char *to:  [max]    */
static int RSAref_bn2bin(BIGNUM *from, unsigned char *to, int max)
	{
	int i;

	i=BN_num_bytes(from);
	if (i > max)
		{
		RSAREFerr(RSAREF_F_RSAREF_BN2BIN,RSAREF_R_LEN);
		return(0);
		}

	memset(to,0,(unsigned int)max);
	if (!BN_bn2bin(from,&(to[max-i])))
		return(0);
	return(1);
	}

#ifdef undef
/* unsigned char *from:  [max]    */
static BIGNUM *RSAref_bin2bn(unsigned char *from, BIGNUM *to, int max)
	{
	int i;
	BIGNUM *ret;

	for (i=0; i<max; i++)
		if (from[i]) break;

	ret=BN_bin2bn(&(from[i]),max-i,to);
	return(ret);
	}

static int RSAref_Public_ref2eay(RSArefPublicKey *from, RSA *to)
	{
	to->n=RSAref_bin2bn(from->m,NULL,RSAref_MAX_LEN);
	to->e=RSAref_bin2bn(from->e,NULL,RSAref_MAX_LEN);
	if ((to->n == NULL) || (to->e == NULL)) return(0);
	return(1);
	}
#endif

static int RSAref_Public_eay2ref(RSA *from, RSArefPublicKey *to)
	{
	to->bits=BN_num_bits(from->n);
	if (!RSAref_bn2bin(from->n,to->m,RSAref_MAX_LEN)) return(0);
	if (!RSAref_bn2bin(from->e,to->e,RSAref_MAX_LEN)) return(0);
	return(1);
	}

#ifdef undef
static int RSAref_Private_ref2eay(RSArefPrivateKey *from, RSA *to)
	{
	if ((to->n=RSAref_bin2bn(from->m,NULL,RSAref_MAX_LEN)) == NULL)
		return(0);
	if ((to->e=RSAref_bin2bn(from->e,NULL,RSAref_MAX_LEN)) == NULL)
		return(0);
	if ((to->d=RSAref_bin2bn(from->d,NULL,RSAref_MAX_LEN)) == NULL)
		return(0);
	if ((to->p=RSAref_bin2bn(from->prime[0],NULL,RSAref_MAX_PLEN)) == NULL)
		return(0);
	if ((to->q=RSAref_bin2bn(from->prime[1],NULL,RSAref_MAX_PLEN)) == NULL)
		return(0);
	if ((to->dmp1=RSAref_bin2bn(from->pexp[0],NULL,RSAref_MAX_PLEN))
		== NULL)
		return(0);
	if ((to->dmq1=RSAref_bin2bn(from->pexp[1],NULL,RSAref_MAX_PLEN))
		== NULL)
		return(0);
	if ((to->iqmp=RSAref_bin2bn(from->coef,NULL,RSAref_MAX_PLEN)) == NULL)
		return(0);
	return(1);
	}
#endif

static int RSAref_Private_eay2ref(RSA *from, RSArefPrivateKey *to)
	{
	to->bits=BN_num_bits(from->n);
	if (!RSAref_bn2bin(from->n,to->m,RSAref_MAX_LEN)) return(0);
	if (!RSAref_bn2bin(from->e,to->e,RSAref_MAX_LEN)) return(0);
	if (!RSAref_bn2bin(from->d,to->d,RSAref_MAX_LEN)) return(0);
	if (!RSAref_bn2bin(from->p,to->prime[0],RSAref_MAX_PLEN)) return(0);
	if (!RSAref_bn2bin(from->q,to->prime[1],RSAref_MAX_PLEN)) return(0);
	if (!RSAref_bn2bin(from->dmp1,to->pexp[0],RSAref_MAX_PLEN)) return(0);
	if (!RSAref_bn2bin(from->dmq1,to->pexp[1],RSAref_MAX_PLEN)) return(0);
	if (!RSAref_bn2bin(from->iqmp,to->coef,RSAref_MAX_PLEN)) return(0);
	return(1);
	}

int RSA_ref_private_decrypt(int len, unsigned char *from, unsigned char *to,
	     RSA *rsa, int padding)
	{
	int i,outlen= -1;
	RSArefPrivateKey RSAkey;

	if (!RSAref_Private_eay2ref(rsa,&RSAkey))
		goto err;
	if ((i=RSAPrivateDecrypt(to,&outlen,from,len,&RSAkey)) != 0)
		{
		RSAREFerr(RSAREF_F_RSA_REF_PRIVATE_DECRYPT,i);
		outlen= -1;
		}
err:
	memset(&RSAkey,0,sizeof(RSAkey));
	return(outlen);
	}

int RSA_ref_private_encrypt(int len, unsigned char *from, unsigned char *to,
	     RSA *rsa, int padding)
	{
	int i,outlen= -1;
	RSArefPrivateKey RSAkey;

	if (padding != RSA_PKCS1_PADDING)
		{
		RSAREFerr(RSAREF_F_RSA_REF_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (!RSAref_Private_eay2ref(rsa,&RSAkey))
		goto err;
	if ((i=RSAPrivateEncrypt(to,&outlen,from,len,&RSAkey)) != 0)
		{
		RSAREFerr(RSAREF_F_RSA_REF_PRIVATE_ENCRYPT,i);
		outlen= -1;
		}
err:
	memset(&RSAkey,0,sizeof(RSAkey));
	return(outlen);
	}

int RSA_ref_public_decrypt(int len, unsigned char *from, unsigned char *to,
	     RSA *rsa, int padding)
	{
	int i,outlen= -1;
	RSArefPublicKey RSAkey;

	if (!RSAref_Public_eay2ref(rsa,&RSAkey))
		goto err;
	if ((i=RSAPublicDecrypt(to,&outlen,from,len,&RSAkey)) != 0)
		{
		RSAREFerr(RSAREF_F_RSA_REF_PUBLIC_DECRYPT,i);
		outlen= -1;
		}
err:
	memset(&RSAkey,0,sizeof(RSAkey));
	return(outlen);
	}

int RSA_ref_public_encrypt(int len, unsigned char *from, unsigned char *to,
	     RSA *rsa, int padding)
	{
	int outlen= -1;
	int i;
	RSArefPublicKey RSAkey;
	RSARandomState rnd;
	unsigned char buf[16];

	if (padding != RSA_PKCS1_PADDING && padding != RSA_SSLV23_PADDING) 
		{
		RSAREFerr(RSAREF_F_RSA_REF_PUBLIC_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	
	R_RandomInit(&rnd);
	R_GetRandomBytesNeeded((unsigned int *)&i,&rnd);
	while (i > 0)
		{
		RAND_bytes(buf,16);
		R_RandomUpdate(&rnd,buf,(unsigned int)((i>16)?16:i));
		i-=16;
		}

	if (!RSAref_Public_eay2ref(rsa,&RSAkey))
		goto err;
	if ((i=RSAPublicEncrypt(to,&outlen,from,len,&RSAkey,&rnd)) != 0)
		{
		RSAREFerr(RSAREF_F_RSA_REF_PUBLIC_ENCRYPT,i);
		outlen= -1;
		goto err;
		}
err:
	memset(&RSAkey,0,sizeof(RSAkey));
	R_RandomFinal(&rnd);
	memset(&rnd,0,sizeof(rnd));
	return(outlen);
	}
#endif
