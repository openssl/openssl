/* fips_rsa_sign.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2007.
 */
/* ====================================================================
 * Copyright (c) 2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#ifdef OPENSSL_FIPS

/* FIPS versions of RSA_sign() and RSA_verify().
 * These will only have to deal with SHA* signatures and by including
 * pregenerated encodings all ASN1 dependencies can be avoided
 */

static const unsigned char sha1_bin[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
  0x00, 0x04, 0x14
};

static const unsigned char sha224_bin[] = {
  0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};

static const unsigned char sha256_bin[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static const unsigned char sha384_bin[] = {
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};

static const unsigned char sha512_bin[] = {
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};


static const unsigned char *fips_digestinfo_encoding(int nid, unsigned int *len)
	{
	switch (nid)
		{

		case NID_sha1:
		*len = sizeof(sha1_bin);
		return sha1_bin;

		case NID_sha224:
		*len = sizeof(sha224_bin);
		return sha224_bin;

		case NID_sha256:
		*len = sizeof(sha256_bin);
		return sha256_bin;

		case NID_sha384:
		*len = sizeof(sha384_bin);
		return sha384_bin;

		case NID_sha512:
		*len = sizeof(sha512_bin);
		return sha512_bin;

		default:
		return NULL;

		}
	}

static int fips_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
	     unsigned char *sigret, unsigned int *siglen, RSA *rsa)
	{
	int i,j,ret=1;
	unsigned int dlen;
	const unsigned char *der;
	/* Largest DigestInfo: 19 (max encoding) + max MD */
	unsigned char tmpdinfo[19 + EVP_MAX_MD_SIZE];
	if((rsa->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_sign)
		{
		return rsa->meth->rsa_sign(type, m, m_len,
			sigret, siglen, rsa);
		}

	if(m_len > EVP_MAX_MD_SIZE)
		{
		RSAerr(RSA_F_RSA_SIGN,RSA_R_INVALID_MESSAGE_LENGTH);
		return 0;
		}

	der = fips_digestinfo_encoding(type, &dlen);
	
	if (!der)
		{
		RSAerr(RSA_F_RSA_SIGN,RSA_R_UNKNOWN_ALGORITHM_TYPE);
		return(0);
		}
	memcpy(tmpdinfo, der, dlen);
	memcpy(tmpdinfo + dlen, m, m_len);

	i = dlen + m_len;

	j=RSA_size(rsa);
	if (i > (j-RSA_PKCS1_PADDING_SIZE))
		{
		RSAerr(RSA_F_RSA_SIGN,RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
		return(0);
		}
	/* NB: call underlying method directly to avoid FIPS blocking */
	j=rsa->meth->rsa_priv_enc(i,tmpdinfo,sigret,rsa,RSA_PKCS1_PADDING);
	if (j <= 0)
		ret=0;
	else
		*siglen=j;

	OPENSSL_cleanse(tmpdinfo,i);
	return(ret);
	}

static int fips_rsa_verify(int dtype,
		const unsigned char *m, unsigned int m_len,
		unsigned char *sigbuf, unsigned int siglen, RSA *rsa)
	{
	int i,ret=0;
	unsigned int dlen;
	unsigned char *s;
	const unsigned char *der;

	if (siglen != (unsigned int)RSA_size(rsa))
		{
		RSAerr(RSA_F_RSA_VERIFY,RSA_R_WRONG_SIGNATURE_LENGTH);
		return(0);
		}

	if((rsa->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_verify)
		{
		return rsa->meth->rsa_verify(dtype, m, m_len,
			sigbuf, siglen, rsa);
		}

	s= OPENSSL_malloc((unsigned int)siglen);
	if (s == NULL)
		{
		RSAerr(RSA_F_RSA_VERIFY,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	/* NB: call underlying method directly to avoid FIPS blocking */
	i=rsa->meth->rsa_pub_dec((int)siglen,sigbuf,s,rsa,RSA_PKCS1_PADDING);

	if (i <= 0) goto err;

	der = fips_digestinfo_encoding(dtype, &dlen);
	
	if (!der)
		{
		RSAerr(RSA_F_RSA_SIGN,RSA_R_UNKNOWN_ALGORITHM_TYPE);
		return(0);
		}

	/* Compare, DigestInfo length, DigestInfo header and finally
	 * digest value itself
	 */
	if ((i != (int)(dlen + m_len)) || memcmp(der, s, dlen)
		|| memcmp(s + dlen, m, m_len))
		{
		RSAerr(RSA_F_RSA_VERIFY,RSA_R_BAD_SIGNATURE);
		goto err;
		}
	else
		ret = 1;
err:
	if (s != NULL)
		{
		OPENSSL_cleanse(s, siglen);
		OPENSSL_free(s);
		}
	return(ret);
	}

#define EVP_PKEY_RSA_fips_method \
				(evp_sign_method *)fips_rsa_sign, \
				(evp_verify_method *)fips_rsa_verify, \
				{EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}

static int init(EVP_MD_CTX *ctx)
	{ return SHA1_Init(ctx->md_data); }

static int update(EVP_MD_CTX *ctx,const void *data,size_t count)
	{ return SHA1_Update(ctx->md_data,data,count); }

static int final(EVP_MD_CTX *ctx,unsigned char *md)
	{ return SHA1_Final(md,ctx->md_data); }

static const EVP_MD sha1_md=
	{
	NID_sha1,
	NID_sha1WithRSAEncryption,
	SHA_DIGEST_LENGTH,
	EVP_MD_FLAG_FIPS,
	init,
	update,
	final,
	NULL,
	NULL,
	EVP_PKEY_RSA_fips_method,
	SHA_CBLOCK,
	sizeof(EVP_MD *)+sizeof(SHA_CTX),
	};

const EVP_MD *EVP_sha1(void)
	{
	return(&sha1_md);
	}

static int init224(EVP_MD_CTX *ctx)
	{ return SHA224_Init(ctx->md_data); }
static int init256(EVP_MD_CTX *ctx)
	{ return SHA256_Init(ctx->md_data); }
/*
 * Even though there're separate SHA224_[Update|Final], we call
 * SHA256 functions even in SHA224 context. This is what happens
 * there anyway, so we can spare few CPU cycles:-)
 */
static int update256(EVP_MD_CTX *ctx,const void *data,size_t count)
	{ return SHA256_Update(ctx->md_data,data,count); }
static int final256(EVP_MD_CTX *ctx,unsigned char *md)
	{ return SHA256_Final(md,ctx->md_data); }

static const EVP_MD sha224_md=
	{
	NID_sha224,
	NID_sha224WithRSAEncryption,
	SHA224_DIGEST_LENGTH,
	EVP_MD_FLAG_FIPS,
	init224,
	update256,
	final256,
	NULL,
	NULL,
	EVP_PKEY_RSA_fips_method,
	SHA256_CBLOCK,
	sizeof(EVP_MD *)+sizeof(SHA256_CTX),
	};

const EVP_MD *EVP_sha224(void)
	{ return(&sha224_md); }

static const EVP_MD sha256_md=
	{
	NID_sha256,
	NID_sha256WithRSAEncryption,
	SHA256_DIGEST_LENGTH,
	EVP_MD_FLAG_FIPS,
	init256,
	update256,
	final256,
	NULL,
	NULL,
	EVP_PKEY_RSA_fips_method,
	SHA256_CBLOCK,
	sizeof(EVP_MD *)+sizeof(SHA256_CTX),
	};

const EVP_MD *EVP_sha256(void)
	{ return(&sha256_md); }

static int init384(EVP_MD_CTX *ctx)
	{ return SHA384_Init(ctx->md_data); }
static int init512(EVP_MD_CTX *ctx)
	{ return SHA512_Init(ctx->md_data); }
/* See comment in SHA224/256 section */
static int update512(EVP_MD_CTX *ctx,const void *data,size_t count)
	{ return SHA512_Update(ctx->md_data,data,count); }
static int final512(EVP_MD_CTX *ctx,unsigned char *md)
	{ return SHA512_Final(md,ctx->md_data); }

static const EVP_MD sha384_md=
	{
	NID_sha384,
	NID_sha384WithRSAEncryption,
	SHA384_DIGEST_LENGTH,
	EVP_MD_FLAG_FIPS,
	init384,
	update512,
	final512,
	NULL,
	NULL,
	EVP_PKEY_RSA_fips_method,
	SHA512_CBLOCK,
	sizeof(EVP_MD *)+sizeof(SHA512_CTX),
	};

const EVP_MD *EVP_sha384(void)
	{ return(&sha384_md); }

static const EVP_MD sha512_md=
	{
	NID_sha512,
	NID_sha512WithRSAEncryption,
	SHA512_DIGEST_LENGTH,
	EVP_MD_FLAG_FIPS,
	init512,
	update512,
	final512,
	NULL,
	NULL,
	EVP_PKEY_RSA_fips_method,
	SHA512_CBLOCK,
	sizeof(EVP_MD *)+sizeof(SHA512_CTX),
	};

const EVP_MD *EVP_sha512(void)
	{ return(&sha512_md); }

#endif
