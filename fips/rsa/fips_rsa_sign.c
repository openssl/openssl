/* fips_rsa_sign.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
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

#define OPENSSL_FIPSAPI

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/fips.h>

#ifdef OPENSSL_FIPS

/* FIPS versions of RSA_sign() and RSA_verify().
 * These will only have to deal with SHA* signatures and by including
 * pregenerated encodings all ASN1 dependencies can be avoided
 */

/* Standard encodings including NULL parameter */

__fips_constseg
static const unsigned char sha1_bin[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
  0x00, 0x04, 0x14
};

__fips_constseg
static const unsigned char sha224_bin[] = {
  0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};

__fips_constseg
static const unsigned char sha256_bin[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

__fips_constseg
static const unsigned char sha384_bin[] = {
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};

__fips_constseg
static const unsigned char sha512_bin[] = {
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

/* Alternate encodings with absent parameters. We don't generate signature
 * using this format but do tolerate received signatures of this form.
 */

__fips_constseg
static const unsigned char sha1_nn_bin[] = {
  0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04,
  0x14
};

__fips_constseg
static const unsigned char sha224_nn_bin[] = {
  0x30, 0x2b, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x04, 0x04, 0x1c
};

__fips_constseg
static const unsigned char sha256_nn_bin[] = {
  0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x01, 0x04, 0x20
};

__fips_constseg
static const unsigned char sha384_nn_bin[] = {
  0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x02, 0x04, 0x30
};

__fips_constseg
static const unsigned char sha512_nn_bin[] = {
  0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x03, 0x04, 0x40
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

static const unsigned char *fips_digestinfo_nn_encoding(int nid, unsigned int *len)
	{
	switch (nid)
		{

		case NID_sha1:
		*len = sizeof(sha1_nn_bin);
		return sha1_nn_bin;

		case NID_sha224:
		*len = sizeof(sha224_nn_bin);
		return sha224_nn_bin;

		case NID_sha256:
		*len = sizeof(sha256_nn_bin);
		return sha256_nn_bin;

		case NID_sha384:
		*len = sizeof(sha384_nn_bin);
		return sha384_nn_bin;

		case NID_sha512:
		*len = sizeof(sha512_nn_bin);
		return sha512_nn_bin;

		default:
		return NULL;

		}
	}

int FIPS_rsa_sign_ctx(RSA *rsa, EVP_MD_CTX *ctx,
			int rsa_pad_mode, int saltlen, const EVP_MD *mgf1Hash,
			unsigned char *sigret, unsigned int *siglen)
	{
	unsigned int md_len, rv;
	unsigned char md[EVP_MAX_MD_SIZE];
        FIPS_digestfinal(ctx, md, &md_len);
	rv = FIPS_rsa_sign_digest(rsa, md, md_len,
					M_EVP_MD_CTX_md(ctx),
					rsa_pad_mode, saltlen,
					mgf1Hash, sigret, siglen);
	OPENSSL_cleanse(md, md_len);
	return rv;
	}


int FIPS_rsa_sign_digest(RSA *rsa, const unsigned char *md, int md_len,
			const EVP_MD *mhash, int rsa_pad_mode, int saltlen,
			const EVP_MD *mgf1Hash,
			unsigned char *sigret, unsigned int *siglen)
	{
	int i=0,j,ret=0;
	unsigned int dlen;
	const unsigned char *der;
	int md_type;
	/* Largest DigestInfo: 19 (max encoding) + max MD */
	unsigned char tmpdinfo[19 + EVP_MAX_MD_SIZE];

	if (FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_RSA_SIGN_DIGEST, FIPS_R_SELFTEST_FAILED);
		return 0;
		}
	if (!mhash && rsa_pad_mode == RSA_PKCS1_PADDING)
		md_type = saltlen;
	else
		md_type = M_EVP_MD_type(mhash);

	if (rsa_pad_mode == RSA_X931_PADDING)
		{
		int hash_id;
		memcpy(tmpdinfo, md, md_len);
		hash_id = RSA_X931_hash_id(md_type);
		if (hash_id == -1)
			{
			RSAerr(RSA_F_FIPS_RSA_SIGN_DIGEST,RSA_R_UNKNOWN_ALGORITHM_TYPE);
			return 0;
			}
		tmpdinfo[md_len] = (unsigned char)hash_id;
		i = md_len + 1;
		}
	else if (rsa_pad_mode == RSA_PKCS1_PADDING)
		{

		der = fips_digestinfo_encoding(md_type, &dlen);
		
		if (!der)
			{
			RSAerr(RSA_F_FIPS_RSA_SIGN_DIGEST,RSA_R_UNKNOWN_ALGORITHM_TYPE);
			return 0;
			}
		memcpy(tmpdinfo, der, dlen);
		memcpy(tmpdinfo + dlen, md, md_len);

		i = dlen + md_len;

		}
	else if (rsa_pad_mode == RSA_PKCS1_PSS_PADDING)
		{
		unsigned char *sbuf;
		i = RSA_size(rsa);
		sbuf = OPENSSL_malloc(RSA_size(rsa));
		if (!sbuf)
			{
			RSAerr(RSA_F_FIPS_RSA_SIGN_DIGEST,ERR_R_MALLOC_FAILURE);
			goto psserr;
			}
		if (!RSA_padding_add_PKCS1_PSS_mgf1(rsa, sbuf, md, mhash,
							mgf1Hash, saltlen))
			goto psserr;
		j=rsa->meth->rsa_priv_enc(i,sbuf,sigret,rsa,RSA_NO_PADDING);
		if (j > 0)
			{
			ret=1;
			*siglen=j;
			}
		psserr:
		OPENSSL_cleanse(sbuf, i);
		OPENSSL_free(sbuf);
		return ret;
		}

	j=RSA_size(rsa);
	if (i > (j-RSA_PKCS1_PADDING_SIZE))
		{
		RSAerr(RSA_F_FIPS_RSA_SIGN_DIGEST,RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
		goto done;
		}
	/* NB: call underlying method directly to avoid FIPS blocking */
	j=rsa->meth->rsa_priv_enc(i,tmpdinfo,sigret,rsa,rsa_pad_mode);
	if (j > 0)
		{
		ret=1;
		*siglen=j;
		}

	done:
	OPENSSL_cleanse(tmpdinfo,i);
	return ret;
	}

int FIPS_rsa_verify_ctx(RSA *rsa, EVP_MD_CTX *ctx,
			int rsa_pad_mode, int saltlen, const EVP_MD *mgf1Hash,
			const unsigned char *sigbuf, unsigned int siglen)
	{
	unsigned int md_len, rv;
	unsigned char md[EVP_MAX_MD_SIZE];
        FIPS_digestfinal(ctx, md, &md_len);
	rv = FIPS_rsa_verify_digest(rsa, md, md_len, M_EVP_MD_CTX_md(ctx),
					rsa_pad_mode, saltlen, mgf1Hash,
					sigbuf, siglen);
	OPENSSL_cleanse(md, md_len);
	return rv;
	}
	
int FIPS_rsa_verify_digest(RSA *rsa, const unsigned char *dig, int diglen,
			const EVP_MD *mhash, int rsa_pad_mode, int saltlen,
			const EVP_MD *mgf1Hash,
			const unsigned char *sigbuf, unsigned int siglen)
	{
	int i,ret=0;
	unsigned int dlen;
	unsigned char *s;
	const unsigned char *der;
	int md_type;
	int rsa_dec_pad_mode;

	if (FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_RSA_VERIFY_DIGEST, FIPS_R_SELFTEST_FAILED);
		return 0;
		}

	if (siglen != (unsigned int)RSA_size(rsa))
		{
		RSAerr(RSA_F_FIPS_RSA_VERIFY_DIGEST,RSA_R_WRONG_SIGNATURE_LENGTH);
		return(0);
		}

	if (!mhash && rsa_pad_mode == RSA_PKCS1_PADDING)
		md_type = saltlen;
	else
		md_type = M_EVP_MD_type(mhash);

	s= OPENSSL_malloc((unsigned int)siglen);
	if (s == NULL)
		{
		RSAerr(RSA_F_FIPS_RSA_VERIFY_DIGEST,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (rsa_pad_mode == RSA_PKCS1_PSS_PADDING)
		rsa_dec_pad_mode = RSA_NO_PADDING;
	else
		rsa_dec_pad_mode = rsa_pad_mode;

	/* NB: call underlying method directly to avoid FIPS blocking */
	i=rsa->meth->rsa_pub_dec((int)siglen,sigbuf,s, rsa, rsa_dec_pad_mode);

	if (i <= 0) goto err;

	if (rsa_pad_mode == RSA_X931_PADDING)
		{
		int hash_id;
		if (i != (int)(diglen + 1))
			{
			RSAerr(RSA_F_FIPS_RSA_VERIFY_DIGEST,RSA_R_BAD_SIGNATURE);
			goto err;
			}
		hash_id = RSA_X931_hash_id(md_type);
		if (hash_id == -1)
			{
			RSAerr(RSA_F_FIPS_RSA_VERIFY_DIGEST,RSA_R_UNKNOWN_ALGORITHM_TYPE);
			goto err;
			}
		if (s[diglen] != (unsigned char)hash_id)
			{
			RSAerr(RSA_F_FIPS_RSA_VERIFY_DIGEST,RSA_R_BAD_SIGNATURE);
			goto err;
			}
		if (memcmp(s, dig, diglen))
			{
			RSAerr(RSA_F_FIPS_RSA_VERIFY_DIGEST,RSA_R_BAD_SIGNATURE);
			goto err;
			}
		ret = 1;
		}
	else if (rsa_pad_mode == RSA_PKCS1_PADDING)
		{

		der = fips_digestinfo_encoding(md_type, &dlen);
		
		if (!der)
			{
			RSAerr(RSA_F_FIPS_RSA_VERIFY_DIGEST,RSA_R_UNKNOWN_ALGORITHM_TYPE);
			return(0);
			}

		/* Compare, DigestInfo length, DigestInfo header and finally
		 * digest value itself
		 */

		/* If length mismatch try alternate encoding */
		if (i != (int)(dlen + diglen))
			der = fips_digestinfo_nn_encoding(md_type, &dlen);

		if ((i != (int)(dlen + diglen)) || memcmp(der, s, dlen)
			|| memcmp(s + dlen, dig, diglen))
			{
			RSAerr(RSA_F_FIPS_RSA_VERIFY_DIGEST,RSA_R_BAD_SIGNATURE);
			goto err;
			}
		ret = 1;

		}
	else if (rsa_pad_mode == RSA_PKCS1_PSS_PADDING)
		{
		ret = RSA_verify_PKCS1_PSS_mgf1(rsa, dig, mhash, mgf1Hash,
						s, saltlen);
		if (ret < 0)
			ret = 0;
		}
err:
	if (s != NULL)
		{
		OPENSSL_cleanse(s, siglen);
		OPENSSL_free(s);
		}
	return(ret);
	}

int FIPS_rsa_sign(RSA *rsa, const unsigned char *msg, int msglen,
			const EVP_MD *mhash, int rsa_pad_mode, int saltlen,
			const EVP_MD *mgf1Hash,
			unsigned char *sigret, unsigned int *siglen)
	{
	unsigned int md_len, rv;
	unsigned char md[EVP_MAX_MD_SIZE];
        FIPS_digest(msg, msglen, md, &md_len, mhash);
	rv = FIPS_rsa_sign_digest(rsa, md, md_len, mhash, rsa_pad_mode,
					saltlen, mgf1Hash, sigret, siglen);
	OPENSSL_cleanse(md, md_len);
	return rv;
	}


int FIPS_rsa_verify(RSA *rsa, const unsigned char *msg, int msglen,
			const EVP_MD *mhash, int rsa_pad_mode, int saltlen,
			const EVP_MD *mgf1Hash,
			const unsigned char *sigbuf, unsigned int siglen)
	{
	unsigned int md_len, rv;
	unsigned char md[EVP_MAX_MD_SIZE];
        FIPS_digest(msg, msglen, md, &md_len, mhash);
	rv = FIPS_rsa_verify_digest(rsa, md, md_len, mhash, rsa_pad_mode,
					saltlen, mgf1Hash, sigbuf, siglen);
	OPENSSL_cleanse(md, md_len);
	return rv;
	}

#endif
