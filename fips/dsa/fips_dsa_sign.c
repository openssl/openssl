/* fips_dsa_sign.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2007.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#ifdef OPENSSL_FIPS

/* FIPS versions of DSA_sign() and DSA_verify().
 * Handle DSA_SIG structures to avoid need to handle ASN1.
 */

DSA_SIG * FIPS_dsa_sign_ctx(DSA *dsa, EVP_MD_CTX *ctx)
	{
	DSA_SIG *s;
	unsigned char dig[EVP_MAX_MD_SIZE];
	unsigned int dlen;
        FIPS_digestfinal(ctx, dig, &dlen);
	s = dsa->meth->dsa_do_sign(dig,dlen,dsa);
	OPENSSL_cleanse(dig, dlen);
	return s;
	}

DSA_SIG * FIPS_dsa_sign_digest(DSA *dsa, const unsigned char *dig, int dlen)
	{
	if (FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_DSA_SIGN_DIGEST, FIPS_R_SELFTEST_FAILED);
		return NULL;
		}
	return dsa->meth->dsa_do_sign(dig, dlen, dsa);
	}

int FIPS_dsa_verify_ctx(DSA *dsa, EVP_MD_CTX *ctx, DSA_SIG *s)
	{
	int ret=-1;
	unsigned char dig[EVP_MAX_MD_SIZE];
	unsigned int dlen;
        FIPS_digestfinal(ctx, dig, &dlen);
	ret=dsa->meth->dsa_do_verify(dig,dlen,s,dsa);
	OPENSSL_cleanse(dig, dlen);
	return ret;
	}

int FIPS_dsa_verify_digest(DSA *dsa,
				const unsigned char *dig, int dlen, DSA_SIG *s)
	{
	if (FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_DSA_VERIFY_DIGEST, FIPS_R_SELFTEST_FAILED);
		return -1;
		}
	return dsa->meth->dsa_do_verify(dig,dlen,s,dsa);
	}

int FIPS_dsa_verify(DSA *dsa, const unsigned char *msg, size_t msglen,
			const EVP_MD *mhash, DSA_SIG *s)
	{
	int ret=-1;
	unsigned char dig[EVP_MAX_MD_SIZE];
	unsigned int dlen;
        FIPS_digest(msg, msglen, dig, &dlen, mhash);
	ret=FIPS_dsa_verify_digest(dsa, dig, dlen, s);
	OPENSSL_cleanse(dig, dlen);
	return ret;
	}

DSA_SIG * FIPS_dsa_sign(DSA *dsa, const unsigned char *msg, size_t msglen,
			const EVP_MD *mhash)
	{
	DSA_SIG *s;
	unsigned char dig[EVP_MAX_MD_SIZE];
	unsigned int dlen;
        FIPS_digest(msg, msglen, dig, &dlen, mhash);
	s = FIPS_dsa_sign_digest(dsa, dig, dlen);
	OPENSSL_cleanse(dig, dlen);
	return s;
	}

#endif
