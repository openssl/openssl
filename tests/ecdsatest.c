/* crypto/ecdsa/ecdsatest.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2000-2005 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by 
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/rand.h>

/* declaration of the test functions */
int x9_62_test_internal(BIO *out, int nid, const char *r, const char *s);
int test_builtin(BIO *);

/* some tests from the X9.62 draft */
int x9_62_test_internal(BIO *out, int nid, const char *r_in, const char *s_in)
	{
	int	ret = 0;
	const char message[] = "abc";
	unsigned char digest[20];
	unsigned int  dgst_len = 0;
	EVP_MD_CTX md_ctx;
	EC_KEY    *key = NULL;
	ECDSA_SIG *signature = NULL;
	BIGNUM    *r = NULL, *s = NULL;

	EVP_MD_CTX_init(&md_ctx);
	/* get the message digest */
	EVP_DigestInit(&md_ctx, EVP_ecdsa());
	EVP_DigestUpdate(&md_ctx, (const void*)message, 3);
	EVP_DigestFinal(&md_ctx, digest, &dgst_len);

	BIO_printf(out, "testing %s: ", OBJ_nid2sn(nid));
	/* create the key */
	if ((key = EC_KEY_new_by_curve_name(nid)) == NULL)
		goto x962_int_err;
	if (!EC_KEY_generate_key(key))
		goto x962_int_err;
	BIO_printf(out, ".");
	(void)BIO_flush(out);
	/* create the signature */
	signature = ECDSA_do_sign(digest, 20, key);
	if (signature == NULL)
		goto x962_int_err;
	BIO_printf(out, ".");
	(void)BIO_flush(out);
	/* compare the created signature with the expected signature */
	if ((r = BN_new()) == NULL || (s = BN_new()) == NULL)
		goto x962_int_err;
	if (!BN_dec2bn(&r, r_in) ||
	    !BN_dec2bn(&s, s_in))
		goto x962_int_err;
	if (BN_cmp(signature->r ,r) || BN_cmp(signature->s, s))
		goto x962_int_err;
	BIO_printf(out, ".");
	(void)BIO_flush(out);
	/* verify the signature */
	if (ECDSA_do_verify(digest, 20, signature, key) != 1)
		goto x962_int_err;
	BIO_printf(out, ".");
	(void)BIO_flush(out);

	BIO_printf(out, " ok\n");
	ret = 1;
x962_int_err:
	if (!ret)
		BIO_printf(out, " failed\n");
	if (key)
		EC_KEY_free(key);
	if (signature)
		ECDSA_SIG_free(signature);
	if (r)
		BN_free(r);
	if (s)
		BN_free(s);
	EVP_MD_CTX_cleanup(&md_ctx);
	return ret;
	}

int test_builtin(BIO *out)
	{
	EC_builtin_curve *curves = NULL;
	size_t		crv_len = 0, n = 0;
	EC_KEY		*eckey = NULL, *wrong_eckey = NULL;
	EC_GROUP	*group;
	ECDSA_SIG	*ecdsa_sig = NULL;
	unsigned char	digest[20], wrong_digest[20];
	unsigned char	*signature = NULL;
	const unsigned char	*sig_ptr;
	unsigned char	*sig_ptr2;
	unsigned char	*raw_buf = NULL;
	unsigned int	sig_len, degree, r_len, s_len, bn_len, buf_len;
	int		nid, ret =  0;
	
	/* fill digest values with some random data */
	if (!RAND_pseudo_bytes(digest, 20) ||
	    !RAND_pseudo_bytes(wrong_digest, 20))
		{
		BIO_printf(out, "ERROR: unable to get random data\n");
		goto builtin_err;
		}

	/* create and verify a ecdsa signature with every availble curve
	 * (with ) */
	BIO_printf(out, "\ntesting ECDSA_sign() and ECDSA_verify() "
		"with some internal curves:\n");

	/* get a list of all internal curves */
	crv_len = EC_get_builtin_curves(NULL, 0);

	curves = reallocarray(NULL, sizeof(EC_builtin_curve), crv_len);

	if (curves == NULL)
		{
		BIO_printf(out, "malloc error\n");
		goto builtin_err;
		}
	
	if (!EC_get_builtin_curves(curves, crv_len))
		{
		BIO_printf(out, "unable to get internal curves\n");
		goto builtin_err;
		}

	/* now create and verify a signature for every curve */
	for (n = 0; n < crv_len; n++)
		{
		unsigned char dirt, offset;

		nid = curves[n].nid;
		if (nid == NID_ipsec4)
			continue;
		/* create new ecdsa key (== EC_KEY) */
		if ((eckey = EC_KEY_new()) == NULL)
			goto builtin_err;
		group = EC_GROUP_new_by_curve_name(nid);
		if (group == NULL)
			goto builtin_err;
		if (EC_KEY_set_group(eckey, group) == 0)
			goto builtin_err;
		EC_GROUP_free(group);
		degree = EC_GROUP_get_degree(EC_KEY_get0_group(eckey));
		if (degree < 160)
			/* drop the curve */ 
			{
			EC_KEY_free(eckey);
			eckey = NULL;
			continue;
			}
		BIO_printf(out, "%s: ", OBJ_nid2sn(nid));
		/* create key */
		if (!EC_KEY_generate_key(eckey))
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		/* create second key */
		if ((wrong_eckey = EC_KEY_new()) == NULL)
			goto builtin_err;
		group = EC_GROUP_new_by_curve_name(nid);
		if (group == NULL)
			goto builtin_err;
		if (EC_KEY_set_group(wrong_eckey, group) == 0)
			goto builtin_err;
		EC_GROUP_free(group);
		if (!EC_KEY_generate_key(wrong_eckey))
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}

		BIO_printf(out, ".");
		(void)BIO_flush(out);
		/* check key */
		if (!EC_KEY_check_key(eckey))
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		BIO_printf(out, ".");
		(void)BIO_flush(out);
		/* create signature */
		sig_len = ECDSA_size(eckey);
		if ((signature = malloc(sig_len)) == NULL)
			goto builtin_err;
                if (!ECDSA_sign(0, digest, 20, signature, &sig_len, eckey))
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		BIO_printf(out, ".");
		(void)BIO_flush(out);
		/* verify signature */
		if (ECDSA_verify(0, digest, 20, signature, sig_len, eckey) != 1)
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		BIO_printf(out, ".");
		(void)BIO_flush(out);
		/* verify signature with the wrong key */
		if (ECDSA_verify(0, digest, 20, signature, sig_len, 
			wrong_eckey) == 1)
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		BIO_printf(out, ".");
		(void)BIO_flush(out);
		/* wrong digest */
		if (ECDSA_verify(0, wrong_digest, 20, signature, sig_len,
			eckey) == 1)
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		BIO_printf(out, ".");
		(void)BIO_flush(out);
		/* wrong length */
		if (ECDSA_verify(0, digest, 20, signature, sig_len - 1,
			eckey) == 1)
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		BIO_printf(out, ".");
		(void)BIO_flush(out);

		/* Modify a single byte of the signature: to ensure we don't
		 * garble the ASN1 structure, we read the raw signature and
		 * modify a byte in one of the bignums directly. */
		sig_ptr = signature;
		if ((ecdsa_sig = d2i_ECDSA_SIG(NULL, &sig_ptr, sig_len)) == NULL)
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}

		/* Store the two BIGNUMs in raw_buf. */
		r_len = BN_num_bytes(ecdsa_sig->r);
		s_len = BN_num_bytes(ecdsa_sig->s);
		bn_len = (degree + 7) / 8;
		if ((r_len > bn_len) || (s_len > bn_len))
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		buf_len = 2 * bn_len;
		if ((raw_buf = calloc(1, buf_len)) == NULL)
			goto builtin_err;
		BN_bn2bin(ecdsa_sig->r, raw_buf + bn_len - r_len);
		BN_bn2bin(ecdsa_sig->s, raw_buf + buf_len - s_len);

		/* Modify a single byte in the buffer. */
		offset = raw_buf[10] % buf_len;
		dirt   = raw_buf[11] ? raw_buf[11] : 1;
		raw_buf[offset] ^= dirt;
		/* Now read the BIGNUMs back in from raw_buf. */
		if ((BN_bin2bn(raw_buf, bn_len, ecdsa_sig->r) == NULL) ||
			(BN_bin2bn(raw_buf + bn_len, bn_len, ecdsa_sig->s) == NULL))
			goto builtin_err;

		sig_ptr2 = signature;
		sig_len = i2d_ECDSA_SIG(ecdsa_sig, &sig_ptr2);
		if (ECDSA_verify(0, digest, 20, signature, sig_len, eckey) == 1)
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		/* Sanity check: undo the modification and verify signature. */
		raw_buf[offset] ^= dirt;
		if ((BN_bin2bn(raw_buf, bn_len, ecdsa_sig->r) == NULL) ||
			(BN_bin2bn(raw_buf + bn_len, bn_len, ecdsa_sig->s) == NULL))
			goto builtin_err;

		sig_ptr2 = signature;
		sig_len = i2d_ECDSA_SIG(ecdsa_sig, &sig_ptr2);
		if (ECDSA_verify(0, digest, 20, signature, sig_len, eckey) != 1)
			{
			BIO_printf(out, " failed\n");
			goto builtin_err;
			}
		BIO_printf(out, ".");
		(void)BIO_flush(out);
		
		BIO_printf(out, " ok\n");
		/* cleanup */
		/* clean bogus errors */
		ERR_clear_error();
		free(signature);
		signature = NULL;
		EC_KEY_free(eckey);
		eckey = NULL;
		EC_KEY_free(wrong_eckey);
		wrong_eckey = NULL;
		ECDSA_SIG_free(ecdsa_sig);
		ecdsa_sig = NULL;
		free(raw_buf);
		raw_buf = NULL;
		}

	ret = 1;	
builtin_err:
	if (eckey)
		EC_KEY_free(eckey);
	if (wrong_eckey)
		EC_KEY_free(wrong_eckey);
	if (ecdsa_sig)
		ECDSA_SIG_free(ecdsa_sig);
	free(signature);
	free(raw_buf);
	free(curves);

	return ret;
	}

int main(void)
	{
	int 	ret = 1;
	BIO	*out;

	out = BIO_new_fp(stdout, BIO_NOCLOSE);

	ERR_load_crypto_strings();

	/* the tests */
	if (!test_builtin(out)) goto err;
	
	ret = 0;
err:	
	if (ret) 	
		BIO_printf(out, "\nECDSA test failed\n");
	else 
		BIO_printf(out, "\nECDSA test passed\n");
	if (ret)
		ERR_print_errors(out);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
	CRYPTO_mem_leaks(out);
	if (out != NULL)
		BIO_free(out);
	return ret;
	}	
