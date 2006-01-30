/* fips_rsavtest.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2005.
 */
/* ====================================================================
 * Copyright (c) 2005 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_FIPS

int main(int argc, char *argv[])
{
    printf("No FIPS RSA support\n");
    return(0);
}

#else

int rsa_test(BIO *err, BIO *out, BIO *in, int saltlen);
static int rsa_printver(BIO *err, BIO *out,
		BIGNUM *n, BIGNUM *e,
		const EVP_MD *dgst,
		unsigned char *Msg, long Msglen,
		unsigned char *S, long Slen, int Saltlen);

int main(int argc, char **argv)
	{
	BIO *in = NULL, *out = NULL, *err = NULL;

	int ret = 1;
	int Saltlen = -1;
	ERR_load_crypto_strings();

	err = BIO_new_fp(stderr, BIO_NOCLOSE);

	if (!err)
		{
		fprintf(stderr, "FATAL stderr initialization error\n");
		goto end;
		}

	if(!FIPS_mode_set(1))
		{
		ERR_print_errors(err);
		goto end;
		}

	if ((argc > 2) && !strcmp("-saltlen", argv[1]))
		{
		Saltlen = atoi(argv[2]);
		if (Saltlen < 0)
			{
			BIO_printf(err, "FATAL: Invalid salt length\n");
			goto end;
			}
		argc -= 2;
		argv += 2;
		}
	else if ((argc > 1) && !strcmp("-x931", argv[1]))
		{
		Saltlen = -2;
		argc--;
		argv++;
		}

	if (argc == 1)
		in = BIO_new_fp(stdin, BIO_NOCLOSE);
	else
		in = BIO_new_file(argv[1], "r");

	if (argc < 2)
		out = BIO_new_fp(stdout, BIO_NOCLOSE);
	else
		out = BIO_new_file(argv[2], "w");

	if (!in)
		{
		BIO_printf(err, "FATAL input initialization error\n");
		goto end;
		}

	if (!out)
		{
		fprintf(stderr, "FATAL output initialization error\n");
		goto end;
		}

	if (!rsa_test(err, out, in, Saltlen))
		{
		fprintf(stderr, "FATAL RSAVTEST file processing error\n");
		goto end;
		}
	else
		ret = 0;

	end:

	if (ret && err)
		ERR_print_errors(err);

	if (in)
		BIO_free(in);
	if (out)
		BIO_free(out);
	if (err)
		BIO_free(err);

	return ret;

	}

#define RSA_TEST_MAXLINELEN	10240

int rsa_test(BIO *err, BIO *out, BIO *in, int Saltlen)
	{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	const EVP_MD *dgst = NULL;
	BIGNUM *n = NULL, *e = NULL;
	unsigned char *Msg = NULL, *S = NULL;
	long Msglen, Slen;
	int ret = 0;
	int lnum = 0;

	olinebuf = OPENSSL_malloc(RSA_TEST_MAXLINELEN);
	linebuf = OPENSSL_malloc(RSA_TEST_MAXLINELEN);

	if (!linebuf || !olinebuf)
		goto error;

	while (BIO_gets(in, olinebuf, RSA_TEST_MAXLINELEN) > 0)
		{
		lnum++;
		strcpy(linebuf, olinebuf);
		keyword = linebuf;
		/* Skip leading space */
		while (isspace((unsigned char)*keyword))
			keyword++;

		/* Look for = sign */
		p = strchr(linebuf, '=');

		/* If no = or starts with [ (for [foo = bar] line) just copy */
		if (!p || *keyword=='[')
			{
			if (!BIO_puts(out, olinebuf))
				goto error;
			continue;
			}

		q = p - 1;

		/* Remove trailing space */
		while (isspace((unsigned char)*q))
			*q-- = 0;


		value = p + 1;

		/* Remove leading space from value */
		while (isspace((unsigned char)*value))
			value++;

		/* Remove trailing space from value */
		p = value + strlen(value) - 1;

		while (*p == '\n' || isspace((unsigned char)*p))
			*p-- = 0;

		if (!strcmp(keyword, "n"))
			{
			if (!BN_hex2bn(&n,value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "e"))
			{
			if (!BN_hex2bn(&e,value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "SHAAlg"))
			{
			if (!strcmp(value, "SHA1"))
				dgst = EVP_sha1();
			else if (!strcmp(value, "SHA224"))
				dgst = EVP_sha224();
			else if (!strcmp(value, "SHA256"))
				dgst = EVP_sha256();
			else if (!strcmp(value, "SHA384"))
				dgst = EVP_sha384();
			else if (!strcmp(value, "SHA512"))
				dgst = EVP_sha512();
			else
				{
				BIO_printf(err,
					"FATAL: unsupported algorithm \"%s\"\n",
								value);
				goto parse_error;
				}
			}
		else if (!strcmp(keyword, "Msg"))
			{
			if (Msg)
				goto parse_error;
			if (strlen(value) & 1)
				*(--value) = '0';
			Msg = string_to_hex(value, &Msglen);
			if (!Msg)
				goto parse_error;
			}
		else if (!strcmp(keyword, "S"))
			{
			if (S)
				goto parse_error;
			if (strlen(value) & 1)
				*(--value) = '0';
			S = string_to_hex(value, &Slen);
			if (!S)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Result"))
			continue;
		else
			goto parse_error;

		BIO_puts(out, olinebuf);

		if (n && e && Msg && S && dgst)
			{
			if (!rsa_printver(err, out, n, e, dgst,
					Msg, Msglen, S, Slen, Saltlen))
				goto error;
			OPENSSL_free(Msg);
			Msg = NULL;
			OPENSSL_free(S);
			S = NULL;
			}

		}


	ret = 1;


	error:

	if (olinebuf)
		OPENSSL_free(olinebuf);
	if (linebuf)
		OPENSSL_free(linebuf);
	if (n)
		BN_free(n);
	if (e)
		BN_free(e);

	return ret;

	parse_error:

	BIO_printf(err, "FATAL parse error processing line %d\n", lnum);

	goto error;

	}

static int rsa_printver(BIO *err, BIO *out,
		BIGNUM *n, BIGNUM *e,
		const EVP_MD *dgst,
		unsigned char *Msg, long Msglen,
		unsigned char *S, long Slen, int Saltlen)
	{
	int ret = 0, r;
	/* Setup RSA and EVP_PKEY structures */
	RSA *rsa_pubkey = NULL;
	EVP_PKEY *pubkey = NULL;
	EVP_MD_CTX ctx;
	unsigned char *buf = NULL;
	rsa_pubkey = RSA_new();
	pubkey = EVP_PKEY_new();
	if (!rsa_pubkey || !pubkey)
		goto error;
	rsa_pubkey->n = BN_dup(n);
	rsa_pubkey->e = BN_dup(e);
	if (!rsa_pubkey->n || !rsa_pubkey->e)
		goto error;
	if (!EVP_PKEY_set1_RSA(pubkey, rsa_pubkey))
		goto error;

	EVP_MD_CTX_init(&ctx);

	if (Saltlen != -1)
		{
		int pad;
		unsigned char mdtmp[EVP_MAX_MD_SIZE];
		buf = OPENSSL_malloc(RSA_size(rsa_pubkey));
		if (Saltlen == -2)
			pad = RSA_X931_PADDING;
		else
			pad = RSA_NO_PADDING;
		if (!buf)
			goto error;
		r = RSA_public_decrypt(Slen, S, buf, rsa_pubkey, pad);

		if (r > 0)
			{
			EVP_DigestInit_ex(&ctx, dgst, NULL);
			if (!EVP_DigestUpdate(&ctx, Msg, Msglen))
				goto error;
			if (!EVP_DigestFinal_ex(&ctx, mdtmp, NULL))
				goto error;
			if (pad == RSA_X931_PADDING)
				{
				int mdlen = EVP_MD_size(dgst);
				if (r != mdlen + 1)
					r = 0;
				else if (buf[mdlen] !=
				    RSA_X931_hash_id(EVP_MD_type(dgst)))
					r = 0;
				else if (memcmp(buf, mdtmp, mdlen))
					r = 0;
				else
					r = 1;
				}
			else
				r = RSA_verify_PKCS1_PSS(rsa_pubkey,
							mdtmp, dgst,
							buf, Saltlen);
			}
		if (r < 0)
			r = 0;
		}
	else
		{

		if (!EVP_VerifyInit_ex(&ctx, dgst, NULL))
			goto error;
		if (!EVP_VerifyUpdate(&ctx, Msg, Msglen))
			goto error;

		r = EVP_VerifyFinal(&ctx, S, Slen, pubkey);

		}

	EVP_MD_CTX_cleanup(&ctx);

	if (r < 0)
		goto error;
	ERR_clear_error();

	if (r == 0)
		BIO_puts(out, "Result = F\n");
	else
		BIO_puts(out, "Result = P\n");

	ret = 1;

	error:
	if (rsa_pubkey)
		RSA_free(rsa_pubkey);
	if (pubkey)
		EVP_PKEY_free(pubkey);
	if (buf)
		OPENSSL_free(buf);

	return ret;
	}
#endif
