/* fips_rsastest.c */
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

static int rsa_stest(BIO *err, BIO *out, BIO *in, int Saltlen);
static int rsa_printsig(BIO *err, BIO *out, RSA *rsa, const EVP_MD *dgst,
		unsigned char *Msg, long Msglen, int Saltlen);

int main(int argc, char **argv)
	{
	BIO *in = NULL, *out = NULL, *err = NULL;

	int ret = 1, Saltlen = -1;
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

	if (!rsa_stest(err, out, in, Saltlen))
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

int rsa_stest(BIO *err, BIO *out, BIO *in, int Saltlen)
	{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	RSA *rsa = NULL;
	const EVP_MD *dgst = NULL;
	unsigned char *Msg = NULL;
	long Msglen;
	int keylen = -1, current_keylen = -1;
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

		/* If no = just copy */
		if (!p)
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

		/* Look for [mod = XXX] for key length */

		if (!strcmp(keyword, "[mod"))
			{
			p = value + strlen(value) - 1;
			if (*p != ']')
				goto parse_error;
			*p = 0;
			keylen = atoi(value);
			if (keylen < 0)
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

		BIO_puts(out, olinebuf);

		/* If key length has changed, generate and output public
		 * key components of new RSA private key.
		 */

		if (keylen != current_keylen)
			{
			if (rsa)
				RSA_free(rsa);
			rsa = RSA_generate_key(keylen, 0x1001, 0, NULL);
			if (!rsa)
				goto error;
			BIO_puts(out, "n = ");
			BN_print(out, rsa->n);
			BIO_puts(out, "\ne = ");
			BN_print(out, rsa->e);
			BIO_puts(out, "\n");
			current_keylen = keylen;
			}

		if (Msg && dgst)
			{
			if (!rsa_printsig(err, out, rsa, dgst, Msg, Msglen,
								Saltlen))
				goto error;
			OPENSSL_free(Msg);
			Msg = NULL;
			}

		}

	ret = 1;

	error:

	if (olinebuf)
		OPENSSL_free(olinebuf);
	if (linebuf)
		OPENSSL_free(linebuf);
	if (rsa)
		RSA_free(rsa);

	return ret;

	parse_error:

	BIO_printf(err, "FATAL parse error processing line %d\n", lnum);

	goto error;

	}

static int rsa_printsig(BIO *err, BIO *out, RSA *rsa, const EVP_MD *dgst,
		unsigned char *Msg, long Msglen, int Saltlen)
	{
	int ret = 0;
	unsigned char *sigbuf = NULL;
	int i, siglen;
	/* EVP_PKEY structure */
	EVP_PKEY *key = NULL;
	EVP_MD_CTX ctx;
	key = EVP_PKEY_new();
	if (!key)
		goto error;
	if (!EVP_PKEY_set1_RSA(key, rsa))
		goto error;

	siglen = EVP_PKEY_size(key);
	sigbuf = OPENSSL_malloc(siglen);
	if (!sigbuf)
		goto error;

	EVP_MD_CTX_init(&ctx);

	if (Saltlen != -1)
		{
		unsigned int mdlen;
		unsigned char mdtmp[EVP_MAX_MD_SIZE + 1];

		if (!EVP_DigestInit_ex(&ctx, dgst, NULL))
			goto error;
		if (!EVP_DigestUpdate(&ctx, Msg, Msglen))
			goto error;
		if (!EVP_DigestFinal(&ctx, mdtmp, &mdlen))
			goto error;
	
		if (Saltlen == -2)
			{
			mdtmp[mdlen] = RSA_X931_hash_id(EVP_MD_type(dgst));
			siglen = RSA_private_encrypt(mdlen + 1, mdtmp,
					sigbuf, rsa, RSA_X931_PADDING);
			if (siglen <= 0)
				goto error;
			}
		else
			{
			if (!RSA_padding_add_PKCS1_PSS(rsa, sigbuf, mdtmp,
							dgst, Saltlen))
				goto error;
			siglen = RSA_private_encrypt(siglen, sigbuf, sigbuf,
						rsa, RSA_NO_PADDING);
			if (siglen <= 0)
				goto error;
			}
		}
	else
		{
		if (!EVP_SignInit_ex(&ctx, dgst, NULL))
			goto error;
		if (!EVP_SignUpdate(&ctx, Msg, Msglen))
			goto error;
		if (!EVP_SignFinal(&ctx, sigbuf, (unsigned int *)&siglen, key))
			goto error;
		}

	EVP_MD_CTX_cleanup(&ctx);

	BIO_puts(out, "S = ");

	for (i = 0; i < siglen; i++)
		BIO_printf(out, "%02X", sigbuf[i]);

	BIO_puts(out, "\n");

	ret = 1;

	error:
	if (key)
		EVP_PKEY_free(key);

	return ret;
	}
#endif
