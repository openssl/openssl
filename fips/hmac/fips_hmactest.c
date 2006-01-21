/* fips_hmactest.c */
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
    printf("No FIPS HMAC support\n");
    return(0);
}

#else

static int hmac_test(BIO *err, const EVP_MD *md, BIO *out, BIO *in);
static int print_hmac(BIO *err, const EVP_MD *md, BIO *out,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Msglen, int Tlen);

int main(int argc, char **argv)
	{
	BIO *in = NULL, *out = NULL, *err = NULL;

	int ret = 1;

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

	if (!hmac_test(err, EVP_sha1(), out, in))
		{
		fprintf(stderr, "FATAL hmac file processing error\n");
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

#define HMAC_TEST_MAXLINELEN	1024

int hmac_test(BIO *err, const EVP_MD *md, BIO *out, BIO *in)
	{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	unsigned char *Key = NULL, *Msg = NULL;
	int Count, Klen, Tlen;
	long Keylen, Msglen;
	int ret = 0;
	int lnum = 0;

	olinebuf = OPENSSL_malloc(HMAC_TEST_MAXLINELEN);
	linebuf = OPENSSL_malloc(HMAC_TEST_MAXLINELEN);

	if (!linebuf || !olinebuf)
		goto error;

	Count = -1;
	Klen = -1;
	Tlen = -1;

	while (BIO_gets(in, olinebuf, HMAC_TEST_MAXLINELEN) > 0)
		{
		lnum++;
		strcpy(linebuf, olinebuf);
		keyword = linebuf;
		/* Skip leading space */
		while (isspace((unsigned char)*keyword))
			keyword++;

		/* Look for = sign */
		p = strchr(linebuf, '=');

		/* If no = or starts with [ (for [L=20] line) just copy */
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

		*p = 0;
		value = p + 1;

		/* Remove leading space from value */
		while (isspace((unsigned char)*value))
			value++;

		/* Remove trailing space from value */
		p = value + strlen(value) - 1;

		while (*p == '\n' || isspace((unsigned char)*p))
			*p-- = 0;

		if (!strcmp(keyword,"[L") && *p==']')
			{
			switch (atoi(value))
				{
				case 20: md=EVP_sha1();   break;
				case 28: md=EVP_sha224(); break;
				case 32: md=EVP_sha256(); break;
				case 48: md=EVP_sha384(); break;
				case 64: md=EVP_sha512(); break;
				default: goto parse_error;
				}
			}
		else if (!strcmp(keyword, "Count"))
			{
			if (Count != -1)
				goto parse_error;
			Count = atoi(value);
			if (Count < 0)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Klen"))
			{
			if (Klen != -1)
				goto parse_error;
			Klen = atoi(value);
			if (Klen < 0)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Tlen"))
			{
			if (Tlen != -1)
				goto parse_error;
			Tlen = atoi(value);
			if (Tlen < 0)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Msg"))
			{
			if (Msg)
				goto parse_error;
			Msg = string_to_hex(value, &Msglen);
			if (!Msg)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Key"))
			{
			if (Key)
				goto parse_error;
			Key = string_to_hex(value, &Keylen);
			if (!Key)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Mac"))
			continue;
		else
			goto parse_error;

		BIO_puts(out, olinebuf);

		if (Key && Msg && (Tlen > 0) && (Klen > 0))
			{
			if (!print_hmac(err, md, out, Key, Klen, Msg, Msglen, Tlen))
				goto error;
			OPENSSL_free(Key);
			Key = NULL;
			OPENSSL_free(Msg);
			Msg = NULL;
			Klen = -1;
			Tlen = -1;
			Count = -1;
			}

		}


	ret = 1;


	error:

	if (olinebuf)
		OPENSSL_free(olinebuf);
	if (linebuf)
		OPENSSL_free(linebuf);
	if (Key)
		OPENSSL_free(Key);
	if (Msg)
		OPENSSL_free(Msg);

	return ret;

	parse_error:

	BIO_printf(err, "FATAL parse error processing line %d\n", lnum);

	goto error;

	}

static int print_hmac(BIO *err, const EVP_MD *emd, BIO *out,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Msglen, int Tlen)
	{
	int i, mdlen;
	unsigned char md[EVP_MAX_MD_SIZE];
	if (!HMAC(emd, Key, Klen, Msg, Msglen, md,
						(unsigned int *)&mdlen))
		{
		BIO_puts(err, "Error calculating HMAC\n");
		return 0;
		}
	if (Tlen > mdlen)
		{
		BIO_puts(err, "Parameter error, Tlen > HMAC length\n");
		return 0;
		}
	BIO_puts(out, "Mac = ");
	for (i = 0; i < Tlen; i++)
		BIO_printf(out, "%02x", md[i]);
	BIO_puts(out, "\n");
	return 1;
	}

#endif
