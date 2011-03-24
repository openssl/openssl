/* fips_cmactest.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
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

#define OPENSSL_FIPSAPI

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#ifndef OPENSSL_FIPS

int main(int argc, char *argv[])
{
    printf("No FIPS CMAC support\n");
    return(0);
}

#else

#include <openssl/fips.h>
#include "fips_utl.h"

static int cmac_test(const EVP_CIPHER *cipher, FILE *out, FILE *in, int mode);
static int print_cmac_gen(const EVP_CIPHER *cipher, FILE *out,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Msglen,
		int Tlen);
static int print_cmac_ver(const EVP_CIPHER *cipher, FILE *out,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Msglen,
		unsigned char *Mac, int Maclen,
		int Tlen);

int main(int argc, char **argv)
	{
	FILE *in = NULL, *out = NULL;
	int mode = 0;		/* 0 => Generate, 1 => Verify */

	int ret = 1;
	fips_set_error_print();
	if(!FIPS_mode_set(1))
		goto end;

	if (argc > 1 && argv[1][0] == '-')
		{
		if (strcmp(argv[1], "-g") == 0)
			mode = 0;
		else if (strcmp(argv[1], "-v") == 0)
			mode = 1;
		else
			{
			fprintf(stderr, "Unknown option %s\n", argv[1]);
			goto end;
			}
		argv++;
		argc--;
		}
	if (argc == 1)
		in = stdin;
	else
		in = fopen(argv[1], "r");

	if (argc < 2)
		out = stdout;
	else
		out = fopen(argv[2], "w");

	if (!in)
		{
		fprintf(stderr, "FATAL input initialization error\n");
		goto end;
		}

	if (!out)
		{
		fprintf(stderr, "FATAL output initialization error\n");
		goto end;
		}

	if (!cmac_test(EVP_aes_256_cbc(), out, in, mode))
		{
		fprintf(stderr, "FATAL cmac file processing error\n");
		goto end;
		}
	else
		ret = 0;

	end:

	if (in && (in != stdin))
		fclose(in);
	if (out && (out != stdout))
		fclose(out);

	return ret;

	}

#define CMAC_TEST_MAXLINELEN	1024

int cmac_test(const EVP_CIPHER *cipher, FILE *out, FILE *in, int mode)
	{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	unsigned char *Key = NULL, *Msg = NULL, *Mac = NULL;
	int Count, Klen, Mlen, Tlen;
	long Keylen, Msglen, Maclen;
	int ret = 0;
	int lnum = 0;

	olinebuf = OPENSSL_malloc(CMAC_TEST_MAXLINELEN);
	linebuf = OPENSSL_malloc(CMAC_TEST_MAXLINELEN);

	if (!linebuf || !olinebuf)
		goto error;

	Count = -1;
	Klen = -1;
	Mlen = -1;
	Tlen = -1;

	while (fgets(olinebuf, CMAC_TEST_MAXLINELEN, in))
		{
		lnum++;
		strcpy(linebuf, olinebuf);
		keyword = linebuf;
		/* Skip leading space */
		while (isspace((unsigned char)*keyword))
			keyword++;

		/* Skip comments */
		if (keyword[0] == '#')
			{
			if (fputs(olinebuf, out) < 0)
				goto error;
			continue;
			}

		/* Look for = sign */
		p = strchr(linebuf, '=');

		/* If no = or starts with [ (for [L=20] line) just copy */
		if (!p)
			{
			if (fputs(olinebuf, out) < 0)
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

		if (!strcmp(keyword, "Count"))
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
		else if (!strcmp(keyword, "Mlen"))
			{
			if (Mlen != -1)
				goto parse_error;
			Mlen = atoi(value);
			if (Mlen < 0)
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
		else if (!strcmp(keyword, "Key"))
			{
			if (Key)
				goto parse_error;
			Key = hex2bin_m(value, &Keylen);
			if (!Key)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Msg"))
			{
			if (Msg)
				goto parse_error;
			Msg = hex2bin_m(value, &Msglen);
			if (!Msg)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Mac"))
			{
			if (mode == 0)
				continue;
			if (Mac)
				goto parse_error;
			Mac = hex2bin_m(value, &Maclen);
			if (!Mac)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Result"))
			{
			if (mode == 1)
				continue;
			goto parse_error;
			}
		else
			goto parse_error;

		fputs(olinebuf, out);

		switch(mode)
			{
		case 0:
			if (Key && Msg && (Tlen > 0) && (Klen > 0))
				{
				if (!print_cmac_gen(cipher, out,
						Key, Klen,
						Msg, Mlen,
						Tlen))
					goto error;
				OPENSSL_free(Key);
				Key = NULL;
				OPENSSL_free(Msg);
				Msg = NULL;
				Klen = -1;
				Mlen = -1;
				Tlen = -1;
				Count = -1;
				}
			break;
		case 1:
			if (Key && Msg && Mac && (Tlen > 0) && (Klen > 0))
				{
				if (!print_cmac_ver(cipher, out,
						Key, Klen,
						Msg, Mlen,
						Mac, Maclen,
						Tlen))
					goto error;
				OPENSSL_free(Key);
				Key = NULL;
				OPENSSL_free(Msg);
				Msg = NULL;
				OPENSSL_free(Mac);
				Mac = NULL;
				Klen = -1;
				Mlen = -1;
				Tlen = -1;
				Count = -1;
				}
			break;
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

	fprintf(stderr, "FATAL parse error processing line %d\n", lnum);

	goto error;

	}

static int print_cmac_gen(const EVP_CIPHER *cipher, FILE *out,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Mlen,
		int Tlen)
	{
	int rc, i;
	size_t reslen;
	unsigned char res[1024];
	CMAC_CTX *cmac_ctx = CMAC_CTX_new();

	CMAC_Init(cmac_ctx, Key, Klen, cipher, 0);
	CMAC_Update(cmac_ctx, Msg, Mlen);
	if (!CMAC_Final(cmac_ctx, res, &reslen))
		{
		fputs("Error calculating CMAC\n", stderr);
		rc = 0;
		}
	else if (Tlen > reslen)
		{
		fputs("Parameter error, Tlen > CMAC length\n", stderr);
		rc = 0;
		}
	else
		{
		fputs("Mac = ", out);
		for (i = 0; i < Tlen; i++)
			fprintf(out, "%02x", res[i]);
		fputs("\n", out);
		rc = 1;
		}
	CMAC_CTX_free(cmac_ctx);
	return rc;
	}

static int print_cmac_ver(const EVP_CIPHER *cipher, FILE *out,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Mlen,
		unsigned char *Mac, int Maclen,
		int Tlen)
	{
	int rc;
	size_t reslen;
	unsigned char res[1024];
	CMAC_CTX *cmac_ctx = CMAC_CTX_new();

	CMAC_Init(cmac_ctx, Key, Klen, cipher, 0);
	CMAC_Update(cmac_ctx, Msg, Mlen);
	if (!CMAC_Final(cmac_ctx, res, &reslen))
		{
		fputs("Error calculating CMAC\n", stderr);
		rc = 0;
		}
	else if (Tlen > reslen)
		{
		fputs("Parameter error, Tlen > CMAC length\n", stderr);
		rc = 0;
		}
	else if (Tlen != Maclen)
		{
		fputs("Parameter error, Tlen != resulting Mac length\n", stderr);
		rc = 0;
		}
	else
		{
		if (!memcmp(Mac, res, Maclen))
			fputs("Result = P\n", out);
		else
			fputs("Result = F\n", out);
		}
	CMAC_CTX_free(cmac_ctx);
	return rc;
	}

#endif
