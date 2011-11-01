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

static int cmac_test(const EVP_CIPHER *cipher, FILE *out, FILE *in,
	int mode, int Klen_counts_keys, int known_keylen);
static int print_cmac_gen(const EVP_CIPHER *cipher, FILE *out,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Msglen,
		int Tlen);
static int print_cmac_ver(const EVP_CIPHER *cipher, FILE *out,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Msglen,
		unsigned char *Mac, int Maclen,
		int Tlen);

#ifdef FIPS_ALGVS
int fips_cmactest_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
	{
	FILE *in = NULL, *out = NULL;
	int mode = 0;		/* 0 => Generate, 1 => Verify */
	int Klen_counts_keys = 0; /* 0 => Klen is size of one key
				     1 => Klen is amount of keys
				  */
	int known_keylen = 0;	/* Only set when Klen_counts_keys = 1 */
	const EVP_CIPHER *cipher = 0;
	int ret = 1;
	fips_algtest_init();

	while (argc > 1 && argv[1][0] == '-')
		{
		switch (argv[1][1])
			{
		case 'a':
			{
			char *p = &argv[1][2];
			if (*p == '\0')
				{
				if (argc <= 2)
					{
					fprintf(stderr, "Option %s needs a value\n", argv[1]);
					goto end;
					}
				argv++;
				argc--;
				p = &argv[1][0];
				}
			if (!strcmp(p, "aes128"))
				cipher = EVP_aes_128_cbc();
			else if (!strcmp(p, "aes192"))
				cipher = EVP_aes_192_cbc();
			else if (!strcmp(p, "aes256"))
				cipher = EVP_aes_256_cbc();
			else if (!strcmp(p, "tdea3") || !strcmp(p, "tdes3"))
				{
				cipher = EVP_des_ede3_cbc();
				Klen_counts_keys = 1;
				known_keylen = 8;
				}
			else
				{
				fprintf(stderr, "Unknown algorithm %s\n", p);
				goto end;
				}
			}
			break;
		case 'g':
			mode = 0;
			break;
		case 'v':
			mode = 1;
			break;
		default:
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

	if (!cmac_test(cipher, out, in, mode,
			Klen_counts_keys, known_keylen))
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

#define CMAC_TEST_MAXLINELEN	150000

int cmac_test(const EVP_CIPHER *cipher, FILE *out, FILE *in,
	int mode, int Klen_counts_keys, int known_keylen)
	{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	unsigned char **Keys = NULL, *Msg = NULL, *Mac = NULL;
	unsigned char *Key = NULL;
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
			if (Klen_counts_keys)
				{
				Keys = OPENSSL_malloc(sizeof(*Keys) * Klen);
				memset(Keys, '\0', sizeof(*Keys) * Klen);
				}
			else
				{
				Keys = OPENSSL_malloc(sizeof(*Keys));
				memset(Keys, '\0', sizeof(*Keys));
				}
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
		else if (!strcmp(keyword, "Key") && !Klen_counts_keys)
			{
			if (Keys[0])
				goto parse_error;
			Keys[0] = hex2bin_m(value, &Keylen);
			if (!Keys[0])
				goto parse_error;
			}
		else if (!strncmp(keyword, "Key", 3) && Klen_counts_keys)
			{
			int keynum = atoi(keyword + 3);
			if (!keynum || keynum > Klen || Keys[keynum-1])
				goto parse_error;
			Keys[keynum-1] = hex2bin_m(value, &Keylen);
			if (!Keys[keynum-1])
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

		if (Keys && Msg && (!mode || Mac) && (Tlen > 0) && (Klen > 0))
			{
			if (Klen_counts_keys)
				{
				int x;
				Key = OPENSSL_malloc(Klen * known_keylen);
				for (x = 0; x < Klen; x++)
					{
					memcpy(Key + x * known_keylen,
						Keys[x], known_keylen);
					OPENSSL_free(Keys[x]);
					}
				Klen *= known_keylen;
				}
			else
				{
				Key = OPENSSL_malloc(Klen);
				memcpy(Key, Keys[0], Klen);
				OPENSSL_free(Keys[0]);
				}
			OPENSSL_free(Keys);

			switch(mode)
				{
			case 0:
				if (!print_cmac_gen(cipher, out,
						Key, Klen,
						Msg, Mlen,
						Tlen))
					goto error;
				break;
			case 1:
				if (!print_cmac_ver(cipher, out,
						Key, Klen,
						Msg, Mlen,
						Mac, Maclen,
						Tlen))
					goto error;
				break;
				}

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
	if (Mac)
		OPENSSL_free(Mac);

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
	unsigned char res[128];
	CMAC_CTX *cmac_ctx = CMAC_CTX_new();

	CMAC_Init(cmac_ctx, Key, Klen, cipher, 0);
	CMAC_Update(cmac_ctx, Msg, Mlen);
	if (!CMAC_Final(cmac_ctx, res, &reslen))
		{
		fputs("Error calculating CMAC\n", stderr);
		rc = 0;
		}
	else if (Tlen > (int)reslen)
		{
		fputs("Parameter error, Tlen > CMAC length\n", stderr);
		rc = 0;
		}
	else
		{
		fputs("Mac = ", out);
		for (i = 0; i < Tlen; i++)
			fprintf(out, "%02x", res[i]);
		fputs(RESP_EOL, out);
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
	int rc = 1;
	size_t reslen;
	unsigned char res[128];
	CMAC_CTX *cmac_ctx = CMAC_CTX_new();

	CMAC_Init(cmac_ctx, Key, Klen, cipher, 0);
	CMAC_Update(cmac_ctx, Msg, Mlen);
	if (!CMAC_Final(cmac_ctx, res, &reslen))
		{
		fputs("Error calculating CMAC\n", stderr);
		rc = 0;
		}
	else if (Tlen > (int)reslen)
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
			fputs("Result = P" RESP_EOL, out);
		else
			fputs("Result = F" RESP_EOL, out);
		}
	CMAC_CTX_free(cmac_ctx);
	return rc;
	}

#endif
