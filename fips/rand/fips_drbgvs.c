/* fips/rand/fips_drbgvs.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
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
 */


#define OPENSSL_FIPSAPI
#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#include <stdio.h>

int main(int argc, char **argv)
{
    printf("No FIPS DRBG support\n");
    return(0);
}
#else

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

static int parse_md(char *str)
	{
	switch(atoi(str + 5))
		{
		case 1:
		return NID_sha1;

		case 224:
		return NID_sha224;

		case 256:
		return NID_sha256;

		case 384:
		return NID_sha384;

		case 512:
		return NID_sha512;

		}

	return NID_undef;
	}

static int parse_aes(char *str, int *pdf)
	{

	if (!strncmp(str + 9, "no", 2))
		*pdf = 0;
	else
		*pdf = DRBG_FLAG_CTR_USE_DF;

	switch(atoi(str + 5))
		{
		case 128:
		return NID_aes_128_ctr;

		case 192:
		return NID_aes_192_ctr;

		case 256:
		return NID_aes_256_ctr;

		default:
		return NID_undef;

		}

	return NID_undef;
	}

typedef struct 
	{
	unsigned char *ent;
	size_t entlen;
	unsigned char *nonce;
	size_t noncelen;
	} TEST_ENT;

static size_t test_entropy(DRBG_CTX *dctx, unsigned char *out,
                                int entropy, size_t min_len, size_t max_len)
	{
	TEST_ENT *t = FIPS_drbg_get_app_data(dctx);
	memcpy(out, t->ent, t->entlen);
	return t->entlen;
	}

static size_t test_nonce(DRBG_CTX *dctx, unsigned char *out,
                                int entropy, size_t min_len, size_t max_len)
	{
	TEST_ENT *t = FIPS_drbg_get_app_data(dctx);
	memcpy(out, t->nonce, t->noncelen);
	return t->noncelen;
	}



int main(int argc,char **argv)
	{
	FILE *in, *out;
	DRBG_CTX *dctx;
	TEST_ENT t;
	int r, nid;
	int pr = 0;
	char buf[2048], lbuf[2048];
	unsigned char randout[2048];
	char *keyword = NULL, *value = NULL;

	unsigned char *ent = NULL, *nonce = NULL, *pers = NULL, *adin = NULL;
	long entlen, noncelen, perslen, adinlen;
	int df;

	int randoutlen = 0;

	int gen = 0;

	fips_set_error_print();

	if (argc == 3)
		{
		in = fopen(argv[1], "r");
		if (!in)
			{
			fprintf(stderr, "Error opening input file\n");
			exit(1);
			}
		out = fopen(argv[2], "w");
		if (!out)
			{
			fprintf(stderr, "Error opening output file\n");
			exit(1);
			}
		}
	else if (argc == 1)
		{
		in = stdin;
		out = stdout;
		}
	else
		{
		fprintf(stderr,"%s (infile outfile)\n",argv[0]);
		exit(1);
		}

	while (fgets(buf, sizeof(buf), in) != NULL)
		{
		fputs(buf, out);
		if (strlen(buf) > 4 && !strncmp(buf, "[SHA-", 5))
			{
			nid = parse_md(buf);
			if (nid == NID_undef)
				exit(1);
			}
		if (strlen(buf) > 12 && !strncmp(buf, "[AES-", 5))
			{
			nid = parse_aes(buf, &df);
			if (nid == NID_undef)
				exit(1);
			}
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;

		if (!strcmp(keyword, "[PredictionResistance"))
			{
			if (!strcmp(value, "True]"))
				pr = 1;
			else if (!strcmp(value, "False]"))
				pr = 0;
			else
				exit(1);
			}

		if (!strcmp(keyword, "EntropyInput"))
			{
			ent = hex2bin_m(value, &entlen);
			t.ent = ent;
			t.entlen = entlen;
			}

		if (!strcmp(keyword, "Nonce"))
			{
			nonce = hex2bin_m(value, &noncelen);
			t.nonce = nonce;
			t.noncelen = noncelen;
			}

		if (!strcmp(keyword, "PersonalizationString"))
			{
			pers = hex2bin_m(value, &perslen);
			dctx = FIPS_drbg_new(nid, df);
			if (!dctx)
				exit (1);
			FIPS_drbg_set_test_mode(dctx, test_entropy, test_nonce);
			FIPS_drbg_set_app_data(dctx, &t);
			randoutlen = (int)FIPS_drbg_get_blocklength(dctx);
			r = FIPS_drbg_instantiate(dctx, 0, pers, perslen);
			if (!r)
				{
				fprintf(stderr, "Error instantiating DRBG\n");
				exit(1);
				}
			OPENSSL_free(pers);
			OPENSSL_free(ent);
			OPENSSL_free(nonce);
			ent = nonce = pers = NULL;
			gen = 0;
			}

		if (!strcmp(keyword, "AdditionalInput"))
			{
			adin = hex2bin_m(value, &adinlen);
			if (pr)
				continue;
			r = FIPS_drbg_generate(dctx, randout, randoutlen, 0, 0,
								adin, adinlen);
			if (!r)
				{
				fprintf(stderr, "Error generating DRBG bits\n");
				exit(1);
				}
			if (!r)
				exit(1);
			OPENSSL_free(adin);
			adin = NULL;
			gen++;
			}

		if (pr)
			{
			if (!strcmp(keyword, "EntropyInputPR"))
				{
				ent = hex2bin_m(value, &entlen);
				t.ent = ent;
				t.entlen = entlen;
				r = FIPS_drbg_generate(dctx,
							randout, randoutlen,
							0, 1, adin, adinlen);
				if (!r)
					{
					fprintf(stderr,
						"Error generating DRBG bits\n");
					exit(1);
					}
				OPENSSL_free(adin);
				OPENSSL_free(ent);
				adin = ent = NULL;
				gen++;
				}
			}
		if (!strcmp(keyword, "EntropyInputReseed"))
			{
			ent = hex2bin_m(value, &entlen);
			t.ent = ent;
			t.entlen = entlen;
			}
		if (!strcmp(keyword, "AdditionalInputReseed"))
			{
			adin = hex2bin_m(value, &adinlen);
			FIPS_drbg_reseed(dctx, adin, adinlen);
			OPENSSL_free(ent);
			OPENSSL_free(adin);
			ent = adin = NULL;
			}
		if (gen == 2)
			{
			OutputValue("ReturnedBits", randout, randoutlen,
									out, 0);
			FIPS_drbg_free(dctx);
			dctx = NULL;
			gen = 0;
			}

		}
	return 0;
	}

#endif
