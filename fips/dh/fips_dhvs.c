/* fips/dh/fips_dhvs.c */
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
    printf("No FIPS DH support\n");
    return(0);
}
#else

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

static const EVP_MD *parse_md(char *line)
	{
	char *p;
	if (line[0] != '[' || line[1] != 'F')
		return NULL;
	p = strchr(line, '-');
	if (!p)
		return NULL;
	line = p + 1;
	p = strchr(line, ']');
	if (!p)
		return NULL;
	*p = 0;
	p = line;
	while(isspace(*p))
		p++;
	if (!strcmp(p, "SHA1"))
		return EVP_sha1();
	else if (!strcmp(p, "SHA224"))
		return EVP_sha224();
	else if (!strcmp(p, "SHA256"))
		return EVP_sha256();
	else if (!strcmp(p, "SHA384"))
		return EVP_sha384();
	else if (!strcmp(p, "SHA512"))
		return EVP_sha512();
	else
		return NULL;
	}

static void output_Zhash(FILE *out, int exout,
				DH *dh, BIGNUM *peerkey, const EVP_MD *md,
				unsigned char *rhash, size_t rhashlen)
	{
	unsigned char *Z;
	unsigned char chash[EVP_MAX_MD_SIZE];
	int Zlen;
	if (rhash == NULL)
		{
		rhashlen = M_EVP_MD_size(md);
		if (!DH_generate_key(dh))
			exit (1);
		do_bn_print_name(out, "YephemIUT", dh->pub_key);
		if (exout)
			do_bn_print_name(out, "XephemIUT", dh->priv_key);
		}
	Z = OPENSSL_malloc(BN_num_bytes(dh->p));
	if (!Z)
		exit(1);
	Zlen = DH_compute_key_padded(Z, peerkey, dh);
	if (exout)
		OutputValue("Z", Z, Zlen, out, 0);
	FIPS_digest(Z, Zlen, chash, NULL, md);
	OutputValue(rhash ? "IUTHashZZ" : "HashZZ", chash, rhashlen, out, 0);
	if (rhash)
		{
		fprintf(out, "Result = %s\n",
				memcmp(chash, rhash, rhashlen) ? "F" : "P");
		}
	else
		{
		BN_clear_free(dh->priv_key);
		BN_clear_free(dh->pub_key);
		dh->priv_key = NULL;
		dh->pub_key = NULL;
		}
	OPENSSL_cleanse(Z, Zlen);
	OPENSSL_free(Z);
	}

#ifdef FIPS_ALGVS
int fips_dhvs_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
	{
	char **args = argv + 1;
	int argn = argc - 1;
	FILE *in, *out;
	char buf[2048], lbuf[2048];
	unsigned char *rhash;
	long rhashlen;
	DH *dh = NULL;
	const EVP_MD *md = NULL;
	BIGNUM *peerkey = NULL;
	char *keyword = NULL, *value = NULL;
	int do_verify = -1, exout = 0;

	fips_algtest_init();

	if (argn && !strcmp(*args, "dhver"))
		{
		do_verify = 1;
		args++;
		argn--;
		}
	else if (argn && !strcmp(*args, "dhgen"))
		{
		do_verify = 0;
		args++;
		argn--;
		}

	if (argn && !strcmp(*args, "-exout"))
		{
		exout = 1;
		args++;
		argn--;
		}

	if (do_verify == -1)
		{
		fprintf(stderr,"%s [dhver|dhgen|] [-exout] (infile outfile)\n",argv[0]);
		exit(1);
		}

	if (argn == 2)
		{
		in = fopen(*args, "r");
		if (!in)
			{
			fprintf(stderr, "Error opening input file\n");
			exit(1);
			}
		out = fopen(args[1], "w");
		if (!out)
			{
			fprintf(stderr, "Error opening output file\n");
			exit(1);
			}
		}
	else if (argn == 0)
		{
		in = stdin;
		out = stdout;
		}
	else
		{
		fprintf(stderr,"%s [dhver|dhgen|] [-exout] (infile outfile)\n",argv[0]);
		exit(1);
		}

	dh = FIPS_dh_new();

	while (fgets(buf, sizeof(buf), in) != NULL)
		{
		fputs(buf, out);
		if (strlen(buf) > 6 && !strncmp(buf, "[F", 2))
			{
			md = parse_md(buf);
			if (md == NULL)
				goto parse_error;
			if (dh)
				FIPS_dh_free(dh);
			dh = FIPS_dh_new();
			continue;
			}
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		if (!strcmp(keyword, "P"))
			{
			if (!do_hex2bn(&dh->p, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "Q"))
			{
			if (!do_hex2bn(&dh->q, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "G"))
			{
			if (!do_hex2bn(&dh->g, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "XephemIUT"))
			{
			if (!do_hex2bn(&dh->priv_key, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "YephemIUT"))
			{
			if (!do_hex2bn(&dh->pub_key, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "YephemCAVS"))
			{
			if (!do_hex2bn(&peerkey, value))
				goto parse_error;
			if (do_verify == 0)
				output_Zhash(out, exout, dh, peerkey, md,
							NULL, 0);
			}
		else if (!strcmp(keyword, "CAVSHashZZ"))
			{
			if (!md)
				goto parse_error;
			rhash = hex2bin_m(value, &rhashlen);
			if (!rhash || rhashlen != M_EVP_MD_size(md))
				goto parse_error;
			output_Zhash(out, exout, dh, peerkey, md,
							rhash, rhashlen);
			}
		}
	if (in && in != stdin)
		fclose(in);
	if (out && out != stdout)
		fclose(out);
	return 0;
	parse_error:
	fprintf(stderr, "Error Parsing request file\n");
	exit(1);
	}

#endif
