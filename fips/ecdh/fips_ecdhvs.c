/* fips/ecdh/fips_ecdhvs.c */
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
    printf("No FIPS ECDH support\n");
    return(0);
}
#else

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

static const EVP_MD *eparse_md(char *line)
	{
	char *p;
	if (line[0] != '[' || line[1] != 'E')
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

static int lookup_curve2(char *cname)
	{
	char *p;
	p = strchr(cname, ']');
	if (!p)
		{
		fprintf(stderr, "Parse error: missing ]\n");
		return NID_undef;
		}
	*p = 0;

	if (!strcmp(cname, "B-163"))
		return NID_sect163r2;
	if (!strcmp(cname, "B-233"))
		return NID_sect233r1;
	if (!strcmp(cname, "B-283"))
		return NID_sect283r1;
	if (!strcmp(cname, "B-409"))
		return NID_sect409r1;
	if (!strcmp(cname, "B-571"))
		return NID_sect571r1;
	if (!strcmp(cname, "K-163"))
		return NID_sect163k1;
	if (!strcmp(cname, "K-233"))
		return NID_sect233k1;
	if (!strcmp(cname, "K-283"))
		return NID_sect283k1;
	if (!strcmp(cname, "K-409"))
		return NID_sect409k1;
	if (!strcmp(cname, "K-571"))
		return NID_sect571k1;
	if (!strcmp(cname, "P-192"))
		return NID_X9_62_prime192v1;
	if (!strcmp(cname, "P-224"))
		return NID_secp224r1;
	if (!strcmp(cname, "P-256"))
		return NID_X9_62_prime256v1;
	if (!strcmp(cname, "P-384"))
		return NID_secp384r1;
	if (!strcmp(cname, "P-521"))
		return NID_secp521r1;

	fprintf(stderr, "Unknown Curve name %s\n", cname);
	return NID_undef;
	}

static int lookup_curve(char *cname)
	{
	char *p;
	p = strchr(cname, ':');
	if (!p)
		{
		fprintf(stderr, "Parse error: missing :\n");
		return NID_undef;
		}
	cname = p + 1;
	while(isspace(*cname))
		cname++;
	return lookup_curve2(cname);
	}

static EC_POINT *make_peer(EC_GROUP *group, BIGNUM *x, BIGNUM *y)
	{
	EC_POINT *peer;
	int rv;
	BN_CTX *c;
	peer = EC_POINT_new(group);
	if (!peer)
		return NULL;
	c = BN_CTX_new();
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
		== NID_X9_62_prime_field)
		rv = EC_POINT_set_affine_coordinates_GFp(group, peer, x, y, c);
	else
#ifdef OPENSSL_NO_EC2M
		{
		fprintf(stderr, "ERROR: GF2m not supported\n");
		exit(1);
		}
#else
		rv = EC_POINT_set_affine_coordinates_GF2m(group, peer, x, y, c);
#endif

	BN_CTX_free(c);
	if (rv)
		return peer;
	EC_POINT_free(peer);
	return NULL;
	}

static int ec_print_key(FILE *out, EC_KEY *key, int add_e, int exout)
	{
	const EC_POINT *pt;
	const EC_GROUP *grp;
	const EC_METHOD *meth;
	int rv;
	BIGNUM *tx, *ty;
	const BIGNUM *d = NULL;
	BN_CTX *ctx;
	ctx = BN_CTX_new();
	if (!ctx)
		return 0;
	tx = BN_CTX_get(ctx);
	ty = BN_CTX_get(ctx);
	if (!tx || !ty)
		return 0;
	grp = EC_KEY_get0_group(key);
	pt = EC_KEY_get0_public_key(key);
	if (exout)
		d = EC_KEY_get0_private_key(key);
	meth = EC_GROUP_method_of(grp);
	if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field)
		rv = EC_POINT_get_affine_coordinates_GFp(grp, pt, tx, ty, ctx);
	else
#ifdef OPENSSL_NO_EC2M
		{
		fprintf(stderr, "ERROR: GF2m not supported\n");
		exit(1);
		}
#else
		rv = EC_POINT_get_affine_coordinates_GF2m(grp, pt, tx, ty, ctx);
#endif

	if (add_e)
		{
		do_bn_print_name(out, "QeIUTx", tx);
		do_bn_print_name(out, "QeIUTy", ty);
		if (d)
			do_bn_print_name(out, "QeIUTd", d);
		}
	else
		{
		do_bn_print_name(out, "QIUTx", tx);
		do_bn_print_name(out, "QIUTy", ty);
		if (d)
			do_bn_print_name(out, "QIUTd", d);
		}

	BN_CTX_free(ctx);

	return rv;

	}

static void ec_output_Zhash(FILE *out, int exout, EC_GROUP *group,
			BIGNUM *ix, BIGNUM *iy, BIGNUM *id, BIGNUM *cx,
			BIGNUM *cy, const EVP_MD *md,
				unsigned char *rhash, size_t rhashlen)
	{
	EC_KEY *ec = NULL;
	EC_POINT *peerkey = NULL;
	unsigned char *Z;
	unsigned char chash[EVP_MAX_MD_SIZE];
	int Zlen;
	ec = EC_KEY_new();
	EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
	EC_KEY_set_group(ec, group);
	peerkey = make_peer(group, cx, cy);
	if (rhash == NULL)
		{
		if (md)
			rhashlen = M_EVP_MD_size(md);
		EC_KEY_generate_key(ec);
		ec_print_key(out, ec, md ? 1 : 0, exout);
		}
	else
		{
		EC_KEY_set_public_key_affine_coordinates(ec, ix, iy);
		EC_KEY_set_private_key(ec, id);
		}
	Zlen = (EC_GROUP_get_degree(group) + 7)/8;
	Z = OPENSSL_malloc(Zlen);
	if (!Z)
		exit(1);
	ECDH_compute_key(Z, Zlen, peerkey, ec, 0);
	if (md)
		{
		if (exout)
			OutputValue("Z", Z, Zlen, out, 0);
		FIPS_digest(Z, Zlen, chash, NULL, md);
		OutputValue(rhash ? "IUTHashZZ" : "HashZZ",
						chash, rhashlen, out, 0);
		if (rhash)
			{
			fprintf(out, "Result = %s\n",
				memcmp(chash, rhash, rhashlen) ? "F" : "P");
			}
		}
	else
		OutputValue("ZIUT", Z, Zlen, out, 0);
	OPENSSL_cleanse(Z, Zlen);
	OPENSSL_free(Z);
	EC_KEY_free(ec);
	EC_POINT_free(peerkey);
	}
		
#ifdef FIPS_ALGVS
int fips_ecdhvs_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
	{
	char **args = argv + 1;
	int argn = argc - 1;
	FILE *in, *out;
	char buf[2048], lbuf[2048];
	unsigned char *rhash = NULL;
	long rhashlen;
	BIGNUM *cx = NULL, *cy = NULL;
	BIGNUM *id = NULL, *ix = NULL, *iy = NULL;
	const EVP_MD *md = NULL;
	EC_GROUP *group = NULL;
	char *keyword = NULL, *value = NULL;
	int do_verify = -1, exout = 0;
	int rv = 1;

	int curve_nids[5] = {0,0,0,0,0};
	int param_set = -1;

	fips_algtest_init();

	if (argn && !strcmp(*args, "ecdhver"))
		{
		do_verify = 1;
		args++;
		argn--;
		}
	else if (argn && !strcmp(*args, "ecdhgen"))
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
		fprintf(stderr,"%s [ecdhver|ecdhgen|] [-exout] (infile outfile)\n",argv[0]);
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

	while (fgets(buf, sizeof(buf), in) != NULL)
		{
		fputs(buf, out);
		if (buf[0] == '[' && buf[1] == 'E')
			{
			int c = buf[2];
			if (c < 'A' || c > 'E')
				goto parse_error;
			param_set = c - 'A';
			/* If just [E?] then initial paramset */
			if (buf[3] == ']')
				continue;
			if (group)
				EC_GROUP_free(group);
			group = EC_GROUP_new_by_curve_name(curve_nids[c - 'A']);
			}
		if (strlen(buf) > 10 && !strncmp(buf, "[Curve", 6))
			{
			int nid;
			if (param_set == -1)
				goto parse_error;
			nid = lookup_curve(buf);
			if (nid == NID_undef)
				goto parse_error;
			curve_nids[param_set] = nid;
			}

		if (strlen(buf) > 4 && buf[0] == '[' && buf[2] == '-')
			{
			int nid = lookup_curve2(buf + 1);
			if (nid == NID_undef)
				goto parse_error;
			if (group)
				EC_GROUP_free(group);
			group = EC_GROUP_new_by_curve_name(nid);
			if (!group)
				{
				fprintf(stderr, "ERROR: unsupported curve %s\n", buf + 1);
				return 1;
				}
			}

		if (strlen(buf) > 6 && !strncmp(buf, "[E", 2))
			{
			md = eparse_md(buf);
			if (md == NULL)
				goto parse_error;
			continue;
			}
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		if (!strcmp(keyword, "QeCAVSx") || !strcmp(keyword, "QCAVSx"))
			{
			if (!do_hex2bn(&cx, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "QeCAVSy") || !strcmp(keyword, "QCAVSy"))
			{
			if (!do_hex2bn(&cy, value))
				goto parse_error;
			if (do_verify == 0)
				ec_output_Zhash(out, exout, group,
						NULL, NULL, NULL,
						cx, cy, md, rhash, rhashlen);
			}
		else if (!strcmp(keyword, "deIUT"))
			{
			if (!do_hex2bn(&id, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "QeIUTx"))
			{
			if (!do_hex2bn(&ix, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "QeIUTy"))
			{
			if (!do_hex2bn(&iy, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "CAVSHashZZ"))
			{
			if (!md)
				goto parse_error;
			rhash = hex2bin_m(value, &rhashlen);
			if (!rhash || rhashlen != M_EVP_MD_size(md))
				goto parse_error;
			ec_output_Zhash(out, exout, group, ix, iy, id, cx, cy,
					md, rhash, rhashlen);
			}
		}
	rv = 0;
	parse_error:
	if (id)
		BN_free(id);
	if (ix)
		BN_free(ix);
	if (iy)
		BN_free(iy);
	if (cx)
		BN_free(cx);
	if (cy)
		BN_free(cy);
	if (group)
		EC_GROUP_free(group);
	if (in && in != stdin)
		fclose(in);
	if (out && out != stdout)
		fclose(out);
	if (rv)
		fprintf(stderr, "Error Parsing request file\n");
	return rv;
	}

#endif
