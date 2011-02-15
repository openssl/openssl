#define OPENSSL_FIPSAPI
#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#include <stdio.h>

int main(int argc, char **argv)
{
    printf("No FIPS ECDSA support\n");
    return(0);
}
#else

#include <string.h>
#include <ctype.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include "fips_utl.h"

#include <openssl/objects.h>


static int lookup_curve(char *in, char *curve_name, const EVP_MD **pmd)
	{
	char *cname, *p;
	/* Copy buffer as we will change it */
	strcpy(curve_name, in);
	cname = curve_name + 1;
	p = strchr(cname, ']');
	if (!p)
		{
		fprintf(stderr, "Parse error: missing ]\n");
		return NID_undef;
		}
	*p = 0;
	p = strchr(cname, ',');
	if (p)
		{
		if (!pmd)
			{
			fprintf(stderr, "Parse error: unexpected digest\n");
			return NID_undef;
			}
		*p = 0;
		p++;

		if (!strcmp(p, "SHA-1"))
			*pmd = EVP_sha1();
		else if (!strcmp(p, "SHA-224"))
			*pmd = EVP_sha224();
		else if (!strcmp(p, "SHA-256"))
			*pmd = EVP_sha256();
		else if (!strcmp(p, "SHA-384"))
			*pmd = EVP_sha384();
		else if (!strcmp(p, "SHA-512"))
			*pmd = EVP_sha512();
		else
			{
			fprintf(stderr, "Unknown digest %s\n", p);
			return NID_undef;
			}
		}
	else if(pmd)
		*pmd = EVP_sha1();

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

static int ec_get_pubkey(EC_KEY *key, BIGNUM *x, BIGNUM *y)
	{
	const EC_POINT *pt;
	const EC_GROUP *grp;
	const EC_METHOD *meth;
	int rv;
	BN_CTX *ctx;
	ctx = BN_CTX_new();
	if (!ctx)
		return 0;
	grp = EC_KEY_get0_group(key);
	pt = EC_KEY_get0_public_key(key);
	meth = EC_GROUP_method_of(grp);
	if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field)
		rv = EC_POINT_get_affine_coordinates_GFp(grp, pt, x, y, ctx);
	else
		rv = EC_POINT_get_affine_coordinates_GF2m(grp, pt, x, y, ctx);

	BN_CTX_free(ctx);

	return rv;

	}

static int KeyPair(void)
	{
	char buf[2048], lbuf[2048];
	char *keyword, *value;
	int curve_nid = NID_undef;
	int i, count;
	BIGNUM *Qx = NULL, *Qy = NULL;
	const BIGNUM *d = NULL;
	EC_KEY *key = NULL;
	Qx = BN_new();
	Qy = BN_new();
	while(fgets(buf, sizeof buf, stdin) != NULL)
		{
		if (*buf == '[' && buf[2] == '-')
			{
			if (buf[2] == '-')
			curve_nid = lookup_curve(buf, lbuf, NULL);
			fputs(buf, stdout);
			continue;
			}
		if (!parse_line(&keyword, &value, lbuf, buf))
			{
			fputs(buf, stdout);
			continue;
			}
		if (!strcmp(keyword, "N"))
			{
			count = atoi(value);

			for (i = 0; i < count; i++)
				{

				key = EC_KEY_new_by_curve_name(curve_nid);
				if (!EC_KEY_generate_key(key))
					{
					fprintf(stderr, "Error generating key\n");
					return 0;
					}

				if (!ec_get_pubkey(key, Qx, Qy))
					{
					fprintf(stderr, "Error getting public key\n");
					return 0;
					}

				d = EC_KEY_get0_private_key(key);

				do_bn_print_name(stdout, "d", d);
				do_bn_print_name(stdout, "Qx", Qx);
				do_bn_print_name(stdout, "Qy", Qy);
				fputs("\n", stdout);
				EC_KEY_free(key);

				}

			}

		}
	BN_free(Qx);
	BN_free(Qy);
	return 1;
	}

static int PKV(void)
	{

	char buf[2048], lbuf[2048];
	char *keyword, *value;
	int curve_nid = NID_undef;
	BIGNUM *Qx = NULL, *Qy = NULL;
	EC_KEY *key = NULL;
	while(fgets(buf, sizeof buf, stdin) != NULL)
		{
		fputs(buf, stdout);
		if (*buf == '[' && buf[2] == '-')
			{
			curve_nid = lookup_curve(buf, lbuf, NULL);
			if (curve_nid == NID_undef)
				return 0;
				
			}
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		if (!strcmp(keyword, "Qx"))
			{
			if (!do_hex2bn(&Qx, value))
				{
				fprintf(stderr, "Invalid Qx value\n");
				return 0;
				}
			}
		if (!strcmp(keyword, "Qy"))
			{
			int rv;
			if (!do_hex2bn(&Qy, value))
				{
				fprintf(stderr, "Invalid Qy value\n");
				return 0;
				}
			key = EC_KEY_new_by_curve_name(curve_nid);
			rv = EC_KEY_set_public_key_affine_coordinates(key, Qx, Qy);
			printf("Result = %s\n", rv ? "P":"F");
			}

		}
	return 1;
	}

static int SigGen(void)
	{
	char buf[2048], lbuf[2048];
	char *keyword, *value;
	unsigned char *msg;
	int curve_nid = NID_undef;
	long mlen;
	BIGNUM *Qx = NULL, *Qy = NULL;
	EC_KEY *key = NULL;
	ECDSA_SIG *sig = NULL;
	const EVP_MD *digest = NULL;
	EVP_MD_CTX mctx;
	EVP_MD_CTX_init(&mctx);
	Qx = BN_new();
	Qy = BN_new();
	while(fgets(buf, sizeof buf, stdin) != NULL)
		{
		fputs(buf, stdout);
		if (*buf == '[')
			{
			curve_nid = lookup_curve(buf, lbuf, &digest);
			if (curve_nid == NID_undef)
				return 0;
			}
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		if (!strcmp(keyword, "Msg"))
			{
			msg = hex2bin_m(value, &mlen);
			if (!msg)
				{
				fprintf(stderr, "Invalid Message\n");
				return 0;
				}

			key = EC_KEY_new_by_curve_name(curve_nid);
			if (!EC_KEY_generate_key(key))
				{
				fprintf(stderr, "Error generating key\n");
				return 0;
				}

			if (!ec_get_pubkey(key, Qx, Qy))
				{
				fprintf(stderr, "Error getting public key\n");
				return 0;
				}

			FIPS_digestinit(&mctx, digest);
			FIPS_digestupdate(&mctx, msg, mlen);
	    		sig = FIPS_ecdsa_sign_ctx(key, &mctx);

			if (!sig)
				{
				fprintf(stderr, "Error signing message\n");
				return 0;
				}

			do_bn_print_name(stdout, "Qx", Qx);
			do_bn_print_name(stdout, "Qy", Qy);
			do_bn_print_name(stdout, "R", sig->r);
			do_bn_print_name(stdout, "S", sig->s);

			EC_KEY_free(key);

			FIPS_ecdsa_sig_free(sig);

			}

		}
	BN_free(Qx);
	BN_free(Qy);
	FIPS_md_ctx_cleanup(&mctx);
	return 1;
	}

static int SigVer(void)
	{
	char buf[2048], lbuf[2048];
	char *keyword, *value;
	unsigned char *msg;
	int curve_nid = NID_undef;
	long mlen;
	BIGNUM *Qx = NULL, *Qy = NULL;
	EC_KEY *key = NULL;
	ECDSA_SIG sg, *sig = &sg;
	const EVP_MD *digest = NULL;
	EVP_MD_CTX mctx;
	EVP_MD_CTX_init(&mctx);
	sig->r = NULL;
	sig->s = NULL;
	while(fgets(buf, sizeof buf, stdin) != NULL)
		{
		fputs(buf, stdout);
		if (*buf == '[')
			{
			curve_nid = lookup_curve(buf, lbuf, &digest);
			if (curve_nid == NID_undef)
				return 0;
			}
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		if (!strcmp(keyword, "Msg"))
			{
			msg = hex2bin_m(value, &mlen);
			if (!msg)
				{
				fprintf(stderr, "Invalid Message\n");
				return 0;
				}
			}
			
		if (!strcmp(keyword, "Qx"))
			{
			if (!do_hex2bn(&Qx, value))
				{
				fprintf(stderr, "Invalid Qx value\n");
				return 0;
				}
			}
		if (!strcmp(keyword, "Qy"))
			{
			if (!do_hex2bn(&Qy, value))
				{
				fprintf(stderr, "Invalid Qy value\n");
				return 0;
				}
			}
		if (!strcmp(keyword, "R"))
			{
			if (!do_hex2bn(&sig->r, value))
				{
				fprintf(stderr, "Invalid R value\n");
				return 0;
				}
			}
		if (!strcmp(keyword, "S"))
			{
			int rv;
			if (!do_hex2bn(&sig->s, value))
				{
				fprintf(stderr, "Invalid S value\n");
				return 0;
				}
			key = EC_KEY_new_by_curve_name(curve_nid);
			rv = EC_KEY_set_public_key_affine_coordinates(key, Qx, Qy);

			if (rv != 1)
				{
				fprintf(stderr, "Error setting public key\n");
				return 0;
				}

			FIPS_digestinit(&mctx, digest);
			FIPS_digestupdate(&mctx, msg, mlen);
			no_err = 1;
	    		rv = FIPS_ecdsa_verify_ctx(key, &mctx, sig);
			no_err = 0;

			printf("Result = %s\n", rv ? "P":"F");
			}

		}
	return 1;
	}

int main(int argc, char **argv)
	{
	const char *cmd = argv[1];
	int rv = 0;
	fips_set_error_print();
	if (!cmd)
		{
		fprintf(stderr, "fips_ecdsavs [KeyPair|PKV|SigGen|SigVer]\n");
		return 1;
		}
	if (!strcmp(cmd, "KeyPair"))
		rv = KeyPair();
	else if (!strcmp(cmd, "PKV"))
		rv = PKV();
	else if (!strcmp(cmd, "SigVer"))
		rv = SigVer();
	else if (!strcmp(cmd, "SigGen"))
		rv = SigGen();
	else
		{
		fprintf(stderr, "Unknown command %s\n", cmd);
		return 1;
		}
	if (rv <= 0)
		{
		fprintf(stderr, "Error running %s\n", cmd);
		return 1;
		}
	return 0;
	}

#endif
