/* apps/ecdsaparam.c */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef OPENSSL_NO_ECDSA
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#undef PROG
#define PROG	ecdsaparam_main

/* -inform arg	  	- input format - default PEM (DER or PEM)
 * -outform arg 	- output format - default PEM
 * -in arg		- input file  - default stdin
 * -out arg		- output file - default stdout
 * -noout
 * -text
 * -check               - validate the ec parameters
 * -C
 * -noout
 * -genkey		- generate a private public keypair based on the supplied curve
 * -named_curve		- use the curve oid instead of the parameters
 * -NIST_192		- use the NIST recommended curve parameters over a 192 bit prime field
 * -NIST_224		- use the NIST recommended curve parameters over a 224 bit prime field
 * -NIST_256		- use the NIST recommended curve parameters over a 256 bit prime field
 * -NIST_384		- use the NIST recommended curve parameters over a 384 bit prime field
 * -NIST_521		- use the NIST recommended curve parameters over a 521 bit prime field
 * -X9_62_192v1		- use the X9_62 192v1 example curve over a 192 bit prime field
 * -X9_62_192v2		- use the X9_62 192v2 example curve over a 192 bit prime field
 * -X9_62_192v3		- use the X9_62 192v3 example curve over a 192 bit prime field
 * -X9_62_239v1		- use the X9_62 239v1 example curve over a 239 bit prime field
 * -X9_62_239v2		- use the X9_62 239v2 example curve over a 239 bit prime field
 * -X9_62_239v3		- use the X9_62 239v3 example curve over a 239 bit prime field
 * -X9_62_256v1		- use the X9_62 239v1 example curve over a 256 bit prime field
 * -SECG_PRIME_112R1    - use the SECG 112r1 recommended curve over a 112 bit prime field
 * -SECG_PRIME_112R2    - use the SECG 112r2 recommended curve over a 112 bit prime field
 * -SECG_PRIME_128R1    - use the SECG 128r1 recommended curve over a 128 bit prime field
 * -SECG_PRIME_128R2    - use the SECG 128r2 recommended curve over a 128 bit prime field
 * -SECG_PRIME_160K1    - use the SECG 160k1 recommended curve over a 160 bit prime field
 * -SECG_PRIME_160R1    - use the SECG 160r1 recommended curve over a 160 bit prime field
 * -SECG_PRIME_160R2    - use the SECG 160r2 recommended curve over a 160 bit prime field
 * -SECG_PRIME_192K1    - use the SECG 192k1 recommended curve over a 192 bit prime field
 * -SECG_PRIME_192R1    - use the SECG 192r1 recommended curve over a 192 bit prime field
 * -SECG_PRIME_224K1    - use the SECG 224k1 recommended curve over a 224 bit prime field
 * -SECG_PRIME_224R1    - use the SECG 224r1 recommended curve over a 224 bit prime field
 * -SECG_PRIME_256K1    - use the SECG 256k1 recommended curve over a 256 bit prime field
 * -SECG_PRIME_256R1    - use the SECG 256r1 recommended curve over a 256 bit prime field
 * -SECG_PRIME_384R1    - use the SECG 384r1 recommended curve over a 384 bit prime field
 * -SECG_PRIME_521R1    - use the SECG 521r1 recommended curve over a 521 bit prime field
 * -WTLS_6              - use the WAP/WTLS recommended curve number 6 over a 112 bit field
 * -WTLS_8              - use the WAP/WTLS recommended curve number 8 over a 112 bit field
 * -WTLS_9              - use the WAP/WTLS recommended curve number 9 over a 160 bit field
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
	ENGINE 	*e = NULL;
	ECDSA 	*ecdsa = NULL;
	int 	i, badops = 0, text = 0;
	BIO 	*in = NULL, *out = NULL;
	int 	informat, outformat, noout = 0, C = 0, ret = 1;
	char 	*infile, *outfile, *prog, *inrand = NULL;
	int 	genkey = 0;
	int	check = 0;
	int 	need_rand = 0;
	char 	*engine=NULL;
	int	curve_type = EC_GROUP_NO_CURVE;
	int	named_curve = 0;
	BIGNUM	*tmp_1 = NULL, *tmp_2 = NULL, *tmp_3 = NULL, *tmp_4 = NULL, *tmp_5 = NULL,
		*tmp_6 = NULL, *tmp_7 = NULL;
	BN_CTX	*ctx = NULL;
	EC_POINT *point = NULL;
	unsigned char *data = NULL;

	apps_startup();

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	if (!load_config(bio_err, NULL))
		goto end;

	infile=NULL;
	outfile=NULL;
	informat=FORMAT_PEM;
	outformat=FORMAT_PEM;

	prog=argv[0];
	argc--;
	argv++;
	while (argc >= 1)
		{
		if 	(strcmp(*argv,"-inform") == 0)
		{
			if (--argc < 1) goto bad;
			informat=str2fmt(*(++argv));
		}
		else if (strcmp(*argv,"-outform") == 0)
		{
			if (--argc < 1) goto bad;
			outformat=str2fmt(*(++argv));
		}
		else if (strcmp(*argv,"-in") == 0)
		{
			if (--argc < 1) goto bad;
			infile= *(++argv);
		}
		else if (strcmp(*argv,"-out") == 0)
		{
			if (--argc < 1) goto bad;
			outfile= *(++argv);
		}
		else if(strcmp(*argv, "-engine") == 0)
		{
			if (--argc < 1) goto bad;
			engine = *(++argv);
		}
		else if (strcmp(*argv,"-text") == 0)
			text = 1;
		else if (strcmp(*argv,"-C") == 0)
			C = 1;
		else if (strcmp(*argv,"-check") == 0)
			check = 1;
		else if (strcmp(*argv,"-genkey") == 0)
		{
			genkey = 1;
			need_rand = 1;
		}
		else if (strcmp(*argv,"-rand") == 0)
		{
			if (--argc < 1) goto bad;
			inrand= *(++argv);
			need_rand=1;
		}
		else if (strcmp(*argv, "-named_curve") == 0)
			named_curve = 1;
		else if (strcmp(*argv, "-NIST_192") == 0)
			curve_type = EC_GROUP_NIST_PRIME_192;
		else if (strcmp(*argv, "-NIST_224") == 0)
			curve_type = EC_GROUP_NIST_PRIME_224;
		else if (strcmp(*argv, "-NIST_256") == 0)
			curve_type = EC_GROUP_NIST_PRIME_256;
		else if (strcmp(*argv, "-NIST_384") == 0)
			curve_type = EC_GROUP_NIST_PRIME_384;
		else if (strcmp(*argv, "-NIST_521") == 0)
			curve_type = EC_GROUP_NIST_PRIME_521;
		else if (strcmp(*argv, "-X9_62_192v1") == 0)
			curve_type = EC_GROUP_X9_62_PRIME_192V1;
		else if (strcmp(*argv, "-X9_62_192v2") == 0)
			curve_type = EC_GROUP_X9_62_PRIME_192V2;
		else if (strcmp(*argv, "-X9_62_192v3") == 0)
			curve_type = EC_GROUP_X9_62_PRIME_192V3;
		else if (strcmp(*argv, "-X9_62_239v1") == 0)
			curve_type = EC_GROUP_X9_62_PRIME_239V1;
		else if (strcmp(*argv, "-X9_62_239v2") == 0)
			curve_type = EC_GROUP_X9_62_PRIME_239V2;
		else if (strcmp(*argv, "-X9_62_239v3") == 0)
			curve_type = EC_GROUP_X9_62_PRIME_239V3;
		else if (strcmp(*argv, "-X9_62_256v1") == 0)
			curve_type = EC_GROUP_X9_62_PRIME_256V1;
		else if (strcmp(*argv, "-SECG_PRIME_112R1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_112R1;
		else if (strcmp(*argv, "-SECG_PRIME_112R2") == 0)
			curve_type = EC_GROUP_SECG_PRIME_112R2;
		else if (strcmp(*argv, "-SECG_PRIME_128R1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_128R1;
		else if (strcmp(*argv, "-SECG_PRIME_128R2") == 0)
			curve_type = EC_GROUP_SECG_PRIME_128R2;
		else if (strcmp(*argv, "-SECG_PRIME_160K1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_160K1;
		else if (strcmp(*argv, "-SECG_PRIME_160R1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_160R1;
		else if (strcmp(*argv, "-SECG_PRIME_160R2") == 0)
			curve_type = EC_GROUP_SECG_PRIME_160R2;
		else if (strcmp(*argv, "-SECG_PRIME_192K1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_192K1;
		else if (strcmp(*argv, "-SECG_PRIME_192R1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_192R1;
		else if (strcmp(*argv, "-SECG_PRIME_224K1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_224K1;
		else if (strcmp(*argv, "-SECG_PRIME_224R1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_224R1;
		else if (strcmp(*argv, "-SECG_PRIME_256K1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_256K1;
		else if (strcmp(*argv, "-SECG_PRIME_256R1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_256R1;
		else if (strcmp(*argv, "-SECG_PRIME_384R1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_384R1;
		else if (strcmp(*argv, "-SECG_PRIME_521R1") == 0)
			curve_type = EC_GROUP_SECG_PRIME_521R1;
		else if (strcmp(*argv, "-WTLS_6") == 0)
			curve_type = EC_GROUP_WTLS_6;
		else if (strcmp(*argv, "-WTLS_8") == 0)
			curve_type = EC_GROUP_WTLS_8;
		else if (strcmp(*argv, "-WTLS_9") == 0)
			curve_type = EC_GROUP_WTLS_9;
		else if (strcmp(*argv, "-noout") == 0)
			noout=1;
		else
		{
			BIO_printf(bio_err,"unknown option %s\n",*argv);
			badops=1;
			break;
		}
		argc--;
		argv++;
	}

	if (badops)
	{
bad:
		BIO_printf(bio_err,"%s [options] [bits] <infile >outfile\n",prog);
		BIO_printf(bio_err,"where options are\n");
		BIO_printf(bio_err," -inform arg        input format - DER or PEM\n");
		BIO_printf(bio_err," -outform arg       output format - DER or PEM\n");
		BIO_printf(bio_err," -in arg            input file\n");
		BIO_printf(bio_err," -out arg           output file\n");
		BIO_printf(bio_err," -text              print as text\n");
		BIO_printf(bio_err," -C                 Output C code\n");
		BIO_printf(bio_err," -check             validate the ec parameters\n");
		BIO_printf(bio_err," -noout             no output\n");
		BIO_printf(bio_err," -rand              files to use for random number input\n");
		BIO_printf(bio_err," -engine e          use engine e, possibly a hardware device.\n");
		BIO_printf(bio_err," -named_curve       use the curve oid instead of the parameters\n");
		BIO_printf(bio_err," -NIST_192          use the NIST recommended curve parameters over a 192 bit prime field\n");
		BIO_printf(bio_err," -NIST_224          use the NIST recommended curve parameters over a 224 bit prime field\n");
		BIO_printf(bio_err," -NIST_256          use the NIST recommended curve parameters over a 256 bit prime field\n");
		BIO_printf(bio_err," -NIST_384          use the NIST recommended curve parameters over a 384 bit prime field\n");
		BIO_printf(bio_err," -NIST_521          use the NIST recommended curve parameters over a 521 bit prime field\n");
		BIO_printf(bio_err," -X9_62_192v1       use the X9_62 192v1 example curve over a 192 bit prime field\n");
		BIO_printf(bio_err," -X9_62_192v2       use the X9_62 192v2 example curve over a 192 bit prime field\n");
		BIO_printf(bio_err," -X9_62_192v3       use the X9_62 192v3 example curve over a 192 bit prime field\n");
		BIO_printf(bio_err," -X9_62_239v1       use the X9_62 239v1 example curve over a 239 bit prime field\n");
		BIO_printf(bio_err," -X9_62_239v2       use the X9_62 239v2 example curve over a 239 bit prime field\n");
		BIO_printf(bio_err," -X9_62_239v3       use the X9_62 239v3 example curve over a 239 bit prime field\n");
		BIO_printf(bio_err," -X9_62_256v1       use the X9_62 239v1 example curve over a 256 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_112R1  use the SECG 112r1 recommended curve over a 112 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_112R2  use the SECG 112r2 recommended curve over a 112 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_128R1  use the SECG 128r1 recommended curve over a 128 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_128R2  use the SECG 128r2 recommended curve over a 128 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_160K1  use the SECG 160k1 recommended curve over a 160 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_160R1  use the SECG 160r1 recommended curve over a 160 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_160R2  use the SECG 160r2 recommended curve over a 160 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_192K1  use the SECG 192k1 recommended curve over a 192 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_192R1  use the SECG 192r1 recommended curve over a 192 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_224K1  use the SECG 224k1 recommended curve over a 224 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_224R1  use the SECG 224r1 recommended curve over a 224 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_256K1  use the SECG 256k1 recommended curve over a 256 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_256R1  use the SECG 256r1 recommended curve over a 256 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_384R1  use the SECG 384r1 recommended curve over a 384 bit prime field\n");
		BIO_printf(bio_err," -SECG_PRIME_521R1  use the SECG 521r1 recommended curve over a 521 bit prime field\n");
		BIO_printf(bio_err," -WTLS_6            use the WAP/WTLS recommended curve number 6 over a 112 bit field\n");
		BIO_printf(bio_err," -WTLS_8            use the WAP/WTLS recommended curve number 8 over a 112 bit field\n");
		BIO_printf(bio_err," -WTLS_9            use the WAP/WTLS recommended curve number 9 over a 112 bit field\n");
		goto end;
	}

	ERR_load_crypto_strings();

	in=BIO_new(BIO_s_file());
	out=BIO_new(BIO_s_file());
	if ((in == NULL) || (out == NULL))
	{
		ERR_print_errors(bio_err);
		goto end;
	}

	if (infile == NULL)
		BIO_set_fp(in,stdin,BIO_NOCLOSE);
	else
	{
		if (BIO_read_filename(in,infile) <= 0)
		{
			perror(infile);
			goto end;
		}
	}
	if (outfile == NULL)
	{
		BIO_set_fp(out,stdout,BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
		{
		BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		out = BIO_push(tmpbio, out);
		}
#endif
	}
	else
	{
		if (BIO_write_filename(out,outfile) <= 0)
		{
			perror(outfile);
			goto end;
		}
	}

        e = setup_engine(bio_err, engine, 0);

	if (need_rand)
	{
		app_RAND_load_file(NULL, bio_err, (inrand != NULL));
		if (inrand != NULL)
			BIO_printf(bio_err,"%ld semi-random bytes loaded\n",
				app_RAND_load_files(inrand));
	}

	if (curve_type != EC_GROUP_NO_CURVE)
	{
		if ((ecdsa = ECDSA_new()) == NULL)
			goto end;
		ecdsa->group = EC_GROUP_new_by_name(curve_type);
		if (named_curve)
			EC_GROUP_set_asn1_flag(ecdsa->group, 
						OPENSSL_EC_NAMED_CURVE);
	}
	else if (informat == FORMAT_ASN1)
		ecdsa = d2i_ECDSAParameters_bio(in,NULL);
	else if (informat == FORMAT_PEM)
		ecdsa = PEM_read_bio_ECDSAParameters(in, NULL, NULL, NULL);
	else
	{
		BIO_printf(bio_err, "bad input format specified\n");
		goto end;
	}
	if (ecdsa == NULL)
	{
		BIO_printf(bio_err, "unable to load ECDSA parameters\n");
		ERR_print_errors(bio_err);
		goto end;
	}

	if (text)
	{
		ECDSAParameters_print(out, ecdsa);
	}

	if (check)
	{
		if (ecdsa == NULL)
			BIO_printf(bio_err, "no elliptic curve parameters\n");
		BIO_printf(bio_err, "checking elliptic curve parameters: ");
		if (!EC_GROUP_check(ecdsa->group, NULL))
		{
			BIO_printf(bio_err, "failed\n");
			ERR_print_errors(bio_err);
		}
		else
			BIO_printf(bio_err, "ok\n");
			
	}
	
	if (C)
	{	/* TODO: characteristic two */
		int 	l, len, bits_p;
		if ((tmp_1 = BN_new()) == NULL || (tmp_2 = BN_new()) == NULL ||
		    (tmp_3 = BN_new()) == NULL || (tmp_4 = BN_new()) == NULL ||
		    (tmp_5 = BN_new()) == NULL || (tmp_6 = BN_new()) == NULL ||
                    (tmp_7 = BN_new()) == NULL || (ctx = BN_CTX_new()) == NULL)
		{
			perror("OPENSSL_malloc");
			goto end;
		}
		if (!EC_GROUP_get_curve_GFp(ecdsa->group, tmp_1, tmp_2, tmp_3, ctx))
			goto end;
		if ((point = EC_GROUP_get0_generator(ecdsa->group)) == NULL)
			goto end;
		if (!EC_POINT_get_affine_coordinates_GFp(ecdsa->group, point, tmp_4, tmp_5, ctx))
			goto end;
		if (!EC_GROUP_get_order(ecdsa->group, tmp_6, ctx))
			goto end;
		if (!EC_GROUP_get_cofactor(ecdsa->group, tmp_7, ctx))
			goto end;
		
		len    = BN_num_bytes(tmp_1);
		bits_p = BN_num_bits(tmp_1);
		data=(unsigned char *)OPENSSL_malloc(len+20);
		if (data == NULL)
		{
			perror("OPENSSL_malloc");
			goto end;
		}
		l = BN_bn2bin(tmp_1, data);
		printf("static unsigned char ecdsa%d_p[]={", bits_p);
		for (i=0; i<l; i++)
		{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
		}
		printf("\n\t};\n\n");

		l = BN_bn2bin(tmp_2, data);
		printf("static unsigned char ecdsa%d_a[]={",bits_p);
		for (i=0; i<l; i++)
		{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
		}
		printf("\n\t};\n");

		l = BN_bn2bin(tmp_3, data);
		printf("static unsigned char ecdsa%d_b[]={", bits_p);
		for (i=0; i<l; i++)
		{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
		}
		printf("\n\t};\n\n");

		l = BN_bn2bin(tmp_4, data);
		printf("static unsigned char ecdsa%d_x[]={", bits_p);
		for (i=0; i<l; i++)
		{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
		}
		printf("\n\t};\n");

		l = BN_bn2bin(tmp_5, data);
		printf("static unsigned char ecdsa%d_y[]={", bits_p);
		for (i=0; i<l; i++)
		{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
		}
		printf("\n\t};\n");

		l = BN_bn2bin(tmp_6, data);
		printf("static unsigned char ecdsa%d_o[]={", bits_p);
		for (i=0; i<l; i++)
		{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
		}
		printf("\n\t};\n");

		l = BN_bn2bin(tmp_7, data);
		printf("static unsigned char ecdsa%d_c[]={", bits_p);
		for (i=0; i<l; i++)
		{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
		}
		printf("\n\t};\n\n");

		/* FIXME:
		 * generated code should check for errors
		 */

		printf("ECDSA *get_ecdsa%d(void)\n\t{\n",bits_p);
		printf("\tint ok=0;\n");
		printf("\tECDSA    *ecdsa=NULL;\n");
		printf("\tEC_POINT *point=NULL;\n");
		printf("\tBIGNUM   *tmp_1=NULL,*tmp_2=NULL,*tmp_3=NULL;\n\n");
		printf("\tif ((ecdsa=ECDSA_new()) == NULL)\n");
		printf("\t\treturn(NULL);\n\n");
		printf("\t/* generate EC_GROUP structure */\n");
		printf("\tif ((tmp_1 = BN_bin2bn(ecdsa%d_p, sizeof(ecdsa%d_p), NULL)) == NULL) goto err;\n", bits_p, bits_p);
		printf("\tif ((tmp_2 = BN_bin2bn(ecdsa%d_a, sizeof(ecdsa%d_a), NULL)) == NULL) goto err;\n", bits_p, bits_p);
		printf("\tif ((tmp_3 = BN_bin2bn(ecdsa%d_b, sizeof(ecdsa%d_b), NULL)) == NULL) goto err;\n", bits_p, bits_p);
		printf("\tif ((ecdsa->group = EC_GROUP_new_curve_GFp(tmp_1, tmp_2, tmp_3, NULL)) == NULL) goto err;\n\n");
		printf("\t/* build generator */\n");
		printf("\tif (!BN_bin2bn(ecdsa%d_x, sizeof(ecdsa%d_x), tmp_1)) goto err;\n", bits_p, bits_p);
		printf("\tif (!BN_bin2bn(ecdsa%d_y, sizeof(ecdsa%d_y), tmp_2)) goto err;\n", bits_p, bits_p);
		printf("\tif ((point = EC_POINT_new(ecdsa->group)) == NULL) goto err;\n");
		printf("\tif (!EC_POINT_set_affine_coordinates_GFp(ecdsa->group, point, tmp_1, tmp_2, NULL)) goto err;\n");
		printf("\t/* set generator, order and cofactor */\n");
		printf("\tif (!BN_bin2bn(ecdsa%d_o, sizeof(ecdsa%d_o), tmp_1)) goto err;\n", bits_p, bits_p);
		printf("\tif (!BN_bin2bn(ecdsa%d_c, sizeof(ecdsa%d_c), tmp_2)) goto err;\n", bits_p, bits_p);
		printf("\tif (!EC_GROUP_set_generator(ecdsa->group, point, tmp_1, tmp_2)) goto err;\n");
		printf("\n\tok=1;\n");
		printf("err:\n");
		printf("\tif (tmp_1) BN_free(tmp_1);\n");
		printf("\tif (tmp_2) BN_free(tmp_2);\n");
		printf("\tif (tmp_3) BN_free(tmp_3);\n");
		printf("\tif (point) EC_POINT_free(point);\n");
		printf("\tif (!ok)\n");
		printf("\t\t{\n");
		printf("\t\tECDSA_free(ecdsa);\n");
		printf("\t\tecdsa = NULL;\n");
		printf("\t\t}\n");
		printf("\treturn(ecdsa);\n\t}\n");
	}


	if (!noout)
	{
		if (outformat == FORMAT_ASN1)
			i = i2d_ECDSAParameters_bio(out, ecdsa);
		else if (outformat == FORMAT_PEM)
			i = PEM_write_bio_ECDSAParameters(out, ecdsa);
		else	
		{
			BIO_printf(bio_err,"bad output format specified for outfile\n");
			goto end;
		}
		if (!i)
		{
			BIO_printf(bio_err, "unable to write ECDSA parameters\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (genkey)
	{
		ECDSA *ecdsakey;

		assert(need_rand);
		if ((ecdsakey = ECDSAParameters_dup(ecdsa)) == NULL) goto end;
		if (!ECDSA_generate_key(ecdsakey)) goto end;
		if (outformat == FORMAT_ASN1)
			i = i2d_ECDSAPrivateKey_bio(out, ecdsakey);
		else if (outformat == FORMAT_PEM)
			i = PEM_write_bio_ECDSAPrivateKey(out, ecdsakey, NULL, NULL, 0, NULL, NULL);
		else	
		{
			BIO_printf(bio_err, "bad output format specified for outfile\n");
			goto end;
		}
		ECDSA_free(ecdsakey);
	}
	if (need_rand)
		app_RAND_write_file(NULL, bio_err);
	ret=0;
end:
	if (in != NULL) 	BIO_free(in);
	if (out != NULL) 	BIO_free_all(out);
	if (ecdsa != NULL) 	ECDSA_free(ecdsa);
	if (tmp_1)		BN_free(tmp_1);
	if (tmp_2)		BN_free(tmp_2);
	if (tmp_3)		BN_free(tmp_3);
	if (tmp_3)		BN_free(tmp_4);
	if (tmp_3)		BN_free(tmp_5);
	if (tmp_3)		BN_free(tmp_6);
	if (tmp_3)		BN_free(tmp_7);
	if (ctx)		BN_CTX_free(ctx);
	if (data)		OPENSSL_free(data);
	apps_shutdown();
	EXIT(ret);
}
#endif
