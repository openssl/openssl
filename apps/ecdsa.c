/* apps/ecdsa.c */
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#undef PROG
#define PROG	ecdsa_main

/* -inform arg	- input format - default PEM (one of DER, NET or PEM)
 * -outform arg - output format - default PEM
 * -in arg	- input file - default stdin
 * -out arg	- output file - default stdout
 * -des		- encrypt output if PEM format with DES in cbc mode
 * -des3	- encrypt output if PEM format
 * -idea	- encrypt output if PEM format
 * -aes128	- encrypt output if PEM format
 * -aes192	- encrypt output if PEM format
 * -aes256	- encrypt output if PEM format
 * -text	- print a text version
 * -pub		- print the ECDSA public key
 * -compressed  - print the public key in compressed form ( default )   
 * -hybrid 	- print the public key in hybrid form
 * -uncompressed - print the public key in uncompressed form
 *		  the last three options ( compressed, hybrid and uncompressed )
 *		  are only used if the "-pub" option is also selected.
 *	  	  For a precise description of the the meaning of compressed,
 *		  hybrid and uncompressed please refer to the X9.62 standart.
 *		  All three forms represents ways to express the ecdsa public
 *		  key ( a point on a elliptic curve ) as octet string. Let len be
 *		  the length ( in bytes ) of an element of the field over which
 *		  the curve is defined, then a compressed octet string has the form
 *		  0x02 + result of BN_bn2bin() of the x coordinate of the public key
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
	ENGINE 	*e = NULL;
	int 	ret = 1;
	ECDSA 	*ecdsa = NULL;
	int 	i, badops = 0;
	const EVP_CIPHER *enc = NULL;
	BIO 	*in = NULL, *out = NULL;
	int 	informat, outformat, text=0, noout=0;
	int  	pubin = 0, pubout = 0;
	char 	*infile, *outfile, *prog, *engine;
	char 	*passargin = NULL, *passargout = NULL;
	char 	*passin = NULL, *passout = NULL;
	int 	pub = 0, point_form = 0;
	unsigned char *buffer = NULL;
	unsigned int  buf_len = 0;
	BIGNUM	*tmp_bn = NULL;

	apps_startup();

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err, stderr, BIO_NOCLOSE|BIO_FP_TEXT);

	if (!load_config(bio_err, NULL))
		goto end;

	engine = NULL;
	infile = NULL;
	outfile = NULL;
	informat = FORMAT_PEM;
	outformat = FORMAT_PEM;

	prog = argv[0];
	argc--;
	argv++;
	while (argc >= 1)
	{
		if (strcmp(*argv,"-inform") == 0)
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
		else if (strcmp(*argv,"-passin") == 0)
		{
			if (--argc < 1) goto bad;
			passargin= *(++argv);
		}
		else if (strcmp(*argv,"-passout") == 0)
		{
			if (--argc < 1) goto bad;
			passargout= *(++argv);
		}
		else if (strcmp(*argv, "-engine") == 0)
		{
			if (--argc < 1) goto bad;
			engine= *(++argv);
		}
		else if (strcmp(*argv, "-noout") == 0)
			noout = 1;
		else if (strcmp(*argv, "-text") == 0)
			text = 1;
		else if (strcmp(*argv, "-pub") == 0)
		{
			pub = 1;
			buffer = (unsigned char *)(*(argv+1));
			if (strcmp((char *)buffer, "compressed") == 0)
				point_form = POINT_CONVERSION_COMPRESSED;
			else if (strcmp((char *)buffer, "hybrid") == 0)
				point_form = POINT_CONVERSION_HYBRID;
			else if (strcmp((char *)buffer, "uncompressed") == 0)
				point_form = POINT_CONVERSION_UNCOMPRESSED;
			if (point_form)
			{
				argc--;
				argv++;
			}
		}
		else if (strcmp(*argv, "-pubin") == 0)
			pubin=1;
		else if (strcmp(*argv, "-pubout") == 0)
			pubout=1;
		else if ((enc=EVP_get_cipherbyname(&(argv[0][1]))) == NULL)
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
		BIO_printf(bio_err, "%s [options] <infile >outfile\n",prog);
		BIO_printf(bio_err, "where options are\n");
		BIO_printf(bio_err, " -inform arg     input format - DER or PEM\n");
		BIO_printf(bio_err, " -outform arg    output format - DER or PEM\n");
		BIO_printf(bio_err, " -in arg         input file\n");
		BIO_printf(bio_err, " -passin arg     input file pass phrase source\n");
		BIO_printf(bio_err, " -out arg        output file\n");
		BIO_printf(bio_err, " -passout arg    output file pass phrase source\n");
		BIO_printf(bio_err, " -engine e       use engine e, possibly a hardware device.\n");
		BIO_printf(bio_err, " -des            encrypt PEM output with cbc des\n");
		BIO_printf(bio_err, " -des3           encrypt PEM output with ede cbc des using 168 bit key\n");
#ifndef OPENSSL_NO_IDEA
		BIO_printf(bio_err, " -idea           encrypt PEM output with cbc idea\n");
#endif
#ifndef OPENSSL_NO_AES
		BIO_printf(bio_err, " -aes128, -aes192, -aes256\n");
		BIO_printf(bio_err, "                 encrypt PEM output with cbc aes\n");
#endif
		BIO_printf(bio_err, " -text           print the key in text\n");
		BIO_printf(bio_err, " -noout          don't print key out\n");
		BIO_printf(bio_err, " -pub [compressed | hybrid | uncompressed] \n");
		BIO_printf(bio_err, "         compressed     print the public key in compressed form ( default )\n");   
		BIO_printf(bio_err, "         hybrid         print the public key in hybrid form\n");
 		BIO_printf(bio_err, "         uncompressed   print the public key in uncompressed form\n");
		goto end;
	}

	ERR_load_crypto_strings();

        e = setup_engine(bio_err, engine, 0);

	if(!app_passwd(bio_err, passargin, passargout, &passin, &passout)) 
	{
		BIO_printf(bio_err, "Error getting passwords\n");
		goto end;
	}

	in = BIO_new(BIO_s_file());
	out = BIO_new(BIO_s_file());
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

	BIO_printf(bio_err,"read ECDSA key\n");
	if (informat == FORMAT_ASN1) 
	{
		if (pubin) 
			ecdsa = d2i_ECDSA_PUBKEY_bio(in, NULL);
		else 
			ecdsa = d2i_ECDSAPrivateKey_bio(in, NULL);
	} else if (informat == FORMAT_PEM) 
	{
		if (pubin) 
			ecdsa = PEM_read_bio_ECDSA_PUBKEY(in, NULL, NULL, NULL);
		else 
			ecdsa = PEM_read_bio_ECDSAPrivateKey(in, NULL, NULL, passin);
	} else
	{
		BIO_printf(bio_err, "bad input format specified for key\n");
		goto end;
	}
	if (ecdsa == NULL)
	{
		BIO_printf(bio_err,"unable to load Key\n");
		ERR_print_errors(bio_err);
		goto end;
	}

	if (outfile == NULL)
	{
		BIO_set_fp(out, stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
		{
			BIO *tmpbio = BIO_new(BIO_f_linebuffer());
			out = BIO_push(tmpbio, out);
		}
#endif
	}
	else
	{
		if (BIO_write_filename(out, outfile) <= 0)
		{
			perror(outfile);
			goto end;
		}
	}

	if (text) 
		if (!ECDSA_print(out, ecdsa, 0))
		{
			perror(outfile);
			ERR_print_errors(bio_err);
			goto end;
		}

	if (pub)
	{
		fprintf(stdout, "Public Key (");
		if (point_form == POINT_CONVERSION_COMPRESSED)
			fprintf(stdout, "COMPRESSED");
		else if (point_form == POINT_CONVERSION_UNCOMPRESSED)
			fprintf(stdout, "UNCOMPRESSED");
		else if (point_form == POINT_CONVERSION_HYBRID)
			fprintf(stdout, "HYBRID");
		fprintf(stdout, ")=");
		buf_len = EC_POINT_point2oct(ecdsa->group, EC_GROUP_get0_generator(ecdsa->group),
					     point_form, NULL, 0, NULL);
		if (!buf_len)
		{
			BIO_printf(bio_err,"invalid public key length\n");
			ERR_print_errors(bio_err);
			goto end;
		}
		if ((tmp_bn = BN_new()) == NULL ||
		    (buffer = OPENSSL_malloc(buf_len)) == NULL) goto end;
		if (!EC_POINT_point2oct(ecdsa->group, EC_GROUP_get0_generator(ecdsa->group),
					     point_form, buffer, buf_len, NULL) ||
		    !BN_bin2bn(buffer, buf_len, tmp_bn))
		{
			BIO_printf(bio_err,"can not encode public key\n");
			ERR_print_errors(bio_err);
			OPENSSL_free(buffer);
			goto end;
		}
		BN_print(out, tmp_bn);
		fprintf(stdout,"\n");
	}

	if (noout) 
		goto end;
	BIO_printf(bio_err, "writing ECDSA key\n");
	if (outformat == FORMAT_ASN1) 
	{
		if(pubin || pubout) 
			i = i2d_ECDSA_PUBKEY_bio(out, ecdsa);
		else 
			i = i2d_ECDSAPrivateKey_bio(out, ecdsa);
	} else if (outformat == FORMAT_PEM) 
	{
		if(pubin || pubout)
			i = PEM_write_bio_ECDSA_PUBKEY(out, ecdsa);
		else 
			i = PEM_write_bio_ECDSAPrivateKey(out, ecdsa, enc,
							NULL, 0, NULL, passout);
	} else 
	{
		BIO_printf(bio_err, "bad output format specified for outfile\n");
		goto end;
	}
	if (!i)
	{
		BIO_printf(bio_err, "unable to write private key\n");
		ERR_print_errors(bio_err);
	}
	else
		ret=0;
end:
	if (in) 	BIO_free(in);
	if (out)	BIO_free_all(out);
	if (ecdsa) 	ECDSA_free(ecdsa);
	if (tmp_bn)	BN_free(tmp_bn);
	if (passin) 	OPENSSL_free(passin);
	if (passout) 	OPENSSL_free(passout);
	apps_shutdown();
	EXIT(ret);
}
#endif
