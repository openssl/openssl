/* apps/dsa.c */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include "bio.h"
#include "err.h"
#include "dsa.h"
#include "evp.h"
#include "x509.h"
#include "pem.h"

#undef PROG
#define PROG	dsa_main

/* -inform arg	- input format - default PEM (one of DER, NET or PEM)
 * -outform arg - output format - default PEM
 * -in arg	- input file - default stdin
 * -out arg	- output file - default stdout
 * -des		- encrypt output if PEM format with DES in cbc mode
 * -des3	- encrypt output if PEM format
 * -idea	- encrypt output if PEM format
 * -text	- print a text version
 * -modulus	- print the DSA public key
 */

int MAIN(argc, argv)
int argc;
char **argv;
	{
	int ret=1;
	DSA *dsa=NULL;
	int i,badops=0;
	EVP_CIPHER *enc=NULL;
	BIO *in=NULL,*out=NULL;
	int informat,outformat,text=0,noout=0;
	char *infile,*outfile,*prog;
	int modulus=0;

	apps_startup();

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

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
		else if (strcmp(*argv,"-noout") == 0)
			noout=1;
		else if (strcmp(*argv,"-text") == 0)
			text=1;
		else if (strcmp(*argv,"-modulus") == 0)
			modulus=1;
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
		BIO_printf(bio_err,"%s [options] <infile >outfile\n",prog);
		BIO_printf(bio_err,"where options are\n");
		BIO_printf(bio_err," -inform arg   input format - one of DER NET PEM\n");
		BIO_printf(bio_err," -outform arg  output format - one of DER NET PEM\n");
		BIO_printf(bio_err," -in arg       inout file\n");
		BIO_printf(bio_err," -out arg      output file\n");
		BIO_printf(bio_err," -des          encrypt PEM output with cbc des\n");
		BIO_printf(bio_err," -des3         encrypt PEM output with ede cbc des using 168 bit key\n");
#ifndef NO_IDEA
		BIO_printf(bio_err," -idea         encrypt PEM output with cbc idea\n");
#endif
		BIO_printf(bio_err," -text         print the key in text\n");
		BIO_printf(bio_err," -noout        don't print key out\n");
		BIO_printf(bio_err," -modulus      print the DSA public value\n");
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

	BIO_printf(bio_err,"read DSA private key\n");
	if	(informat == FORMAT_ASN1)
		dsa=d2i_DSAPrivateKey_bio(in,NULL);
	else if (informat == FORMAT_PEM)
		dsa=PEM_read_bio_DSAPrivateKey(in,NULL,NULL);
	else
		{
		BIO_printf(bio_err,"bad input format specified for key\n");
		goto end;
		}
	if (dsa == NULL)
		{
		BIO_printf(bio_err,"unable to load Private Key\n");
		ERR_print_errors(bio_err);
		goto end;
		}

	if (outfile == NULL)
		BIO_set_fp(out,stdout,BIO_NOCLOSE);
	else
		{
		if (BIO_write_filename(out,outfile) <= 0)
			{
			perror(outfile);
			goto end;
			}
		}

	if (text) 
		if (!DSA_print(out,dsa,0))
			{
			perror(outfile);
			ERR_print_errors(bio_err);
			goto end;
			}

	if (modulus)
		{
		fprintf(stdout,"Public Key=");
		BN_print(out,dsa->pub_key);
		fprintf(stdout,"\n");
		}

	if (noout) goto end;
	BIO_printf(bio_err,"writing DSA private key\n");
	if 	(outformat == FORMAT_ASN1)
		i=i2d_DSAPrivateKey_bio(out,dsa);
	else if (outformat == FORMAT_PEM)
		i=PEM_write_bio_DSAPrivateKey(out,dsa,enc,NULL,0,NULL);
	else	{
		BIO_printf(bio_err,"bad output format specified for outfile\n");
		goto end;
		}
	if (!i)
		{
		BIO_printf(bio_err,"unable to write private key\n");
		ERR_print_errors(bio_err);
		}
	else
		ret=0;
end:
	if (in != NULL) BIO_free(in);
	if (out != NULL) BIO_free(out);
	if (dsa != NULL) DSA_free(dsa);
	EXIT(ret);
	}

