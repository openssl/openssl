/* apps/rsa.c */
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

#ifndef NO_RSA
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#undef PROG
#define PROG	rsa_main

/* -inform arg	- input format - default PEM (one of DER, NET or PEM)
 * -outform arg - output format - default PEM
 * -in arg	- input file - default stdin
 * -out arg	- output file - default stdout
 * -des		- encrypt output if PEM format with DES in cbc mode
 * -des3	- encrypt output if PEM format
 * -idea	- encrypt output if PEM format
 * -text	- print a text version
 * -modulus	- print the RSA key modulus
 * -check	- verify key consistency
 * -pubin	- Expect a public key in input file.
 * -pubout	- Output a public key.
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
	{
	int ret=1;
	RSA *rsa=NULL;
	int i,badops=0;
	const EVP_CIPHER *enc=NULL;
	BIO *in=NULL,*out=NULL;
	int informat,outformat,text=0,check=0,noout=0;
	int pubin = 0, pubout = 0;
	char *infile,*outfile,*prog;
	char *passargin = NULL, *passargout = NULL;
	char *passin = NULL, *passout = NULL;
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
		else if (strcmp(*argv,"-pubin") == 0)
			pubin=1;
		else if (strcmp(*argv,"-pubout") == 0)
			pubout=1;
		else if (strcmp(*argv,"-noout") == 0)
			noout=1;
		else if (strcmp(*argv,"-text") == 0)
			text=1;
		else if (strcmp(*argv,"-modulus") == 0)
			modulus=1;
		else if (strcmp(*argv,"-check") == 0)
			check=1;
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
		BIO_printf(bio_err," -inform arg     input format - one of DER NET PEM\n");
		BIO_printf(bio_err," -outform arg    output format - one of DER NET PEM\n");
		BIO_printf(bio_err," -in arg         input file\n");
		BIO_printf(bio_err," -passin arg     input file pass phrase source\n");
		BIO_printf(bio_err," -out arg        output file\n");
		BIO_printf(bio_err," -passout arg    output file pass phrase source\n");
		BIO_printf(bio_err," -des            encrypt PEM output with cbc des\n");
		BIO_printf(bio_err," -des3           encrypt PEM output with ede cbc des using 168 bit key\n");
#ifndef NO_IDEA
		BIO_printf(bio_err," -idea           encrypt PEM output with cbc idea\n");
#endif
		BIO_printf(bio_err," -text           print the key in text\n");
		BIO_printf(bio_err," -noout          don't print key out\n");
		BIO_printf(bio_err," -modulus        print the RSA key modulus\n");
		BIO_printf(bio_err," -check          verify key consistency\n");
		BIO_printf(bio_err," -pubin          expect a public key in input file\n");
		BIO_printf(bio_err," -pubout         output a public key\n");
		goto end;
		}

	ERR_load_crypto_strings();

	if(!app_passwd(bio_err, passargin, passargout, &passin, &passout)) {
		BIO_printf(bio_err, "Error getting passwords\n");
		goto end;
	}

	if(check && pubin) {
		BIO_printf(bio_err, "Only private keys can be checked\n");
		goto end;
	}

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

	BIO_printf(bio_err,"read RSA key\n");
	if	(informat == FORMAT_ASN1) {
		if (pubin) rsa=d2i_RSA_PUBKEY_bio(in,NULL);
		else rsa=d2i_RSAPrivateKey_bio(in,NULL);
	}
#ifndef NO_RC4
	else if (informat == FORMAT_NETSCAPE)
		{
		BUF_MEM *buf=NULL;
		unsigned char *p;
		int size=0;

		buf=BUF_MEM_new();
		for (;;)
			{
			if ((buf == NULL) || (!BUF_MEM_grow(buf,size+1024*10)))
				goto end;
			i=BIO_read(in,&(buf->data[size]),1024*10);
			size+=i;
			if (i == 0) break;
			if (i < 0)
				{
				perror("reading private key");
				BUF_MEM_free(buf);
				goto end;
				}
			}
		p=(unsigned char *)buf->data;
		rsa=d2i_Netscape_RSA(NULL,&p,(long)size,NULL);
		BUF_MEM_free(buf);
		}
#endif
	else if (informat == FORMAT_PEM) {
		if(pubin) rsa=PEM_read_bio_RSA_PUBKEY(in,NULL,NULL,NULL);
		else rsa=PEM_read_bio_RSAPrivateKey(in,NULL, NULL,passin);
	}
	else
		{
		BIO_printf(bio_err,"bad input format specified for key\n");
		goto end;
		}
	if (rsa == NULL)
		{
		BIO_printf(bio_err,"unable to load key\n");
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
		if (!RSA_print(out,rsa,0))
			{
			perror(outfile);
			ERR_print_errors(bio_err);
			goto end;
			}

	if (modulus)
		{
		BIO_printf(out,"Modulus=");
		BN_print(out,rsa->n);
		BIO_printf(out,"\n");
		}

	if (check)
		{
		int r = RSA_check_key(rsa);

		if (r == 1)
			BIO_printf(out,"RSA key ok\n");
		else if (r == 0)
			{
			long e;

			while ((e = ERR_peek_error()) != 0 &&
				ERR_GET_LIB(e) == ERR_LIB_RSA &&
				ERR_GET_FUNC(e) == RSA_F_RSA_CHECK_KEY &&
				ERR_GET_REASON(e) != ERR_R_MALLOC_FAILURE)
				{
				BIO_printf(out, "RSA key error: %s\n", ERR_reason_error_string(e));
				ERR_get_error(); /* remove e from error stack */
				}
			}
		
		if (r == -1 || ERR_peek_error() != 0) /* should happen only if r == -1 */
			{
			ERR_print_errors(bio_err);
			goto end;
			}
		}
		
	if (noout)
		{
		ret = 0;
		goto end;
		}
	BIO_printf(bio_err,"writing RSA key\n");
	if 	(outformat == FORMAT_ASN1) {
		if(pubout || pubin) i=i2d_RSA_PUBKEY_bio(out,rsa);
		else i=i2d_RSAPrivateKey_bio(out,rsa);
	}
#ifndef NO_RC4
	else if (outformat == FORMAT_NETSCAPE)
		{
		unsigned char *p,*pp;
		int size;

		i=1;
		size=i2d_Netscape_RSA(rsa,NULL,NULL);
		if ((p=(unsigned char *)Malloc(size)) == NULL)
			{
			BIO_printf(bio_err,"Malloc failure\n");
			goto end;
			}
		pp=p;
		i2d_Netscape_RSA(rsa,&p,NULL);
		BIO_write(out,(char *)pp,size);
		Free(pp);
		}
#endif
	else if (outformat == FORMAT_PEM) {
		if(pubout || pubin)
		    i=PEM_write_bio_RSA_PUBKEY(out,rsa);
		else i=PEM_write_bio_RSAPrivateKey(out,rsa,
						enc,NULL,0,NULL,passout);
	} else	{
		BIO_printf(bio_err,"bad output format specified for outfile\n");
		goto end;
		}
	if (!i)
		{
		BIO_printf(bio_err,"unable to write key\n");
		ERR_print_errors(bio_err);
		}
	else
		ret=0;
end:
	if(in != NULL) BIO_free(in);
	if(out != NULL) BIO_free(out);
	if(rsa != NULL) RSA_free(rsa);
	if(passin) Free(passin);
	if(passout) Free(passout);
	EXIT(ret);
	}
#else /* !NO_RSA */

# if PEDANTIC
static void *dummy=&dummy;
# endif

#endif
