/* apps/pem_mail.c */
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
#include "rsa.h"
#include "evp.h"
#include "objects.h"
#include "x509.h"
#include "err.h"
#include "pem.h"
#include "apps.h"

#undef PROG
#define PROG	pem_mail_main

static char *usage[]={
"usage: pem_mail args\n",
"\n",
" -in arg         - input file - default stdin\n",
" -out arg        - output file - default stdout\n",
" -cert arg       - the certificate to use\n",
" -key arg        - the private key to use\n",
" -MIC           - sign the message\n",
" -enc arg        - encrypt with one of cbc-des\n",
NULL
};


typedef struct lines_St
	{
	char *line;
	struct lines_st *next;
	} LINES;

int main(argc, argv)
int argc;
char **argv;
	{
	FILE *in;
	RSA *rsa=NULL;
	EVP_MD_CTX ctx;
	unsigned int mic=0,i,n;
	unsigned char buf[1024*15];
	char *prog,*infile=NULL,*outfile=NULL,*key=NULL;
	int badops=0;

	apps_startup();

	prog=argv[0];
	argc--;
	argv++;
	while (argc >= 1)
		{
		if (strcmp(*argv,"-key") == 0)
			{
			if (--argc < 1) goto bad;
			key= *(++argv);
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
		else if (strcmp(*argv,"-mic") == 0)
			mic=1;
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
		BIO_printf(bio_err,"%s [options] <infile >outfile\n",prog);
		BIO_printf(bio_err,"where options  are\n");
		EXIT(1);
		}

	if (key == NULL)
		{ BIO_printf(bio_err,"you need to specify a key\n"); EXIT(1); }
	in=fopen(key,"r");
	if (in == NULL) { perror(key); EXIT(1); }
	rsa=PEM_read_RSAPrivateKey(in,NULL,NULL);
	if (rsa == NULL)
		{
		BIO_printf(bio_err,"unable to load Private Key\n");
		ERR_print_errors(bio_err);
		EXIT(1);
		}
	fclose(in);

	PEM_SignInit(&ctx,EVP_md5());
	for (;;)
		{
		i=fread(buf,1,1024*10,stdin);
		if (i <= 0) break;
		PEM_SignUpdate(&ctx,buf,i);
		}
	if (!PEM_SignFinal(&ctx,buf,&n,rsa)) goto err;
	BIO_printf(bio_err,"%s\n",buf);
	EXIT(0);
err:
	ERR_print_errors(bio_err);
	EXIT(1);
	}
