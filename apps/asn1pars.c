/* apps/asn1pars.c */
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
#include "apps.h"
#include "err.h"
#include "evp.h"
#include "x509.h"
#include "pem.h"

#define FORMAT_UNDEF	0
#define FORMAT_ASN1	1
#define FORMAT_TEXT	2
#define FORMAT_PEM	3

/* -inform arg	- input format - default PEM (DER or PEM)
 * -in arg	- input file - default stdin
 * -i		- indent the details by depth
 * -offset	- where in the file to start
 * -length	- how many bytes to use
 * -oid file	- extra oid decription file
 */

#undef PROG
#define PROG	asn1parse_main

int MAIN(argc, argv)
int argc;
char **argv;
	{
	int i,badops=0,offset=0,ret=1;
	unsigned int length=0;
	long num;
	BIO *in=NULL,*out=NULL,*b64=NULL;
	int informat,indent=0;
	char *infile=NULL,*str=NULL,*prog,*oidfile=NULL;
	BUF_MEM *buf=NULL;

	informat=FORMAT_PEM;

	apps_startup();

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

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
		else if (strcmp(*argv,"-in") == 0)
			{
			if (--argc < 1) goto bad;
			infile= *(++argv);
			}
		else if (strcmp(*argv,"-i") == 0)
			{
			indent=1;
			}
		else if (strcmp(*argv,"-oid") == 0)
			{
			if (--argc < 1) goto bad;
			oidfile= *(++argv);
			}
		else if (strcmp(*argv,"-offset") == 0)
			{
			if (--argc < 1) goto bad;
			offset= atoi(*(++argv));
			}
		else if (strcmp(*argv,"-length") == 0)
			{
			if (--argc < 1) goto bad;
			length= atoi(*(++argv));
			if (length == 0) goto bad;
			}
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
		BIO_printf(bio_err,"%s [options] <infile\n",prog);
		BIO_printf(bio_err,"where options are\n");
		BIO_printf(bio_err," -inform arg   input format - one of DER TXT PEM\n");
		BIO_printf(bio_err," -in arg       inout file\n");
		BIO_printf(bio_err," -offset arg   offset into file\n");
		BIO_printf(bio_err," -length arg   lenth of section in file\n");
		BIO_printf(bio_err," -i            indent entries\n");
		BIO_printf(bio_err," -oid file     file of extra oid definitions\n");
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
	BIO_set_fp(out,stdout,BIO_NOCLOSE|BIO_FP_TEXT);

	if (oidfile != NULL)
		{
		if (BIO_read_filename(in,oidfile) <= 0)
			{
			BIO_printf(bio_err,"problems opening %s\n",oidfile);
			ERR_print_errors(bio_err);
			goto end;
			}
		OBJ_create_objects(in);
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

	if ((buf=BUF_MEM_new()) == NULL) goto end;
	if (!BUF_MEM_grow(buf,BUFSIZ*8)) goto end; /* Pre-allocate :-) */

	if (informat == FORMAT_PEM)
		{
		BIO *tmp;

		if ((b64=BIO_new(BIO_f_base64())) == NULL)
			goto end;
		BIO_push(b64,in);
		tmp=in;
		in=b64;
		b64=tmp;
		}

	num=0;
	for (;;)
		{
		if (!BUF_MEM_grow(buf,(int)num+BUFSIZ)) goto end;
		i=BIO_read(in,&(buf->data[num]),BUFSIZ);
		if (i <= 0) break;
		num+=i;
		}
	str=buf->data;

	if (length == 0) length=(unsigned int)num;
	if (!ASN1_parse(out,(unsigned char *)&(str[offset]),length,indent))
		{
		ERR_print_errors(bio_err);
		goto end;
		}
	ret=0;
end:
	if (in != NULL) BIO_free(in);
	if (out != NULL) BIO_free(out);
	if (b64 != NULL) BIO_free(b64);
	if (ret != 0)
		ERR_print_errors(bio_err);
	if (buf != NULL) BUF_MEM_free(buf);
	OBJ_cleanup();
	EXIT(ret);
	}

