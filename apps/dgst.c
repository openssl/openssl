/* apps/dgst.c */
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
#include <string.h>
#include <stdlib.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#undef BUFSIZE
#define BUFSIZE	1024*8

#undef PROG
#define PROG	dgst_main

void do_fp(unsigned char *buf,BIO *f,int sep);

int MAIN(int, char **);

int MAIN(int argc, char **argv)
	{
	unsigned char *buf=NULL;
	int i,err=0;
	const EVP_MD *md=NULL,*m;
	BIO *in=NULL,*inp;
	BIO *bmd=NULL;
	const char *name;
#define PROG_NAME_SIZE  16
	char pname[PROG_NAME_SIZE];
	int separator=0;
	int debug=0;

	apps_startup();

	if ((buf=(unsigned char *)Malloc(BUFSIZE)) == NULL)
		{
		BIO_printf(bio_err,"out of memory\n");
		goto end;
		}
	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	/* first check the program name */
	program_name(argv[0],pname,PROG_NAME_SIZE);

	md=EVP_get_digestbyname(pname);

	argc--;
	argv++;
	while (argc > 0)
		{
		if ((*argv)[0] != '-') break;
		if (strcmp(*argv,"-c") == 0)
			separator=1;
		else if (strcmp(*argv,"-d") == 0)
			debug=1;
		else if ((m=EVP_get_digestbyname(&((*argv)[1]))) != NULL)
			md=m;
		else
			break;
		argc--;
		argv++;
		}

	if (md == NULL)
		md=EVP_md5();

	if ((argc > 0) && (argv[0][0] == '-')) /* bad option */
		{
		BIO_printf(bio_err,"unknown option '%s'\n",*argv);
		BIO_printf(bio_err,"options are\n");
		BIO_printf(bio_err,"-c   to output the digest with separating colons\n");
		BIO_printf(bio_err,"-d   to output debug info\n");
		BIO_printf(bio_err,"-%3s to use the %s message digest algorithm (default)\n",
			LN_md5,LN_md5);
		BIO_printf(bio_err,"-%3s to use the %s message digest algorithm\n",
			LN_md2,LN_md2);
		BIO_printf(bio_err,"-%3s to use the %s message digest algorithm\n",
			LN_sha1,LN_sha1);
		BIO_printf(bio_err,"-%3s to use the %s message digest algorithm\n",
			LN_sha,LN_sha);
		BIO_printf(bio_err,"-%3s to use the %s message digest algorithm\n",
			LN_mdc2,LN_mdc2);
		BIO_printf(bio_err,"-%3s to use the %s message digest algorithm\n",
			LN_ripemd160,LN_ripemd160);
		err=1;
		goto end;
		}
	
	in=BIO_new(BIO_s_file());
	bmd=BIO_new(BIO_f_md());
	if (debug)
		{
		BIO_set_callback(in,BIO_debug_callback);
		/* needed for windows 3.1 */
		BIO_set_callback_arg(in,bio_err);
		}

	if ((in == NULL) || (bmd == NULL))
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	/* we use md as a filter, reading from 'in' */
	BIO_set_md(bmd,md);
	inp=BIO_push(bmd,in);

	if (argc == 0)
		{
		BIO_set_fp(in,stdin,BIO_NOCLOSE);
		do_fp(buf,inp,separator);
		}
	else
		{
		name=OBJ_nid2sn(md->type);
		for (i=0; i<argc; i++)
			{
			if (BIO_read_filename(in,argv[i]) <= 0)
				{
				perror(argv[i]);
				err++;
				continue;
				}
			printf("%s(%s)= ",name,argv[i]);
			do_fp(buf,inp,separator);
			(void)BIO_reset(bmd);
			}
		}
end:
	if (buf != NULL)
		{
		memset(buf,0,BUFSIZE);
		Free(buf);
		}
	if (in != NULL) BIO_free(in);
	if (bmd != NULL) BIO_free(bmd);
	EXIT(err);
	}

void do_fp(unsigned char *buf, BIO *bp, int sep)
	{
	int len;
	int i;

	for (;;)
		{
		i=BIO_read(bp,(char *)buf,BUFSIZE);
		if (i <= 0) break;
		}
	len=BIO_gets(bp,(char *)buf,BUFSIZE);

	for (i=0; i<len; i++)
		{
		if (sep && (i != 0))
			putc(':',stdout);
		printf("%02x",buf[i]);
		}
	printf("\n");
	}

