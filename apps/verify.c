/* apps/verify.c */
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
#include "bio.h"
#include "err.h"
#include "x509.h"
#include "pem.h"

#undef PROG
#define PROG	verify_main

#ifndef NOPROTO
static int MS_CALLBACK cb(int ok, X509_STORE_CTX *ctx);
static int check(X509_STORE *ctx,char *file);
#else
static int MS_CALLBACK cb();
static int check();
#endif

static int v_verbose=0;

int MAIN(argc, argv)
int argc;
char **argv;
	{
	int i,ret=1;
	char *CApath=NULL,*CAfile=NULL;
	X509_STORE *cert_ctx=NULL;
	X509_LOOKUP *lookup=NULL;

	cert_ctx=X509_STORE_new();
	if (cert_ctx == NULL) goto end;
	X509_STORE_set_verify_cb_func(cert_ctx,cb);

	ERR_load_crypto_strings();

	apps_startup();

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	argc--;
	argv++;
	for (;;)
		{
		if (argc >= 1)
			{
			if (strcmp(*argv,"-CApath") == 0)
				{
				if (argc-- < 1) goto end;
				CApath= *(++argv);
				}
			else if (strcmp(*argv,"-CAfile") == 0)
				{
				if (argc-- < 1) goto end;
				CAfile= *(++argv);
				}
			else if (strcmp(*argv,"-help") == 0)
				goto end;
			else if (strcmp(*argv,"-verbose") == 0)
				v_verbose=1;
			else if (argv[0][0] == '-')
				goto end;
			else
				break;
			argc--;
			argv++;
			}
		else
			break;
		}

	lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_file());
	if (lookup == NULL) abort();
	if (!X509_LOOKUP_load_file(lookup,CAfile,X509_FILETYPE_PEM))
		X509_LOOKUP_load_file(lookup,NULL,X509_FILETYPE_DEFAULT);
		
	lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_hash_dir());
	if (lookup == NULL) abort();
	if (!X509_LOOKUP_add_dir(lookup,CApath,X509_FILETYPE_PEM))
		X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);


	if (argc < 1) check(cert_ctx,NULL);
	else
		for (i=0; i<argc; i++)
			check(cert_ctx,argv[i]);
	ret=0;
end:
	if (ret == 1)
		BIO_printf(bio_err,"usage: verify [-verbose] [-CApath path] [-CAfile file] cert1 cert2 ...\n");
	if (cert_ctx != NULL) X509_STORE_free(cert_ctx);
	EXIT(ret);
	}

static int check(ctx,file)
X509_STORE *ctx;
char *file;
	{
	X509 *x=NULL;
	BIO *in=NULL;
	int i=0,ret=0;
	X509_STORE_CTX csc;

	in=BIO_new(BIO_s_file());
	if (in == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	if (file == NULL)
		BIO_set_fp(in,stdin,BIO_NOCLOSE);
	else
		{
		if (BIO_read_filename(in,file) <= 0)
			{
			perror(file);
			goto end;
			}
		}

	x=PEM_read_bio_X509(in,NULL,NULL);
	if (x == NULL)
		{
		fprintf(stdout,"%s: unable to load certificate file\n",
			(file == NULL)?"stdin":file);
		ERR_print_errors(bio_err);
		goto end;
		}
	fprintf(stdout,"%s: ",(file == NULL)?"stdin":file);

	X509_STORE_CTX_init(&csc,ctx,x,NULL);
	i=X509_verify_cert(&csc);
	X509_STORE_CTX_cleanup(&csc);

	ret=0;
end:
	if (i)
		{
		fprintf(stdout,"OK\n");
		ret=1;
		}
	else
		ERR_print_errors(bio_err);
	if (x != NULL) X509_free(x);
	if (in != NULL) BIO_free(in);

	return(ret);
	}

static int MS_CALLBACK cb(ok,ctx)
int ok;
X509_STORE_CTX *ctx;
	{
	char buf[256];

	if (!ok)
		{
		/* since we are just checking the certificates, it is
		 * ok if they are self signed. */
		if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
			ok=1;
		else
			{
			X509_NAME_oneline(
				X509_get_subject_name(ctx->current_cert),buf,256);
			printf("%s\n",buf);
			printf("error %d at %d depth lookup:%s\n",ctx->error,
				ctx->error_depth,
				X509_verify_cert_error_string(ctx->error));
			if (ctx->error == X509_V_ERR_CERT_HAS_EXPIRED)
				ok=1;
			}
		}
	if (!v_verbose)
		ERR_clear_error();
	return(ok);
	}

