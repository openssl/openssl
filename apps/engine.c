/* apps/engine.c -*- mode: C; c-file-style: "eay" -*- */
/* Written by Richard Levitte <richard@levitte.org> for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NO_STDIO
#define APPS_WIN16
#endif
#include "apps.h"
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>

#undef PROG
#define PROG	engine_main

static char *engine_usage[]={
"usage: engine opts [engine ...]\n",
" -v          - verbose mode, a textual listing of the engines in OpenSSL\n",
#if 0
" -c          - for each engine, also list the capabilities\n",
" -t          - for each engine, check that they are really available\n",
#endif
NULL
};

static void identity(void *ptr)
	{
	return;
	}

int MAIN(int, char **);

int MAIN(int argc, char **argv)
	{
	int ret=1,i;
	char **pp;
	int verbose=0, list_cap=0, test_avail=0;
	ENGINE *e;
	STACK *engines = sk_new_null();
	int badops=0;
	BIO *bio_out=NULL;

	apps_startup();

	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	bio_out=BIO_new_fp(stdout,BIO_NOCLOSE);
#ifdef VMS
	{
	BIO *tmpbio = BIO_new(BIO_f_linebuffer());
	bio_out = BIO_push(tmpbio, bio_out);
	}
#endif

	argc--;
	argv++;
	while (argc >= 1)
		{
		if (strcmp(*argv,"-v") == 0)
			verbose=1;
		else if (strcmp(*argv,"-c") == 0)
			{
			list_cap=1;

			/* When list_cap is implemented. remove the following
			 * 3 lines.
			 */
			BIO_printf(bio_err, "-c not yet supported\n");
			badops=1;
			break;
			}
		else if (strcmp(*argv,"-t") == 0)
			test_avail=1;
		else if ((strncmp(*argv,"-h",2) == 0) ||
			 (strcmp(*argv,"-?") == 0))
			{
			badops=1;
			break;
			}
		else
			{
			sk_push(engines,*argv);
			}
		argc--;
		argv++;
		}

	if (badops)
		{
		for (pp=engine_usage; (*pp != NULL); pp++)
			BIO_printf(bio_err,"%s",*pp);
		goto end;
		}

	if (sk_num(engines) == 0)
		{
		for(e = ENGINE_get_first(); e != NULL; e = ENGINE_get_next(e))
			{
			sk_push(engines,(char *)ENGINE_get_id(e));
			}
		}

	for (i=0; i<sk_num(engines); i++)
		{
		const char *id = sk_value(engines,i);
		if ((e = ENGINE_by_id(id)) != NULL)
			{
			const char *name = ENGINE_get_name(e);
			BIO_printf(bio_out, "%s (%s)", name, id);
			if (list_cap || test_avail)
				BIO_printf(bio_out, ": ");
			if (test_avail)
				{
				if (ENGINE_init(e))
					{
					BIO_printf(bio_out, "available");
					ENGINE_finish(e);
					}
				else
					{
					BIO_printf(bio_out, "unavailable");
					}
				}
			BIO_printf(bio_out, "\n");
			}
		else
			BIO_printf(bio_err, "Engine %s does not exist\n", id);
		}

	ret=0;
	if (0)
		{
err:
		SSL_load_error_strings();
		ERR_print_errors(bio_err);
		}
end:
	sk_pop_free(engines, identity);
	if (bio_out != NULL) BIO_free_all(bio_out);
	EXIT(ret);
	}

