/* apps/ssleay.c */
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

#ifndef DEBUG
#undef DEBUG
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bio.h"
#include "crypto.h"
#include "lhash.h"
#include "conf.h"
#include "x509.h"
#include "pem.h"
#include "ssl.h"
#define SSLEAY	/* turn off a few special case MONOLITH macros */
#define USE_SOCKETS /* needed for the _O_BINARY defs in the MS world */
#define SSLEAY_SRC
#include "apps.h"
#include "s_apps.h"
#include "err.h"

/*
#ifdef WINDOWS
#include "bss_file.c"
#endif
*/

#ifndef NOPROTO
static unsigned long MS_CALLBACK hash(FUNCTION *a);
static int MS_CALLBACK cmp(FUNCTION *a,FUNCTION *b);
static LHASH *prog_init(void );
static int do_cmd(LHASH *prog,int argc,char *argv[]);
#else
static unsigned long MS_CALLBACK hash();
static int MS_CALLBACK cmp();
static LHASH *prog_init();
static int do_cmd();
#endif

LHASH *config=NULL;
char *default_config_file=NULL;

#ifdef DEBUG
static void sig_stop(i)
int i;
	{
	char *a=NULL;

	*a='\0';
	}
#endif

/* Make sure there is only one when MONOLITH is defined */
#ifdef MONOLITH
BIO *bio_err=NULL;
#endif

int main(Argc,Argv)
int Argc;
char *Argv[];
	{
	ARGS arg;
#define PROG_NAME_SIZE	16
	char pname[PROG_NAME_SIZE];
	FUNCTION f,*fp;
	MS_STATIC char *prompt,buf[1024],config_name[256];
	int n,i,ret=0;
	int argc;
	char **argv,*p;
	LHASH *prog=NULL;
	long errline;
 
	arg.data=NULL;
	arg.count=0;

	/* SSLeay_add_ssl_algorithms(); is called in apps_startup() */
	apps_startup();

#if defined(DEBUG) && !defined(WINDOWS) && !defined(MSDOS)
#ifdef SIGBUS
	signal(SIGBUS,sig_stop);
#endif
#ifdef SIGSEGV
	signal(SIGSEGV,sig_stop);
#endif
#endif

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	ERR_load_crypto_strings();

	/* Lets load up our environment a little */
	p=getenv("SSLEAY_CONF");
	if (p == NULL)
		{
		strcpy(config_name,X509_get_default_cert_area());
		strcat(config_name,"/lib/");
		strcat(config_name,SSLEAY_CONF);
		p=config_name;
		}

	default_config_file=p;

	config=CONF_load(config,p,&errline);
	if (config == NULL) ERR_clear_error();

	prog=prog_init();

	/* first check the program name */
	program_name(Argv[0],pname,PROG_NAME_SIZE);

	f.name=pname;
	fp=(FUNCTION *)lh_retrieve(prog,(char *)&f);
	if (fp != NULL)
		{
		Argv[0]=pname;
		ret=fp->func(Argc,Argv);
		goto end;
		}

	/* ok, now check that there are not arguments, if there are,
	 * run with them, shifting the ssleay off the front */
	if (Argc != 1)
		{
		Argc--;
		Argv++;
		ret=do_cmd(prog,Argc,Argv);
		if (ret < 0) ret=0;
		goto end;
		}

	/* ok, lets enter the old 'SSLeay>' mode */
	
	for (;;)
		{
		ret=0;
		p=buf;
		n=1024;
		i=0;
		for (;;)
			{
			p[0]='\0';
			if (i++)
				prompt=">";
			else	prompt="SSLeay>";
			fputs(prompt,stdout);
			fflush(stdout);
			fgets(p,n,stdin);
			if (p[0] == '\0') goto end;
			i=strlen(p);
			if (i <= 1) break;
			if (p[i-2] != '\\') break;
			i-=2;
			p+=i;
			n-=i;
			}
		if (!chopup_args(&arg,buf,&argc,&argv)) break;

		ret=do_cmd(prog,argc,argv);
		if (ret < 0)
			{
			ret=0;
			goto end;
			}
		if (ret != 0)
			BIO_printf(bio_err,"error in %s\n",argv[0]);
		BIO_flush(bio_err);
		}
	BIO_printf(bio_err,"bad exit\n");
	ret=1;
end:
	if (config != NULL)
		{
		CONF_free(config);
		config=NULL;
		}
	if (prog != NULL) lh_free(prog);
	if (arg.data != NULL) Free(arg.data);
	ERR_remove_state(0);

	EVP_cleanup();

	CRYPTO_mem_leaks(bio_err);
	if (bio_err != NULL)
		{
		BIO_free(bio_err);
		bio_err=NULL;
		}
	EXIT(ret);
	}

static int do_cmd(prog,argc,argv)
LHASH *prog;
int argc;
char *argv[];
	{
	FUNCTION f,*fp;
	int i,ret=1,tp,nl;

	if ((argc <= 0) || (argv[0] == NULL))
		{ ret=0; goto end; }
	f.name=argv[0];
	fp=(FUNCTION *)lh_retrieve(prog,(char *)&f);
	if (fp != NULL)
		{
		ret=fp->func(argc,argv);
		}
	else if ((strcmp(argv[0],"quit") == 0) ||
		(strcmp(argv[0],"q") == 0) ||
		(strcmp(argv[0],"exit") == 0) ||
		(strcmp(argv[0],"bye") == 0))
		{
		ret= -1;
		goto end;
		}
	else
		{
		BIO_printf(bio_err,"'%s' is a bad command, valid commands are",
			argv[0]);
		i=0;
		fp=functions;
		tp=0;
		for (fp=functions; fp->name != NULL; fp++)
			{
			nl=0;
			if (((i++) % 5) == 0)
				{
				BIO_printf(bio_err,"\n");
				nl=1;
				}
			if (fp->type != tp)
				{
				tp=fp->type;
				if (!nl) BIO_printf(bio_err,"\n");
				if (tp == FUNC_TYPE_MD)
					{
					i=1;
					BIO_printf(bio_err,
						"Message Digest commands - see the dgst command for more details\n");
					}
				else if (tp == FUNC_TYPE_CIPHER)
					{
					i=1;
					BIO_printf(bio_err,"Cipher commands - see the enc command for more details\n");
					}
				}
			BIO_printf(bio_err,"%-15s",fp->name);
			}
		BIO_printf(bio_err,"\nquit\n");
		ret=0;
		}
end:
	return(ret);
	}

static LHASH *prog_init()
	{
	LHASH *ret;
	FUNCTION *f;

	if ((ret=lh_new(hash,cmp)) == NULL) return(NULL);

	for (f=functions; f->name != NULL; f++)
		lh_insert(ret,(char *)f);
	return(ret);
	}

static int MS_CALLBACK cmp(a,b)
FUNCTION *a,*b;
	{
	return(strncmp(a->name,b->name,8));
	}

static unsigned long MS_CALLBACK hash(a)
FUNCTION *a;
	{
	return(lh_strhash(a->name));
	}

#undef SSLEAY
