/* apps/s_client.c */
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
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/e_os2.h>
#ifdef OPENSSL_NO_STDIO
#define APPS_WIN16
#endif

/* With IPv6, it looks like Digital has mixed up the proper order of
   recursive header file inclusion, resulting in the compiler complaining
   that u_int isn't defined, but only if _POSIX_C_SOURCE is defined, which
   is needed to have fileno() declared correctly...  So let's define u_int */
#if defined(OPENSSL_SYS_VMS_DECC) && !defined(__U_INT)
#define __U_INT
typedef unsigned int u_int;
#endif

#define USE_SOCKETS
#include "apps.h"
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "s_apps.h"

#ifdef OPENSSL_SYS_WINDOWS
#include <conio.h>
#endif

#ifdef OPENSSL_SYS_WINCE
/* Windows CE incorrectly defines fileno as returning void*, so to avoid problems below... */
#ifdef fileno
#undef fileno
#endif
#define fileno(a) (int)_fileno(a)
#endif


#if (defined(OPENSSL_SYS_VMS) && __VMS_VER < 70000000)
/* FIONBIO used as a switch to enable ioctl, and that isn't in VMS < 7.0 */
#undef FIONBIO
#endif

#undef PROG
#define PROG	s_client_main

/*#define SSL_HOST_NAME	"www.netscape.com" */
/*#define SSL_HOST_NAME	"193.118.187.102" */
#define SSL_HOST_NAME	"localhost"

/*#define TEST_CERT "client.pem" */ /* no default cert. */

#undef BUFSIZZ
#define BUFSIZZ 1024*8

extern int verify_depth;
extern int verify_error;

#ifdef FIONBIO
static int c_nbio=0;
#endif
static int c_Pause=0;
static int c_debug=0;
static int c_msg=0;
static int c_showcerts=0;

static void sc_usage(void);
static void print_stuff(BIO *berr,SSL *con,int full);
static BIO *bio_c_out=NULL;
static int c_quiet=0;
static int c_ign_eof=0;

static void sc_usage(void)
	{
	BIO_printf(bio_err,"usage: s_client args\n");
	BIO_printf(bio_err,"\n");
	BIO_printf(bio_err," -host host     - use -connect instead\n");
	BIO_printf(bio_err," -port port     - use -connect instead\n");
	BIO_printf(bio_err," -connect host:port - who to connect to (default is %s:%s)\n",SSL_HOST_NAME,PORT_STR);

	BIO_printf(bio_err," -verify arg   - turn on peer certificate verification\n");
	BIO_printf(bio_err," -cert arg     - certificate file to use, PEM format assumed\n");
	BIO_printf(bio_err," -key arg      - Private key file to use, PEM format assumed, in cert file if\n");
	BIO_printf(bio_err,"                 not specified but cert file is.\n");
	BIO_printf(bio_err," -CApath arg   - PEM format directory of CA's\n");
	BIO_printf(bio_err," -CAfile arg   - PEM format file of CA's\n");
	BIO_printf(bio_err," -reconnect    - Drop and re-make the connection with the same Session-ID\n");
	BIO_printf(bio_err," -pause        - sleep(1) after each read(2) and write(2) system call\n");
	BIO_printf(bio_err," -showcerts    - show all certificates in the chain\n");
	BIO_printf(bio_err," -debug        - extra output\n");
	BIO_printf(bio_err," -msg          - Show protocol messages\n");
	BIO_printf(bio_err," -nbio_test    - more ssl protocol testing\n");
	BIO_printf(bio_err," -state        - print the 'ssl' states\n");
#ifdef FIONBIO
	BIO_printf(bio_err," -nbio         - Run with non-blocking IO\n");
#endif
	BIO_printf(bio_err," -crlf         - convert LF from terminal into CRLF\n");
	BIO_printf(bio_err," -quiet        - no s_client output\n");
	BIO_printf(bio_err," -ign_eof      - ignore input eof (default when -quiet)\n");
	BIO_printf(bio_err," -ssl2         - just use SSLv2\n");
	BIO_printf(bio_err," -ssl3         - just use SSLv3\n");
	BIO_printf(bio_err," -tls1         - just use TLSv1\n");
	BIO_printf(bio_err," -no_tls1/-no_ssl3/-no_ssl2 - turn off that protocol\n");
	BIO_printf(bio_err," -bugs         - Switch on all SSL implementation bug workarounds\n");
	BIO_printf(bio_err," -serverpref   - Use server's cipher preferences (only SSLv2)\n");
	BIO_printf(bio_err," -cipher       - preferred cipher to use, use the 'openssl ciphers'\n");
	BIO_printf(bio_err,"                 command to see what is available\n");
	BIO_printf(bio_err," -starttls prot - use the STARTTLS command before starting TLS\n");
	BIO_printf(bio_err,"                 for those protocols that support it, where\n");
	BIO_printf(bio_err,"                 'prot' defines which one to assume.  Currently,\n");
	BIO_printf(bio_err,"                 only \"smtp\" is supported.\n");
#ifndef OPENSSL_NO_ENGINE
	BIO_printf(bio_err," -engine id    - Initialise and use the specified engine\n");
#endif
	BIO_printf(bio_err," -rand file%cfile%c...\n", LIST_SEPARATOR_CHAR, LIST_SEPARATOR_CHAR);

	}

int MAIN(int, char **);

int MAIN(int argc, char **argv)
	{
	int off=0;
	SSL *con=NULL,*con2=NULL;
	X509_STORE *store = NULL;
	int s,k,width,state=0;
	char *cbuf=NULL,*sbuf=NULL,*mbuf=NULL;
	int cbuf_len,cbuf_off;
	int sbuf_len,sbuf_off;
	fd_set readfds,writefds;
	short port=PORT;
	int full_log=1;
	char *host=SSL_HOST_NAME;
	char *cert_file=NULL,*key_file=NULL;
	char *CApath=NULL,*CAfile=NULL,*cipher=NULL;
	int reconnect=0,badop=0,verify=SSL_VERIFY_NONE,bugs=0;
	int crlf=0;
	int write_tty,read_tty,write_ssl,read_ssl,tty_on,ssl_pending;
	SSL_CTX *ctx=NULL;
	int ret=1,in_init=1,i,nbio_test=0;
	int smtp_starttls = 0;
	int prexit = 0, vflags = 0;
	SSL_METHOD *meth=NULL;
	BIO *sbio;
	char *inrand=NULL;
#ifndef OPENSSL_NO_ENGINE
	char *engine_id=NULL;
	ENGINE *e=NULL;
#endif
#ifdef OPENSSL_SYS_WINDOWS
	struct timeval tv;
#endif

#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_SSL3)
	meth=SSLv23_client_method();
#elif !defined(OPENSSL_NO_SSL3)
	meth=SSLv3_client_method();
#elif !defined(OPENSSL_NO_SSL2)
	meth=SSLv2_client_method();
#endif

	apps_startup();
	c_Pause=0;
	c_quiet=0;
	c_ign_eof=0;
	c_debug=0;
	c_msg=0;
	c_showcerts=0;

	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);

	if (!load_config(bio_err, NULL))
		goto end;

	if (	((cbuf=OPENSSL_malloc(BUFSIZZ)) == NULL) ||
		((sbuf=OPENSSL_malloc(BUFSIZZ)) == NULL) ||
		((mbuf=OPENSSL_malloc(BUFSIZZ)) == NULL))
		{
		BIO_printf(bio_err,"out of memory\n");
		goto end;
		}

	verify_depth=0;
	verify_error=X509_V_OK;
#ifdef FIONBIO
	c_nbio=0;
#endif

	argc--;
	argv++;
	while (argc >= 1)
		{
		if	(strcmp(*argv,"-host") == 0)
			{
			if (--argc < 1) goto bad;
			host= *(++argv);
			}
		else if	(strcmp(*argv,"-port") == 0)
			{
			if (--argc < 1) goto bad;
			port=atoi(*(++argv));
			if (port == 0) goto bad;
			}
		else if (strcmp(*argv,"-connect") == 0)
			{
			if (--argc < 1) goto bad;
			if (!extract_host_port(*(++argv),&host,NULL,&port))
				goto bad;
			}
		else if	(strcmp(*argv,"-verify") == 0)
			{
			verify=SSL_VERIFY_PEER;
			if (--argc < 1) goto bad;
			verify_depth=atoi(*(++argv));
			BIO_printf(bio_err,"verify depth is %d\n",verify_depth);
			}
		else if	(strcmp(*argv,"-cert") == 0)
			{
			if (--argc < 1) goto bad;
			cert_file= *(++argv);
			}
		else if	(strcmp(*argv,"-crl_check") == 0)
			vflags |= X509_V_FLAG_CRL_CHECK;
		else if	(strcmp(*argv,"-crl_check_all") == 0)
			vflags |= X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL;
		else if	(strcmp(*argv,"-prexit") == 0)
			prexit=1;
		else if	(strcmp(*argv,"-crlf") == 0)
			crlf=1;
		else if	(strcmp(*argv,"-quiet") == 0)
			{
			c_quiet=1;
			c_ign_eof=1;
			}
		else if	(strcmp(*argv,"-ign_eof") == 0)
			c_ign_eof=1;
		else if	(strcmp(*argv,"-pause") == 0)
			c_Pause=1;
		else if	(strcmp(*argv,"-debug") == 0)
			c_debug=1;
		else if	(strcmp(*argv,"-msg") == 0)
			c_msg=1;
		else if	(strcmp(*argv,"-showcerts") == 0)
			c_showcerts=1;
		else if	(strcmp(*argv,"-nbio_test") == 0)
			nbio_test=1;
		else if	(strcmp(*argv,"-state") == 0)
			state=1;
#ifndef OPENSSL_NO_SSL2
		else if	(strcmp(*argv,"-ssl2") == 0)
			meth=SSLv2_client_method();
#endif
#ifndef OPENSSL_NO_SSL3
		else if	(strcmp(*argv,"-ssl3") == 0)
			meth=SSLv3_client_method();
#endif
#ifndef OPENSSL_NO_TLS1
		else if	(strcmp(*argv,"-tls1") == 0)
			meth=TLSv1_client_method();
#endif
		else if (strcmp(*argv,"-bugs") == 0)
			bugs=1;
		else if	(strcmp(*argv,"-key") == 0)
			{
			if (--argc < 1) goto bad;
			key_file= *(++argv);
			}
		else if	(strcmp(*argv,"-reconnect") == 0)
			{
			reconnect=5;
			}
		else if	(strcmp(*argv,"-CApath") == 0)
			{
			if (--argc < 1) goto bad;
			CApath= *(++argv);
			}
		else if	(strcmp(*argv,"-CAfile") == 0)
			{
			if (--argc < 1) goto bad;
			CAfile= *(++argv);
			}
		else if (strcmp(*argv,"-no_tls1") == 0)
			off|=SSL_OP_NO_TLSv1;
		else if (strcmp(*argv,"-no_ssl3") == 0)
			off|=SSL_OP_NO_SSLv3;
		else if (strcmp(*argv,"-no_ssl2") == 0)
			off|=SSL_OP_NO_SSLv2;
		else if (strcmp(*argv,"-serverpref") == 0)
			off|=SSL_OP_CIPHER_SERVER_PREFERENCE;
		else if	(strcmp(*argv,"-cipher") == 0)
			{
			if (--argc < 1) goto bad;
			cipher= *(++argv);
			}
#ifdef FIONBIO
		else if (strcmp(*argv,"-nbio") == 0)
			{ c_nbio=1; }
#endif
		else if	(strcmp(*argv,"-starttls") == 0)
			{
			if (--argc < 1) goto bad;
			++argv;
			if (strcmp(*argv,"smtp") == 0)
				smtp_starttls = 1;
			else
				goto bad;
			}
#ifndef OPENSSL_NO_ENGINE
		else if	(strcmp(*argv,"-engine") == 0)
			{
			if (--argc < 1) goto bad;
			engine_id = *(++argv);
			}
#endif
		else if (strcmp(*argv,"-rand") == 0)
			{
			if (--argc < 1) goto bad;
			inrand= *(++argv);
			}
		else
			{
			BIO_printf(bio_err,"unknown option %s\n",*argv);
			badop=1;
			break;
			}
		argc--;
		argv++;
		}
	if (badop)
		{
bad:
		sc_usage();
		goto end;
		}

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

#ifndef OPENSSL_NO_ENGINE
        e = setup_engine(bio_err, engine_id, 1);
#endif

	if (!app_RAND_load_file(NULL, bio_err, 1) && inrand == NULL
		&& !RAND_status())
		{
		BIO_printf(bio_err,"warning, not much extra random data, consider using the -rand option\n");
		}
	if (inrand != NULL)
		BIO_printf(bio_err,"%ld semi-random bytes loaded\n",
			app_RAND_load_files(inrand));

	if (bio_c_out == NULL)
		{
		if (c_quiet && !c_debug && !c_msg)
			{
			bio_c_out=BIO_new(BIO_s_null());
			}
		else
			{
			if (bio_c_out == NULL)
				bio_c_out=BIO_new_fp(stdout,BIO_NOCLOSE);
			}
		}

	ctx=SSL_CTX_new(meth);
	if (ctx == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	if (bugs)
		SSL_CTX_set_options(ctx,SSL_OP_ALL|off);
	else
		SSL_CTX_set_options(ctx,off);

	if (state) SSL_CTX_set_info_callback(ctx,apps_ssl_info_callback);
	if (cipher != NULL)
		if(!SSL_CTX_set_cipher_list(ctx,cipher)) {
		BIO_printf(bio_err,"error setting cipher list\n");
		ERR_print_errors(bio_err);
		goto end;
	}
#if 0
	else
		SSL_CTX_set_cipher_list(ctx,getenv("SSL_CIPHER"));
#endif

	SSL_CTX_set_verify(ctx,verify,verify_callback);
	if (!set_cert_stuff(ctx,cert_file,key_file))
		goto end;

	if ((!SSL_CTX_load_verify_locations(ctx,CAfile,CApath)) ||
		(!SSL_CTX_set_default_verify_paths(ctx)))
		{
		/* BIO_printf(bio_err,"error setting default verify locations\n"); */
		ERR_print_errors(bio_err);
		/* goto end; */
		}

	store = SSL_CTX_get_cert_store(ctx);
	X509_STORE_set_flags(store, vflags);

	con=SSL_new(ctx);
#ifndef OPENSSL_NO_KRB5
	if (con  &&  (con->kssl_ctx = kssl_ctx_new()) != NULL)
                {
                kssl_ctx_setstring(con->kssl_ctx, KSSL_SERVER, host);
		}
#endif	/* OPENSSL_NO_KRB5  */
/*	SSL_set_cipher_list(con,"RC4-MD5"); */

re_start:

	if (init_client(&s,host,port) == 0)
		{
		BIO_printf(bio_err,"connect:errno=%d\n",get_last_socket_error());
		SHUTDOWN(s);
		goto end;
		}
	BIO_printf(bio_c_out,"CONNECTED(%08X)\n",s);

#ifdef FIONBIO
	if (c_nbio)
		{
		unsigned long l=1;
		BIO_printf(bio_c_out,"turning on non blocking io\n");
		if (BIO_socket_ioctl(s,FIONBIO,&l) < 0)
			{
			ERR_print_errors(bio_err);
			goto end;
			}
		}
#endif                                              
	if (c_Pause & 0x01) con->debug=1;
	sbio=BIO_new_socket(s,BIO_NOCLOSE);

	if (nbio_test)
		{
		BIO *test;

		test=BIO_new(BIO_f_nbio_test());
		sbio=BIO_push(test,sbio);
		}

	if (c_debug)
		{
		con->debug=1;
		BIO_set_callback(sbio,bio_dump_cb);
		BIO_set_callback_arg(sbio,bio_c_out);
		}
	if (c_msg)
		{
		SSL_set_msg_callback(con, msg_cb);
		SSL_set_msg_callback_arg(con, bio_c_out);
		}

	SSL_set_bio(con,sbio,sbio);
	SSL_set_connect_state(con);

	/* ok, lets connect */
	width=SSL_get_fd(con)+1;

	read_tty=1;
	write_tty=0;
	tty_on=0;
	read_ssl=1;
	write_ssl=1;
	
	cbuf_len=0;
	cbuf_off=0;
	sbuf_len=0;
	sbuf_off=0;

	/* This is an ugly hack that does a lot of assumptions */
	if (smtp_starttls)
		{
		BIO_read(sbio,mbuf,BUFSIZZ);
		BIO_printf(sbio,"STARTTLS\r\n");
		BIO_read(sbio,sbuf,BUFSIZZ);
		}

	for (;;)
		{
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		if (SSL_in_init(con) && !SSL_total_renegotiations(con))
			{
			in_init=1;
			tty_on=0;
			}
		else
			{
			tty_on=1;
			if (in_init)
				{
				in_init=0;
				print_stuff(bio_c_out,con,full_log);
				if (full_log > 0) full_log--;

				if (smtp_starttls)
					{
					BIO_printf(bio_err,"%s",mbuf);
					/* We don't need to know any more */
					smtp_starttls = 0;
					}

				if (reconnect)
					{
					reconnect--;
					BIO_printf(bio_c_out,"drop connection and then reconnect\n");
					SSL_shutdown(con);
					SSL_set_connect_state(con);
					SHUTDOWN(SSL_get_fd(con));
					goto re_start;
					}
				}
			}

		ssl_pending = read_ssl && SSL_pending(con);

		if (!ssl_pending)
			{
#ifndef OPENSSL_SYS_WINDOWS
			if (tty_on)
				{
				if (read_tty)  FD_SET(fileno(stdin),&readfds);
				if (write_tty) FD_SET(fileno(stdout),&writefds);
				}
			if (read_ssl)
				FD_SET(SSL_get_fd(con),&readfds);
			if (write_ssl)
				FD_SET(SSL_get_fd(con),&writefds);
#else
			if(!tty_on || !write_tty) {
				if (read_ssl)
					FD_SET(SSL_get_fd(con),&readfds);
				if (write_ssl)
					FD_SET(SSL_get_fd(con),&writefds);
			}
#endif
/*			printf("mode tty(%d %d%d) ssl(%d%d)\n",
				tty_on,read_tty,write_tty,read_ssl,write_ssl);*/

			/* Note: under VMS with SOCKETSHR the second parameter
			 * is currently of type (int *) whereas under other
			 * systems it is (void *) if you don't have a cast it
			 * will choke the compiler: if you do have a cast then
			 * you can either go for (int *) or (void *).
			 */
#ifdef OPENSSL_SYS_WINDOWS
			/* Under Windows we make the assumption that we can
			 * always write to the tty: therefore if we need to
			 * write to the tty we just fall through. Otherwise
			 * we timeout the select every second and see if there
			 * are any keypresses. Note: this is a hack, in a proper
			 * Windows application we wouldn't do this.
			 */
			i=0;
			if(!write_tty) {
				if(read_tty) {
					tv.tv_sec = 1;
					tv.tv_usec = 0;
					i=select(width,(void *)&readfds,(void *)&writefds,
						 NULL,&tv);
#ifdef OPENSSL_SYS_WINCE
					if(!i && (!_kbhit() || !read_tty) ) continue;
#else
					if(!i && (!((_kbhit()) || (WAIT_OBJECT_0 == WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE), 0))) || !read_tty) ) continue;
#endif
				} else 	i=select(width,(void *)&readfds,(void *)&writefds,
					 NULL,NULL);
			}
#else
			i=select(width,(void *)&readfds,(void *)&writefds,
				 NULL,NULL);
#endif
			if ( i < 0)
				{
				BIO_printf(bio_err,"bad select %d\n",
				get_last_socket_error());
				goto shut;
				/* goto end; */
				}
			}

		if (!ssl_pending && FD_ISSET(SSL_get_fd(con),&writefds))
			{
			k=SSL_write(con,&(cbuf[cbuf_off]),
				(unsigned int)cbuf_len);
			switch (SSL_get_error(con,k))
				{
			case SSL_ERROR_NONE:
				cbuf_off+=k;
				cbuf_len-=k;
				if (k <= 0) goto end;
				/* we have done a  write(con,NULL,0); */
				if (cbuf_len <= 0)
					{
					read_tty=1;
					write_ssl=0;
					}
				else /* if (cbuf_len > 0) */
					{
					read_tty=0;
					write_ssl=1;
					}
				break;
			case SSL_ERROR_WANT_WRITE:
				BIO_printf(bio_c_out,"write W BLOCK\n");
				write_ssl=1;
				read_tty=0;
				break;
			case SSL_ERROR_WANT_READ:
				BIO_printf(bio_c_out,"write R BLOCK\n");
				write_tty=0;
				read_ssl=1;
				write_ssl=0;
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				BIO_printf(bio_c_out,"write X BLOCK\n");
				break;
			case SSL_ERROR_ZERO_RETURN:
				if (cbuf_len != 0)
					{
					BIO_printf(bio_c_out,"shutdown\n");
					goto shut;
					}
				else
					{
					read_tty=1;
					write_ssl=0;
					break;
					}
				
			case SSL_ERROR_SYSCALL:
				if ((k != 0) || (cbuf_len != 0))
					{
					BIO_printf(bio_err,"write:errno=%d\n",
						get_last_socket_error());
					goto shut;
					}
				else
					{
					read_tty=1;
					write_ssl=0;
					}
				break;
			case SSL_ERROR_SSL:
				ERR_print_errors(bio_err);
				goto shut;
				}
			}
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
		/* Assume Windows/DOS can always write */
		else if (!ssl_pending && write_tty)
#else
		else if (!ssl_pending && FD_ISSET(fileno(stdout),&writefds))
#endif
			{
#ifdef CHARSET_EBCDIC
			ascii2ebcdic(&(sbuf[sbuf_off]),&(sbuf[sbuf_off]),sbuf_len);
#endif
			i=write(fileno(stdout),&(sbuf[sbuf_off]),sbuf_len);

			if (i <= 0)
				{
				BIO_printf(bio_c_out,"DONE\n");
				goto shut;
				/* goto end; */
				}

			sbuf_len-=i;;
			sbuf_off+=i;
			if (sbuf_len <= 0)
				{
				read_ssl=1;
				write_tty=0;
				}
			}
		else if (ssl_pending || FD_ISSET(SSL_get_fd(con),&readfds))
			{
#ifdef RENEG
{ static int iiii; if (++iiii == 52) { SSL_renegotiate(con); iiii=0; } }
#endif
#if 1
			k=SSL_read(con,sbuf,1024 /* BUFSIZZ */ );
#else
/* Demo for pending and peek :-) */
			k=SSL_read(con,sbuf,16);
{ char zbuf[10240]; 
printf("read=%d pending=%d peek=%d\n",k,SSL_pending(con),SSL_peek(con,zbuf,10240));
}
#endif

			switch (SSL_get_error(con,k))
				{
			case SSL_ERROR_NONE:
				if (k <= 0)
					goto end;
				sbuf_off=0;
				sbuf_len=k;

				read_ssl=0;
				write_tty=1;
				break;
			case SSL_ERROR_WANT_WRITE:
				BIO_printf(bio_c_out,"read W BLOCK\n");
				write_ssl=1;
				read_tty=0;
				break;
			case SSL_ERROR_WANT_READ:
				BIO_printf(bio_c_out,"read R BLOCK\n");
				write_tty=0;
				read_ssl=1;
				if ((read_tty == 0) && (write_ssl == 0))
					write_ssl=1;
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				BIO_printf(bio_c_out,"read X BLOCK\n");
				break;
			case SSL_ERROR_SYSCALL:
				BIO_printf(bio_err,"read:errno=%d\n",get_last_socket_error());
				goto shut;
			case SSL_ERROR_ZERO_RETURN:
				BIO_printf(bio_c_out,"closed\n");
				goto shut;
			case SSL_ERROR_SSL:
				ERR_print_errors(bio_err);
				goto shut;
				/* break; */
				}
			}

#ifdef OPENSSL_SYS_WINDOWS
#ifdef OPENSSL_SYS_WINCE
		else if (_kbhit())
#else
		else if ((_kbhit()) || (WAIT_OBJECT_0 == WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE), 0)))
#endif
#else
		else if (FD_ISSET(fileno(stdin),&readfds))
#endif
			{
			if (crlf)
				{
				int j, lf_num;

				i=read(fileno(stdin),cbuf,BUFSIZZ/2);
				lf_num = 0;
				/* both loops are skipped when i <= 0 */
				for (j = 0; j < i; j++)
					if (cbuf[j] == '\n')
						lf_num++;
				for (j = i-1; j >= 0; j--)
					{
					cbuf[j+lf_num] = cbuf[j];
					if (cbuf[j] == '\n')
						{
						lf_num--;
						i++;
						cbuf[j+lf_num] = '\r';
						}
					}
				assert(lf_num == 0);
				}
			else
				i=read(fileno(stdin),cbuf,BUFSIZZ);

			if ((!c_ign_eof) && ((i <= 0) || (cbuf[0] == 'Q')))
				{
				BIO_printf(bio_err,"DONE\n");
				goto shut;
				}

			if ((!c_ign_eof) && (cbuf[0] == 'R'))
				{
				BIO_printf(bio_err,"RENEGOTIATING\n");
				SSL_renegotiate(con);
				cbuf_len=0;
				}
			else
				{
				cbuf_len=i;
				cbuf_off=0;
#ifdef CHARSET_EBCDIC
				ebcdic2ascii(cbuf, cbuf, i);
#endif
				}

			write_ssl=1;
			read_tty=0;
			}
		}
shut:
	SSL_shutdown(con);
	SHUTDOWN(SSL_get_fd(con));
	ret=0;
end:
	if(prexit) print_stuff(bio_c_out,con,1);
	if (con != NULL) SSL_free(con);
	if (con2 != NULL) SSL_free(con2);
	if (ctx != NULL) SSL_CTX_free(ctx);
	if (cbuf != NULL) { OPENSSL_cleanse(cbuf,BUFSIZZ); OPENSSL_free(cbuf); }
	if (sbuf != NULL) { OPENSSL_cleanse(sbuf,BUFSIZZ); OPENSSL_free(sbuf); }
	if (mbuf != NULL) { OPENSSL_cleanse(mbuf,BUFSIZZ); OPENSSL_free(mbuf); }
	if (bio_c_out != NULL)
		{
		BIO_free(bio_c_out);
		bio_c_out=NULL;
		}
	apps_shutdown();
	OPENSSL_EXIT(ret);
	}


static void print_stuff(BIO *bio, SSL *s, int full)
	{
	X509 *peer=NULL;
	char *p;
	static char *space="                ";
	char buf[BUFSIZ];
	STACK_OF(X509) *sk;
	STACK_OF(X509_NAME) *sk2;
	SSL_CIPHER *c;
	X509_NAME *xn;
	int j,i;

	if (full)
		{
		int got_a_chain = 0;

		sk=SSL_get_peer_cert_chain(s);
		if (sk != NULL)
			{
			got_a_chain = 1; /* we don't have it for SSL2 (yet) */

			BIO_printf(bio,"---\nCertificate chain\n");
			for (i=0; i<sk_X509_num(sk); i++)
				{
				X509_NAME_oneline(X509_get_subject_name(
					sk_X509_value(sk,i)),buf,sizeof buf);
				BIO_printf(bio,"%2d s:%s\n",i,buf);
				X509_NAME_oneline(X509_get_issuer_name(
					sk_X509_value(sk,i)),buf,sizeof buf);
				BIO_printf(bio,"   i:%s\n",buf);
				if (c_showcerts)
					PEM_write_bio_X509(bio,sk_X509_value(sk,i));
				}
			}

		BIO_printf(bio,"---\n");
		peer=SSL_get_peer_certificate(s);
		if (peer != NULL)
			{
			BIO_printf(bio,"Server certificate\n");
			if (!(c_showcerts && got_a_chain)) /* Redundant if we showed the whole chain */
				PEM_write_bio_X509(bio,peer);
			X509_NAME_oneline(X509_get_subject_name(peer),
				buf,sizeof buf);
			BIO_printf(bio,"subject=%s\n",buf);
			X509_NAME_oneline(X509_get_issuer_name(peer),
				buf,sizeof buf);
			BIO_printf(bio,"issuer=%s\n",buf);
			}
		else
			BIO_printf(bio,"no peer certificate available\n");

		sk2=SSL_get_client_CA_list(s);
		if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0))
			{
			BIO_printf(bio,"---\nAcceptable client certificate CA names\n");
			for (i=0; i<sk_X509_NAME_num(sk2); i++)
				{
				xn=sk_X509_NAME_value(sk2,i);
				X509_NAME_oneline(xn,buf,sizeof(buf));
				BIO_write(bio,buf,strlen(buf));
				BIO_write(bio,"\n",1);
				}
			}
		else
			{
			BIO_printf(bio,"---\nNo client certificate CA names sent\n");
			}
		p=SSL_get_shared_ciphers(s,buf,sizeof buf);
		if (p != NULL)
			{
			/* This works only for SSL 2.  In later protocol
			 * versions, the client does not know what other
			 * ciphers (in addition to the one to be used
			 * in the current connection) the server supports. */

			BIO_printf(bio,"---\nCiphers common between both SSL endpoints:\n");
			j=i=0;
			while (*p)
				{
				if (*p == ':')
					{
					BIO_write(bio,space,15-j%25);
					i++;
					j=0;
					BIO_write(bio,((i%3)?" ":"\n"),1);
					}
				else
					{
					BIO_write(bio,p,1);
					j++;
					}
				p++;
				}
			BIO_write(bio,"\n",1);
			}

		BIO_printf(bio,"---\nSSL handshake has read %ld bytes and written %ld bytes\n",
			BIO_number_read(SSL_get_rbio(s)),
			BIO_number_written(SSL_get_wbio(s)));
		}
	BIO_printf(bio,((s->hit)?"---\nReused, ":"---\nNew, "));
	c=SSL_get_current_cipher(s);
	BIO_printf(bio,"%s, Cipher is %s\n",
		SSL_CIPHER_get_version(c),
		SSL_CIPHER_get_name(c));
	if (peer != NULL) {
		EVP_PKEY *pktmp;
		pktmp = X509_get_pubkey(peer);
		BIO_printf(bio,"Server public key is %d bit\n",
							 EVP_PKEY_bits(pktmp));
		EVP_PKEY_free(pktmp);
	}
	SSL_SESSION_print(bio,SSL_get_session(s));
	BIO_printf(bio,"---\n");
	if (peer != NULL)
		X509_free(peer);
	/* flush, or debugging output gets mixed with http response */
	BIO_flush(bio);
	}

