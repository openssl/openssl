/* apps/s_server.c */
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
#include <sys/types.h>
#include <sys/stat.h>
#ifdef NO_STDIO
#define APPS_WIN16
#endif
#include "lhash.h"
#include "bn.h"
#define USE_SOCKETS
#include "apps.h"
#include "err.h"
#include "pem.h"
#include "x509.h"
#include "ssl.h"
#include "s_apps.h"

#ifndef NOPROTO
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int export);
static int sv_body(char *hostname, int s);
static int www_body(char *hostname, int s);
static void close_accept_socket(void );
static void sv_usage(void);
static int init_ssl_connection(SSL *s);
static void print_stats(BIO *bp,SSL_CTX *ctx);
#ifndef NO_DH
static DH *load_dh_param(void );
static DH *get_dh512(void);
#endif
/* static void s_server_init(void);*/
#else
static RSA MS_CALLBACK *tmp_rsa_cb();
static int sv_body();
static int www_body();
static void close_accept_socket();
static void sv_usage();
static int init_ssl_connection();
static void print_stats();
#ifndef NO_DH
static DH *load_dh_param();
static DH *get_dh512();
#endif
/* static void s_server_init(); */
#endif


#ifndef S_ISDIR
#define S_ISDIR(a)	(((a) & _S_IFMT) == _S_IFDIR)
#endif

#ifndef NO_DH
static unsigned char dh512_p[]={
	0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
	0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
	0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
	0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
	0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
	0x47,0x74,0xE8,0x33,
	};
static unsigned char dh512_g[]={
	0x02,
	};

static DH *get_dh512()
	{
	DH *dh=NULL;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		return(NULL);
	return(dh);
	}
#endif

/* static int load_CA(SSL_CTX *ctx, char *file);*/

#undef BUFSIZZ
#define BUFSIZZ	8*1024
static int accept_socket= -1;

#define TEST_CERT	"server.pem"
#undef PROG
#define PROG		s_server_main

#define DH_PARAM	"server.pem"

extern int verify_depth;

static char *cipher=NULL;
static int s_server_verify=SSL_VERIFY_NONE;
static char *s_cert_file=TEST_CERT,*s_key_file=NULL;
static char *s_dcert_file=NULL,*s_dkey_file=NULL;
#ifdef FIONBIO
static int s_nbio=0;
#endif
static int s_nbio_test=0;
static SSL_CTX *ctx=NULL;
static int www=0;

static BIO *bio_s_out=NULL;
static int s_debug=0;
static int s_quiet=0;

#if 0
static void s_server_init()
	{
	cipher=NULL;
	s_server_verify=SSL_VERIFY_NONE;
	s_dcert_file=NULL;
	s_dkey_file=NULL;
	s_cert_file=TEST_CERT;
	s_key_file=NULL;
#ifdef FIONBIO
	s_nbio=0;
#endif
	s_nbio_test=0;
	ctx=NULL;
	www=0;

	bio_s_out=NULL;
	s_debug=0;
	s_quiet=0;
	}
#endif

static void sv_usage()
	{
	BIO_printf(bio_err,"usage: s_server [args ...]\n");
	BIO_printf(bio_err,"\n");
	BIO_printf(bio_err," -accept arg   - port to accept on (default is %d\n",PORT);
	BIO_printf(bio_err," -verify arg   - turn on peer certificate verification\n");
	BIO_printf(bio_err," -Verify arg   - turn on peer certificate verification, must have a cert.\n");
	BIO_printf(bio_err," -cert arg     - certificate file to use, PEM format assumed\n");
	BIO_printf(bio_err,"                 (default is %s)\n",TEST_CERT);
	BIO_printf(bio_err," -key arg      - RSA file to use, PEM format assumed, in cert file if\n");
	BIO_printf(bio_err,"                 not specified (default is %s)\n",TEST_CERT);
#ifdef FIONBIO
	BIO_printf(bio_err," -nbio         - Run with non-blocking IO\n");
#endif
	BIO_printf(bio_err," -nbio_test    - test with the non-blocking test bio\n");
	BIO_printf(bio_err," -debug        - Print more output\n");
	BIO_printf(bio_err," -state        - Print the SSL states\n");
	BIO_printf(bio_err," -CApath arg   - PEM format directory of CA's\n");
	BIO_printf(bio_err," -CAfile arg   - PEM format file of CA's\n");
	BIO_printf(bio_err," -nocert       - Don't use any certificates (Anon-DH)\n");
	BIO_printf(bio_err," -cipher arg   - play with 'ssleay ciphers' to see what goes here\n");
	BIO_printf(bio_err," -quiet        - No server output\n");
	BIO_printf(bio_err," -no_tmp_rsa   - Do not generate a tmp RSA key\n");
	BIO_printf(bio_err," -ssl2         - Just talk SSLv2\n");
	BIO_printf(bio_err," -ssl3         - Just talk SSLv3\n");
	BIO_printf(bio_err," -tls1         - Just talk TLSv1\n");
	BIO_printf(bio_err," -no_ssl2      - Just disable SSLv2\n");
	BIO_printf(bio_err," -no_ssl3      - Just disable SSLv3\n");
	BIO_printf(bio_err," -no_tls1      - Just disable TLSv1\n");
	BIO_printf(bio_err," -bugs         - Turn on SSL bug compatability\n");
	BIO_printf(bio_err," -www          - Respond to a 'GET /' with a status page\n");
	BIO_printf(bio_err," -WWW          - Returns requested page from to a 'GET <path> HTTP/1.0'\n");
	}

static int local_argc=0;
static char **local_argv;
static int hack=0;

int MAIN(argc, argv)
int argc;
char *argv[];
	{
	short port=PORT;
	char *CApath=NULL,*CAfile=NULL;
	int badop=0,bugs=0;
	int ret=1;
	int off=0;
	int no_tmp_rsa=0,nocert=0;
	int state=0;
	SSL_METHOD *meth=NULL;
#ifndef NO_DH
	DH *dh=NULL;
#endif

#if !defined(NO_SSL2) && !defined(NO_SSL3)
	meth=SSLv23_server_method();
#elif !defined(NO_SSL3)
	meth=SSLv3_server_method();
#elif !defined(NO_SSL2)
	meth=SSLv2_server_method();
#endif

	local_argc=argc;
	local_argv=argv;

	apps_startup();
	s_quiet=0;
	s_debug=0;

	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);

	verify_depth=0;
#ifdef FIONBIO
	s_nbio=0;
#endif
	s_nbio_test=0;

	argc--;
	argv++;

	while (argc >= 1)
		{
		if	((strcmp(*argv,"-port") == 0) ||
			 (strcmp(*argv,"-accept") == 0))
			{
			if (--argc < 1) goto bad;
			if (!extract_port(*(++argv),&port))
				goto bad;
			}
		else if	(strcmp(*argv,"-verify") == 0)
			{
			s_server_verify=SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE;
			if (--argc < 1) goto bad;
			verify_depth=atoi(*(++argv));
			BIO_printf(bio_err,"verify depth is %d\n",verify_depth);
			}
		else if	(strcmp(*argv,"-Verify") == 0)
			{
			s_server_verify=SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
				SSL_VERIFY_CLIENT_ONCE;
			if (--argc < 1) goto bad;
			verify_depth=atoi(*(++argv));
			BIO_printf(bio_err,"verify depth is %d, must return a certificate\n",verify_depth);
			}
		else if	(strcmp(*argv,"-cert") == 0)
			{
			if (--argc < 1) goto bad;
			s_cert_file= *(++argv);
			}
		else if	(strcmp(*argv,"-key") == 0)
			{
			if (--argc < 1) goto bad;
			s_key_file= *(++argv);
			}
		else if	(strcmp(*argv,"-dcert") == 0)
			{
			if (--argc < 1) goto bad;
			s_dcert_file= *(++argv);
			}
		else if	(strcmp(*argv,"-dkey") == 0)
			{
			if (--argc < 1) goto bad;
			s_dkey_file= *(++argv);
			}
		else if (strcmp(*argv,"-nocert") == 0)
			{
			nocert=1;
			}
		else if	(strcmp(*argv,"-CApath") == 0)
			{
			if (--argc < 1) goto bad;
			CApath= *(++argv);
			}
		else if	(strcmp(*argv,"-cipher") == 0)
			{
			if (--argc < 1) goto bad;
			cipher= *(++argv);
			}
		else if	(strcmp(*argv,"-CAfile") == 0)
			{
			if (--argc < 1) goto bad;
			CAfile= *(++argv);
			}
#ifdef FIONBIO	
		else if	(strcmp(*argv,"-nbio") == 0)
			{ s_nbio=1; }
#endif
		else if	(strcmp(*argv,"-nbio_test") == 0)
			{
#ifdef FIONBIO	
			s_nbio=1;
#endif
			s_nbio_test=1;
			}
		else if	(strcmp(*argv,"-debug") == 0)
			{ s_debug=1; }
		else if	(strcmp(*argv,"-hack") == 0)
			{ hack=1; }
		else if	(strcmp(*argv,"-state") == 0)
			{ state=1; }
		else if	(strcmp(*argv,"-quiet") == 0)
			{ s_quiet=1; }
		else if	(strcmp(*argv,"-bugs") == 0)
			{ bugs=1; }
		else if	(strcmp(*argv,"-no_tmp_rsa") == 0)
			{ no_tmp_rsa=1; }
		else if	(strcmp(*argv,"-www") == 0)
			{ www=1; }
		else if	(strcmp(*argv,"-WWW") == 0)
			{ www=2; }
		else if	(strcmp(*argv,"-no_ssl2") == 0)
			{ off|=SSL_OP_NO_SSLv2; }
		else if	(strcmp(*argv,"-no_ssl3") == 0)
			{ off|=SSL_OP_NO_SSLv3; }
		else if	(strcmp(*argv,"-no_tls1") == 0)
			{ off|=SSL_OP_NO_TLSv1; }
#ifndef NO_SSL2
		else if	(strcmp(*argv,"-ssl2") == 0)
			{ meth=SSLv2_server_method(); }
#endif
#ifndef NO_SSL3
		else if	(strcmp(*argv,"-ssl3") == 0)
			{ meth=SSLv3_server_method(); }
#endif
#ifndef NO_TLS1
		else if	(strcmp(*argv,"-tls1") == 0)
			{ meth=TLSv1_server_method(); }
#endif
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
		sv_usage();
		goto end;
		}

	if (bio_s_out == NULL)
		{
		if (s_quiet && !s_debug)
			{
			bio_s_out=BIO_new(BIO_s_null());
			}
		else
			{
			if (bio_s_out == NULL)
				bio_s_out=BIO_new_fp(stdout,BIO_NOCLOSE);
			}
		}

#if !defined(NO_RSA) || !defined(NO_DSA)
	if (nocert)
#endif
		{
		s_cert_file=NULL;
		s_key_file=NULL;
		s_dcert_file=NULL;
		s_dkey_file=NULL;
		}

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	ctx=SSL_CTX_new(meth);
	if (ctx == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	SSL_CTX_set_quiet_shutdown(ctx,1);
	if (bugs) SSL_CTX_set_options(ctx,SSL_OP_ALL);
	if (hack) SSL_CTX_set_options(ctx,SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG);
	SSL_CTX_set_options(ctx,off);
	if (hack) SSL_CTX_set_options(ctx,SSL_OP_NON_EXPORT_FIRST);

	if (state) SSL_CTX_set_info_callback(ctx,apps_ssl_info_callback);

	SSL_CTX_sess_set_cache_size(ctx,128);

#if 0
	if (cipher == NULL) cipher=getenv("SSL_CIPHER");
#endif

#if 0
	if (s_cert_file == NULL)
		{
		BIO_printf(bio_err,"You must specify a certificate file for the server to use\n");
		goto end;
		}
#endif

	if ((!SSL_CTX_load_verify_locations(ctx,CAfile,CApath)) ||
		(!SSL_CTX_set_default_verify_paths(ctx)))
		{
		/* BIO_printf(bio_err,"X509_load_verify_locations\n"); */
		ERR_print_errors(bio_err);
		/* goto end; */
		}

#ifndef NO_DH
	/* EAY EAY EAY evil hack */
	dh=load_dh_param();
	if (dh != NULL)
		{
		BIO_printf(bio_s_out,"Setting temp DH parameters\n");
		}
	else
		{
		BIO_printf(bio_s_out,"Using default temp DH parameters\n");
		dh=get_dh512();
		}
	BIO_flush(bio_s_out);

	SSL_CTX_set_tmp_dh(ctx,dh);
	DH_free(dh);
#endif
	
	if (!set_cert_stuff(ctx,s_cert_file,s_key_file))
		goto end;
	if (s_dcert_file != NULL)
		{
		if (!set_cert_stuff(ctx,s_dcert_file,s_dkey_file))
			goto end;
		}

#if 1
	SSL_CTX_set_tmp_rsa_callback(ctx,tmp_rsa_cb);
#else
	if (!no_tmp_rsa && SSL_CTX_need_tmp_RSA(ctx))
		{
		RSA *rsa;

		BIO_printf(bio_s_out,"Generating temp (512 bit) RSA key...");
		BIO_flush(bio_s_out);

		rsa=RSA_generate_key(512,RSA_F4,NULL);

		if (!SSL_CTX_set_tmp_rsa(ctx,rsa))
			{
			ERR_print_errors(bio_err);
			goto end;
			}
		RSA_free(rsa);
		BIO_printf(bio_s_out,"\n");
		}
#endif

	if (cipher != NULL)
		SSL_CTX_set_cipher_list(ctx,cipher);
	SSL_CTX_set_verify(ctx,s_server_verify,verify_callback);

	SSL_CTX_set_client_CA_list(ctx,SSL_load_client_CA_file(s_cert_file));

	BIO_printf(bio_s_out,"ACCEPT\n");
	if (www)
		do_server(port,&accept_socket,www_body);
	else
		do_server(port,&accept_socket,sv_body);
	print_stats(bio_s_out,ctx);
	ret=0;
end:
	if (ctx != NULL) SSL_CTX_free(ctx);
	if (bio_s_out != NULL)
		{
		BIO_free(bio_s_out);
		bio_s_out=NULL;
		}
	EXIT(ret);
	}

static void print_stats(bio,ssl_ctx)
BIO *bio;
SSL_CTX *ssl_ctx;
	{
	BIO_printf(bio,"%4ld items in the session cache\n",
		SSL_CTX_sess_number(ssl_ctx));
	BIO_printf(bio,"%4d client connects (SSL_connect())\n",
		SSL_CTX_sess_connect(ssl_ctx));
	BIO_printf(bio,"%4d client renegotiates (SSL_connect())\n",
		SSL_CTX_sess_connect_renegotiate(ssl_ctx));
	BIO_printf(bio,"%4d client connects that finished\n",
		SSL_CTX_sess_connect_good(ssl_ctx));
	BIO_printf(bio,"%4d server accepts (SSL_accept())\n",
		SSL_CTX_sess_accept(ssl_ctx));
	BIO_printf(bio,"%4d server renegotiates (SSL_accept())\n",
		SSL_CTX_sess_accept_renegotiate(ssl_ctx));
	BIO_printf(bio,"%4d server accepts that finished\n",
		SSL_CTX_sess_accept_good(ssl_ctx));
	BIO_printf(bio,"%4d session cache hits\n",SSL_CTX_sess_hits(ssl_ctx));
	BIO_printf(bio,"%4d session cache misses\n",SSL_CTX_sess_misses(ssl_ctx));
	BIO_printf(bio,"%4d session cache timeouts\n",SSL_CTX_sess_timeouts(ssl_ctx));
	BIO_printf(bio,"%4d callback cache hits\n",SSL_CTX_sess_cb_hits(ssl_ctx));
	BIO_printf(bio,"%4d cache full overflows (%d allowed)\n",
		SSL_CTX_sess_cache_full(ssl_ctx),
		SSL_CTX_sess_get_cache_size(ssl_ctx));
	}

static int sv_body(hostname, s)
char *hostname;
int s;
	{
	char *buf=NULL;
	fd_set readfds;
	int ret=1,width;
	int k,i;
	unsigned long l;
	SSL *con=NULL;
	BIO *sbio;

	if ((buf=Malloc(BUFSIZZ)) == NULL)
		{
		BIO_printf(bio_err,"out of memory\n");
		goto err;
		}
#ifdef FIONBIO	
	if (s_nbio)
		{
		unsigned long sl=1;

		if (!s_quiet)
			BIO_printf(bio_err,"turning on non blocking io\n");
		if (BIO_socket_ioctl(s,FIONBIO,&sl) < 0)
			ERR_print_errors(bio_err);
		}
#endif

	if (con == NULL)
		con=(SSL *)SSL_new(ctx);
	SSL_clear(con);

	sbio=BIO_new_socket(s,BIO_NOCLOSE);
	if (s_nbio_test)
		{
		BIO *test;

		test=BIO_new(BIO_f_nbio_test());
		sbio=BIO_push(test,sbio);
		}
	SSL_set_bio(con,sbio,sbio);
	SSL_set_accept_state(con);
	/* SSL_set_fd(con,s); */

	if (s_debug)
		{
		con->debug=1;
		BIO_set_callback(SSL_get_rbio(con),bio_dump_cb);
		BIO_set_callback_arg(SSL_get_rbio(con),bio_s_out);
		}

	width=s+1;
	for (;;)
		{
		FD_ZERO(&readfds);
#ifndef WINDOWS
		FD_SET(fileno(stdin),&readfds);
#endif
		FD_SET(s,&readfds);
		i=select(width,&readfds,NULL,NULL,NULL);
		if (i <= 0) continue;
		if (FD_ISSET(fileno(stdin),&readfds))
			{
			i=read(fileno(stdin),buf,128/*BUFSIZZ*/);
			if (!s_quiet)
				{
				if ((i <= 0) || (buf[0] == 'Q'))
					{
					BIO_printf(bio_s_out,"DONE\n");
					SHUTDOWN(s);
					close_accept_socket();
					ret= -11;
					goto err;
					}
				if ((i <= 0) || (buf[0] == 'q'))
					{
					BIO_printf(bio_s_out,"DONE\n");
					SHUTDOWN(s);
	/*				close_accept_socket();
					ret= -11;*/
					goto err;
					}
				if ((buf[0] == 'r') && 
					((buf[1] == '\n') || (buf[1] == '\r')))
					{
					SSL_renegotiate(con);
					i=SSL_do_handshake(con);
					printf("SSL_do_handshake -> %d\n",i);
					i=0; /*13; */
					continue;
					strcpy(buf,"server side RE-NEGOTIATE\n");
					}
				if ((buf[0] == 'R') &&
					((buf[1] == '\0') || (buf[1] == '\r')))
					{
					SSL_set_verify(con,
						SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE,NULL);
					SSL_renegotiate(con);
					i=SSL_do_handshake(con);
					printf("SSL_do_handshake -> %d\n",i);
					i=0; /* 13; */
					continue;
					strcpy(buf,"server side RE-NEGOTIATE asking for client cert\n");
					}
				if (buf[0] == 'P')
					{
					static char *str="Lets print some clear text\n";
					BIO_write(SSL_get_wbio(con),str,strlen(str));
					}
				if (buf[0] == 'S')
					{
					print_stats(bio_s_out,SSL_get_SSL_CTX(con));
					}
				}
			l=k=0;
			for (;;)
				{
				/* should do a select for the write */
#ifdef RENEG
{ static count=0; if (++count == 100) { count=0; SSL_renegotiate(con); } }
#endif
				k=SSL_write(con,&(buf[l]),(unsigned int)i);
				switch (SSL_get_error(con,k))
					{
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_X509_LOOKUP:
					BIO_printf(bio_s_out,"Write BLOCK\n");
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
					BIO_printf(bio_s_out,"ERROR\n");
					ERR_print_errors(bio_err);
					ret=1;
					goto err;
					break;
				case SSL_ERROR_ZERO_RETURN:
					BIO_printf(bio_s_out,"DONE\n");
					ret=1;
					goto err;
					}
				l+=k;
				i-=k;
				if (i <= 0) break;
				}
			}
		if (FD_ISSET(s,&readfds))
			{
			if (!SSL_is_init_finished(con))
				{
				i=init_ssl_connection(con);
				
				if (i < 0)
					{
					ret=0;
					goto err;
					}
				else if (i == 0)
					{
					ret=1;
					goto err;
					}
				}
			else
				{
				i=SSL_read(con,(char *)buf,128 /*BUFSIZZ */);
				switch (SSL_get_error(con,i))
					{
				case SSL_ERROR_NONE:
					write(fileno(stdout),buf,
						(unsigned int)i);
					break;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_X509_LOOKUP:
					BIO_printf(bio_s_out,"Read BLOCK\n");
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
					BIO_printf(bio_s_out,"ERROR\n");
					ERR_print_errors(bio_err);
					ret=1;
					goto err;
				case SSL_ERROR_ZERO_RETURN:
					BIO_printf(bio_s_out,"DONE\n");
					ret=1;
					goto err;
					}
				}
			}
		}
err:
	BIO_printf(bio_s_out,"shutting down SSL\n");
#if 1
	SSL_set_shutdown(con,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
	SSL_shutdown(con);
#endif
	if (con != NULL) SSL_free(con);
	BIO_printf(bio_s_out,"CONNECTION CLOSED\n");
	if (buf != NULL)
		{
		memset(buf,0,BUFSIZZ);
		Free(buf);
		}
	if (ret >= 0)
		BIO_printf(bio_s_out,"ACCEPT\n");
	return(ret);
	}

static void close_accept_socket()
	{
	BIO_printf(bio_err,"shutdown accept socket\n");
	if (accept_socket >= 0)
		{
		SHUTDOWN2(accept_socket);
		}
	}

static int init_ssl_connection(con)
SSL *con;
	{
	int i;
	char *str;
	X509 *peer;
	long verify_error;
	MS_STATIC char buf[BUFSIZ];

	if ((i=SSL_accept(con)) <= 0)
		{
		if (BIO_sock_should_retry(i))
			{
			BIO_printf(bio_s_out,"DELAY\n");
			return(1);
			}

		BIO_printf(bio_err,"ERROR\n");
		verify_error=SSL_get_verify_result(con);
		if (verify_error != X509_V_OK)
			{
			BIO_printf(bio_err,"verify error:%s\n",
				X509_verify_cert_error_string(verify_error));
			}
		else
			ERR_print_errors(bio_err);
		return(0);
		}

	PEM_write_bio_SSL_SESSION(bio_s_out,SSL_get_session(con));

	peer=SSL_get_peer_certificate(con);
	if (peer != NULL)
		{
		BIO_printf(bio_s_out,"Client certificate\n");
		PEM_write_bio_X509(bio_s_out,peer);
		X509_NAME_oneline(X509_get_subject_name(peer),buf,BUFSIZ);
		BIO_printf(bio_s_out,"subject=%s\n",buf);
		X509_NAME_oneline(X509_get_issuer_name(peer),buf,BUFSIZ);
		BIO_printf(bio_s_out,"issuer=%s\n",buf);
		X509_free(peer);
		}

	if (SSL_get_shared_ciphers(con,buf,BUFSIZ) != NULL)
		BIO_printf(bio_s_out,"Shared ciphers:%s\n",buf);
	str=SSL_CIPHER_get_name(SSL_get_current_cipher(con));
	BIO_printf(bio_s_out,"CIPHER is %s\n",(str != NULL)?str:"(NONE)");
	if (con->hit) BIO_printf(bio_s_out,"Reused session-id\n");
	return(1);
	}

#ifndef NO_DH
static DH *load_dh_param()
	{
	DH *ret=NULL;
	BIO *bio;

	if ((bio=BIO_new_file(DH_PARAM,"r")) == NULL)
		goto err;
	ret=PEM_read_bio_DHparams(bio,NULL,NULL);
err:
	if (bio != NULL) BIO_free(bio);
	return(ret);
	}
#endif

#if 0
static int load_CA(ctx,file)
SSL_CTX *ctx;
char *file;
	{
	FILE *in;
	X509 *x=NULL;

	if ((in=fopen(file,"r")) == NULL)
		return(0);

	for (;;)
		{
		if (PEM_read_X509(in,&x,NULL) == NULL)
			break;
		SSL_CTX_add_client_CA(ctx,x);
		}
	if (x != NULL) X509_free(x);
	fclose(in);
	return(1);
	}
#endif

static int www_body(hostname, s)
char *hostname;
int s;
	{
	char buf[1024];
	int ret=1;
	int i,j,k,blank,dot;
	struct stat st_buf;
	SSL *con;
	SSL_CIPHER *c;
	BIO *io,*ssl_bio,*sbio;
	long total_bytes;

	io=BIO_new(BIO_f_buffer());
	ssl_bio=BIO_new(BIO_f_ssl());
	if ((io == NULL) || (ssl_bio == NULL)) goto err;

#ifdef FIONBIO	
	if (s_nbio)
		{
		unsigned long sl=1;

		if (!s_quiet)
			BIO_printf(bio_err,"turning on non blocking io\n");
		if (BIO_socket_ioctl(s,FIONBIO,&sl) < 0)
			ERR_print_errors(bio_err);
		}
#endif

	/* lets make the output buffer a reasonable size */
	if (!BIO_set_write_buffer_size(io,253 /*16*1024*/)) goto err;

	if ((con=(SSL *)SSL_new(ctx)) == NULL) goto err;

	sbio=BIO_new_socket(s,BIO_NOCLOSE);
	if (s_nbio_test)
		{
		BIO *test;

		test=BIO_new(BIO_f_nbio_test());
		sbio=BIO_push(test,sbio);
		}
	SSL_set_bio(con,sbio,sbio);
	SSL_set_accept_state(con);

	/* SSL_set_fd(con,s); */
	BIO_set_ssl(ssl_bio,con,BIO_CLOSE);
	BIO_push(io,ssl_bio);

	if (s_debug)
		{
		con->debug=1;
		BIO_set_callback(SSL_get_rbio(con),bio_dump_cb);
		BIO_set_callback_arg(SSL_get_rbio(con),bio_s_out);
		}

	blank=0;
	for (;;)
		{
		if (hack)
			{
			i=SSL_accept(con);

			switch (SSL_get_error(con,i))
				{
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_X509_LOOKUP:
				continue;
			case SSL_ERROR_SYSCALL:
			case SSL_ERROR_SSL:
			case SSL_ERROR_ZERO_RETURN:
				ret=1;
				goto err;
				break;
				}

			SSL_renegotiate(con);
			SSL_write(con,NULL,0);
			}

		i=BIO_gets(io,buf,sizeof(buf)-1);
		if (i < 0) /* error */
			{
			if (!BIO_should_retry(io))
				{
				if (!s_quiet)
					ERR_print_errors(bio_err);
				goto err;
				}
			else
				{
				BIO_printf(bio_s_out,"read R BLOCK\n");
#ifndef MSDOS
				sleep(1);
#endif
				continue;
				}
			}
		else if (i == 0) /* end of input */
			{
			ret=1;
			goto end;
			}

		/* else we have data */
		if (	((www == 1) && (strncmp("GET ",buf,4) == 0)) ||
			((www == 2) && (strncmp("GET /stats ",buf,10) == 0)))
			{
			char *p;
			X509 *peer;
			STACK *sk;
			static char *space="                          ";

			BIO_puts(io,"HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
			BIO_puts(io,"<HTML><BODY BGCOLOR=ffffff>\n");
			BIO_puts(io,"<pre>\n");
/*			BIO_puts(io,SSLeay_version(SSLEAY_VERSION));*/
			BIO_puts(io,"\n");
			for (i=0; i<local_argc; i++)
				{
				BIO_puts(io,local_argv[i]);
				BIO_write(io," ",1);
				}
			BIO_puts(io,"\n");

			/* The following is evil and should not really
			 * be done */
			BIO_printf(io,"Ciphers supported in s_server binary\n");
			sk=SSL_get_ciphers(con);
			j=sk_num(sk);
			for (i=0; i<j; i++)
				{
				c=(SSL_CIPHER *)sk_value(sk,i);
				BIO_printf(io,"%-11s:%-25s",
					SSL_CIPHER_get_version(c),
					SSL_CIPHER_get_name(c));
				if ((((i+1)%2) == 0) && (i+1 != j))
					BIO_puts(io,"\n");
				}
			BIO_puts(io,"\n");
			p=SSL_get_shared_ciphers(con,buf,sizeof(buf));
			if (p != NULL)
				{
				BIO_printf(io,"---\nCiphers common between both SSL end points:\n");
				j=i=0;
				while (*p)
					{
					if (*p == ':')
						{
						BIO_write(io,space,26-j);
						i++;
						j=0;
						BIO_write(io,((i%3)?" ":"\n"),1);
						}
					else
						{
						BIO_write(io,p,1);
						j++;
						}
					p++;
					}
				BIO_puts(io,"\n");
				}
			BIO_printf(io,((con->hit)
				?"---\nReused, "
				:"---\nNew, "));
			c=SSL_get_current_cipher(con);
			BIO_printf(io,"%s, Cipher is %s\n",
				SSL_CIPHER_get_version(c),
				SSL_CIPHER_get_name(c));
			SSL_SESSION_print(io,SSL_get_session(con));
			BIO_printf(io,"---\n");
			print_stats(io,SSL_get_SSL_CTX(con));
			BIO_printf(io,"---\n");
			peer=SSL_get_peer_certificate(con);
			if (peer != NULL)
				{
				BIO_printf(io,"Client certificate\n");
				X509_print(io,peer);
				PEM_write_bio_X509(io,peer);
				}
			else
				BIO_puts(io,"no client certificate available\n");
			BIO_puts(io,"</BODY></HTML>\r\n\r\n");
			break;
			}
		else if ((www == 2) && (strncmp("GET ",buf,4) == 0))
			{
			BIO *file;
			char *p,*e;
			static char *text="HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n";

			/* skip the '/' */
			p= &(buf[5]);
			dot=0;
			for (e=p; *e != '\0'; e++)
				{
				if (e[0] == ' ') break;
				if (	(e[0] == '.') &&
					(strncmp(&(e[-1]),"/../",4) == 0))
					dot=1;
				}
			

			if (*e == '\0')
				{
				BIO_puts(io,text);
				BIO_printf(io,"'%s' is an invalid file name\r\n",p);
				break;
				}
			*e='\0';

			if (dot)
				{
				BIO_puts(io,text);
				BIO_printf(io,"'%s' contains '..' reference\r\n",p);
				break;
				}

			if (*p == '/')
				{
				BIO_puts(io,text);
				BIO_printf(io,"'%s' is an invalid path\r\n",p);
				break;
				}

			/* append if a directory lookup */
			if (e[-1] == '/')
				strcat(p,"index.html");

			/* if a directory, do the index thang */
			if (stat(p,&st_buf) < 0)
				{
				BIO_puts(io,text);
				BIO_printf(io,"Error accessing '%s'\r\n",p);
				ERR_print_errors(io);
				break;
				}
			if (S_ISDIR(st_buf.st_mode))
				{
				strcat(p,"/index.html");
				}

			if ((file=BIO_new_file(p,"r")) == NULL)
				{
				BIO_puts(io,text);
				BIO_printf(io,"Error opening '%s'\r\n",p);
				ERR_print_errors(io);
				break;
				}

			if (!s_quiet)
				BIO_printf(bio_err,"FILE:%s\n",p);

			i=strlen(p);
			if (	((i > 5) && (strcmp(&(p[i-5]),".html") == 0)) ||
				((i > 4) && (strcmp(&(p[i-4]),".php") == 0)) ||
				((i > 4) && (strcmp(&(p[i-4]),".htm") == 0)))
				BIO_puts(io,"HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
			else
				BIO_puts(io,"HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n");
			/* send the file */
			total_bytes=0;
			for (;;)
				{
				i=BIO_read(file,buf,1024);
				if (i <= 0) break;

				total_bytes+=i;
				fprintf(stderr,"%d\n",i);
				if (total_bytes > 3*1024)
					{
					total_bytes=0;
					fprintf(stderr,"RENEGOTIATE\n");
					SSL_renegotiate(con);
					}

				for (j=0; j<i; )
					{
#ifdef RENEG
{ static count=0; if (++count == 13) { SSL_renegotiate(con); } }
#endif
					k=BIO_write(io,&(buf[j]),i-j);
					if (k <= 0)
						{
						if (!BIO_should_retry(io))
							goto write_error;
						else
							{
							BIO_printf(bio_s_out,"rwrite W BLOCK\n");
							}
						}
					else
						{
						j+=k;
						}
					}
				}
write_error:
			BIO_free(file);
			break;
			}
		}

	for (;;)
		{
		i=(int)BIO_flush(io);
		if (i <= 0)
			{
			if (!BIO_should_retry(io))
				break;
			}
		else
			break;
		}
end:
#if 1
	/* make sure we re-use sessions */
	SSL_set_shutdown(con,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
	/* This kills performace */
/*	SSL_shutdown(con); A shutdown gets sent in the
 *	BIO_free_all(io) procession */
#endif

err:

	if (ret >= 0)
		BIO_printf(bio_s_out,"ACCEPT\n");

	if (io != NULL) BIO_free_all(io);
/*	if (ssl_bio != NULL) BIO_free(ssl_bio);*/
	return(ret);
	}

static RSA MS_CALLBACK *tmp_rsa_cb(s,export)
SSL *s;
int export;
	{
	static RSA *rsa_tmp=NULL;

	if (rsa_tmp == NULL)
		{
		if (!s_quiet)
			{
			BIO_printf(bio_err,"Generating temp (512 bit) RSA key...");
			BIO_flush(bio_err);
			}
#ifndef NO_RSA
		rsa_tmp=RSA_generate_key(512,RSA_F4,NULL,NULL);
#endif
		if (!s_quiet)
			{
			BIO_printf(bio_err,"\n");
			BIO_flush(bio_err);
			}
		}
	return(rsa_tmp);
	}
