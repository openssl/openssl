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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define USE_SOCKETS
#ifdef NO_STDIO
#define APPS_WIN16
#endif
#include "apps.h"
#include "x509.h"
#include "ssl.h"
#include "err.h"
#include "pem.h"
#include "s_apps.h"

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

#ifndef NOPROTO
static void sc_usage(void);
static void print_stuff(BIO *berr,SSL *con,int full);
#else
static void sc_usage();
static void print_stuff();
#endif

static BIO *bio_c_out=NULL;
static int c_quiet=0;

static void sc_usage()
	{
	BIO_printf(bio_err,"usage: client args\n");
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
	BIO_printf(bio_err," -debug        - extra output\n");
	BIO_printf(bio_err," -nbio_test    - more ssl protocol testing\n");
	BIO_printf(bio_err," -state        - print the 'ssl' states\n");
#ifdef FIONBIO
	BIO_printf(bio_err," -nbio         - Run with non-blocking IO\n");
#endif
	BIO_printf(bio_err," -quiet        - no s_client output\n");
	BIO_printf(bio_err," -ssl2         - just use SSLv2\n");
	BIO_printf(bio_err," -ssl3         - just use SSLv3\n");
	BIO_printf(bio_err," -tls1         - just use TLSv1\n");
	BIO_printf(bio_err," -no_tls1/-no_ssl3/-no_ssl2 - turn off that protocol\n");
	BIO_printf(bio_err," -bugs         - Switch on all SSL implementation bug workarounds\n");
	BIO_printf(bio_err," -cipher       - prefered cipher to use, use the 'ssleay ciphers'\n");
	BIO_printf(bio_err,"                 command to se what is available\n");

	}

int MAIN(argc, argv)
int argc;
char **argv;
	{
	int off=0;
	SSL *con=NULL,*con2=NULL;
	int s,k,width,state=0;
	char *cbuf=NULL,*sbuf=NULL;
	int cbuf_len,cbuf_off;
	int sbuf_len,sbuf_off;
	fd_set readfds,writefds;
	short port=PORT;
	int full_log=1;
	char *host=SSL_HOST_NAME;
	char *cert_file=NULL,*key_file=NULL;
	char *CApath=NULL,*CAfile=NULL,*cipher=NULL;
	int reconnect=0,badop=0,verify=SSL_VERIFY_NONE,bugs=0;
	int write_tty,read_tty,write_ssl,read_ssl,tty_on;
	SSL_CTX *ctx=NULL;
	int ret=1,in_init=1,i,nbio_test=0;
	SSL_METHOD *meth=NULL;
	BIO *sbio;
	/*static struct timeval timeout={10,0};*/

#if !defined(NO_SSL2) && !defined(NO_SSL3)
	meth=SSLv23_client_method();
#elif !defined(NO_SSL3)
	meth=SSLv3_client_method();
#elif !defined(NO_SSL2)
	meth=SSLv2_client_method();
#endif

	apps_startup();
	c_Pause=0;
	c_quiet=0;
	c_debug=0;

	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);

	if (	((cbuf=Malloc(BUFSIZZ)) == NULL) ||
		((sbuf=Malloc(BUFSIZZ)) == NULL))
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
		else if	(strcmp(*argv,"-quiet") == 0)
			c_quiet=1;
		else if	(strcmp(*argv,"-pause") == 0)
			c_Pause=1;
		else if	(strcmp(*argv,"-debug") == 0)
			c_debug=1;
		else if	(strcmp(*argv,"-nbio_test") == 0)
			nbio_test=1;
		else if	(strcmp(*argv,"-state") == 0)
			state=1;
#ifndef NO_SSL2
		else if	(strcmp(*argv,"-ssl2") == 0)
			meth=SSLv2_client_method();
#endif
#ifndef NO_SSL3
		else if	(strcmp(*argv,"-ssl3") == 0)
			meth=SSLv3_client_method();
#endif
#ifndef NO_TLS1
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
		else if	(strcmp(*argv,"-cipher") == 0)
			{
			if (--argc < 1) goto bad;
			cipher= *(++argv);
			}
#ifdef FIONBIO
		else if (strcmp(*argv,"-nbio") == 0)
			{ c_nbio=1; }
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
		sc_usage();
		goto end;
		}

	if (bio_c_out == NULL)
		{
		if (c_quiet)
			{
			bio_c_out=BIO_new(BIO_s_null());
			}
		else
			{
			if (bio_c_out == NULL)
				bio_c_out=BIO_new_fp(stdout,BIO_NOCLOSE);
			}
		}

	SSLeay_add_ssl_algorithms();
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
		SSL_CTX_set_cipher_list(ctx,cipher);
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
		/* BIO_printf(bio_err,"error seting default verify locations\n"); */
		ERR_print_errors(bio_err);
		/* goto end; */
		}

	SSL_load_error_strings();

	con=(SSL *)SSL_new(ctx);
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

#ifndef WINDOWS
		if (tty_on)
			{
			if (read_tty)  FD_SET(fileno(stdin),&readfds);
			if (write_tty) FD_SET(fileno(stdout),&writefds);
			}
#endif
		if (read_ssl)
			FD_SET(SSL_get_fd(con),&readfds);
		if (write_ssl)
			FD_SET(SSL_get_fd(con),&writefds);

/*		printf("mode tty(%d %d%d) ssl(%d%d)\n",
			tty_on,read_tty,write_tty,read_ssl,write_ssl);*/

		i=select(width,&readfds,&writefds,NULL,NULL);
		if ( i < 0)
			{
			BIO_printf(bio_err,"bad select %d\n",
				get_last_socket_error());
			goto shut;
			/* goto end; */
			}

		if (FD_ISSET(SSL_get_fd(con),&writefds))
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
#ifndef WINDOWS
		else if (FD_ISSET(fileno(stdout),&writefds))
			{
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
#endif
		else if (FD_ISSET(SSL_get_fd(con),&readfds))
			{
#ifdef RENEG
{ static int iiii; if (++iiii == 52) { SSL_renegotiate(con); iiii=0; } }
#endif
			k=SSL_read(con,sbuf,1024 /* BUFSIZZ */ );

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
				break;
				}
			}

#ifndef WINDOWS
		else if (FD_ISSET(fileno(stdin),&readfds))
			{
			i=read(fileno(stdin),cbuf,BUFSIZZ);

			if ((!c_quiet) && ((i <= 0) || (cbuf[0] == 'Q')))
				{
				BIO_printf(bio_err,"DONE\n");
				goto shut;
				}

			if ((!c_quiet) && (cbuf[0] == 'R'))
				{
				SSL_renegotiate(con);
				read_tty=0;
				write_ssl=1;
				}
			else
				{
				cbuf_len=i;
				cbuf_off=0;
				}

			read_tty=0;
			write_ssl=1;
			}
#endif
		}
shut:
	SSL_shutdown(con);
	SHUTDOWN(SSL_get_fd(con));
	ret=0;
end:
	if (con != NULL) SSL_free(con);
	if (con2 != NULL) SSL_free(con2);
	if (ctx != NULL) SSL_CTX_free(ctx);
	if (cbuf != NULL) { memset(cbuf,0,BUFSIZZ); Free(cbuf); }
	if (sbuf != NULL) { memset(sbuf,0,BUFSIZZ); Free(sbuf); }
	if (bio_c_out != NULL)
		{
		BIO_free(bio_c_out);
		bio_c_out=NULL;
		}
	EXIT(ret);
	}


static void print_stuff(bio,s,full)
BIO *bio;
SSL *s;
int full;
	{
	X509 *peer=NULL;
	char *p;
	static char *space="                ";
	char buf[BUFSIZ];
	STACK *sk;
	SSL_CIPHER *c;
	X509_NAME *xn;
	int j,i;

	if (full)
		{
		sk=SSL_get_peer_cert_chain(s);
		if (sk != NULL)
			{
			BIO_printf(bio,"---\nCertficate chain\n");
			for (i=0; i<sk_num(sk); i++)
				{
				X509_NAME_oneline(X509_get_subject_name((X509 *)
					sk_value(sk,i)),buf,BUFSIZ);
				BIO_printf(bio,"%2d s:%s\n",i,buf);
				X509_NAME_oneline(X509_get_issuer_name((X509 *)
					sk_value(sk,i)),buf,BUFSIZ);
				BIO_printf(bio,"   i:%s\n",buf);
				}
			}

		BIO_printf(bio,"---\n");
		peer=SSL_get_peer_certificate(s);
		if (peer != NULL)
			{
			BIO_printf(bio,"Server certificate\n");
			PEM_write_bio_X509(bio,peer);
			X509_NAME_oneline(X509_get_subject_name(peer),
				buf,BUFSIZ);
			BIO_printf(bio,"subject=%s\n",buf);
			X509_NAME_oneline(X509_get_issuer_name(peer),
				buf,BUFSIZ);
			BIO_printf(bio,"issuer=%s\n",buf);
			}
		else
			BIO_printf(bio,"no peer certificate available\n");

		sk=SSL_get_client_CA_list(s);
		if ((sk != NULL) && (sk_num(sk) > 0))
			{
			BIO_printf(bio,"---\nAcceptable client certificate CA names\n");
			for (i=0; i<sk_num(sk); i++)
				{
				xn=(X509_NAME *)sk_value(sk,i);
				X509_NAME_oneline(xn,buf,sizeof(buf));
				BIO_write(bio,buf,strlen(buf));
				BIO_write(bio,"\n",1);
				}
			}
		else
			{
			BIO_printf(bio,"---\nNo client certificate CA names sent\n");
			}
		p=SSL_get_shared_ciphers(s,buf,BUFSIZ);
		if (p != NULL)
			{
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
	if (peer != NULL)
		BIO_printf(bio,"Server public key is %d bit\n",
			EVP_PKEY_bits(X509_get_pubkey(peer)));
	SSL_SESSION_print(bio,SSL_get_session(s));
	BIO_printf(bio,"---\n");
	if (peer != NULL)
		X509_free(peer);
	}

