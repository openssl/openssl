/* ssl/ssltest.c */
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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "openssl/e_os.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifdef WINDOWS
#include "../crypto/bio/bss_file.c"
#endif

#ifdef VMS
#  define TEST_SERVER_CERT "SYS$DISK:[-.APPS]SERVER.PEM"
#  define TEST_CLIENT_CERT "SYS$DISK:[-.APPS]CLIENT.PEM"
#else
#  define TEST_SERVER_CERT "../apps/server.pem"
#  define TEST_CLIENT_CERT "../apps/client.pem"
#endif

static int MS_CALLBACK verify_callback(int ok, X509_STORE_CTX *ctx);
#ifndef NO_RSA
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int is_export,int keylength);
static void free_tmp_rsa(void);
#endif
#ifndef NO_DH
static DH *get_dh512(void);
static DH *get_dh1024(void);
static DH *get_dh1024dsa(void);
#endif

static BIO *bio_err=NULL;
static BIO *bio_stdout=NULL;

static char *cipher=NULL;
static int verbose=0;
static int debug=0;
#if 0
/* Not used yet. */
#ifdef FIONBIO
static int s_nbio=0;
#endif
#endif

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

int doit_biopair(SSL *s_ssl,SSL *c_ssl,long bytes,clock_t *s_time,clock_t *c_time);
int doit(SSL *s_ssl,SSL *c_ssl,long bytes);
static void sv_usage(void)
	{
	fprintf(stderr,"usage: ssltest [args ...]\n");
	fprintf(stderr,"\n");
	fprintf(stderr," -server_auth  - check server certificate\n");
	fprintf(stderr," -client_auth  - do client authentication\n");
	fprintf(stderr," -v            - more output\n");
	fprintf(stderr," -d            - debug output\n");
	fprintf(stderr," -reuse        - use session-id reuse\n");
	fprintf(stderr," -num <val>    - number of connections to perform\n");
	fprintf(stderr," -bytes <val>  - number of bytes to swap between client/server\n");
#ifndef NO_DH
	fprintf(stderr," -dhe1024      - use 1024 bit key (safe prime) for DHE\n");
	fprintf(stderr," -dhe1024dsa   - use 1024 bit key (with 160-bit subprime) for DHE\n");
	fprintf(stderr," -no_dhe       - disable DHE\n");
#endif
#ifndef NO_SSL2
	fprintf(stderr," -ssl2         - use SSLv2\n");
#endif
#ifndef NO_SSL3
	fprintf(stderr," -ssl3         - use SSLv3\n");
#endif
#ifndef NO_TLS1
	fprintf(stderr," -tls1         - use TLSv1\n");
#endif
	fprintf(stderr," -CApath arg   - PEM format directory of CA's\n");
	fprintf(stderr," -CAfile arg   - PEM format file of CA's\n");
	fprintf(stderr," -cert arg     - Server certificate file\n");
	fprintf(stderr," -key arg      - Server key file (default: same as -cert)\n");
	fprintf(stderr," -c_cert arg   - Client certificate file\n");
	fprintf(stderr," -c_key arg    - Client key file (default: same as -c_cert)\n");
	fprintf(stderr," -cipher arg   - The cipher list\n");
	fprintf(stderr," -bio_pair     - Use BIO pairs\n");
	fprintf(stderr," -f            - Test even cases that can't work\n");
	fprintf(stderr," -time         - measure processor time used by client and server\n");
	}

static void print_details(SSL *c_ssl, const char *prefix)
	{
	SSL_CIPHER *ciph;
	X509 *cert;
		
	ciph=SSL_get_current_cipher(c_ssl);
	BIO_printf(bio_stdout,"%s%s, cipher %s %s",
		prefix,
		SSL_get_version(c_ssl),
		SSL_CIPHER_get_version(ciph),
		SSL_CIPHER_get_name(ciph));
	cert=SSL_get_peer_certificate(c_ssl);
	if (cert != NULL)
		{
		EVP_PKEY *pkey = X509_get_pubkey(cert);
		if (pkey != NULL)
			{
			if (0) 
				;
#ifndef NO_RSA
			else if (pkey->type == EVP_PKEY_RSA && pkey->pkey.rsa != NULL
				&& pkey->pkey.rsa->n != NULL)
				{
				BIO_printf(bio_stdout, ", %d bit RSA",
					BN_num_bits(pkey->pkey.rsa->n));
				}
#endif
#ifndef NO_DSA
			else if (pkey->type == EVP_PKEY_DSA && pkey->pkey.dsa != NULL
				&& pkey->pkey.dsa->p != NULL)
				{
				BIO_printf(bio_stdout, ", %d bit DSA",
					BN_num_bits(pkey->pkey.dsa->p));
				}
#endif
			EVP_PKEY_free(pkey);
			}
		X509_free(cert);
		}
	/* The SSL API does not allow us to look at temporary RSA/DH keys,
	 * otherwise we should print their lengths too */
	BIO_printf(bio_stdout,"\n");
	}

int main(int argc, char *argv[])
	{
	char *CApath=NULL,*CAfile=NULL;
	int badop=0;
	int bio_pair=0;
	int force=0;
	int tls1=0,ssl2=0,ssl3=0,ret=1;
	int client_auth=0;
	int server_auth=0,i;
	char *server_cert=TEST_SERVER_CERT;
	char *server_key=NULL;
	char *client_cert=TEST_CLIENT_CERT;
	char *client_key=NULL;
	SSL_CTX *s_ctx=NULL;
	SSL_CTX *c_ctx=NULL;
	SSL_METHOD *meth=NULL;
	SSL *c_ssl,*s_ssl;
	int number=1,reuse=0;
	long bytes=1L;
#ifndef NO_DH
	DH *dh;
	int dhe1024 = 0, dhe1024dsa = 0;
#endif
	int no_dhe = 0;
	int print_time = 0;
	clock_t s_time = 0, c_time = 0;

	verbose = 0;
	debug = 0;
	cipher = 0;
	
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	RAND_seed(rnd_seed, sizeof rnd_seed);

	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	bio_stdout=BIO_new_fp(stdout,BIO_NOCLOSE);

	argc--;
	argv++;

	while (argc >= 1)
		{
		if	(strcmp(*argv,"-server_auth") == 0)
			server_auth=1;
		else if	(strcmp(*argv,"-client_auth") == 0)
			client_auth=1;
		else if	(strcmp(*argv,"-v") == 0)
			verbose=1;
		else if	(strcmp(*argv,"-d") == 0)
			debug=1;
		else if	(strcmp(*argv,"-reuse") == 0)
			reuse=1;
#ifndef NO_DH
		else if	(strcmp(*argv,"-dhe1024") == 0)
			dhe1024=1;
		else if	(strcmp(*argv,"-dhe1024dsa") == 0)
			dhe1024dsa=1;
#endif
		else if	(strcmp(*argv,"-no_dhe") == 0)
			no_dhe=1;
		else if	(strcmp(*argv,"-ssl2") == 0)
			ssl2=1;
		else if	(strcmp(*argv,"-tls1") == 0)
			tls1=1;
		else if	(strcmp(*argv,"-ssl3") == 0)
			ssl3=1;
		else if	(strncmp(*argv,"-num",4) == 0)
			{
			if (--argc < 1) goto bad;
			number= atoi(*(++argv));
			if (number == 0) number=1;
			}
		else if	(strcmp(*argv,"-bytes") == 0)
			{
			if (--argc < 1) goto bad;
			bytes= atol(*(++argv));
			if (bytes == 0L) bytes=1L;
			i=strlen(argv[0]);
			if (argv[0][i-1] == 'k') bytes*=1024L;
			if (argv[0][i-1] == 'm') bytes*=1024L*1024L;
			}
		else if	(strcmp(*argv,"-cert") == 0)
			{
			if (--argc < 1) goto bad;
			server_cert= *(++argv);
			}
		else if	(strcmp(*argv,"-s_cert") == 0)
			{
			if (--argc < 1) goto bad;
			server_cert= *(++argv);
			}
		else if	(strcmp(*argv,"-key") == 0)
			{
			if (--argc < 1) goto bad;
			server_key= *(++argv);
			}
		else if	(strcmp(*argv,"-s_key") == 0)
			{
			if (--argc < 1) goto bad;
			server_key= *(++argv);
			}
		else if	(strcmp(*argv,"-c_cert") == 0)
			{
			if (--argc < 1) goto bad;
			client_cert= *(++argv);
			}
		else if	(strcmp(*argv,"-c_key") == 0)
			{
			if (--argc < 1) goto bad;
			client_key= *(++argv);
			}
		else if	(strcmp(*argv,"-cipher") == 0)
			{
			if (--argc < 1) goto bad;
			cipher= *(++argv);
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
		else if	(strcmp(*argv,"-bio_pair") == 0)
			{
			bio_pair = 1;
			}
		else if	(strcmp(*argv,"-f") == 0)
			{
			force = 1;
			}
		else if	(strcmp(*argv,"-time") == 0)
			{
			print_time = 1;
			}
		else
			{
			fprintf(stderr,"unknown option %s\n",*argv);
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

	if (!ssl2 && !ssl3 && !tls1 && number > 1 && !reuse && !force)
		{
		fprintf(stderr, "This case cannot work.  Use -f to perform "
			"the test anyway (and\n-d to see what happens), "
			"or add one of -ssl2, -ssl3, -tls1, -reuse\n"
			"to avoid protocol mismatch.\n");
		exit(1);
		}

	if (print_time)
		{
		if (!bio_pair)
			{
			fprintf(stderr, "Using BIO pair (-bio_pair)\n");
			bio_pair = 1;
			}
		if (number < 50 && !force)
			fprintf(stderr, "Warning: For accurate timings, use more connections (e.g. -num 1000)\n");
		}

/*	if (cipher == NULL) cipher=getenv("SSL_CIPHER"); */

	SSL_library_init();
	SSL_load_error_strings();

#if !defined(NO_SSL2) && !defined(NO_SSL3)
	if (ssl2)
		meth=SSLv2_method();
	else 
	if (tls1)
		meth=TLSv1_method();
	else
	if (ssl3)
		meth=SSLv3_method();
	else
		meth=SSLv23_method();
#else
#ifdef NO_SSL2
	meth=SSLv3_method();
#else
	meth=SSLv2_method();
#endif
#endif

	c_ctx=SSL_CTX_new(meth);
	s_ctx=SSL_CTX_new(meth);
	if ((c_ctx == NULL) || (s_ctx == NULL))
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	if (cipher != NULL)
		{
		SSL_CTX_set_cipher_list(c_ctx,cipher);
		SSL_CTX_set_cipher_list(s_ctx,cipher);
		}

#ifndef NO_DH
	if (!no_dhe)
		{
		if (dhe1024dsa)
			{
			/* use SSL_OP_SINGLE_DH_USE to avoid small subgroup attacks */
			SSL_CTX_set_options(s_ctx, SSL_OP_SINGLE_DH_USE);
			dh=get_dh1024dsa();
			}
		else if (dhe1024)
			dh=get_dh1024();
		else
			dh=get_dh512();
		SSL_CTX_set_tmp_dh(s_ctx,dh);
		DH_free(dh);
		}
#else
	(void)no_dhe;
#endif

#ifndef NO_RSA
	SSL_CTX_set_tmp_rsa_callback(s_ctx,tmp_rsa_cb);
#endif

	if (!SSL_CTX_use_certificate_file(s_ctx,server_cert,SSL_FILETYPE_PEM))
		{
		ERR_print_errors(bio_err);
		}
	else if (!SSL_CTX_use_PrivateKey_file(s_ctx,
		(server_key?server_key:server_cert), SSL_FILETYPE_PEM))
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	if (client_auth)
		{
		SSL_CTX_use_certificate_file(c_ctx,client_cert,
			SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(c_ctx,
			(client_key?client_key:client_cert),
			SSL_FILETYPE_PEM);
		}

	if (	(!SSL_CTX_load_verify_locations(s_ctx,CAfile,CApath)) ||
		(!SSL_CTX_set_default_verify_paths(s_ctx)) ||
		(!SSL_CTX_load_verify_locations(c_ctx,CAfile,CApath)) ||
		(!SSL_CTX_set_default_verify_paths(c_ctx)))
		{
		/* fprintf(stderr,"SSL_load_verify_locations\n"); */
		ERR_print_errors(bio_err);
		/* goto end; */
		}

	if (client_auth)
		{
		BIO_printf(bio_err,"client authentication\n");
		SSL_CTX_set_verify(s_ctx,
			SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_callback);
		}
	if (server_auth)
		{
		BIO_printf(bio_err,"server authentication\n");
		SSL_CTX_set_verify(c_ctx,SSL_VERIFY_PEER,
			verify_callback);
		}
	
	{
		int session_id_context = 0;
		SSL_CTX_set_session_id_context(s_ctx, (void *)&session_id_context, sizeof session_id_context);
	}

	c_ssl=SSL_new(c_ctx);
	s_ssl=SSL_new(s_ctx);

	for (i=0; i<number; i++)
		{
		if (!reuse) SSL_set_session(c_ssl,NULL);
		if (bio_pair)
			ret=doit_biopair(s_ssl,c_ssl,bytes,&s_time,&c_time);
		else
			ret=doit(s_ssl,c_ssl,bytes);
		}

	if (!verbose)
		{
		print_details(c_ssl, "");
		}
	if ((number > 1) || (bytes > 1L))
		BIO_printf(bio_stdout, "%d handshakes of %ld bytes done\n",number,bytes);
	if (print_time)
		{
#ifdef CLOCKS_PER_SEC
		/* "To determine the time in seconds, the value returned
		 * by the clock function should be divided by the value
		 * of the macro CLOCKS_PER_SEC."
		 *                                       -- ISO/IEC 9899 */
		BIO_printf(bio_stdout, "Approximate total server time: %6.2f s\n"
			"Approximate total client time: %6.2f s\n",
			(double)s_time/CLOCKS_PER_SEC,
			(double)c_time/CLOCKS_PER_SEC);
#else
		/* "`CLOCKS_PER_SEC' undeclared (first use this function)"
		 *                            -- cc on NeXTstep/OpenStep */
		BIO_printf(bio_stdout,
			"Approximate total server time: %6.2f units\n"
			"Approximate total client time: %6.2f units\n",
			(double)s_time,
			(double)c_time);
#endif
		}

	SSL_free(s_ssl);
	SSL_free(c_ssl);

end:
	if (s_ctx != NULL) SSL_CTX_free(s_ctx);
	if (c_ctx != NULL) SSL_CTX_free(c_ctx);

	if (bio_stdout != NULL) BIO_free(bio_stdout);

#ifndef NO_RSA
	free_tmp_rsa();
#endif
	ERR_free_strings();
	ERR_remove_state(0);
	EVP_cleanup();
	CRYPTO_mem_leaks(bio_err);
	if (bio_err != NULL) BIO_free(bio_err);
	EXIT(ret);
	}

int doit_biopair(SSL *s_ssl, SSL *c_ssl, long count,
	clock_t *s_time, clock_t *c_time)
	{
	long cw_num = count, cr_num = count, sw_num = count, sr_num = count;
	BIO *s_ssl_bio = NULL, *c_ssl_bio = NULL;
	BIO *server = NULL, *server_io = NULL, *client = NULL, *client_io = NULL;
	int ret = 1;
	
	size_t bufsiz = 256; /* small buffer for testing */

	if (!BIO_new_bio_pair(&server, bufsiz, &server_io, bufsiz))
		goto err;
	if (!BIO_new_bio_pair(&client, bufsiz, &client_io, bufsiz))
		goto err;
	
	s_ssl_bio = BIO_new(BIO_f_ssl());
	if (!s_ssl_bio)
		goto err;

	c_ssl_bio = BIO_new(BIO_f_ssl());
	if (!c_ssl_bio)
		goto err;

	SSL_set_connect_state(c_ssl);
	SSL_set_bio(c_ssl, client, client);
	(void)BIO_set_ssl(c_ssl_bio, c_ssl, BIO_NOCLOSE);

	SSL_set_accept_state(s_ssl);
	SSL_set_bio(s_ssl, server, server);
	(void)BIO_set_ssl(s_ssl_bio, s_ssl, BIO_NOCLOSE);

	do
		{
		/* c_ssl_bio:          SSL filter BIO
		 *
		 * client:             pseudo-I/O for SSL library
		 *
		 * client_io:          client's SSL communication; usually to be
		 *                     relayed over some I/O facility, but in this
		 *                     test program, we're the server, too:
		 *
		 * server_io:          server's SSL communication
		 *
		 * server:             pseudo-I/O for SSL library
		 *
		 * s_ssl_bio:          SSL filter BIO
		 *
		 * The client and the server each employ a "BIO pair":
		 * client + client_io, server + server_io.
		 * BIO pairs are symmetric.  A BIO pair behaves similar
		 * to a non-blocking socketpair (but both endpoints must
		 * be handled by the same thread).
		 * [Here we could connect client and server to the ends
		 * of a single BIO pair, but then this code would be less
		 * suitable as an example for BIO pairs in general.]
		 *
		 * Useful functions for querying the state of BIO pair endpoints:
		 *
		 * BIO_ctrl_pending(bio)              number of bytes we can read now
		 * BIO_ctrl_get_read_request(bio)     number of bytes needed to fulfil
		 *                                      other side's read attempt
		 * BIO_ctrl_get_write_guarantee(bio)   number of bytes we can write now
		 *
		 * ..._read_request is never more than ..._write_guarantee;
		 * it depends on the application which one you should use.
		 */

		/* We have non-blocking behaviour throughout this test program, but
		 * can be sure that there is *some* progress in each iteration; so
		 * we don't have to worry about ..._SHOULD_READ or ..._SHOULD_WRITE
		 * -- we just try everything in each iteration
		 */

			{
			/* CLIENT */
		
			MS_STATIC char cbuf[1024*8];
			int i, r;
			clock_t c_clock = clock();

			if (debug)
				if (SSL_in_init(c_ssl))
					printf("client waiting in SSL_connect - %s\n",
						SSL_state_string_long(c_ssl));

			if (cw_num > 0)
				{
				/* Write to server. */
				
				if (cw_num > (long)sizeof cbuf)
					i = sizeof cbuf;
				else
					i = (int)cw_num;
				r = BIO_write(c_ssl_bio, cbuf, i);
				if (r < 0)
					{
					if (!BIO_should_retry(c_ssl_bio))
						{
						fprintf(stderr,"ERROR in CLIENT\n");
						goto err;
						}
					/* BIO_should_retry(...) can just be ignored here.
					 * The library expects us to call BIO_write with
					 * the same arguments again, and that's what we will
					 * do in the next iteration. */
					}
				else if (r == 0)
					{
					fprintf(stderr,"SSL CLIENT STARTUP FAILED\n");
					goto err;
					}
				else
					{
					if (debug)
						printf("client wrote %d\n", r);
					cw_num -= r;				
					}
				}

			if (cr_num > 0)
				{
				/* Read from server. */

				r = BIO_read(c_ssl_bio, cbuf, sizeof(cbuf));
				if (r < 0)
					{
					if (!BIO_should_retry(c_ssl_bio))
						{
						fprintf(stderr,"ERROR in CLIENT\n");
						goto err;
						}
					/* Again, "BIO_should_retry" can be ignored. */
					}
				else if (r == 0)
					{
					fprintf(stderr,"SSL CLIENT STARTUP FAILED\n");
					goto err;
					}
				else
					{
					if (debug)
						printf("client read %d\n", r);
					cr_num -= r;
					}
				}

			/* c_time and s_time increments will typically be very small
			 * (depending on machine speed and clock tick intervals),
			 * but sampling over a large number of connections should
			 * result in fairly accurate figures.  We cannot guarantee
			 * a lot, however -- if each connection lasts for exactly
			 * one clock tick, it will be counted only for the client
			 * or only for the server or even not at all.
			 */
			*c_time += (clock() - c_clock);
			}

			{
			/* SERVER */
		
			MS_STATIC char sbuf[1024*8];
			int i, r;
			clock_t s_clock = clock();

			if (debug)
				if (SSL_in_init(s_ssl))
					printf("server waiting in SSL_accept - %s\n",
						SSL_state_string_long(s_ssl));

			if (sw_num > 0)
				{
				/* Write to client. */
				
				if (sw_num > (long)sizeof sbuf)
					i = sizeof sbuf;
				else
					i = (int)sw_num;
				r = BIO_write(s_ssl_bio, sbuf, i);
				if (r < 0)
					{
					if (!BIO_should_retry(s_ssl_bio))
						{
						fprintf(stderr,"ERROR in SERVER\n");
						goto err;
						}
					/* Ignore "BIO_should_retry". */
					}
				else if (r == 0)
					{
					fprintf(stderr,"SSL SERVER STARTUP FAILED\n");
					goto err;
					}
				else
					{
					if (debug)
						printf("server wrote %d\n", r);
					sw_num -= r;				
					}
				}

			if (sr_num > 0)
				{
				/* Read from client. */

				r = BIO_read(s_ssl_bio, sbuf, sizeof(sbuf));
				if (r < 0)
					{
					if (!BIO_should_retry(s_ssl_bio))
						{
						fprintf(stderr,"ERROR in SERVER\n");
						goto err;
						}
					/* blah, blah */
					}
				else if (r == 0)
					{
					fprintf(stderr,"SSL SERVER STARTUP FAILED\n");
					goto err;
					}
				else
					{
					if (debug)
						printf("server read %d\n", r);
					sr_num -= r;
					}
				}

			*s_time += (clock() - s_clock);
			}
			
			{
			/* "I/O" BETWEEN CLIENT AND SERVER. */

			size_t r1, r2;
			BIO *io1 = server_io, *io2 = client_io;
			/* we use the non-copying interface for io1
			 * and the standard BIO_write/BIO_read interface for io2
			 */
			
			static int prev_progress = 1;
			int progress = 0;
			
			/* io1 to io2 */
			do
				{
				size_t num;
				int r;

				r1 = BIO_ctrl_pending(io1);
				r2 = BIO_ctrl_get_write_guarantee(io2);

				num = r1;
				if (r2 < num)
					num = r2;
				if (num)
					{
					char *dataptr;

					if (INT_MAX < num) /* yeah, right */
						num = INT_MAX;
					
					r = BIO_nread(io1, &dataptr, (int)num);
					assert(r > 0);
					assert(r <= (int)num);
					/* possibly r < num (non-contiguous data) */
					num = r;
					r = BIO_write(io2, dataptr, (int)num);
					if (r != (int)num) /* can't happen */
						{
						fprintf(stderr, "ERROR: BIO_write could not write "
							"BIO_ctrl_get_write_guarantee() bytes");
						goto err;
						}
					progress = 1;

					if (debug)
						printf((io1 == client_io) ?
							"C->S relaying: %d bytes\n" :
							"S->C relaying: %d bytes\n",
							(int)num);
					}
				}
			while (r1 && r2);

			/* io2 to io1 */
			{
				size_t num;
				int r;

				r1 = BIO_ctrl_pending(io2);
				r2 = BIO_ctrl_get_read_request(io1);
				/* here we could use ..._get_write_guarantee instead of
				 * ..._get_read_request, but by using the latter
				 * we test restartability of the SSL implementation
				 * more thoroughly */
				num = r1;
				if (r2 < num)
					num = r2;
				if (num)
					{
					char *dataptr;
					
					if (INT_MAX < num)
						num = INT_MAX;

					if (num > 1)
						--num; /* test restartability even more thoroughly */
					
					r = BIO_nwrite0(io1, &dataptr);
					assert(r > 0);
					if (r < (int)num)
						num = r;
					r = BIO_read(io2, dataptr, (int)num);
					if (r != (int)num) /* can't happen */
						{
						fprintf(stderr, "ERROR: BIO_read could not read "
							"BIO_ctrl_pending() bytes");
						goto err;
						}
					progress = 1;
					r = BIO_nwrite(io1, &dataptr, (int)num);
					if (r != (int)num) /* can't happen */
						{
						fprintf(stderr, "ERROR: BIO_nwrite() did not accept "
							"BIO_nwrite0() bytes");
						goto err;
						}
					
					if (debug)
						printf((io2 == client_io) ?
							"C->S relaying: %d bytes\n" :
							"S->C relaying: %d bytes\n",
							(int)num);
					}
			} /* no loop, BIO_ctrl_get_read_request now returns 0 anyway */

			if (!progress && !prev_progress)
				if (cw_num > 0 || cr_num > 0 || sw_num > 0 || sr_num > 0)
					{
					fprintf(stderr, "ERROR: got stuck\n");
					if (strcmp("SSLv2", SSL_get_version(c_ssl)) == 0)
						{
						fprintf(stderr, "This can happen for SSL2 because "
							"CLIENT-FINISHED and SERVER-VERIFY are written \n"
							"concurrently ...");
						if (strncmp("2SCF", SSL_state_string(c_ssl), 4) == 0
							&& strncmp("2SSV", SSL_state_string(s_ssl), 4) == 0)
							{
							fprintf(stderr, " ok.\n");
							goto end;
							}
						}
					fprintf(stderr, " ERROR.\n");
					goto err;
					}
			prev_progress = progress;
			}
		}
	while (cw_num > 0 || cr_num > 0 || sw_num > 0 || sr_num > 0);

	if (verbose)
		print_details(c_ssl, "DONE via BIO pair: ");
end:
	ret = 0;

 err:
	ERR_print_errors(bio_err);
	
	if (server)
		BIO_free(server);
	if (server_io)
		BIO_free(server_io);
	if (client)
		BIO_free(client);
	if (client_io)
		BIO_free(client_io);
	if (s_ssl_bio)
		BIO_free(s_ssl_bio);
	if (c_ssl_bio)
		BIO_free(c_ssl_bio);

	return ret;
	}


#define W_READ	1
#define W_WRITE	2
#define C_DONE	1
#define S_DONE	2

int doit(SSL *s_ssl, SSL *c_ssl, long count)
	{
	MS_STATIC char cbuf[1024*8],sbuf[1024*8];
	long cw_num=count,cr_num=count;
	long sw_num=count,sr_num=count;
	int ret=1;
	BIO *c_to_s=NULL;
	BIO *s_to_c=NULL;
	BIO *c_bio=NULL;
	BIO *s_bio=NULL;
	int c_r,c_w,s_r,s_w;
	int c_want,s_want;
	int i,j;
	int done=0;
	int c_write,s_write;
	int do_server=0,do_client=0;

	c_to_s=BIO_new(BIO_s_mem());
	s_to_c=BIO_new(BIO_s_mem());
	if ((s_to_c == NULL) || (c_to_s == NULL))
		{
		ERR_print_errors(bio_err);
		goto err;
		}

	c_bio=BIO_new(BIO_f_ssl());
	s_bio=BIO_new(BIO_f_ssl());
	if ((c_bio == NULL) || (s_bio == NULL))
		{
		ERR_print_errors(bio_err);
		goto err;
		}

	SSL_set_connect_state(c_ssl);
	SSL_set_bio(c_ssl,s_to_c,c_to_s);
	BIO_set_ssl(c_bio,c_ssl,BIO_NOCLOSE);

	SSL_set_accept_state(s_ssl);
	SSL_set_bio(s_ssl,c_to_s,s_to_c);
	BIO_set_ssl(s_bio,s_ssl,BIO_NOCLOSE);

	c_r=0; s_r=1;
	c_w=1; s_w=0;
	c_want=W_WRITE;
	s_want=0;
	c_write=1,s_write=0;

	/* We can always do writes */
	for (;;)
		{
		do_server=0;
		do_client=0;

		i=(int)BIO_pending(s_bio);
		if ((i && s_r) || s_w) do_server=1;

		i=(int)BIO_pending(c_bio);
		if ((i && c_r) || c_w) do_client=1;

		if (do_server && debug)
			{
			if (SSL_in_init(s_ssl))
				printf("server waiting in SSL_accept - %s\n",
					SSL_state_string_long(s_ssl));
/*			else if (s_write)
				printf("server:SSL_write()\n");
			else
				printf("server:SSL_read()\n"); */
			}

		if (do_client && debug)
			{
			if (SSL_in_init(c_ssl))
				printf("client waiting in SSL_connect - %s\n",
					SSL_state_string_long(c_ssl));
/*			else if (c_write)
				printf("client:SSL_write()\n");
			else
				printf("client:SSL_read()\n"); */
			}

		if (!do_client && !do_server)
			{
			fprintf(stdout,"ERROR IN STARTUP\n");
			ERR_print_errors(bio_err);
			break;
			}
		if (do_client && !(done & C_DONE))
			{
			if (c_write)
				{
				j=(cw_num > (long)sizeof(cbuf))
					?sizeof(cbuf):(int)cw_num;
				i=BIO_write(c_bio,cbuf,j);
				if (i < 0)
					{
					c_r=0;
					c_w=0;
					if (BIO_should_retry(c_bio))
						{
						if (BIO_should_read(c_bio))
							c_r=1;
						if (BIO_should_write(c_bio))
							c_w=1;
						}
					else
						{
						fprintf(stderr,"ERROR in CLIENT\n");
						ERR_print_errors(bio_err);
						goto err;
						}
					}
				else if (i == 0)
					{
					fprintf(stderr,"SSL CLIENT STARTUP FAILED\n");
					goto err;
					}
				else
					{
					if (debug)
						printf("client wrote %d\n",i);
					/* ok */
					s_r=1;
					c_write=0;
					cw_num-=i;
					}
				}
			else
				{
				i=BIO_read(c_bio,cbuf,sizeof(cbuf));
				if (i < 0)
					{
					c_r=0;
					c_w=0;
					if (BIO_should_retry(c_bio))
						{
						if (BIO_should_read(c_bio))
							c_r=1;
						if (BIO_should_write(c_bio))
							c_w=1;
						}
					else
						{
						fprintf(stderr,"ERROR in CLIENT\n");
						ERR_print_errors(bio_err);
						goto err;
						}
					}
				else if (i == 0)
					{
					fprintf(stderr,"SSL CLIENT STARTUP FAILED\n");
					goto err;
					}
				else
					{
					if (debug)
						printf("client read %d\n",i);
					cr_num-=i;
					if (sw_num > 0)
						{
						s_write=1;
						s_w=1;
						}
					if (cr_num <= 0)
						{
						s_write=1;
						s_w=1;
						done=S_DONE|C_DONE;
						}
					}
				}
			}

		if (do_server && !(done & S_DONE))
			{
			if (!s_write)
				{
				i=BIO_read(s_bio,sbuf,sizeof(cbuf));
				if (i < 0)
					{
					s_r=0;
					s_w=0;
					if (BIO_should_retry(s_bio))
						{
						if (BIO_should_read(s_bio))
							s_r=1;
						if (BIO_should_write(s_bio))
							s_w=1;
						}
					else
						{
						fprintf(stderr,"ERROR in SERVER\n");
						ERR_print_errors(bio_err);
						goto err;
						}
					}
				else if (i == 0)
					{
					ERR_print_errors(bio_err);
					fprintf(stderr,"SSL SERVER STARTUP FAILED in SSL_read\n");
					goto err;
					}
				else
					{
					if (debug)
						printf("server read %d\n",i);
					sr_num-=i;
					if (cw_num > 0)
						{
						c_write=1;
						c_w=1;
						}
					if (sr_num <= 0)
						{
						s_write=1;
						s_w=1;
						c_write=0;
						}
					}
				}
			else
				{
				j=(sw_num > (long)sizeof(sbuf))?
					sizeof(sbuf):(int)sw_num;
				i=BIO_write(s_bio,sbuf,j);
				if (i < 0)
					{
					s_r=0;
					s_w=0;
					if (BIO_should_retry(s_bio))
						{
						if (BIO_should_read(s_bio))
							s_r=1;
						if (BIO_should_write(s_bio))
							s_w=1;
						}
					else
						{
						fprintf(stderr,"ERROR in SERVER\n");
						ERR_print_errors(bio_err);
						goto err;
						}
					}
				else if (i == 0)
					{
					ERR_print_errors(bio_err);
					fprintf(stderr,"SSL SERVER STARTUP FAILED in SSL_write\n");
					goto err;
					}
				else
					{
					if (debug)
						printf("server wrote %d\n",i);
					sw_num-=i;
					s_write=0;
					c_r=1;
					if (sw_num <= 0)
						done|=S_DONE;
					}
				}
			}

		if ((done & S_DONE) && (done & C_DONE)) break;
		}

	if (verbose)
		print_details(c_ssl, "DONE: ");
	ret=0;
err:
	/* We have to set the BIO's to NULL otherwise they will be
	 * OPENSSL_free()ed twice.  Once when th s_ssl is SSL_free()ed and
	 * again when c_ssl is SSL_free()ed.
	 * This is a hack required because s_ssl and c_ssl are sharing the same
	 * BIO structure and SSL_set_bio() and SSL_free() automatically
	 * BIO_free non NULL entries.
	 * You should not normally do this or be required to do this */
	if (s_ssl != NULL)
		{
		s_ssl->rbio=NULL;
		s_ssl->wbio=NULL;
		}
	if (c_ssl != NULL)
		{
		c_ssl->rbio=NULL;
		c_ssl->wbio=NULL;
		}

	if (c_to_s != NULL) BIO_free(c_to_s);
	if (s_to_c != NULL) BIO_free(s_to_c);
	if (c_bio != NULL) BIO_free_all(c_bio);
	if (s_bio != NULL) BIO_free_all(s_bio);
	return(ret);
	}

static int MS_CALLBACK verify_callback(int ok, X509_STORE_CTX *ctx)
	{
	char *s,buf[256];

	s=X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),buf,256);
	if (s != NULL)
		{
		if (ok)
			fprintf(stderr,"depth=%d %s\n",ctx->error_depth,buf);
		else
			fprintf(stderr,"depth=%d error=%d %s\n",
				ctx->error_depth,ctx->error,buf);
		}

	if (ok == 0)
		{
		switch (ctx->error)
			{
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			ok=1;
			}
		}

	return(ok);
	}

#ifndef NO_RSA
static RSA *rsa_tmp=NULL;

static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int is_export, int keylength)
	{
	if (rsa_tmp == NULL)
		{
		BIO_printf(bio_err,"Generating temp (%d bit) RSA key...",keylength);
		(void)BIO_flush(bio_err);
		rsa_tmp=RSA_generate_key(keylength,RSA_F4,NULL,NULL);
		BIO_printf(bio_err,"\n");
		(void)BIO_flush(bio_err);
		}
	return(rsa_tmp);
	}

static void free_tmp_rsa(void)
	{
	if (rsa_tmp != NULL)
		{
		RSA_free(rsa_tmp);
		rsa_tmp = NULL;
		}
	}
#endif

#ifndef NO_DH
/* These DH parameters have been generated as follows:
 *    $ openssl dhparam -C -noout 512
 *    $ openssl dhparam -C -noout 1024
 *    $ openssl dhparam -C -noout -dsaparam 1024
 * (The third function has been renamed to avoid name conflicts.)
 */
DH *get_dh512()
	{
	static unsigned char dh512_p[]={
		0xCB,0xC8,0xE1,0x86,0xD0,0x1F,0x94,0x17,0xA6,0x99,0xF0,0xC6,
		0x1F,0x0D,0xAC,0xB6,0x25,0x3E,0x06,0x39,0xCA,0x72,0x04,0xB0,
		0x6E,0xDA,0xC0,0x61,0xE6,0x7A,0x77,0x25,0xE8,0x3B,0xB9,0x5F,
		0x9A,0xB6,0xB5,0xFE,0x99,0x0B,0xA1,0x93,0x4E,0x35,0x33,0xB8,
		0xE1,0xF1,0x13,0x4F,0x59,0x1A,0xD2,0x57,0xC0,0x26,0x21,0x33,
		0x02,0xC5,0xAE,0x23,
		};
	static unsigned char dh512_g[]={
		0x02,
		};
	DH *dh;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		{ DH_free(dh); return(NULL); }
	return(dh);
	}

DH *get_dh1024()
	{
	static unsigned char dh1024_p[]={
		0xF8,0x81,0x89,0x7D,0x14,0x24,0xC5,0xD1,0xE6,0xF7,0xBF,0x3A,
		0xE4,0x90,0xF4,0xFC,0x73,0xFB,0x34,0xB5,0xFA,0x4C,0x56,0xA2,
		0xEA,0xA7,0xE9,0xC0,0xC0,0xCE,0x89,0xE1,0xFA,0x63,0x3F,0xB0,
		0x6B,0x32,0x66,0xF1,0xD1,0x7B,0xB0,0x00,0x8F,0xCA,0x87,0xC2,
		0xAE,0x98,0x89,0x26,0x17,0xC2,0x05,0xD2,0xEC,0x08,0xD0,0x8C,
		0xFF,0x17,0x52,0x8C,0xC5,0x07,0x93,0x03,0xB1,0xF6,0x2F,0xB8,
		0x1C,0x52,0x47,0x27,0x1B,0xDB,0xD1,0x8D,0x9D,0x69,0x1D,0x52,
		0x4B,0x32,0x81,0xAA,0x7F,0x00,0xC8,0xDC,0xE6,0xD9,0xCC,0xC1,
		0x11,0x2D,0x37,0x34,0x6C,0xEA,0x02,0x97,0x4B,0x0E,0xBB,0xB1,
		0x71,0x33,0x09,0x15,0xFD,0xDD,0x23,0x87,0x07,0x5E,0x89,0xAB,
		0x6B,0x7C,0x5F,0xEC,0xA6,0x24,0xDC,0x53,
		};
	static unsigned char dh1024_g[]={
		0x02,
		};
	DH *dh;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
	dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		{ DH_free(dh); return(NULL); }
	return(dh);
	}

DH *get_dh1024dsa()
	{
	static unsigned char dh1024_p[]={
		0xC8,0x00,0xF7,0x08,0x07,0x89,0x4D,0x90,0x53,0xF3,0xD5,0x00,
		0x21,0x1B,0xF7,0x31,0xA6,0xA2,0xDA,0x23,0x9A,0xC7,0x87,0x19,
		0x3B,0x47,0xB6,0x8C,0x04,0x6F,0xFF,0xC6,0x9B,0xB8,0x65,0xD2,
		0xC2,0x5F,0x31,0x83,0x4A,0xA7,0x5F,0x2F,0x88,0x38,0xB6,0x55,
		0xCF,0xD9,0x87,0x6D,0x6F,0x9F,0xDA,0xAC,0xA6,0x48,0xAF,0xFC,
		0x33,0x84,0x37,0x5B,0x82,0x4A,0x31,0x5D,0xE7,0xBD,0x52,0x97,
		0xA1,0x77,0xBF,0x10,0x9E,0x37,0xEA,0x64,0xFA,0xCA,0x28,0x8D,
		0x9D,0x3B,0xD2,0x6E,0x09,0x5C,0x68,0xC7,0x45,0x90,0xFD,0xBB,
		0x70,0xC9,0x3A,0xBB,0xDF,0xD4,0x21,0x0F,0xC4,0x6A,0x3C,0xF6,
		0x61,0xCF,0x3F,0xD6,0x13,0xF1,0x5F,0xBC,0xCF,0xBC,0x26,0x9E,
		0xBC,0x0B,0xBD,0xAB,0x5D,0xC9,0x54,0x39,
		};
	static unsigned char dh1024_g[]={
		0x3B,0x40,0x86,0xE7,0xF3,0x6C,0xDE,0x67,0x1C,0xCC,0x80,0x05,
		0x5A,0xDF,0xFE,0xBD,0x20,0x27,0x74,0x6C,0x24,0xC9,0x03,0xF3,
		0xE1,0x8D,0xC3,0x7D,0x98,0x27,0x40,0x08,0xB8,0x8C,0x6A,0xE9,
		0xBB,0x1A,0x3A,0xD6,0x86,0x83,0x5E,0x72,0x41,0xCE,0x85,0x3C,
		0xD2,0xB3,0xFC,0x13,0xCE,0x37,0x81,0x9E,0x4C,0x1C,0x7B,0x65,
		0xD3,0xE6,0xA6,0x00,0xF5,0x5A,0x95,0x43,0x5E,0x81,0xCF,0x60,
		0xA2,0x23,0xFC,0x36,0xA7,0x5D,0x7A,0x4C,0x06,0x91,0x6E,0xF6,
		0x57,0xEE,0x36,0xCB,0x06,0xEA,0xF5,0x3D,0x95,0x49,0xCB,0xA7,
		0xDD,0x81,0xDF,0x80,0x09,0x4A,0x97,0x4D,0xA8,0x22,0x72,0xA1,
		0x7F,0xC4,0x70,0x56,0x70,0xE8,0x20,0x10,0x18,0x8F,0x2E,0x60,
		0x07,0xE7,0x68,0x1A,0x82,0x5D,0x32,0xA2,
		};
	DH *dh;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
	dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		{ DH_free(dh); return(NULL); }
	dh->length = 160;
	return(dh);
	}
#endif
