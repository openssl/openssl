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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "e_os.h"
#include "bio.h"
#include "crypto.h"
#include "x509.h"
#include "ssl.h"
#include "err.h"
#ifdef WINDOWS
#include "../crypto/bio/bss_file.c"
#endif

#define TEST_SERVER_CERT "../apps/server.pem"
#define TEST_CLIENT_CERT "../apps/client.pem"

#ifndef NOPROTO
int MS_CALLBACK verify_callback(int ok, X509_STORE_CTX *ctx);
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int export);
#ifndef NO_DSA
static DH *get_dh512(void);
#endif
#else
int MS_CALLBACK verify_callback();
static RSA MS_CALLBACK *tmp_rsa_cb();
#ifndef NO_DSA
static DH *get_dh512();
#endif
#endif

BIO *bio_err=NULL;
BIO *bio_stdout=NULL;

static char *cipher=NULL;
int verbose=0;
int debug=0;
#ifdef FIONBIO
static int s_nbio=0;
#endif


#ifndef  NOPROTO
int doit(SSL *s_ssl,SSL *c_ssl,long bytes);
#else
int doit();
#endif

static void sv_usage()
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
	fprintf(stderr," -cert arg     - Certificate file\n");
	fprintf(stderr," -s_cert arg   - Just the server certificate file\n");
	fprintf(stderr," -c_cert arg   - Just the client certificate file\n");
	fprintf(stderr," -cipher arg   - The cipher list\n");
	}

int main(argc, argv)
int argc;
char *argv[];
	{
	char *CApath=NULL,*CAfile=NULL;
	int badop=0;
	int tls1=0,ssl2=0,ssl3=0,ret=1;
	int client_auth=0;
	int server_auth=0,i;
	char *server_cert=TEST_SERVER_CERT;
	char *client_cert=TEST_CLIENT_CERT;
	SSL_CTX *s_ctx=NULL;
	SSL_CTX *c_ctx=NULL;
	SSL_METHOD *meth=NULL;
	SSL *c_ssl,*s_ssl;
	int number=1,reuse=0;
	long bytes=1L;
	SSL_CIPHER *ciph;
#ifndef NO_DH
	DH *dh;
#endif

	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	bio_stdout=BIO_new_fp(stdout,BIO_NOCLOSE);

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

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
		else if	(strcmp(*argv,"-c_cert") == 0)
			{
			if (--argc < 1) goto bad;
			client_cert= *(++argv);
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

/*	if (cipher == NULL) cipher=getenv("SSL_CIPHER"); */

	SSLeay_add_ssl_algorithms();
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
	dh=get_dh512();
	SSL_CTX_set_tmp_dh(s_ctx,dh);
	DH_free(dh);
#endif

#ifndef NO_RSA
	SSL_CTX_set_tmp_rsa_callback(s_ctx,tmp_rsa_cb);
#endif

	if (!SSL_CTX_use_certificate_file(s_ctx,server_cert,SSL_FILETYPE_PEM))
		{
		ERR_print_errors(bio_err);
		}
	else if (!SSL_CTX_use_PrivateKey_file(s_ctx,server_cert,
		SSL_FILETYPE_PEM))
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	if (client_auth)
		{
		SSL_CTX_use_certificate_file(c_ctx,client_cert,
			SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(c_ctx,client_cert,
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
		fprintf(stderr,"client authentication\n");
		SSL_CTX_set_verify(s_ctx,
			SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_callback);
		}
	if (server_auth)
		{
		fprintf(stderr,"server authentication\n");
		SSL_CTX_set_verify(c_ctx,SSL_VERIFY_PEER,
			verify_callback);
		}

	c_ssl=SSL_new(c_ctx);
	s_ssl=SSL_new(s_ctx);

	for (i=0; i<number; i++)
		{
		if (!reuse) SSL_set_session(c_ssl,NULL);
		ret=doit(s_ssl,c_ssl,bytes);
		}

	if (!verbose)
		{
		ciph=SSL_get_current_cipher(c_ssl);
		fprintf(stdout,"Protocol %s, cipher %s, %s\n",
			SSL_get_version(c_ssl),
			SSL_CIPHER_get_version(ciph),
			SSL_CIPHER_get_name(ciph));
		}
	if ((number > 1) || (bytes > 1L))
		printf("%d handshakes of %ld bytes done\n",number,bytes);

	SSL_free(s_ssl);
	SSL_free(c_ssl);

end:
	if (s_ctx != NULL) SSL_CTX_free(s_ctx);
	if (c_ctx != NULL) SSL_CTX_free(c_ctx);

	if (bio_stdout != NULL) BIO_free(bio_stdout);

	ERR_remove_state(0);
	EVP_cleanup();
	CRYPTO_mem_leaks(bio_err);
	EXIT(ret);
	}

#define W_READ	1
#define W_WRITE	2
#define C_DONE	1
#define S_DONE	2

int doit(s_ssl,c_ssl,count)
SSL *s_ssl,*c_ssl;
long count;
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
	SSL_CIPHER *ciph;

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

	ciph=SSL_get_current_cipher(c_ssl);
	if (verbose)
		fprintf(stdout,"DONE, protocol %s, cipher %s, %s\n",
			SSL_get_version(c_ssl),
			SSL_CIPHER_get_version(ciph),
			SSL_CIPHER_get_name(ciph));
	ret=0;
err:
	/* We have to set the BIO's to NULL otherwise they will be
	 * Free()ed twice.  Once when th s_ssl is SSL_free()ed and
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

int MS_CALLBACK verify_callback(ok, ctx)
int ok;
X509_STORE_CTX *ctx;
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

static RSA MS_CALLBACK *tmp_rsa_cb(s,export)
SSL *s;
int export;
	{
	static RSA *rsa_tmp=NULL;

	if (rsa_tmp == NULL)
		{
		BIO_printf(bio_err,"Generating temp (512 bit) RSA key...");
		BIO_flush(bio_err);
#ifndef NO_RSA
		rsa_tmp=RSA_generate_key(512,RSA_F4,NULL,NULL);
#endif
		BIO_printf(bio_err,"\n");
		BIO_flush(bio_err);
		}
	return(rsa_tmp);
	}


