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
#include <sys/types.h>
#include <sys/stat.h>
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

#include <openssl/lhash.h>
#include <openssl/bn.h>
#define USE_SOCKETS
#include "apps.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
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

#ifndef OPENSSL_NO_RSA
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int is_export, int keylength);
#endif
static int sv_body(char *hostname, int s, unsigned char *context);
static int www_body(char *hostname, int s, unsigned char *context);
static void close_accept_socket(void );
static void sv_usage(void);
static int init_ssl_connection(SSL *s);
static void print_stats(BIO *bp,SSL_CTX *ctx);
static int generate_session_id(const SSL *ssl, unsigned char *id,
				unsigned int *id_len);
#ifndef OPENSSL_NO_DH
static DH *load_dh_param(char *dhfile);
static DH *get_dh512(void);
#endif
#ifdef MONOLITH
static void s_server_init(void);
#endif

#ifndef S_ISDIR
# if defined(_S_IFMT) && defined(_S_IFDIR)
#  define S_ISDIR(a)	(((a) & _S_IFMT) == _S_IFDIR)
# else
#  define S_ISDIR(a)	(((a) & S_IFMT) == S_IFDIR)
# endif
#endif

#ifndef OPENSSL_NO_DH
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

static DH *get_dh512(void)
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
#define BUFSIZZ	16*1024
static int bufsize=BUFSIZZ;
static int accept_socket= -1;

#define TEST_CERT	"server.pem"
#undef PROG
#define PROG		s_server_main

extern int verify_depth;

static char *cipher=NULL;
static int s_server_verify=SSL_VERIFY_NONE;
static int s_server_session_id_context = 1; /* anything will do */
static char *s_cert_file=TEST_CERT,*s_key_file=NULL;
static char *s_dcert_file=NULL,*s_dkey_file=NULL;
#ifdef FIONBIO
static int s_nbio=0;
#endif
static int s_nbio_test=0;
int s_crlf=0;
static SSL_CTX *ctx=NULL;
static int www=0;

static BIO *bio_s_out=NULL;
static int s_debug=0;
static int s_msg=0;
static int s_quiet=0;

static int hack=0;
#ifndef OPENSSL_NO_ENGINE
static char *engine_id=NULL;
#endif
static const char *session_id_prefix=NULL;

#ifdef MONOLITH
static void s_server_init(void)
	{
	accept_socket=-1;
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
	s_msg=0;
	s_quiet=0;
	hack=0;
#ifndef OPENSSL_NO_ENGINE
	engine_id=NULL;
#endif
	}
#endif

static void sv_usage(void)
	{
	BIO_printf(bio_err,"usage: s_server [args ...]\n");
	BIO_printf(bio_err,"\n");
	BIO_printf(bio_err," -accept arg   - port to accept on (default is %d)\n",PORT);
	BIO_printf(bio_err," -context arg  - set session ID context\n");
	BIO_printf(bio_err," -verify arg   - turn on peer certificate verification\n");
	BIO_printf(bio_err," -Verify arg   - turn on peer certificate verification, must have a cert.\n");
	BIO_printf(bio_err," -cert arg     - certificate file to use, PEM format assumed\n");
	BIO_printf(bio_err,"                 (default is %s)\n",TEST_CERT);
	BIO_printf(bio_err," -key arg      - Private Key file to use, PEM format assumed, in cert file if\n");
	BIO_printf(bio_err,"                 not specified (default is %s)\n",TEST_CERT);
	BIO_printf(bio_err," -dcert arg    - second certificate file to use (usually for DSA)\n");
	BIO_printf(bio_err," -dkey arg     - second private key file to use (usually for DSA)\n");
	BIO_printf(bio_err," -dhparam arg  - DH parameter file to use, in cert file if not specified\n");
	BIO_printf(bio_err,"                 or a default set of parameters is used\n");
#ifdef FIONBIO
	BIO_printf(bio_err," -nbio         - Run with non-blocking IO\n");
#endif
	BIO_printf(bio_err," -nbio_test    - test with the non-blocking test bio\n");
	BIO_printf(bio_err," -crlf         - convert LF from terminal into CRLF\n");
	BIO_printf(bio_err," -debug        - Print more output\n");
	BIO_printf(bio_err," -msg          - Show protocol messages\n");
	BIO_printf(bio_err," -state        - Print the SSL states\n");
	BIO_printf(bio_err," -CApath arg   - PEM format directory of CA's\n");
	BIO_printf(bio_err," -CAfile arg   - PEM format file of CA's\n");
	BIO_printf(bio_err," -nocert       - Don't use any certificates (Anon-DH)\n");
	BIO_printf(bio_err," -cipher arg   - play with 'openssl ciphers' to see what goes here\n");
	BIO_printf(bio_err," -serverpref   - Use server's cipher preferences\n");
	BIO_printf(bio_err," -quiet        - No server output\n");
	BIO_printf(bio_err," -no_tmp_rsa   - Do not generate a tmp RSA key\n");
	BIO_printf(bio_err," -ssl2         - Just talk SSLv2\n");
	BIO_printf(bio_err," -ssl3         - Just talk SSLv3\n");
	BIO_printf(bio_err," -tls1         - Just talk TLSv1\n");
	BIO_printf(bio_err," -no_ssl2      - Just disable SSLv2\n");
	BIO_printf(bio_err," -no_ssl3      - Just disable SSLv3\n");
	BIO_printf(bio_err," -no_tls1      - Just disable TLSv1\n");
#ifndef OPENSSL_NO_DH
	BIO_printf(bio_err," -no_dhe       - Disable ephemeral DH\n");
#endif
	BIO_printf(bio_err," -bugs         - Turn on SSL bug compatibility\n");
	BIO_printf(bio_err," -www          - Respond to a 'GET /' with a status page\n");
	BIO_printf(bio_err," -WWW          - Respond to a 'GET /<path> HTTP/1.0' with file ./<path>\n");
	BIO_printf(bio_err," -HTTP         - Respond to a 'GET /<path> HTTP/1.0' with file ./<path>\n");
        BIO_printf(bio_err,"                 with the assumption it contains a complete HTTP response.\n");
#ifndef OPENSSL_NO_ENGINE
	BIO_printf(bio_err," -engine id    - Initialise and use the specified engine\n");
#endif
	BIO_printf(bio_err," -id_prefix arg - Generate SSL/TLS session IDs prefixed by 'arg'\n");
	BIO_printf(bio_err," -rand file%cfile%c...\n", LIST_SEPARATOR_CHAR, LIST_SEPARATOR_CHAR);
	}

static int local_argc=0;
static char **local_argv;

#ifdef CHARSET_EBCDIC
static int ebcdic_new(BIO *bi);
static int ebcdic_free(BIO *a);
static int ebcdic_read(BIO *b, char *out, int outl);
static int ebcdic_write(BIO *b, const char *in, int inl);
static long ebcdic_ctrl(BIO *b, int cmd, long num, void *ptr);
static int ebcdic_gets(BIO *bp, char *buf, int size);
static int ebcdic_puts(BIO *bp, const char *str);

#define BIO_TYPE_EBCDIC_FILTER	(18|0x0200)
static BIO_METHOD methods_ebcdic=
	{
	BIO_TYPE_EBCDIC_FILTER,
	"EBCDIC/ASCII filter",
	ebcdic_write,
	ebcdic_read,
	ebcdic_puts,
	ebcdic_gets,
	ebcdic_ctrl,
	ebcdic_new,
	ebcdic_free,
	};

typedef struct
{
	size_t	alloced;
	char	buff[1];
} EBCDIC_OUTBUFF;

BIO_METHOD *BIO_f_ebcdic_filter()
{
	return(&methods_ebcdic);
}

static int ebcdic_new(BIO *bi)
{
	EBCDIC_OUTBUFF *wbuf;

	wbuf = (EBCDIC_OUTBUFF *)OPENSSL_malloc(sizeof(EBCDIC_OUTBUFF) + 1024);
	wbuf->alloced = 1024;
	wbuf->buff[0] = '\0';

	bi->ptr=(char *)wbuf;
	bi->init=1;
	bi->flags=0;
	return(1);
}

static int ebcdic_free(BIO *a)
{
	if (a == NULL) return(0);
	if (a->ptr != NULL)
		OPENSSL_free(a->ptr);
	a->ptr=NULL;
	a->init=0;
	a->flags=0;
	return(1);
}
	
static int ebcdic_read(BIO *b, char *out, int outl)
{
	int ret=0;

	if (out == NULL || outl == 0) return(0);
	if (b->next_bio == NULL) return(0);

	ret=BIO_read(b->next_bio,out,outl);
	if (ret > 0)
		ascii2ebcdic(out,out,ret);
	return(ret);
}

static int ebcdic_write(BIO *b, const char *in, int inl)
{
	EBCDIC_OUTBUFF *wbuf;
	int ret=0;
	int num;
	unsigned char n;

	if ((in == NULL) || (inl <= 0)) return(0);
	if (b->next_bio == NULL) return(0);

	wbuf=(EBCDIC_OUTBUFF *)b->ptr;

	if (inl > (num = wbuf->alloced))
	{
		num = num + num;  /* double the size */
		if (num < inl)
			num = inl;
		OPENSSL_free(wbuf);
		wbuf=(EBCDIC_OUTBUFF *)OPENSSL_malloc(sizeof(EBCDIC_OUTBUFF) + num);

		wbuf->alloced = num;
		wbuf->buff[0] = '\0';

		b->ptr=(char *)wbuf;
	}

	ebcdic2ascii(wbuf->buff, in, inl);

	ret=BIO_write(b->next_bio, wbuf->buff, inl);

	return(ret);
}

static long ebcdic_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	long ret;

	if (b->next_bio == NULL) return(0);
	switch (cmd)
	{
	case BIO_CTRL_DUP:
		ret=0L;
		break;
	default:
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
		break;
	}
	return(ret);
}

static int ebcdic_gets(BIO *bp, char *buf, int size)
{
	int i, ret=0;
	if (bp->next_bio == NULL) return(0);
/*	return(BIO_gets(bp->next_bio,buf,size));*/
	for (i=0; i<size-1; ++i)
	{
		ret = ebcdic_read(bp,&buf[i],1);
		if (ret <= 0)
			break;
		else if (buf[i] == '\n')
		{
			++i;
			break;
		}
	}
	if (i < size)
		buf[i] = '\0';
	return (ret < 0 && i == 0) ? ret : i;
}

static int ebcdic_puts(BIO *bp, const char *str)
{
	if (bp->next_bio == NULL) return(0);
	return ebcdic_write(bp, str, strlen(str));
}
#endif

int MAIN(int, char **);

int MAIN(int argc, char *argv[])
	{
	X509_STORE *store = NULL;
	int vflags = 0;
	short port=PORT;
	char *CApath=NULL,*CAfile=NULL;
	char *context = NULL;
	char *dhfile = NULL;
	int badop=0,bugs=0;
	int ret=1;
	int off=0;
	int no_tmp_rsa=0,no_dhe=0,nocert=0;
	int state=0;
	SSL_METHOD *meth=NULL;
#ifndef OPENSSL_NO_ENGINE
	ENGINE *e=NULL;
#endif
	char *inrand=NULL;

#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_SSL3)
	meth=SSLv23_server_method();
#elif !defined(OPENSSL_NO_SSL3)
	meth=SSLv3_server_method();
#elif !defined(OPENSSL_NO_SSL2)
	meth=SSLv2_server_method();
#endif

	local_argc=argc;
	local_argv=argv;

	apps_startup();
#ifdef MONOLITH
	s_server_init();
#endif

	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);

	if (!load_config(bio_err, NULL))
		goto end;

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
		else if	(strcmp(*argv,"-context") == 0)
			{
			if (--argc < 1) goto bad;
			context= *(++argv);
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
		else if	(strcmp(*argv,"-dhparam") == 0)
			{
			if (--argc < 1) goto bad;
			dhfile = *(++argv);
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
		else if (strcmp(*argv,"-crl_check") == 0)
			{
			vflags |= X509_V_FLAG_CRL_CHECK;
			}
		else if (strcmp(*argv,"-crl_check") == 0)
			{
			vflags |= X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL;
			}
		else if	(strcmp(*argv,"-serverpref") == 0)
			{ off|=SSL_OP_CIPHER_SERVER_PREFERENCE; }
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
		else if	(strcmp(*argv,"-msg") == 0)
			{ s_msg=1; }
		else if	(strcmp(*argv,"-hack") == 0)
			{ hack=1; }
		else if	(strcmp(*argv,"-state") == 0)
			{ state=1; }
		else if	(strcmp(*argv,"-crlf") == 0)
			{ s_crlf=1; }
		else if	(strcmp(*argv,"-quiet") == 0)
			{ s_quiet=1; }
		else if	(strcmp(*argv,"-bugs") == 0)
			{ bugs=1; }
		else if	(strcmp(*argv,"-no_tmp_rsa") == 0)
			{ no_tmp_rsa=1; }
		else if	(strcmp(*argv,"-no_dhe") == 0)
			{ no_dhe=1; }
		else if	(strcmp(*argv,"-www") == 0)
			{ www=1; }
		else if	(strcmp(*argv,"-WWW") == 0)
			{ www=2; }
		else if	(strcmp(*argv,"-HTTP") == 0)
			{ www=3; }
		else if	(strcmp(*argv,"-no_ssl2") == 0)
			{ off|=SSL_OP_NO_SSLv2; }
		else if	(strcmp(*argv,"-no_ssl3") == 0)
			{ off|=SSL_OP_NO_SSLv3; }
		else if	(strcmp(*argv,"-no_tls1") == 0)
			{ off|=SSL_OP_NO_TLSv1; }
#ifndef OPENSSL_NO_SSL2
		else if	(strcmp(*argv,"-ssl2") == 0)
			{ meth=SSLv2_server_method(); }
#endif
#ifndef OPENSSL_NO_SSL3
		else if	(strcmp(*argv,"-ssl3") == 0)
			{ meth=SSLv3_server_method(); }
#endif
#ifndef OPENSSL_NO_TLS1
		else if	(strcmp(*argv,"-tls1") == 0)
			{ meth=TLSv1_server_method(); }
#endif
		else if (strcmp(*argv, "-id_prefix") == 0)
			{
			if (--argc < 1) goto bad;
			session_id_prefix = *(++argv);
			}
#ifndef OPENSSL_NO_ENGINE
		else if (strcmp(*argv,"-engine") == 0)
			{
			if (--argc < 1) goto bad;
			engine_id= *(++argv);
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
		sv_usage();
		goto end;
		}

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

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

	if (bio_s_out == NULL)
		{
		if (s_quiet && !s_debug && !s_msg)
			{
			bio_s_out=BIO_new(BIO_s_null());
			}
		else
			{
			if (bio_s_out == NULL)
				bio_s_out=BIO_new_fp(stdout,BIO_NOCLOSE);
			}
		}

#if !defined(OPENSSL_NO_RSA) || !defined(OPENSSL_NO_DSA)
	if (nocert)
#endif
		{
		s_cert_file=NULL;
		s_key_file=NULL;
		s_dcert_file=NULL;
		s_dkey_file=NULL;
		}

	ctx=SSL_CTX_new(meth);
	if (ctx == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}
	if (session_id_prefix)
		{
		if(strlen(session_id_prefix) >= 32)
			BIO_printf(bio_err,
"warning: id_prefix is too long, only one new session will be possible\n");
		else if(strlen(session_id_prefix) >= 16)
			BIO_printf(bio_err,
"warning: id_prefix is too long if you use SSLv2\n");
		if(!SSL_CTX_set_generate_session_id(ctx, generate_session_id))
			{
			BIO_printf(bio_err,"error setting 'id_prefix'\n");
			ERR_print_errors(bio_err);
			goto end;
			}
		BIO_printf(bio_err,"id_prefix '%s' set.\n", session_id_prefix);
		}
	SSL_CTX_set_quiet_shutdown(ctx,1);
	if (bugs) SSL_CTX_set_options(ctx,SSL_OP_ALL);
	if (hack) SSL_CTX_set_options(ctx,SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG);
	SSL_CTX_set_options(ctx,off);

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
	store = SSL_CTX_get_cert_store(ctx);
	X509_STORE_set_flags(store, vflags);

#ifndef OPENSSL_NO_DH
	if (!no_dhe)
		{
		DH *dh=NULL;

		if (dhfile)
			dh = load_dh_param(dhfile);
		else if (s_cert_file)
			dh = load_dh_param(s_cert_file);

		if (dh != NULL)
			{
			BIO_printf(bio_s_out,"Setting temp DH parameters\n");
			}
		else
			{
			BIO_printf(bio_s_out,"Using default temp DH parameters\n");
			dh=get_dh512();
			}
		(void)BIO_flush(bio_s_out);

		SSL_CTX_set_tmp_dh(ctx,dh);
		DH_free(dh);
		}
#endif
	
	if (!set_cert_stuff(ctx,s_cert_file,s_key_file))
		goto end;
	if (s_dcert_file != NULL)
		{
		if (!set_cert_stuff(ctx,s_dcert_file,s_dkey_file))
			goto end;
		}

#ifndef OPENSSL_NO_RSA
#if 1
	if (!no_tmp_rsa)
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
#endif

	if (cipher != NULL)
		if(!SSL_CTX_set_cipher_list(ctx,cipher)) {
		BIO_printf(bio_err,"error setting cipher list\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	SSL_CTX_set_verify(ctx,s_server_verify,verify_callback);
	SSL_CTX_set_session_id_context(ctx,(void*)&s_server_session_id_context,
		sizeof s_server_session_id_context);

	if (CAfile != NULL)
	    SSL_CTX_set_client_CA_list(ctx,SSL_load_client_CA_file(CAfile));

	BIO_printf(bio_s_out,"ACCEPT\n");
	if (www)
		do_server(port,&accept_socket,www_body, context);
	else
		do_server(port,&accept_socket,sv_body, context);
	print_stats(bio_s_out,ctx);
	ret=0;
end:
	if (ctx != NULL) SSL_CTX_free(ctx);
	if (bio_s_out != NULL)
		{
		BIO_free(bio_s_out);
		bio_s_out=NULL;
		}
	apps_shutdown();
	OPENSSL_EXIT(ret);
	}

static void print_stats(BIO *bio, SSL_CTX *ssl_ctx)
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

static int sv_body(char *hostname, int s, unsigned char *context)
	{
	char *buf=NULL;
	fd_set readfds;
	int ret=1,width;
	int k,i;
	unsigned long l;
	SSL *con=NULL;
	BIO *sbio;
#ifdef OPENSSL_SYS_WINDOWS
	struct timeval tv;
#endif

	if ((buf=OPENSSL_malloc(bufsize)) == NULL)
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

	if (con == NULL) {
		con=SSL_new(ctx);
#ifndef OPENSSL_NO_KRB5
		if ((con->kssl_ctx = kssl_ctx_new()) != NULL)
                        {
                        kssl_ctx_setstring(con->kssl_ctx, KSSL_SERVICE,
								KRB5SVC);
                        kssl_ctx_setstring(con->kssl_ctx, KSSL_KEYTAB,
								KRB5KEYTAB);
                        }
#endif	/* OPENSSL_NO_KRB5 */
		if(context)
		      SSL_set_session_id_context(con, context,
						 strlen((char *)context));
	}
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
	if (s_msg)
		{
		SSL_set_msg_callback(con, msg_cb);
		SSL_set_msg_callback_arg(con, bio_s_out);
		}

	width=s+1;
	for (;;)
		{
		int read_from_terminal;
		int read_from_sslcon;

		read_from_terminal = 0;
		read_from_sslcon = SSL_pending(con);

		if (!read_from_sslcon)
			{
			FD_ZERO(&readfds);
#ifndef OPENSSL_SYS_WINDOWS
			FD_SET(fileno(stdin),&readfds);
#endif
			FD_SET(s,&readfds);
			/* Note: under VMS with SOCKETSHR the second parameter is
			 * currently of type (int *) whereas under other systems
			 * it is (void *) if you don't have a cast it will choke
			 * the compiler: if you do have a cast then you can either
			 * go for (int *) or (void *).
			 */
#ifdef OPENSSL_SYS_WINDOWS
			/* Under Windows we can't select on stdin: only
			 * on sockets. As a workaround we timeout the select every
			 * second and check for any keypress. In a proper Windows
			 * application we wouldn't do this because it is inefficient.
			 */
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			i=select(width,(void *)&readfds,NULL,NULL,&tv);
			if((i < 0) || (!i && !_kbhit() ) )continue;
			if(_kbhit())
				read_from_terminal = 1;
#else
			i=select(width,(void *)&readfds,NULL,NULL,NULL);
			if (i <= 0) continue;
			if (FD_ISSET(fileno(stdin),&readfds))
				read_from_terminal = 1;
#endif
			if (FD_ISSET(s,&readfds))
				read_from_sslcon = 1;
			}
		if (read_from_terminal)
			{
			if (s_crlf)
				{
				int j, lf_num;

				i=read(fileno(stdin), buf, bufsize/2);
				lf_num = 0;
				/* both loops are skipped when i <= 0 */
				for (j = 0; j < i; j++)
					if (buf[j] == '\n')
						lf_num++;
				for (j = i-1; j >= 0; j--)
					{
					buf[j+lf_num] = buf[j];
					if (buf[j] == '\n')
						{
						lf_num--;
						i++;
						buf[j+lf_num] = '\r';
						}
					}
				assert(lf_num == 0);
				}
			else
				i=read(fileno(stdin),buf,bufsize);
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
					/* strcpy(buf,"server side RE-NEGOTIATE\n"); */
					}
				if ((buf[0] == 'R') &&
					((buf[1] == '\n') || (buf[1] == '\r')))
					{
					SSL_set_verify(con,
						SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE,NULL);
					SSL_renegotiate(con);
					i=SSL_do_handshake(con);
					printf("SSL_do_handshake -> %d\n",i);
					i=0; /* 13; */
					continue;
					/* strcpy(buf,"server side RE-NEGOTIATE asking for client cert\n"); */
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
#ifdef CHARSET_EBCDIC
			ebcdic2ascii(buf,buf,i);
#endif
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
					/* break; */
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
		if (read_from_sslcon)
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
again:	
				i=SSL_read(con,(char *)buf,bufsize);
				switch (SSL_get_error(con,i))
					{
				case SSL_ERROR_NONE:
#ifdef CHARSET_EBCDIC
					ascii2ebcdic(buf,buf,i);
#endif
					write(fileno(stdout),buf,
						(unsigned int)i);
					if (SSL_pending(con)) goto again;
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
		OPENSSL_cleanse(buf,bufsize);
		OPENSSL_free(buf);
		}
	if (ret >= 0)
		BIO_printf(bio_s_out,"ACCEPT\n");
	return(ret);
	}

static void close_accept_socket(void)
	{
	BIO_printf(bio_err,"shutdown accept socket\n");
	if (accept_socket >= 0)
		{
		SHUTDOWN2(accept_socket);
		}
	}

static int init_ssl_connection(SSL *con)
	{
	int i;
	const char *str;
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
		X509_NAME_oneline(X509_get_subject_name(peer),buf,sizeof buf);
		BIO_printf(bio_s_out,"subject=%s\n",buf);
		X509_NAME_oneline(X509_get_issuer_name(peer),buf,sizeof buf);
		BIO_printf(bio_s_out,"issuer=%s\n",buf);
		X509_free(peer);
		}

	if (SSL_get_shared_ciphers(con,buf,sizeof buf) != NULL)
		BIO_printf(bio_s_out,"Shared ciphers:%s\n",buf);
	str=SSL_CIPHER_get_name(SSL_get_current_cipher(con));
	BIO_printf(bio_s_out,"CIPHER is %s\n",(str != NULL)?str:"(NONE)");
	if (con->hit) BIO_printf(bio_s_out,"Reused session-id\n");
	if (SSL_ctrl(con,SSL_CTRL_GET_FLAGS,0,NULL) &
		TLS1_FLAGS_TLS_PADDING_BUG)
		BIO_printf(bio_s_out,"Peer has incorrect TLSv1 block padding\n");

	return(1);
	}

#ifndef OPENSSL_NO_DH
static DH *load_dh_param(char *dhfile)
	{
	DH *ret=NULL;
	BIO *bio;

	if ((bio=BIO_new_file(dhfile,"r")) == NULL)
		goto err;
	ret=PEM_read_bio_DHparams(bio,NULL,NULL,NULL);
err:
	if (bio != NULL) BIO_free(bio);
	return(ret);
	}
#endif

#if 0
static int load_CA(SSL_CTX *ctx, char *file)
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

static int www_body(char *hostname, int s, unsigned char *context)
	{
	char *buf=NULL;
	int ret=1;
	int i,j,k,blank,dot;
	struct stat st_buf;
	SSL *con;
	SSL_CIPHER *c;
	BIO *io,*ssl_bio,*sbio;
	long total_bytes;

	buf=OPENSSL_malloc(bufsize);
	if (buf == NULL) return(0);
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
	if (!BIO_set_write_buffer_size(io,bufsize)) goto err;

	if ((con=SSL_new(ctx)) == NULL) goto err;
#ifndef OPENSSL_NO_KRB5
	if ((con->kssl_ctx = kssl_ctx_new()) != NULL)
		{
		kssl_ctx_setstring(con->kssl_ctx, KSSL_SERVICE, KRB5SVC);
		kssl_ctx_setstring(con->kssl_ctx, KSSL_KEYTAB, KRB5KEYTAB);
		}
#endif	/* OPENSSL_NO_KRB5 */
	if(context) SSL_set_session_id_context(con, context,
					       strlen((char *)context));

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
#ifdef CHARSET_EBCDIC
	io = BIO_push(BIO_new(BIO_f_ebcdic_filter()),io);
#endif

	if (s_debug)
		{
		con->debug=1;
		BIO_set_callback(SSL_get_rbio(con),bio_dump_cb);
		BIO_set_callback_arg(SSL_get_rbio(con),bio_s_out);
		}
	if (s_msg)
		{
		SSL_set_msg_callback(con, msg_cb);
		SSL_set_msg_callback_arg(con, bio_s_out);
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
				/* break; */
				}

			SSL_renegotiate(con);
			SSL_write(con,NULL,0);
			}

		i=BIO_gets(io,buf,bufsize-1);
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
#if !defined(OPENSSL_SYS_MSDOS) && !defined(__DJGPP__)
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
			STACK_OF(SSL_CIPHER) *sk;
			static char *space="                          ";

			BIO_puts(io,"HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
			BIO_puts(io,"<HTML><BODY BGCOLOR=\"#ffffff\">\n");
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
			j=sk_SSL_CIPHER_num(sk);
			for (i=0; i<j; i++)
				{
				c=sk_SSL_CIPHER_value(sk,i);
				BIO_printf(io,"%-11s:%-25s",
					SSL_CIPHER_get_version(c),
					SSL_CIPHER_get_name(c));
				if ((((i+1)%2) == 0) && (i+1 != j))
					BIO_puts(io,"\n");
				}
			BIO_puts(io,"\n");
			p=SSL_get_shared_ciphers(con,buf,bufsize);
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
		else if ((www == 2 || www == 3)
                         && (strncmp("GET /",buf,5) == 0))
			{
			BIO *file;
			char *p,*e;
			static char *text="HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n";

			/* skip the '/' */
			p= &(buf[5]);

			dot = 1;
			for (e=p; *e != '\0'; e++)
				{
				if (e[0] == ' ')
					break;

				switch (dot)
					{
				case 1:
					dot = (e[0] == '.') ? 2 : 0;
					break;
				case 2:
					dot = (e[0] == '.') ? 3 : 0;
					break;
				case 3:
					dot = (e[0] == '/') ? -1 : 0;
					break;
					}
				if (dot == 0)
					dot = (e[0] == '/') ? 1 : 0;
				}
			dot = (dot == 3) || (dot == -1); /* filename contains ".." component */

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

#if 0
			/* append if a directory lookup */
			if (e[-1] == '/')
				strcat(p,"index.html");
#endif

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
#if 0 /* must check buffer size */
				strcat(p,"/index.html");
#else
				BIO_puts(io,text);
				BIO_printf(io,"'%s' is a directory\r\n",p);
				break;
#endif
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

                        if (www == 2)
                                {
                                i=strlen(p);
                                if (	((i > 5) && (strcmp(&(p[i-5]),".html") == 0)) ||
                                        ((i > 4) && (strcmp(&(p[i-4]),".php") == 0)) ||
                                        ((i > 4) && (strcmp(&(p[i-4]),".htm") == 0)))
                                        BIO_puts(io,"HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
                                else
                                        BIO_puts(io,"HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n");
                                }
			/* send the file */
			total_bytes=0;
			for (;;)
				{
				i=BIO_read(file,buf,bufsize);
				if (i <= 0) break;

#ifdef RENEG
				total_bytes+=i;
				fprintf(stderr,"%d\n",i);
				if (total_bytes > 3*1024)
					{
					total_bytes=0;
					fprintf(stderr,"RENEGOTIATE\n");
					SSL_renegotiate(con);
					}
#endif

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
	/* This kills performance */
/*	SSL_shutdown(con); A shutdown gets sent in the
 *	BIO_free_all(io) procession */
#endif

err:

	if (ret >= 0)
		BIO_printf(bio_s_out,"ACCEPT\n");

	if (buf != NULL) OPENSSL_free(buf);
	if (io != NULL) BIO_free_all(io);
/*	if (ssl_bio != NULL) BIO_free(ssl_bio);*/
	return(ret);
	}

#ifndef OPENSSL_NO_RSA
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int is_export, int keylength)
	{
	static RSA *rsa_tmp=NULL;

	if (rsa_tmp == NULL)
		{
		if (!s_quiet)
			{
			BIO_printf(bio_err,"Generating temp (%d bit) RSA key...",keylength);
			(void)BIO_flush(bio_err);
			}
		rsa_tmp=RSA_generate_key(keylength,RSA_F4,NULL,NULL);
		if (!s_quiet)
			{
			BIO_printf(bio_err,"\n");
			(void)BIO_flush(bio_err);
			}
		}
	return(rsa_tmp);
	}
#endif

#define MAX_SESSION_ID_ATTEMPTS 10
static int generate_session_id(const SSL *ssl, unsigned char *id,
				unsigned int *id_len)
	{
	unsigned int count = 0;
	do	{
		RAND_pseudo_bytes(id, *id_len);
		/* Prefix the session_id with the required prefix. NB: If our
		 * prefix is too long, clip it - but there will be worse effects
		 * anyway, eg. the server could only possibly create 1 session
		 * ID (ie. the prefix!) so all future session negotiations will
		 * fail due to conflicts. */
		memcpy(id, session_id_prefix,
			(strlen(session_id_prefix) < *id_len) ?
			strlen(session_id_prefix) : *id_len);
		}
	while(SSL_has_matching_session_id(ssl, id, *id_len) &&
		(++count < MAX_SESSION_ID_ATTEMPTS));
	if(count >= MAX_SESSION_ID_ATTEMPTS)
		return 0;
	return 1;
	}
