/* apps/apps.h */
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

#ifndef HEADER_APPS_H
#define HEADER_APPS_H

#include "openssl/e_os.h"

#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>

int app_RAND_load_file(const char *file, BIO *bio_e, int dont_warn);
int app_RAND_write_file(const char *file, BIO *bio_e);
/* When `file' is NULL, use defaults.
 * `bio_e' is for error messages. */
void app_RAND_allow_write_file(void);
long app_RAND_load_files(char *file); /* `file' is a list of files to read,
                                       * separated by LIST_SEPARATOR_CHAR
                                       * (see e_os.h).  The string is
                                       * destroyed! */

#ifdef NO_STDIO
BIO_METHOD *BIO_s_file();
#endif

#ifdef WIN32
#define rename(from,to) WIN32_rename((from),(to))
int WIN32_rename(char *oldname,char *newname);
#endif

#ifndef MONOLITH

#define MAIN(a,v)	main(a,v)

#ifndef NON_MAIN
BIO *bio_err=NULL;
#else
extern BIO *bio_err;
#endif

#else

#define MAIN(a,v)	PROG(a,v)
#include <openssl/conf.h>
extern LHASH *config;
extern char *default_config_file;
extern BIO *bio_err;

#endif

#include <signal.h>

#ifdef SIGPIPE
#define do_pipe_sig()	signal(SIGPIPE,SIG_IGN)
#else
#define do_pipe_sig()
#endif

#if defined(MONOLITH) && !defined(OPENSSL_C)
#  define apps_startup()	do_pipe_sig()
#else
#  if defined(MSDOS) || defined(WIN16) || defined(WIN32)
#    ifdef _O_BINARY
#      define apps_startup() \
		_fmode=_O_BINARY; do_pipe_sig(); CRYPTO_malloc_init(); \
		SSLeay_add_all_algorithms()
#    else
#      define apps_startup() \
		_fmode=O_BINARY; do_pipe_sig(); CRYPTO_malloc_init(); \
		SSLeay_add_all_algorithms()
#    endif
#  else
#    define apps_startup()	do_pipe_sig(); SSLeay_add_all_algorithms();
#  endif
#endif

typedef struct args_st
	{
	char **data;
	int count;
	} ARGS;

int should_retry(int i);
int args_from_file(char *file, int *argc, char **argv[]);
int str2fmt(char *s);
void program_name(char *in,char *out,int size);
int chopup_args(ARGS *arg,char *buf, int *argc, char **argv[]);
#ifdef HEADER_X509_H
int dump_cert_text(BIO *out, X509 *x);
#endif
int app_passwd(BIO *err, char *arg1, char *arg2, char **pass1, char **pass2);
#define FORMAT_UNDEF    0
#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define FORMAT_NETSCAPE 4

#define APP_PASS_LEN	1024

#endif
