/* apps/s_cb.c */
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
#define USE_SOCKETS
#define NON_MAIN
#include "apps.h"
#undef NON_MAIN
#undef USE_SOCKETS
#include "err.h"
#include "x509.h"
#include "ssl.h"
#include "s_apps.h"

int verify_depth=0;
int verify_error=X509_V_OK;

int MS_CALLBACK verify_callback(ok, ctx)
int ok;
X509_STORE_CTX *ctx;
	{
	char buf[256];
	X509 *err_cert;
	int err,depth;

	err_cert=X509_STORE_CTX_get_current_cert(ctx);
	err=	X509_STORE_CTX_get_error(ctx);
	depth=	X509_STORE_CTX_get_error_depth(ctx);

	X509_NAME_oneline(X509_get_subject_name(err_cert),buf,256);
	BIO_printf(bio_err,"depth=%d %s\n",depth,buf);
	if (!ok)
		{
		BIO_printf(bio_err,"verify error:num=%d:%s\n",err,
			X509_verify_cert_error_string(err));
		if (verify_depth >= depth)
			{
			ok=1;
			verify_error=X509_V_OK;
			}
		else
			{
			ok=0;
			verify_error=X509_V_ERR_CERT_CHAIN_TOO_LONG;
			}
		}
	switch (ctx->error)
		{
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),buf,256);
		BIO_printf(bio_err,"issuer= %s\n",buf);
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		BIO_printf(bio_err,"notBefore=");
		ASN1_UTCTIME_print(bio_err,X509_get_notBefore(ctx->current_cert));
		BIO_printf(bio_err,"\n");
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		BIO_printf(bio_err,"notAfter=");
		ASN1_UTCTIME_print(bio_err,X509_get_notAfter(ctx->current_cert));
		BIO_printf(bio_err,"\n");
		break;
		}
	BIO_printf(bio_err,"verify return:%d\n",ok);
	return(ok);
	}

int set_cert_stuff(ctx, cert_file, key_file)
SSL_CTX *ctx;
char *cert_file;
char *key_file;
	{
	if (cert_file != NULL)
		{
		SSL *ssl;
		X509 *x509;

		if (SSL_CTX_use_certificate_file(ctx,cert_file,
			SSL_FILETYPE_PEM) <= 0)
			{
			BIO_printf(bio_err,"unable to get certificate from '%s'\n",cert_file);
			ERR_print_errors(bio_err);
			return(0);
			}
		if (key_file == NULL) key_file=cert_file;
		if (SSL_CTX_use_PrivateKey_file(ctx,key_file,
			SSL_FILETYPE_PEM) <= 0)
			{
			BIO_printf(bio_err,"unable to get private key from '%s'\n",key_file);
			ERR_print_errors(bio_err);
			return(0);
			}

		ssl=SSL_new(ctx);
		x509=SSL_get_certificate(ssl);

		if (x509 != NULL)
			EVP_PKEY_copy_parameters(X509_get_pubkey(x509),
				SSL_get_privatekey(ssl));
		SSL_free(ssl);

		/* If we are using DSA, we can copy the parameters from
		 * the private key */
		
		
		/* Now we know that a key and cert have been set against
		 * the SSL context */
		if (!SSL_CTX_check_private_key(ctx))
			{
			BIO_printf(bio_err,"Private key does not match the certificate public key\n");
			return(0);
			}
		}
	return(1);
	}

long MS_CALLBACK bio_dump_cb(bio,cmd,argp,argi,argl,ret)
BIO *bio;
int cmd;
char *argp;
int argi;
long argl;
long ret;
	{
	BIO *out;

	out=(BIO *)BIO_get_callback_arg(bio);
	if (out == NULL) return(ret);

	if (cmd == (BIO_CB_READ|BIO_CB_RETURN))
		{
		BIO_printf(out,"read from %08X [%08lX] (%d bytes => %ld (0x%X))\n",
			bio,argp,argi,ret,ret);
		BIO_dump(out,argp,(int)ret);
		return(ret);
		}
	else if (cmd == (BIO_CB_WRITE|BIO_CB_RETURN))
		{
		BIO_printf(out,"write to %08X [%08lX] (%d bytes => %ld (0x%X))\n",
			bio,argp,argi,ret,ret);
		BIO_dump(out,argp,(int)ret);
		}
	return(ret);
	}

void MS_CALLBACK apps_ssl_info_callback(s,where,ret)
SSL *s;
int where;
int ret;
	{
	char *str;
	int w;

	w=where& ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT) str="SSL_connect";
	else if (w & SSL_ST_ACCEPT) str="SSL_accept";
	else str="undefined";

	if (where & SSL_CB_LOOP)
		{
		BIO_printf(bio_err,"%s:%s\n",str,SSL_state_string_long(s));
		}
	else if (where & SSL_CB_ALERT)
		{
		str=(where & SSL_CB_READ)?"read":"write";
		BIO_printf(bio_err,"SSL3 alert %s:%s:%s\n",
			str,
			SSL_alert_type_string_long(ret),
			SSL_alert_desc_string_long(ret));
		}
	else if (where & SSL_CB_EXIT)
		{
		if (ret == 0)
			BIO_printf(bio_err,"%s:failed in %s\n",
				str,SSL_state_string_long(s));
		else if (ret < 0)
			{
			BIO_printf(bio_err,"%s:error in %s\n",
				str,SSL_state_string_long(s));
			}
		}
	}

