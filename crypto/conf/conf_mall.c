/* conf_mall.c */
/* Written by Stephen Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2001.
 */
/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
#include <openssl/crypto.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/dso.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

void OPENSSL_load_builtin_modules(void)
	{
	/* Add builtin modules here */
	ASN1_add_oid_module();
	}

/* This is the automatic configuration loader: it is called automatically by
 * OpenSSL when any of a number of standard initialisation functions are called,
 * unless this is overridden by calling OPENSSL_no_config()
 */

static int openssl_configured = 0;

void OPENSSL_config(void)
	{
	char *file, config_name[256];
	if (openssl_configured)
		return;

	OPENSSL_load_builtin_modules();

	file = getenv("OPENSSL_CONF");
	if (!file)
                {
		strcpy(config_name,X509_get_default_cert_area());
#ifndef OPENSSL_SYS_VMS
		strcat(config_name,"/");
#endif
		strcat(config_name,OPENSSL_CONF);
		file=config_name;
                }

	if(CONF_modules_load_file(file, "openssl_config", 0) <= 0)
		{
		BIO *bio_err;

		ERR_load_crypto_strings();
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			{
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
			BIO_printf(bio_err,"Auto configuration failed\n");
			ERR_print_errors(bio_err);
			}
		exit(1);
		}

	return;

	}

void OPENSSL_no_config()
	{
	openssl_configured = 1;
	}
