/* ocsp.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include <string.h>
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include "apps.h"

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert, X509 *issuer,
				STACK_OF(OCSP_CERTID) *ids);
static int add_ocsp_serial(OCSP_REQUEST **req, char *serial, X509 *issuer,
				STACK_OF(OCSP_CERTID) *ids);
static int print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
				STACK *names, STACK_OF(OCSP_CERTID) *ids);

#undef PROG
#define PROG ocsp_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
	{
	char **args;
	char *host = NULL, *path = "/";
	char *reqin = NULL, *respin = NULL;
	char *reqout = NULL, *respout = NULL;
	char *signfile = NULL, *keyfile = NULL;
	char *outfile = NULL;
	int add_nonce = 1, noverify = 0;
	OCSP_REQUEST *req = NULL;
	OCSP_RESPONSE *resp = NULL;
	OCSP_BASICRESP *bs = NULL;
	X509 *issuer = NULL, *cert = NULL;
	X509 *signer = NULL;
	EVP_PKEY *key = NULL;
	BIO *cbio = NULL, *derbio = NULL;
	BIO *out = NULL;
	int req_text = 0, resp_text = 0;
	char *CAfile = NULL, *CApath = NULL;
	X509_STORE *store = NULL;
	int ret = 1;
	int badarg = 0;
	int i;
	STACK *reqnames = NULL;
	STACK_OF(OCSP_CERTID) *ids = NULL;
	if (bio_err == NULL) bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	ERR_load_crypto_strings();
	args = argv + 1;
	reqnames = sk_new_null();
	ids = sk_OCSP_CERTID_new_null();
	while (!badarg && *args && *args[0] == '-')
		{
		if (!strcmp(*args, "-out"))
			{
			if (args[1])
				{
				args++;
				outfile = *args;
				}
			else badarg = 1;
			}
		else if (!strcmp(*args, "-host"))
			{
			if (args[1])
				{
				args++;
				host = *args;
				}
			else badarg = 1;
			}
		else if (!strcmp(*args, "-noverify"))
			noverify = 1;
		else if (!strcmp(*args, "-nonce"))
			add_nonce = 2;
		else if (!strcmp(*args, "-no_nonce"))
			add_nonce = 0;
		else if (!strcmp(*args, "-text"))
			{
			req_text = 1;
			resp_text = 1;
			}
		else if (!strcmp(*args, "-req_text"))
			req_text = 1;
		else if (!strcmp(*args, "-resp_text"))
			resp_text = 1;
		else if (!strcmp(*args, "-reqin"))
			{
			if (args[1])
				{
				args++;
				reqin = *args;
				}
			else badarg = 1;
			}
		else if (!strcmp(*args, "-respin"))
			{
			if (args[1])
				{
				args++;
				respin = *args;
				}
			else badarg = 1;
			}
		else if (!strcmp(*args, "-signer"))
			{
			if (args[1])
				{
				args++;
				signfile = *args;
				}
			else badarg = 1;
			}
		else if (!strcmp (*args, "-CAfile"))
			{
			if (args[1])
				{
				args++;
				CAfile = *args;
				}
			else badarg = 1;
			}
		else if (!strcmp (*args, "-CApath"))
			{
			if (args[1])
				{
				args++;
				CApath = *args;
				}
			else badarg = 1;
			}
		 else if (!strcmp(*args, "-signkey"))
			{
			if (args[1])
				{
				args++;
				keyfile = *args;
				}
			else badarg = 1;
			}
		else if (!strcmp(*args, "-reqout"))
			{
			if (args[1])
				{
				args++;
				reqout = *args;
				}
			else badarg = 1;
			}
		else if (!strcmp(*args, "-respout"))
			{
			if (args[1])
				{
				args++;
				respout = *args;
				}
			else badarg = 1;
			}
		 else if (!strcmp(*args, "-path"))
			{
			if (args[1])
				{
				args++;
				path = *args;
				}
			else badarg = 1;
			}
		else if (!strcmp(*args, "-issuer"))
			{
			if (args[1])
				{
				args++;
				X509_free(issuer);
				issuer = load_cert(bio_err, *args, FORMAT_PEM);
				if(!issuer) goto end;
				}
			else badarg = 1;
			}
		else if (!strcmp (*args, "-cert"))
			{
			if (args[1])
				{
				args++;
				X509_free(cert);
				cert = load_cert(bio_err, *args, FORMAT_PEM);
				if(!cert) goto end;
				if(!add_ocsp_cert(&req, cert, issuer, ids))
					goto end;
				if(!sk_push(reqnames, *args))
					goto end;
				}
			else badarg = 1;
			}
		else if (!strcmp(*args, "-serial"))
			{
			if (args[1])
				{
				args++;
				if(!add_ocsp_serial(&req, *args, issuer, ids))
					goto end;
				if(!sk_push(reqnames, *args))
					goto end;
				}
			else badarg = 1;
			}
		else badarg = 1;
		args++;
		}

	/* Have we anything to do? */
	if (!req && !reqin && !respin) badarg = 1;

	if (badarg)
		{
		BIO_printf (bio_err, "OCSP utility\n");
		BIO_printf (bio_err, "Usage ocsp [options]\n");
		BIO_printf (bio_err, "where options are\n");
		BIO_printf (bio_err, "-out file     output filename\n");
		BIO_printf (bio_err, "-issuer file  issuer certificate\n");
		BIO_printf (bio_err, "-cert file    certificate to check\n");
		BIO_printf (bio_err, "-serial n     serial number to check\n");
		BIO_printf (bio_err, "-signer file  certificate to sign OCSP request with\n");
		BIO_printf (bio_err, "-signkey file private key to sign OCSP request with\n");
		BIO_printf (bio_err, "-req_text     print text form of request\n");
		BIO_printf (bio_err, "-resp_text    print text form of response\n");
		BIO_printf (bio_err, "-text         print text form of request and response\n");
		BIO_printf (bio_err, "-reqout file  write DER encoded OCSP request to \"file\"\n");
		BIO_printf (bio_err, "-respout file write DER encoded OCSP reponse to \"file\"\n");
		BIO_printf (bio_err, "-reqin file   read DER encoded OCSP request from \"file\"\n");
		BIO_printf (bio_err, "-respin file  read DER encoded OCSP reponse from \"file\"\n");
		BIO_printf (bio_err, "-nonce        add OCSP nonce to request\n");
		BIO_printf (bio_err, "-no_nonce     don't add OCSP nonce to request\n");
		BIO_printf (bio_err, "-host host:n  send OCSP request to host on port n\n");
		BIO_printf (bio_err, "-path         path to use in OCSP request\n");
		BIO_printf (bio_err, "-CApath dir   trusted certificates directory\n");
		BIO_printf (bio_err, "-CAfile file  trusted certificates file\n");
		BIO_printf (bio_err, "-noverify     don't verify response\n");
		goto end;
		}

	if(outfile) out = BIO_new_file(outfile, "w");
	else out = BIO_new_fp(stdout, BIO_NOCLOSE);

	if(!out)
		{
		BIO_printf(bio_err, "Error opening output file\n");
		goto end;
		}

	if (!req && (add_nonce != 2)) add_nonce = 0;

	if (!req && reqin)
		{
		derbio = BIO_new_file(reqin, "rb");
		if (!derbio)
			{
			BIO_printf(bio_err, "Error Opening OCSP request file\n");
			goto end;
			}
		req = d2i_OCSP_REQUEST_bio(derbio, NULL);
		BIO_free(derbio);
		if(!req)
			{
			BIO_printf(bio_err, "Error reading OCSP request\n");
			goto end;
			}
		}

	if (!req && (signfile || reqout || host || add_nonce))
		{
		BIO_printf(bio_err, "Need an OCSP request for this operation!\n");
		goto end;
		}

	if (req && add_nonce) OCSP_request_add1_nonce(req, NULL, -1);

	if (signfile)
		{
		if (!keyfile) keyfile = signfile;
		signer = load_cert(bio_err, signfile, FORMAT_PEM);
		if (!signer)
			{
			BIO_printf(bio_err, "Error loading signer certificate\n");
			goto end;
			}
		key = load_key(bio_err, keyfile, FORMAT_PEM, NULL, NULL);
		if (!key)
			{
			BIO_printf(bio_err, "Error loading signer private key\n");
			goto end;
			}
		if (!OCSP_request_sign(req, signer, key, EVP_sha1(), NULL, 0))
			{
			BIO_printf(bio_err, "Error signing OCSP request\n");
			goto end;
			}
		}

	if (reqout)
		{
		derbio = BIO_new_file(reqout, "wb");
		if (!derbio)
			{
			BIO_printf(bio_err, "Error opening file %s\n", reqout);
			goto end;
			}
		i2d_OCSP_REQUEST_bio(derbio, req);
		BIO_free(derbio);
		}

	if (req_text && req) OCSP_REQUEST_print(out, req, 0);

	if (host)
		{
		cbio = BIO_new_connect(host);
		if (!cbio)
			{
			BIO_printf(bio_err, "Error creating connect BIO\n");
			goto end;
			}
		if (BIO_do_connect(cbio) <= 0)
			{
			BIO_printf(bio_err, "Error connecting BIO\n");
			goto end;
			}
		resp = OCSP_sendreq_bio(cbio, path, req);
		BIO_free(cbio);
		cbio = NULL;
		if (!resp)
			{
			BIO_printf(bio_err, "Error querying OCSP responsder\n");
			goto end;
			}
		}
	else if (respin)
		{
		derbio = BIO_new_file(respin, "rb");
		if (!derbio)
			{
			BIO_printf(bio_err, "Error Opening OCSP response file\n");
			goto end;
			}
		resp = d2i_OCSP_RESPONSE_bio(derbio, NULL);
		BIO_free(derbio);
		if(!resp)
			{
			BIO_printf(bio_err, "Error reading OCSP response\n");
			goto end;
			}
	
		}
	else
		{
		ret = 0;
		goto end;
		}

	if (respout)
		{
		derbio = BIO_new_file(respout, "wb");
		if(!derbio)
			{
			BIO_printf(bio_err, "Error opening file %s\n", respout);
			goto end;
			}
		i2d_OCSP_RESPONSE_bio(derbio, resp);
		BIO_free(derbio);
		}

	i = OCSP_response_status(resp);

	if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL)
		{
		BIO_printf(out, "Responder Error: %s (%ld)\n",
				OCSP_response_status_str(i), i);
		ret = 0;
		goto end;
		}

	if (resp_text) OCSP_RESPONSE_print(out, resp, 0);

	store = setup_verify(bio_err, CAfile, CApath);
	if(!store) goto end;

	bs = OCSP_response_get1_basic(resp);

	if (!bs)
		{
		BIO_printf(bio_err, "Error parsing response\n");
		goto end;
		}

	if (!noverify)
		{
		if (req && (OCSP_check_nonce(req, bs) <= 0))
			{
			BIO_printf(bio_err, "Nonce Verify error\n");
			goto end;
			}

		i = OCSP_basic_verify(bs, NULL, store, 0);

		if(i <= 0)
			{
			BIO_printf(bio_err, "Response Verify Failure\n", i);
			ERR_print_errors(bio_err);
			}
		else
			BIO_printf(bio_err, "Response verify OK\n");

		}

	if (!print_ocsp_summary(out, bs, req, reqnames, ids))
		goto end;

	ret = 0;

end:
	ERR_print_errors(bio_err);
	X509_free(signer);
	X509_STORE_free(store);
	EVP_PKEY_free(key);
	X509_free(issuer);
	X509_free(cert);
	BIO_free(cbio);
	BIO_free(out);
	OCSP_REQUEST_free(req);
	OCSP_RESPONSE_free(resp);
	OCSP_BASICRESP_free(bs);
	sk_free(reqnames);
	sk_OCSP_CERTID_free(ids);

	EXIT(ret);
}

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert, X509 *issuer,
				STACK_OF(OCSP_CERTID) *ids)
	{
	OCSP_CERTID *id;
	if(!issuer)
		{
		BIO_printf(bio_err, "No issuer certificate specified\n");
		return 0;
		}
	if(!*req) *req = OCSP_REQUEST_new();
	if(!*req) goto err;
	id = OCSP_cert_to_id(NULL, cert, issuer);
	if(!id || !sk_OCSP_CERTID_push(ids, id)) goto err;
	if(!OCSP_request_add0_id(*req, id)) goto err;
	return 1;

	err:
	BIO_printf(bio_err, "Error Creating OCSP request\n");
	return 0;
	}

static int add_ocsp_serial(OCSP_REQUEST **req, char *serial, X509 *issuer,
				STACK_OF(OCSP_CERTID) *ids)
	{
	OCSP_CERTID *id;
	X509_NAME *iname;
	ASN1_BIT_STRING *ikey;
	ASN1_INTEGER *sno;
	if(!issuer)
		{
		BIO_printf(bio_err, "No issuer certificate specified\n");
		return 0;
		}
	if(!*req) *req = OCSP_REQUEST_new();
	if(!*req) goto err;
	iname = X509_get_subject_name(issuer);
	ikey = issuer->cert_info->key->public_key;
	sno = s2i_ASN1_INTEGER(NULL, serial);
	if(!sno)
		{
		BIO_printf(bio_err, "Error converting serial number %s\n", serial);
		return 0;
		}
	id = OCSP_cert_id_new(EVP_sha1(), iname, ikey, sno);
	ASN1_INTEGER_free(sno);
	if(!id || !sk_OCSP_CERTID_push(ids, id)) goto err;
	if(!OCSP_request_add0_id(*req, id)) goto err;
	return 1;

	err:
	BIO_printf(bio_err, "Error Creating OCSP request\n");
	return 0;
	}

static int print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
					STACK *names, STACK_OF(OCSP_CERTID) *ids)
	{
	OCSP_CERTID *id;
	char *name;
	int i;

	int status, reason;

	ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

	if (!bs || !req || !sk_num(names) || !sk_OCSP_CERTID_num(ids))
		return 1;

	for (i = 0; i < sk_OCSP_CERTID_num(ids); i++)
		{
		id = sk_OCSP_CERTID_value(ids, i);
		name = sk_value(names, i);
		BIO_printf(out, "%s: ", name);

		if(!OCSP_resp_find_status(bs, id, &status, &reason,
					&rev, &thisupd, &nextupd))
			{
			BIO_puts(out, "ERROR: No Status found.\n");
			continue;
			}
		BIO_printf(out, "%s\n", OCSP_cert_status_str(status));

		BIO_puts(out, "\tThis Update: ");
		ASN1_GENERALIZEDTIME_print(out, thisupd);
		BIO_puts(out, "\n");

		if(nextupd)
			{
			BIO_puts(out, "\tNext Update: ");
			ASN1_GENERALIZEDTIME_print(out, thisupd);
			BIO_puts(out, "\n");
			}

		if (status != V_OCSP_CERTSTATUS_REVOKED)
			continue;

		if (reason != -1)
			BIO_printf(out, "\tReason: %s\n",
				OCSP_crl_reason_str(reason));

		BIO_puts(out, "\tRevocation Time: ");
		ASN1_GENERALIZEDTIME_print(out, rev);
		BIO_puts(out, "\n");
		}

	return 1;
	}

