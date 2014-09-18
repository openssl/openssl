/* v3_scts.c */
/* Written by Rob Stradling (rob@comodo.com) for the OpenSSL project 2014.
 */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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

#include "../e_os.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int main(int argc, char **argv)
	{
	EVP_PKEY *logpkey = NULL;
	X509_PUBKEY *logpubkey = NULL;
	X509 *issuercert = NULL, *cert = NULL, *precertsigningcert = NULL;
	STACK_OF(SCT) *sk = NULL;
	SCT *sct = NULL;
	log_entry_type entrytype = PRECERT_ENTRY;
	FILE *f = NULL;
	size_t sctlen = 4096;
	unsigned char *sctbuf = NULL;
	const unsigned char *p;
	const char *szLogPubKeyFilename, *szIssuerCertFilename;
	const char *szCertFilename, *szSCTFilename, *szSCTContext;
	const char *szPrecertSigningCertFilename;
	int ret = 0;

	if(argc != 7)
		{
		fprintf(stderr, "%s <test file>\n", argv[0]);
		EXIT(1);
		}

	szLogPubKeyFilename = argv[1];
	szIssuerCertFilename = argv[2];
	szCertFilename = argv[3];
	szSCTContext = argv[4];
	szSCTFilename = argv[5];
	szPrecertSigningCertFilename = argv[6];

	if ((f=fopen(szLogPubKeyFilename, "r")) == NULL)
		{
		perror(szLogPubKeyFilename);
		EXIT(2);
		}
	if ((logpkey=PEM_read_PUBKEY(f, NULL, NULL, NULL)) == NULL)
		{
		fprintf(stderr, "PEM_read_PUBKEY failed\n");
		ret = 3;
		goto done;
		}
	if (!X509_PUBKEY_set(&logpubkey, logpkey))
		{
		fprintf(stderr, "X509_PUBKEY_set failed\n");
		ret = 4;
		goto done;
		}
	fclose(f);
	f = NULL;

	if ((f=fopen(szIssuerCertFilename, "r")) == NULL)
		{
		perror(szIssuerCertFilename);
		ret = 5;
		goto done;
		}
	if ((issuercert=PEM_read_X509(f, NULL, NULL, NULL)) == NULL)
		{
		fprintf(stderr, "%s: PEM_read_X509 failed\n",
			szIssuerCertFilename);
		ret = 6;
		goto done;
		}
	fclose(f);
	f = NULL;

	if ((f=fopen(szCertFilename, "r")) == NULL)
		{
		perror(szCertFilename);
		ret = 7;
		goto done;
		}
	if ((cert=PEM_read_X509(f, NULL, NULL, NULL)) == NULL)
		{
		fprintf(stderr, "%s: PEM_read_X509 failed\n", szCertFilename);
		ret = 8;
		goto done;
		}
	fclose(f);
	f = NULL;

	if (!strcmp(szSCTContext, "embedded"))
		{
		if ((sk=X509_get_ext_d2i(cert, NID_ct_precert_scts, NULL, NULL))
			== NULL)
			{
			fprintf(stderr, "X509_get_ext_d2i failed\n");
			ret = 9;
			goto done;
			}
		if (sk_SCT_num(sk) < 1)
			{
			fprintf(stderr, "Empty SCT list\n");
			ret = 10;
			goto done;
			}
		}
	else
		{
		if (!strcmp(szSCTContext, "cert"))
			entrytype = X509_ENTRY;
		else if (strcmp(szSCTContext, "precert") != 0)
			{
			fprintf(stderr, "%s: invalid SCT context\n",
				szSCTContext);
			ret = 11;
			goto done;
			}

		if ((f=fopen(szSCTFilename, "r")) == NULL)
			{
			perror(szSCTFilename);
			ret = 12;
			goto done;
			}
		if ((p=sctbuf=OPENSSL_malloc(sctlen)) == NULL)
			{
			fprintf(stderr, "OPENSSL_malloc failed\n");
			ret = 13;
			goto done;
			}
		if ((sctlen=fread(sctbuf, 1, sctlen, f)) == 0)
			{
			fprintf(stderr, "fread returned 0\n");
			ret = 14;
			goto done;
			}
		fclose(f);
		f = NULL;
		if ((sct=o2i_SCT(NULL, &p, sctlen)) == NULL)
			{
			fprintf(stderr, "o2i_SCT failed\n");
			ret = 15;
			goto done;
			}
		}

	if (strcmp(szPrecertSigningCertFilename, "NULL") != 0)
		{
		if ((f=fopen(szPrecertSigningCertFilename, "r")) == NULL)
			{
			perror(szPrecertSigningCertFilename);
			ret = 16;
			goto done;
			}
		if ((precertsigningcert=PEM_read_X509(f, NULL, NULL, NULL))
				== NULL)
			{
			fprintf(stderr, "%s: PEM_read_X509 failed\n",
				szPrecertSigningCertFilename);
			ret = 17;
			goto done;
			}
		fclose(f);
		f = NULL;
		}

	/* FIXME: Need to be able to pass precertsigningcert to SCT_verify */

	if (SCT_verify(sct ? sct : sk_SCT_value(sk, 0), entrytype, cert,
		       logpubkey, issuercert) != 1)
		ret = 100;

	done:
	if (precertsigningcert) X509_free(precertsigningcert);
	if (sctbuf) OPENSSL_free(sctbuf);
	if (sk) SCT_LIST_free(sk);
	if (sct) SCT_free(sct);
	if (cert) X509_free(cert);
	if (issuercert) X509_free(issuercert);
	if (logpubkey) X509_PUBKEY_free(logpubkey);
	if (logpkey) EVP_PKEY_free(logpkey);
	if (f) fclose(f);
	return ret;
	}
