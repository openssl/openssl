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
#include "cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include "../ssl/ssl_locl.h"

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#define SCTS_TIMESTAMP unsigned __int64
#elif defined(__arch64__)
#define SCTS_TIMESTAMP unsigned long
#else
#define SCTS_TIMESTAMP unsigned long long
#endif


static int i2r_scts(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *oct, BIO *out, int indent);

const X509V3_EXT_METHOD v3_ct_scts[] = {
{ NID_ct_precert_scts, 0, ASN1_ITEM_ref(ASN1_OCTET_STRING),
0,0,0,0,
0,0,0,0,
(X509V3_EXT_I2R)i2r_scts, NULL,
NULL},

{ NID_ct_cert_scts, 0, ASN1_ITEM_ref(ASN1_OCTET_STRING),
0,0,0,0,
0,0,0,0,
(X509V3_EXT_I2R)i2r_scts, NULL,
NULL},
};

static void tls12_signature_print(BIO *out, const unsigned char *data)
	{
	int nid = NID_undef;
	/* RFC6962 only permits two signature algorithms */
	if (data[0] == TLSEXT_hash_sha256)
		{
		if (data[1] == TLSEXT_signature_rsa)
			nid = NID_sha256WithRSAEncryption;
		else if (data[1] == TLSEXT_signature_ecdsa)
			nid = NID_ecdsa_with_SHA256;
		}
	if (nid == NID_undef)
		BIO_printf(out, "%02X%02X", data[0], data[1]);
	else
		BIO_printf(out, "%s", OBJ_nid2ln(nid));
	}

static void timestamp_print(BIO *out, SCTS_TIMESTAMP timestamp)
	{
	ASN1_GENERALIZEDTIME *gen;
	char genstr[20];
	gen = ASN1_GENERALIZEDTIME_new();
	ASN1_GENERALIZEDTIME_adj(gen, (time_t)0,
					(int)(timestamp / 86400000),
					(timestamp % 86400000) / 1000);
	/* Note GeneralizedTime from ASN1_GENERALIZETIME_adj is always 15
	 * characters long with a final Z. Update it with fractional seconds.
	 */
	BIO_snprintf(genstr, sizeof(genstr), "%.14s.%03dZ",
				ASN1_STRING_data(gen),
				(unsigned int)(timestamp % 1000));
	ASN1_GENERALIZEDTIME_set_string(gen, genstr);
	ASN1_GENERALIZEDTIME_print(out, gen);
	ASN1_GENERALIZEDTIME_free(gen);
	}

static int i2r_scts(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *oct,
		       BIO *out, int indent)
	{
	SCTS_TIMESTAMP timestamp;
	unsigned char* data = oct->data;
	unsigned short listlen, sctlen = 0, fieldlen;

	if (oct->length < 2)
		return 0;
	n2s(data, listlen);
	if (listlen != oct->length - 2)
		return 0;

	while (listlen > 0)
		{
		if (listlen < 2)
			return 0;
		n2s(data, sctlen);
		listlen -= 2;

		if ((sctlen < 1) || (sctlen > listlen))
			return 0;
		listlen -= sctlen;

		BIO_printf(out, "%*sSigned Certificate Timestamp:", indent,
			   "");
		BIO_printf(out, "\n%*sVersion   : ", indent + 4, "");

		if (*data == 0)		/* SCT v1 */
			{
			BIO_printf(out, "v1(0)");

			/* Fixed-length header:
			 *		struct {
			 * (1 byte)	  Version sct_version;
			 * (32 bytes)	  LogID id;
			 * (8 bytes)	  uint64 timestamp;
			 * (2 bytes + ?)  CtExtensions extensions;
			 */
			if (sctlen < 43)
				return 0;
			sctlen -= 43;

			BIO_printf(out, "\n%*sLog ID    : ", indent + 4, "");
			BIO_hex_string(out, indent + 16, 16, data + 1, 32);

			data += 33;
			n2l8(data, timestamp);
			BIO_printf(out, "\n%*sTimestamp : ", indent + 4, "");
			timestamp_print(out, timestamp);

			n2s(data, fieldlen);
			if (sctlen < fieldlen)
				return 0;
			sctlen -= fieldlen;
			BIO_printf(out, "\n%*sExtensions: ", indent + 4, "");
			if (fieldlen == 0)
				BIO_printf(out, "none");
			else
				BIO_hex_string(out, indent + 16, 16, data,
					       fieldlen);
			data += fieldlen;

			/* digitally-signed struct header:
			 * (1 byte) Hash algorithm
			 * (1 byte) Signature algorithm
			 * (2 bytes + ?) Signature
			 */
			if (sctlen < 4)
				return 0;
			sctlen -= 4;

			BIO_printf(out, "\n%*sSignature : ", indent + 4, "");
			tls12_signature_print(out, data);
			data += 2;
			n2s(data, fieldlen);
			if (sctlen != fieldlen)
				return 0;
			BIO_printf(out, "\n%*s            ", indent + 4, "");
			BIO_hex_string(out, indent + 16, 16, data, fieldlen);
			data += fieldlen;
			}
		else			/* Unknown version */
			{
			BIO_printf(out, "unknown\n%*s", indent + 16, "");
			BIO_hex_string(out, indent + 16, 16, data, sctlen);
			data += sctlen;
			}

		if (listlen > 0) BIO_printf(out, "\n");
		}

	return 1;
	}
