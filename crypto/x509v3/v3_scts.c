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
#include "o_time.h"
#include <openssl/x509v3.h>
#include "../ssl/ssl_locl.h"

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


/* <ripped>
 * from crypto/asn1/t_x509.c
 */
static const char *mon[12]=
    {
    "Jan","Feb","Mar","Apr","May","Jun",
    "Jul","Aug","Sep","Oct","Nov","Dec"
    };
/* </ripped> */


/* <ripped>
 * from ssl/t1_lib.c
 */
typedef struct 
	{
	int nid;
	int id;
	} tls12_lookup;

static tls12_lookup tls12_md[] = {
	{NID_md5, TLSEXT_hash_md5},
	{NID_sha1, TLSEXT_hash_sha1},
	{NID_sha224, TLSEXT_hash_sha224},
	{NID_sha256, TLSEXT_hash_sha256},
	{NID_sha384, TLSEXT_hash_sha384},
	{NID_sha512, TLSEXT_hash_sha512}
};

static tls12_lookup tls12_sig[] = {
	{EVP_PKEY_RSA, TLSEXT_signature_rsa},
	{EVP_PKEY_DSA, TLSEXT_signature_dsa},
	{EVP_PKEY_EC, TLSEXT_signature_ecdsa}
};

static int tls12_find_nid(int id, tls12_lookup *table, size_t tlen)
	{
	size_t i;
	for (i = 0; i < tlen; i++)
		{
		if ((table[i].id) == id)
			return table[i].nid;
		}
	return NID_undef;
	}

/* Convert TLS 1.2 signature algorithm extension values into NIDs */
static void tls1_lookup_sigalg(int *phash_nid, int *psign_nid,
			int *psignhash_nid, const unsigned char *data)
	{
	int sign_nid = 0, hash_nid = 0;
	if (!phash_nid && !psign_nid && !psignhash_nid)
		return;
	if (phash_nid || psignhash_nid)
		{
		hash_nid = tls12_find_nid(data[0], tls12_md,
					sizeof(tls12_md)/sizeof(tls12_lookup));
		if (phash_nid)
			*phash_nid = hash_nid;
		}
	if (psign_nid || psignhash_nid)
		{
		sign_nid = tls12_find_nid(data[1], tls12_sig,
					sizeof(tls12_sig)/sizeof(tls12_lookup));
		if (psign_nid)
			*psign_nid = sign_nid;
		}
	if (psignhash_nid)
		{
		if (sign_nid && hash_nid)
			OBJ_find_sigid_by_algs(psignhash_nid,
							hash_nid, sign_nid);
		else
			*psignhash_nid = NID_undef;
		}
	}
/* </ripped> */


static int i2r_scts(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *oct,
	     BIO *out, int indent)
{
	BN_ULLONG timestamp;
	unsigned char* data = oct->data;
	unsigned short listlen, sctlen, fieldlen, linelen;
	int signhash_nid;
	time_t unix_epoch = 0;
	struct tm tm1;

	if (oct->length < 2)
		return 0;
	n2s(data, listlen);
	if (listlen != oct->length - 2)
		return 0;

	while (listlen > 0) {
		if (listlen < 2)
			return 0;
		n2s(data, sctlen);
		listlen -= 2;

		if ((sctlen < 1) || (sctlen > listlen))
			return 0;
		listlen -= sctlen;

		if (*data == 0) {	/* v1 SCT */
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

			BIO_printf(out, "\n%*sVersion   : v1(0)", indent, "");

			BIO_printf(out, "\n%*sLog ID    : ", indent, "");
			BIO_printf(out, "%s:", hex_to_string(data + 1, 16));
			BIO_printf(out, "\n%*s            ", indent, "");
			BIO_printf(out, "%s", hex_to_string(data + 17, 16));

			data += 33;
			n2l8(data, timestamp);
			OPENSSL_gmtime(&unix_epoch, &tm1);
			OPENSSL_gmtime_adj(&tm1, timestamp / 86400000,
						(timestamp % 86400000) / 1000);
			BIO_printf(out, "\n%*sTimestamp : ", indent, "");
			BIO_printf(out, "%s %2d %02d:%02d:%02d.%03u %d UTC",
				   mon[tm1.tm_mon], tm1.tm_mday, tm1.tm_hour,
				   tm1.tm_min, tm1.tm_sec,
				   (unsigned int)(timestamp % 1000),
				   tm1.tm_year + 1900);

			n2s(data, fieldlen);
			if (sctlen < fieldlen)
				return 0;
			sctlen -= fieldlen;
			BIO_printf(out, "\n%*sExtensions:", indent, "");
			if (fieldlen == 0)
				BIO_printf(out, " none");
			for (linelen = 16; fieldlen > 0; ) {
				if (linelen > fieldlen)
					linelen = fieldlen;
				BIO_printf(out, "\n%*s       ", indent, "");
				BIO_printf(out, "%s",
					   hex_to_string(data, linelen));
				if (fieldlen > 16)
					BIO_printf(out, ":");
				data += linelen;
				fieldlen -= linelen;
			}

			/* digitally-signed struct header:
			 * (1 byte) Hash algorithm
			 * (1 byte) Signature algorithm
			 * (2 bytes + ?) Signature
			 */
			if (sctlen < 4)
				return 0;
			sctlen -= 4;

			tls1_lookup_sigalg(NULL, NULL, &signhash_nid, data);
			data += 2;
			n2s(data, fieldlen);
			if (sctlen != fieldlen)
				return 0;
			BIO_printf(out, "\n%*sSignature : ", indent, "");
			BIO_printf(out, "%s", OBJ_nid2ln(signhash_nid));
			for (linelen = 16; fieldlen > 0; ) {
				if (linelen > fieldlen)
					linelen = fieldlen;
				BIO_printf(out, "\n%*s            ", indent,
					   "");
				BIO_printf(out, "%s",
					   hex_to_string(data, linelen));
				if (fieldlen > 16)
					BIO_printf(out, ":");
				data += linelen;
				fieldlen -= linelen;
			}

			BIO_printf(out, "\n");
		}
	}

	return 1;
}
