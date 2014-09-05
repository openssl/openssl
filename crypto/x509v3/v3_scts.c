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

#include <limits.h>
#include "cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "../ssl/ssl_locl.h"

#define n2l8(c,l)	(l =((SCT_TIMESTAMP)(*((c)++)))<<56, \
			 l|=((SCT_TIMESTAMP)(*((c)++)))<<48, \
			 l|=((SCT_TIMESTAMP)(*((c)++)))<<40, \
			 l|=((SCT_TIMESTAMP)(*((c)++)))<<32, \
			 l|=((SCT_TIMESTAMP)(*((c)++)))<<24, \
			 l|=((SCT_TIMESTAMP)(*((c)++)))<<16, \
			 l|=((SCT_TIMESTAMP)(*((c)++)))<< 8, \
			 l|=((SCT_TIMESTAMP)(*((c)++))))

/* From RFC6962:
 *      opaque SerializedSCT<1..2^16-1>;
 *
 *      struct {
 *          SerializedSCT sct_list <1..2^16-1>;
 *      } SignedCertificateTimestampList;
 */
#if INT_MAX < 65535
#define MAX_SCT_SIZE		INT_MAX
#else
#define MAX_SCT_SIZE		65535
#endif
#define MAX_SCT_LIST_SIZE	MAX_SCT_SIZE

struct SCT_st {
	/* The encoded SCT */
	unsigned char *sct;
	unsigned short sctlen;

	/* Components of the SCT.  "logid", "ext" and "sig" point to addresses
	 * inside "sct".
	 */
	unsigned char version;
	unsigned char *logid;
	unsigned short logidlen;
	SCT_TIMESTAMP timestamp;
	unsigned char *ext;
	unsigned short extlen;
	unsigned char hash_alg;
	unsigned char sig_alg;
	unsigned char *sig;
	unsigned short siglen;
};

static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
				   const int len);
static int i2d_SCT_LIST(STACK_OF(SCT) *a, unsigned char **pp);
static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
			BIO *out, int indent);

const X509V3_EXT_METHOD v3_ct_scts[] = {
{ NID_ct_precert_scts, 0, NULL,
0,(X509V3_EXT_FREE)SCT_LIST_free,
(X509V3_EXT_D2I)d2i_SCT_LIST, (X509V3_EXT_I2D)i2d_SCT_LIST,
0,0,0,0,
(X509V3_EXT_I2R)i2r_SCT_LIST, 0,
NULL},

{ NID_ct_cert_scts, 0, NULL,
0,(X509V3_EXT_FREE)SCT_LIST_free,
(X509V3_EXT_D2I)d2i_SCT_LIST, (X509V3_EXT_I2D)i2d_SCT_LIST,
0,0,0,0,
(X509V3_EXT_I2R)i2r_SCT_LIST, 0,
NULL},
};

static int get_signature_nid(const unsigned char hash_alg,
			    const unsigned char sig_alg)
{
	/* RFC6962 only permits two signature algorithms */
	if (hash_alg == TLSEXT_hash_sha256)
		{
		if (sig_alg == TLSEXT_signature_rsa)
			return NID_sha256WithRSAEncryption;
		else if (sig_alg == TLSEXT_signature_ecdsa)
			return NID_ecdsa_with_SHA256;
		}
	return NID_undef;
}

static void tls12_signature_print(BIO *out, const unsigned char hash_alg,
				  const unsigned char sig_alg)
	{
	int nid = get_signature_nid(hash_alg, sig_alg);
	if (nid == NID_undef)
		BIO_printf(out, "%02X%02X", hash_alg, sig_alg);
	else
		BIO_printf(out, "%s", OBJ_nid2ln(nid));
	}

static void timestamp_print(BIO *out, SCT_TIMESTAMP timestamp)
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

static int base64_decode(
	const char *in,
	unsigned char **out
)
{
	EVP_ENCODE_CTX ctx;
	int len = 0;

	if (!in || !out || !(*out))
		return -1;

	EVP_DecodeInit(&ctx);
	if (EVP_DecodeUpdate(&ctx, *out, &len, (unsigned char*)in,
			     strlen(in)) == -1)
		return -1;

	*out += len;
	return len;
}

static int sct_parse(SCT *sct)
	{
	unsigned char *p;
	unsigned short len, len2;

	if (!sct || !sct->sct)
		return 0;

	p = sct->sct;
	len = sct->sctlen;

	sct->version = *p++;
	if (sct->version == 0)		/* SCT v1 */
		{
		/* Fixed-length header:
		 *		struct {
		 * (1 byte)	  Version sct_version;
		 * (32 bytes)	  LogID id;
		 * (8 bytes)	  uint64 timestamp;
		 * (2 bytes + ?)  CtExtensions extensions;
		 */
		if (len < 43)
			return 0;
		len -= 43;

		sct->logid = p;
		sct->logidlen = 32;
		p += 32;

		n2l8(p, sct->timestamp);

		n2s(p, len2);
		if (len < len2)
			return 0;
		sct->ext = p;
		sct->extlen = len2;
		p += len2;
		len -= len2;

		/* digitally-signed struct header:
		 * (1 byte)       Hash algorithm
		 * (1 byte)       Signature algorithm
		 * (2 bytes + ?)  Signature
		 */
		if (len < 4)
			return 0;
		len -= 4;

		sct->hash_alg = *p++;
		sct->sig_alg = *p++;
		n2s(p, len2);
		if (len != len2)
			return 0;
		sct->sig = p;
		sct->siglen = len2;
		return 1;
		}

	return 0;
	}

static int sct_encode_precerttbs(X509 *cert, unsigned char **tbsder,
				 const int nid_ext_to_delete)
	{
	int index;

	if (!cert || !tbsder || !(*tbsder))
		return -1;

	index = X509_get_ext_by_NID(cert, nid_ext_to_delete, -1);
	if (index != -1)
		{
		X509_EXTENSION *ext = X509_delete_ext(cert, index);
		if (ext) X509_EXTENSION_free(ext);
		/* Don't allow duplicate CT extensions */
		if (X509_get_ext_by_NID(cert, nid_ext_to_delete, -1) != -1)
			return -1;
		}
	else if (nid_ext_to_delete == NID_ct_precert_poison)
		return -1;

	cert->cert_info->enc.modified = 1;
	return i2d_X509_CINF(cert->cert_info, tbsder);
	}

SCT *SCT_new(void)
	{
	SCT *sct = OPENSSL_malloc(sizeof(SCT));
	if (!sct)
		X509V3err(X509V3_F_SCT_NEW, ERR_R_MALLOC_FAILURE);
	else
		memset(sct, 0, sizeof(SCT));

	return sct;
	}

void SCT_free(SCT *sct)
	{
	if (sct)
		{
		if (sct->sct) OPENSSL_free(sct->sct);
		OPENSSL_free(sct);
		}
	}

SCT *o2i_SCT(SCT **psct, const unsigned char **in, const size_t len)
	{
	SCT *sct = NULL;

	if (!in || !(*in))
		{
		X509V3err(X509V3_F_O2I_SCT, ERR_R_PASSED_NULL_PARAMETER);
		goto err;
		}
	else if (len > MAX_SCT_SIZE)
		{
		X509V3err(X509V3_F_O2I_SCT, X509V3_R_SCT_INVALID);
		goto err;
		}

	if ((sct=SCT_new()) == NULL)
		goto err;

	if ((sct->sct=OPENSSL_malloc(len)) == NULL)
		{
		X509V3err(X509V3_F_O2I_SCT, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	memcpy(sct->sct, *in, len);
	sct->sctlen = len;

	if (!sct_parse(sct))
		{
		X509V3err(X509V3_F_O2I_SCT, X509V3_R_SCT_INVALID);
		goto err;
		}

	*in += len;

	if (psct)
		{
		if (*psct)
			{
			if ((*psct)->sct) OPENSSL_free((*psct)->sct);
			memcpy(*psct, sct, sizeof(SCT));
			OPENSSL_free(sct);
			sct = *psct;
			}
		else
			*psct = sct;
		}

	return sct;

	err:
	if (sct) SCT_free(sct);
	return NULL;
	}

int i2o_SCT(const SCT *sct, unsigned char **out)
{
	if (!sct)
		{
		X509V3err(X509V3_F_I2O_SCT, ERR_R_PASSED_NULL_PARAMETER);
		return -1;
		}
	else if (!sct->sct)
		{
		X509V3err(X509V3_F_I2O_SCT, X509V3_R_SCT_NOT_SET);
		return -1;
		}

	if (out)
		{
		if (*out)
			{
			memcpy(*out, sct->sct, sct->sctlen);
			*out += sct->sctlen;
			}
		else
			{
			*out = OPENSSL_malloc(sct->sctlen);
			if (!(*out))
				{
				X509V3err(X509V3_F_I2O_SCT,
					  ERR_R_MALLOC_FAILURE);
				return -1;
				}
			memcpy(*out, sct->sct, sct->sctlen);
			}
		}

	return sct->sctlen;
}

int SCT_set0(SCT *sct, const unsigned char version, const char *logid_base64,
	     const SCT_TIMESTAMP timestamp, const char *extensions_base64,
	     const char *signature_base64)
	{
	size_t len;
	unsigned char *p, *p2;

	if (!sct || !logid_base64 || !extensions_base64 || !signature_base64)
		{
		X509V3err(X509V3_F_SCT_SET0, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}

	/* RFC6962 section 4.1 says we "MUST NOT expect this to be 0", but we
	 * can only construct SCT versions that have been defined.
	 */
	if (version != 0)
		{
		X509V3err(X509V3_F_SCT_SET0, X509V3_R_SCT_UNSUPPORTED_VERSION);
		return 0;
		}

	len = 43 + ((strlen(extensions_base64) * 3) / 4) + 4
		+ ((strlen(signature_base64) * 3) / 4);
	if ((len > MAX_SCT_SIZE) || (strlen(logid_base64) != 44))
		{
		X509V3err(X509V3_F_SCT_SET0, X509V3_R_SCT_INVALID);
		return 0;
		}
	sct->sctlen = (unsigned short)len;

	if ((p=sct->sct=OPENSSL_malloc(sct->sctlen)) == NULL)
		{
		X509V3err(X509V3_F_SCT_SET0, ERR_R_MALLOC_FAILURE);
		return 0;
		}

	*p++ = version;

	if (base64_decode(logid_base64, &p) < 0)
		{
		X509err(X509V3_F_SCT_SET0, X509_R_BASE64_DECODE_ERROR);
		goto err;
		}

	l2n8(timestamp, p);

	p2 = p;
	p += 2;
	if ((len=base64_decode(extensions_base64, &p)) < 0)
		{
		X509err(X509V3_F_SCT_SET0, X509_R_BASE64_DECODE_ERROR);
		goto err;
		}
	s2n(len, p2);

	if (base64_decode(signature_base64, &p) < 0)
		{
		X509err(X509V3_F_SCT_SET0, X509_R_BASE64_DECODE_ERROR);
		goto err;
		}

	sct->sctlen = p - sct->sct;

	if (!sct_parse(sct))
		{
		X509V3err(X509V3_F_SCT_SET0, X509V3_R_SCT_INVALID);
		goto err;
		}

	return 1;

	err:
	if (sct->sct)
		{
		OPENSSL_free(sct->sct);
		sct->sct = NULL;
		}
	return 0;
	}

int SCT_get0_version(const SCT *sct, unsigned char *version)
	{
	if (!sct || !version)
		{
		X509V3err(X509V3_F_SCT_GET0_VERSION,
			  ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	else if (!sct->sct)
		{
		X509V3err(X509V3_F_SCT_GET0_VERSION, X509V3_R_SCT_NOT_SET);
		return 0;
		}
		
	*version = sct->version;
	return 1;
	}

int SCT_get0_logid(const SCT *sct, unsigned char **logid, size_t *logidlen)
	{
	if (!sct || !logid || !logidlen)
		{
		X509V3err(X509V3_F_SCT_GET0_LOGID, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	else if (!sct->sct)
		{
		X509V3err(X509V3_F_SCT_GET0_LOGID, X509V3_R_SCT_NOT_SET);
		return 0;
		}

	*logid = sct->logid;
	*logidlen = sct->logidlen;
	return 1;
	}

int SCT_get0_timestamp(const SCT *sct, SCT_TIMESTAMP *timestamp)
	{
	if (!sct || !timestamp)
		{
		X509V3err(X509V3_F_SCT_GET0_TIMESTAMP,
			  ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	else if (!sct->sct)
		{
		X509V3err(X509V3_F_SCT_GET0_TIMESTAMP, X509V3_R_SCT_NOT_SET);
		return 0;
		}

	*timestamp = sct->timestamp;
	return 1;
	}

int SCT_get0_signature_nid(const SCT *sct, int *nid)
	{
	if (!sct || !nid)
		{
		X509V3err(X509V3_F_SCT_GET0_SIGNATURE_NID,
			  ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	else if (!sct->sct)
		{
		X509V3err(X509V3_F_SCT_GET0_TIMESTAMP, X509V3_R_SCT_NOT_SET);
		return 0;
		}

	*nid = get_signature_nid(sct->hash_alg, sct->sig_alg);
	return 1;
	}

int SCT_verify(const SCT *sct, const LogEntryType entry_type, X509 *cert,
	       X509_PUBKEY *log_pubkey, X509 *issuer_cert)
	{
	EVP_MD_CTX verifyctx;
	EVP_PKEY *log_pkey = NULL;
	unsigned char *log_spki = NULL, *issuer_spki = NULL;
	unsigned char *digitally_signed = NULL;
	unsigned char *p, *p2;
	unsigned char md[32];
	unsigned int mdlen = 32;
	int ret = 0;
	int nid_ext_to_delete;
	int len;
	size_t len2;

	if (!sct || !cert || !log_pubkey
			|| ((entry_type == precert_entry) && !issuer_cert))
		{
		X509V3err(X509V3_F_SCT_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
		return -1;
		}
	else if (!sct->sct)
		{
		X509V3err(X509V3_F_SCT_VERIFY, X509V3_R_SCT_NOT_SET);
		return -1;
		}
	else if (sct->version != 0)
		{
		X509V3err(X509V3_F_SCT_VERIFY,
			  X509V3_R_SCT_UNSUPPORTED_VERSION);
		return 0;
		}

	/* Check that SHA-256(log_pubkey) matches sct->logid */
	if ((len=i2d_X509_PUBKEY(log_pubkey, &log_spki)) <= 0)
		return 0;
	if (!EVP_Digest(log_spki, len, md, &mdlen, EVP_sha256(), NULL))
		goto done;
	if (memcmp(md, sct->logid, 32) != 0)
		{
		X509V3err(X509V3_F_SCT_VERIFY, X509V3_R_SCT_LOG_ID_MISMATCH);
		goto done;
		}

	/*	    digitally-signed struct {
	 * (1 byte)	Version sct_version;
	 * (1 byte)	SignatureType signature_type = certificate_timestamp;
	 * (8 bytes)	uint64 timestamp;
	 * (2 bytes)	LogEntryType entry_type;
	 * (? bytes)	select(entry_type) {
	 *		    case x509_entry: ASN.1Cert;
	 *		    case precert_entry: PreCert;
	 *		} signed_entry;
	 * (2 bytes + sct->extlen)  CtExtensions extensions;
	 */
	if ((len2=i2d_X509(cert, NULL)) < 0)
		goto done;
	len2 += 14 + sct->extlen
			+ 32	/* PreCert.issuer_key_hash */
			+ 3;	/* Certificate length: <1..2^24-1> */
	if ((len2 > INT_MAX)
			|| (p=digitally_signed=OPENSSL_malloc(len2)) == NULL)
		{
		X509V3err(X509V3_F_SCT_VERIFY, ERR_R_MALLOC_FAILURE);
		goto done;
		}

	*p++ = sct->version;
	*p++ = 0;			/* 0 = certificate_timestamp */
	l2n8(sct->timestamp, p);
	s2n(entry_type, p);

	if (X509_get_ext_by_NID(cert, NID_ct_precert_poison, -1) != -1)
		nid_ext_to_delete = NID_ct_precert_poison;
	else
		nid_ext_to_delete = NID_ct_precert_scts;

	if (entry_type == x509_entry)
		{
		if (nid_ext_to_delete == NID_ct_precert_poison)
			goto done;

		p2 = p;
		p += 3;
		if (i2d_X509(cert, &p) < 0)
			goto done;
		}
	else	/* entry_type == precert_entry */
		{
		/* Calculate PreCert.issuer_key_hash */
		if ((len=i2d_X509_PUBKEY(issuer_cert->cert_info->key,
					 &issuer_spki)) <= 0)
			goto done;
		if (!EVP_Digest(issuer_spki, len, p, &mdlen, EVP_sha256(),
			        NULL))
			goto done;
		p += mdlen;

		/* Append PreCert.tbs_certificate */
		p2 = p;
		p += 3;
		if (sct_encode_precerttbs(cert, &p, nid_ext_to_delete) < 0)
			goto done;
		}

	l2n3((p - p2 - 3), p2);

	s2n(sct->extlen, p);
	memcpy(p, sct->ext, sct->extlen);
	len2 = (p - digitally_signed) + sct->extlen;

	/* Verify signature */
	EVP_MD_CTX_init(&verifyctx);
	if (!EVP_VerifyInit(&verifyctx, EVP_sha256())
			|| !EVP_VerifyUpdate(&verifyctx, digitally_signed, len2)
			|| ((log_pkey=X509_PUBKEY_get(log_pubkey)) == NULL))
		goto cleanup;
	if ((ret=EVP_VerifyFinal(&verifyctx, sct->sig, sct->siglen,
				 log_pkey)) == 0)
		X509V3err(X509V3_F_SCT_VERIFY, X509V3_R_SCT_INVALID_SIGNATURE);

	cleanup:
	EVP_MD_CTX_cleanup(&verifyctx);

	done:
	if (log_pkey) EVP_PKEY_free(log_pkey);
	if (issuer_spki) OPENSSL_free(issuer_spki);
	if (digitally_signed) OPENSSL_free(digitally_signed);
	if (log_spki) OPENSSL_free(log_spki);
	return ret;
	}

void SCT_LIST_free(STACK_OF(SCT) *a)
	{
	sk_SCT_pop_free(a, SCT_free);
	}

STACK_OF(SCT) *o2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
			    const size_t len)
	{
	STACK_OF(SCT) *sk = NULL;
	SCT *sct;
	unsigned short listlen, sctlen;

	if (!pp || !(*pp))
		{
		X509V3err(X509V3_F_O2I_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	else if ((len < 2) || (len > MAX_SCT_LIST_SIZE))
		{
		X509V3err(X509V3_F_O2I_SCT_LIST, X509V3_R_SCT_LIST_INVALID);
		return NULL;
		}

	n2s((*pp), listlen);
	if (listlen != len - 2)
		return NULL;

	if (a && *a)
		{
		sk = *a;
		while ((sct=sk_SCT_pop(sk)) != NULL) SCT_free(sct);
		}
	else if ((sk=sk_SCT_new_null()) == NULL)
		return NULL;

	while (listlen > 0)
		{
		if (listlen < 2)
			goto err;
		n2s((*pp), sctlen);
		listlen -= 2;

		if ((sctlen < 1) || (sctlen > listlen))
			goto err;
		listlen -= sctlen;

		if ((sct=o2i_SCT(NULL, pp, sctlen)) == NULL)
			goto err;
		if (!sk_SCT_push(sk, sct))
			{
			SCT_free(sct);
			goto err;
			}
		}

	if (a && !(*a)) *a = sk;
	return sk;

	err:
	if (!(a && *a)) SCT_LIST_free(sk);
	return NULL;
	}

int i2o_SCT_LIST(STACK_OF(SCT) *a, unsigned char **pp)
	{
	int len, sctlen, i, newpp = 0;
	size_t len2;
	unsigned char *p = NULL, *p2;

	if (!a)
		{
		X509V3err(X509V3_F_I2O_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
		return -1;
		}

	if (pp)
		{
		if (*pp == NULL)
			{
			if ((len=i2o_SCT_LIST(a, NULL)) == -1)
				{
				X509V3err(X509V3_F_I2O_SCT_LIST,
					  X509V3_R_SCT_LIST_INVALID);
				return -1;
				}
			if ((*pp=OPENSSL_malloc(len)) == NULL)
				{
				X509V3err(X509V3_F_I2O_SCT_LIST,
					  ERR_R_MALLOC_FAILURE);
				return -1;
				}
			newpp = 1;
			}
		p = (*pp) + 2;
		}

	len2 = 2;
	for (i = 0; i < sk_SCT_num(a); i++)
		{
		if (pp)
			{
			p2 = p;
			p += 2;
			}
		if ((sctlen=i2o_SCT(sk_SCT_value(a, i), &p)) == -1)
			goto err;
		if (pp) s2n(sctlen, p2);
		len2 += 2 + sctlen;
		}

	if (len2 > MAX_SCT_LIST_SIZE)
		goto err;

	if (pp)
		{
		p = *pp;
		s2n((len2 - 2), p);
		}
	if (!newpp) pp = pp + len2;
	return len2;

	err:
	if (newpp)
		{
		OPENSSL_free(*pp);
		*pp = NULL;
		}
	return -1;
	}

static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
				   const int len)
	{
	ASN1_OCTET_STRING *oct = NULL;
	STACK_OF(SCT) *sk = NULL;
	const unsigned char *p;

	if (!pp || !(*pp))
		{
		X509V3err(X509V3_F_D2I_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}

	p = *pp;
	if (d2i_ASN1_OCTET_STRING(&oct, &p, len) == NULL)
		return NULL;

	p = oct->data;
	if ((sk=o2i_SCT_LIST(a, &p, oct->length)) != NULL)
		*pp += len;

	M_ASN1_OCTET_STRING_free(oct);
	return sk;
	}

static int i2d_SCT_LIST(STACK_OF(SCT) *a, unsigned char **out)
	{
	ASN1_OCTET_STRING oct;
	int len;

	if (!a)
		{
		X509V3err(X509V3_F_I2D_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
		return -1;
		}

	oct.data = NULL;
	if ((oct.length=i2o_SCT_LIST(a, &(oct.data))) == -1)
		return -1;

	len = i2d_ASN1_OCTET_STRING(&oct, out);
	OPENSSL_free(oct.data);
	return len;
}

static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
			BIO *out, int indent)
	{
	SCT *sct;
	int i;

	for (i = 0; i < sk_SCT_num(sct_list);) {
		sct = sk_SCT_value(sct_list, i);

		BIO_printf(out, "%*sSigned Certificate Timestamp:", indent, "");
		BIO_printf(out, "\n%*sVersion   : ", indent + 4, "");

		if (sct->version == 0)	/* SCT v1 */
			{
			BIO_printf(out, "v1(0)");

			BIO_printf(out, "\n%*sLog ID    : ", indent + 4, "");
			BIO_hex_string(out, indent + 16, 16, sct->logid,
				       sct->logidlen);

			BIO_printf(out, "\n%*sTimestamp : ", indent + 4, "");
			timestamp_print(out, sct->timestamp);

			BIO_printf(out, "\n%*sExtensions: ", indent + 4, "");
			if (sct->extlen == 0)
				BIO_printf(out, "none");
			else
				BIO_hex_string(out, indent + 16, 16, sct->ext,
					       sct->extlen);

			BIO_printf(out, "\n%*sSignature : ", indent + 4, "");
			tls12_signature_print(out, sct->hash_alg, sct->sig_alg);
			BIO_printf(out, "\n%*s            ", indent + 4, "");
			BIO_hex_string(out, indent + 16, 16, sct->sig,
				       sct->siglen);
			}
		else			/* Unknown version */
			{
			BIO_printf(out, "unknown\n%*s", indent + 16, "");
			BIO_hex_string(out, indent + 16, 16, sct->sct,
				       sct->sctlen);
			}

		if (++i < sk_SCT_num(sct_list)) BIO_printf(out, "\n");
		}

	return 1;
	}
