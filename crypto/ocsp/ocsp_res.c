/* ocsp_req.c */
/* Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project. */

/* History:
   This file was originally part of ocsp.c and was transfered to Richard
   Levitte from CertCo by Kathy Weinhold in mid-spring 2000 to be included
   in OpenSSL or released as a patch kit. */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/asn1_mac.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Make sure we work well with older variants of OpenSSL */
#ifndef OPENSSL_malloc
#define OPENSSL_malloc Malloc
#endif
#ifndef OPENSSL_realloc
#define OPENSSL_realloc Realloc
#endif
#ifndef OPENSSL_free
#define OPENSSL_free Free
#endif

IMPLEMENT_STACK_OF(OCSP_SINGLERESP)
IMPLEMENT_ASN1_SET_OF(OCSP_SINGLERESP)

OCSP_RESPBYTES *OCSP_RESPBYTES_new(void)
	{
	ASN1_CTX c;
	OCSP_RESPBYTES *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_RESPBYTES);
	M_ASN1_New(ret->responseType, ASN1_OBJECT_new);
	M_ASN1_New(ret->response, ASN1_OCTET_STRING_new);
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_RESPBYTES_NEW);
	}
	
void OCSP_RESPBYTES_free(OCSP_RESPBYTES *a)
	{
	if (a == NULL) return;
	ASN1_OBJECT_free(a->responseType);
	ASN1_OCTET_STRING_free(a->response);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_RESPBYTES(OCSP_RESPBYTES *a,
		       unsigned char **pp)
	{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->responseType, i2d_ASN1_OBJECT);
	M_ASN1_I2D_len(a->response, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->responseType, i2d_ASN1_OBJECT);
	M_ASN1_I2D_put(a->response, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_finish();
	}

OCSP_RESPBYTES *d2i_OCSP_RESPBYTES(OCSP_RESPBYTES **a,
				   unsigned char **pp,
				   long length)
	{
	M_ASN1_D2I_vars(a,OCSP_RESPBYTES *,OCSP_RESPBYTES_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->responseType, d2i_ASN1_OBJECT);
	M_ASN1_D2I_get(ret->response, d2i_ASN1_OCTET_STRING);
	M_ASN1_D2I_Finish(a,OCSP_RESPBYTES_free,ASN1_F_D2I_OCSP_RESPBYTES);
	}

int i2a_OCSP_RESPBYTES(BIO *bp,
		       OCSP_RESPBYTES* a)
        {
	i2a_ASN1_OBJECT(bp, a->responseType);
	i2a_ASN1_STRING(bp, a->response, V_ASN1_OCTET_STRING);
	return 2;
	}

OCSP_RESPONSE *OCSP_RESPONSE_new(void)
	{
	ASN1_CTX c;
	OCSP_RESPONSE *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_RESPONSE);
	M_ASN1_New(ret->responseStatus, ASN1_ENUMERATED_new);
	ret->responseBytes = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_RESPONSE_NEW);
	}
	
void OCSP_RESPONSE_free(OCSP_RESPONSE *a)
	{
	if (a == NULL) return;
	ASN1_ENUMERATED_free(a->responseStatus);
	OCSP_RESPBYTES_free(a->responseBytes);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_RESPONSE(OCSP_RESPONSE *a,
		      unsigned char **pp)
	{
	int v=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->responseStatus, i2d_ASN1_ENUMERATED);
	M_ASN1_I2D_len_EXP_opt(a->responseBytes, i2d_OCSP_RESPBYTES, 0, v);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->responseStatus, i2d_ASN1_ENUMERATED);
	M_ASN1_I2D_put_EXP_opt(a->responseBytes, i2d_OCSP_RESPBYTES, 0, v);
	M_ASN1_I2D_finish();
	}

OCSP_RESPONSE *d2i_OCSP_RESPONSE(OCSP_RESPONSE **a,
				 unsigned char **pp,
				 long length)
	{
	M_ASN1_D2I_vars(a,OCSP_RESPONSE *,OCSP_RESPONSE_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->responseStatus, d2i_ASN1_ENUMERATED);
	M_ASN1_D2I_get_EXP_opt(ret->responseBytes, d2i_OCSP_RESPBYTES, 0);
	M_ASN1_D2I_Finish(a,OCSP_RESPONSE_free,ASN1_F_D2I_OCSP_RESPONSE);
	}

int i2a_OCSP_RESPONSE(BIO *bp, OCSP_RESPONSE* a)
        {
	i2a_ASN1_STRING(bp, a->responseStatus, V_ASN1_ENUMERATED);
	i2a_OCSP_RESPBYTES(bp, a->responseBytes);
	return a->responseBytes ? 2 : 1;
	}

OCSP_RESPID *OCSP_RESPID_new(void)
	{
	ASN1_CTX c;
	OCSP_RESPID *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_RESPID);
	ret->tag = -1;
	ret->value.byName = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_RESPID_NEW);
	}
	
void OCSP_RESPID_free(OCSP_RESPID *a)
	{
	if (a == NULL) return;
	switch (a->tag)
		{
		case V_OCSP_RESPID_NAME:
		        X509_NAME_free(a->value.byName);
		        break;
		case V_OCSP_RESPID_KEY:
		        ASN1_OCTET_STRING_free(a->value.byKey);
		        break;
		}
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_RESPID(OCSP_RESPID *a, unsigned char **pp)
	{
	int v=0;
	M_ASN1_I2D_vars(a);
	switch (a->tag)
		{
		case V_OCSP_RESPID_NAME:
			v = i2d_X509_NAME(a->value.byName,NULL);
			ret += ASN1_object_size(1, v, V_OCSP_RESPID_NAME);
		        if (pp==NULL) return ret;
			p=*pp;
			ASN1_put_object(&p, 1, v, 
					V_OCSP_RESPID_NAME,
					V_ASN1_CONTEXT_SPECIFIC);
			i2d_X509_NAME(a->value.byName,&p);
		        break;
		case V_OCSP_RESPID_KEY:
			v = i2d_ASN1_OCTET_STRING(a->value.byKey,NULL);
			ret += ASN1_object_size(1, v, V_OCSP_RESPID_KEY);
		        if (pp==NULL) return ret;
			p=*pp;
			ASN1_put_object(&p, 1, v, 
					V_OCSP_RESPID_KEY,
					V_ASN1_CONTEXT_SPECIFIC);
			i2d_ASN1_OCTET_STRING(a->value.byKey,&p);
		        break;
		}
	if (pp && *pp) *pp=p;
	return(r);
	}

OCSP_RESPID *d2i_OCSP_RESPID(OCSP_RESPID **a,
			     unsigned char **pp,
			     long length)
	{
	int inf,xclass;
	M_ASN1_D2I_vars(a,OCSP_RESPID *,OCSP_RESPID_new);

	M_ASN1_D2I_Init();
	c.slen = length; /* simulate sequence */
	inf=ASN1_get_object(&c.p,&c.slen,&ret->tag,&xclass,c.slen);
	if (inf & 0x80) goto err;
	switch (ret->tag)
		{
		case V_OCSP_RESPID_NAME:
			M_ASN1_D2I_get(ret->value.byName, d2i_X509_NAME);
		        break;
		case V_OCSP_RESPID_KEY:
			M_ASN1_D2I_get(ret->value.byKey, d2i_ASN1_OCTET_STRING);
		        break;
		default:
		        ASN1err(ASN1_F_D2I_OCSP_RESPID,ASN1_R_BAD_TYPE);
		        break;
		}
	M_ASN1_D2I_Finish(a,OCSP_RESPID_free,ASN1_F_D2I_OCSP_RESPID);
	}

int i2a_OCSP_RESPID(BIO *bp, OCSP_RESPID* a)
        {
	switch (a->tag)
		{
		case V_OCSP_RESPID_NAME:
		        X509_NAME_print(bp, a->value.byName, 16);
		        break;
		case V_OCSP_RESPID_KEY:
		        i2a_ASN1_STRING(bp, a->value.byKey, V_ASN1_OCTET_STRING);
		        break;
		}

	return 1;
	}

OCSP_RESPDATA *OCSP_RESPDATA_new(void)
	{
	ASN1_CTX c;
	OCSP_RESPDATA *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_RESPDATA);
	ret->version = NULL;
	M_ASN1_New(ret->responderId, OCSP_RESPID_new);
	M_ASN1_New(ret->producedAt, ASN1_GENERALIZEDTIME_new);
	ret->responses = NULL;
	ret->responseExtensions = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_RESPDATA_NEW);
	}
	
void OCSP_RESPDATA_free(OCSP_RESPDATA *a)
	{
	if (a == NULL) return;
	ASN1_INTEGER_free(a->version);
	OCSP_RESPID_free(a->responderId);
	ASN1_GENERALIZEDTIME_free(a->producedAt);
	sk_OCSP_SINGLERESP_pop_free(a->responses, OCSP_SINGLERESP_free);
	sk_X509_EXTENSION_pop_free(a->responseExtensions, X509_EXTENSION_free);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_RESPDATA(OCSP_RESPDATA *a,
		      unsigned char **pp)
	{
	int v1=0,v2=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len_EXP_opt(a->version, i2d_ASN1_INTEGER, 0, v1);
	M_ASN1_I2D_len(a->responderId, i2d_OCSP_RESPID);
	M_ASN1_I2D_len(a->producedAt, i2d_ASN1_GENERALIZEDTIME);
	M_ASN1_I2D_len_SEQUENCE_type(OCSP_SINGLERESP, a->responses, 
				i2d_OCSP_SINGLERESP);
	M_ASN1_I2D_len_EXP_SEQUENCE_opt_type(X509_EXTENSION,
	     a->responseExtensions, i2d_X509_EXTENSION, 1,
	     V_ASN1_SEQUENCE, v2);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put_EXP_opt(a->version, i2d_ASN1_INTEGER, 0, v1);
	M_ASN1_I2D_put(a->responderId, i2d_OCSP_RESPID);
	M_ASN1_I2D_put(a->producedAt, i2d_ASN1_GENERALIZEDTIME);
	M_ASN1_I2D_put_SEQUENCE_type(OCSP_SINGLERESP, a->responses,
				     i2d_OCSP_SINGLERESP);
	M_ASN1_I2D_put_EXP_SEQUENCE_opt_type(X509_EXTENSION,
	     a->responseExtensions, i2d_X509_EXTENSION, 1,
	     V_ASN1_SEQUENCE, v2);
	M_ASN1_I2D_finish();
	}

OCSP_RESPDATA *d2i_OCSP_RESPDATA(OCSP_RESPDATA **a,
				 unsigned char **pp,
				 long length)
	{
	M_ASN1_D2I_vars(a,OCSP_RESPDATA *,OCSP_RESPDATA_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	/* we have the optional version field */
	if (M_ASN1_next == (V_ASN1_CONTEXT_SPECIFIC | V_ASN1_CONSTRUCTED | 0))
		{ M_ASN1_D2I_get_EXP_opt(ret->version,d2i_ASN1_INTEGER,0);}
	else
		{
		if (ret->version != NULL)
			{
			ASN1_INTEGER_free(ret->version);
			ret->version=NULL;
			}
		}
	M_ASN1_D2I_get(ret->responderId, d2i_OCSP_RESPID);
	M_ASN1_D2I_get(ret->producedAt, d2i_ASN1_GENERALIZEDTIME);
	M_ASN1_D2I_get_seq_type(OCSP_SINGLERESP, ret->responses,
			d2i_OCSP_SINGLERESP, OCSP_SINGLERESP_free);
	/* there is no M_ASN1_D2I_get_EXP_seq* code, so
	   we're using the set version */
	M_ASN1_D2I_get_EXP_set_opt_type(X509_EXTENSION,
		ret->responseExtensions, d2i_X509_EXTENSION, 
	        X509_EXTENSION_free, 1, V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a,OCSP_RESPDATA_free,ASN1_F_D2I_OCSP_RESPDATA);
	}

int i2a_OCSP_RESPDATA(BIO *bp, OCSP_RESPDATA* a)
        {
	int i, j=2;
	if (a->version == NULL) BIO_puts(bp, "0");
	else i2a_ASN1_INTEGER(bp, a->version);
	i2a_OCSP_RESPID(bp, a->responderId);
	if (!ASN1_GENERALIZEDTIME_print(bp, a->producedAt)) return 0;
	if (a->responses != NULL)
		{
		for (i=0; i<sk_OCSP_SINGLERESP_num(a->responses); i++)
			if (sk_OCSP_SINGLERESP_value(a->responses,i) != NULL)
				i2a_OCSP_SINGLERESP(bp, 
				      sk_OCSP_SINGLERESP_value(a->responses,i));
		j+=sk_OCSP_SINGLERESP_num(a->responses);
		}
#ifdef UNDEF
	/* XXX need generic extension print method or need to register
	 * ocsp extensions with existing extension handler mechanism,
	 * invoke i2a callbacks.
	 */
	if (a->responseExtensions != NULL)
		{
		for (i=0; i<sk_X509_EXTENSION_num(a->responseExtensions); i++)
			if (sk_X509_EXTENSION_value(a->responseExtensions,i) != NULL)
				i2a_X509_EXTENSION(bp, 
				   sk_X509_EXTENSION_value(a->responseExtensions,i));
		j+=sk_X509_EXTENSION_num(a->responseExtensions);
		}
#endif
	return j;
	}

OCSP_BASICRESP *OCSP_BASICRESP_new(void)
	{
	ASN1_CTX c;
	OCSP_BASICRESP *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_BASICRESP);
	M_ASN1_New(ret->tbsResponseData, OCSP_RESPDATA_new);
	M_ASN1_New(ret->signatureAlgorithm, X509_ALGOR_new);
	M_ASN1_New(ret->signature, ASN1_BIT_STRING_new);
	ret->certs = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_BASICRESP_NEW);
	}
	
void OCSP_BASICRESP_free(OCSP_BASICRESP *a)
	{
	if (a == NULL) return;
	OCSP_RESPDATA_free(a->tbsResponseData);
	X509_ALGOR_free(a->signatureAlgorithm);
	ASN1_BIT_STRING_free(a->signature);
	sk_X509_pop_free(a->certs, X509_free);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_BASICRESP(OCSP_BASICRESP *a, unsigned char **pp)
	{
	int v=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->tbsResponseData, i2d_OCSP_RESPDATA);
	M_ASN1_I2D_len(a->signatureAlgorithm, i2d_X509_ALGOR);
	M_ASN1_I2D_len(a->signature, i2d_ASN1_BIT_STRING);
	M_ASN1_I2D_len_EXP_SEQUENCE_opt_type(X509, a->certs, 
			     i2d_X509, 0, V_ASN1_SEQUENCE, v);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->tbsResponseData, i2d_OCSP_RESPDATA);
	M_ASN1_I2D_put(a->signatureAlgorithm, i2d_X509_ALGOR);
	M_ASN1_I2D_put(a->signature, i2d_ASN1_BIT_STRING);
	M_ASN1_I2D_put_EXP_SEQUENCE_opt_type(X509, a->certs,
			     i2d_X509, 0, V_ASN1_SEQUENCE, v);
	M_ASN1_I2D_finish();
	}

OCSP_BASICRESP *d2i_OCSP_BASICRESP(OCSP_BASICRESP **a,
				   unsigned char **pp,
				   long length)
	{
	M_ASN1_D2I_vars(a,OCSP_BASICRESP *,OCSP_BASICRESP_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->tbsResponseData, d2i_OCSP_RESPDATA);
	M_ASN1_D2I_get(ret->signatureAlgorithm, d2i_X509_ALGOR);
	M_ASN1_D2I_get(ret->signature, d2i_ASN1_BIT_STRING);
	/* there is no M_ASN1_D2I_get_EXP_seq* code, so
	   we're using the set version */
	M_ASN1_D2I_get_EXP_set_opt_type(X509, ret->certs, d2i_X509, 
				   X509_free, 0, V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a,OCSP_BASICRESP_free,ASN1_F_D2I_OCSP_BASICRESP);
	}

int i2a_OCSP_BASICRESP(BIO *bp, OCSP_BASICRESP* a)
        {
	int i, j=3;
	i2a_OCSP_RESPDATA(bp, a->tbsResponseData);
#ifdef UNDEF
	/* XXX this guy isn't implemented. */
	i2a_X509_ALGOR(bp, a->signatureAlgorithm);
#else   /* instead, just show OID, not param */
	i2a_ASN1_OBJECT(bp, a->signatureAlgorithm->algorithm);
#endif
	i2a_ASN1_STRING(bp, a->signature, V_ASN1_BIT_STRING);
	if (a->certs != NULL)
		{
		for (i=0; i<sk_X509_num(a->certs); i++)
			if (sk_X509_value(a->certs,i) != NULL)
				X509_print(bp, sk_X509_value(a->certs,i));
		j+=sk_X509_num(a->certs);
		}
	return j;
	}

OCSP_REVOKEDINFO *OCSP_REVOKEDINFO_new(void)
	{
	ASN1_CTX c;
	OCSP_REVOKEDINFO *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_REVOKEDINFO);
	M_ASN1_New(ret->revocationTime, ASN1_GENERALIZEDTIME_new);
	ret->revocationReason = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_REVOKEDINFO_NEW);
	}
	
void OCSP_REVOKEDINFO_free(OCSP_REVOKEDINFO *a)
	{
	if (a == NULL) return;
	ASN1_GENERALIZEDTIME_free(a->revocationTime);
	ASN1_ENUMERATED_free(a->revocationReason);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_REVOKEDINFO(OCSP_REVOKEDINFO *a, unsigned char **pp)
	{
	int v=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->revocationTime, i2d_ASN1_GENERALIZEDTIME);
	M_ASN1_I2D_len_EXP_opt(a->revocationReason, i2d_ASN1_ENUMERATED, 0, v);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->revocationTime, i2d_ASN1_GENERALIZEDTIME); 
	M_ASN1_I2D_put_EXP_opt(a->revocationReason, i2d_ASN1_ENUMERATED, 0, v);
	M_ASN1_I2D_finish();
	}

OCSP_REVOKEDINFO *d2i_OCSP_REVOKEDINFO(OCSP_REVOKEDINFO **a,
				       unsigned char **pp,
				       long length)
	{
	M_ASN1_D2I_vars(a,OCSP_REVOKEDINFO *,OCSP_REVOKEDINFO_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->revocationTime, d2i_ASN1_GENERALIZEDTIME);
	M_ASN1_D2I_get_EXP_opt(ret->revocationReason, d2i_ASN1_ENUMERATED, 0);
	M_ASN1_D2I_Finish(a,OCSP_REVOKEDINFO_free,ASN1_F_D2I_OCSP_REVOKEDINFO);
	}

int i2a_OCSP_REVOKEDINFO(BIO *bp, OCSP_REVOKEDINFO* a)
        {
	int i=0; 
	if (!ASN1_GENERALIZEDTIME_print(bp, a->revocationTime)) return 0;
	if (a->revocationReason)
		{
                i2a_ASN1_STRING(bp, a->revocationReason, V_ASN1_ENUMERATED);
		i++;
		}
	return i;
	}

OCSP_CERTSTATUS *OCSP_CERTSTATUS_new(void)

	{
	ASN1_CTX c;
	OCSP_CERTSTATUS *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_CERTSTATUS);
	ret->tag = -1;
	ret->revoked = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_CERTSTATUS_NEW);
	}
	
void OCSP_CERTSTATUS_free(OCSP_CERTSTATUS *a)
	{
	if (a == NULL) return;
	OCSP_REVOKEDINFO_free(a->revoked);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_CERTSTATUS(OCSP_CERTSTATUS *a, unsigned char **pp)
	{
	unsigned char *qq;
	M_ASN1_I2D_vars(a);
	ret += 0; /* shush, compiler, shush... */
	if (a == NULL) return(0);
	switch (a->tag)
		{
		case V_OCSP_CERTSTATUS_GOOD:
		case V_OCSP_CERTSTATUS_UNKNOWN:
		        r = 2;
			if (pp)
				{
				qq=p=*pp;
				ASN1_put_object(&p,0,0,
						V_ASN1_NULL,V_ASN1_UNIVERSAL);
				*qq=(V_ASN1_CONTEXT_SPECIFIC|a->tag|
				                   (*qq&V_ASN1_CONSTRUCTED));
				}
		        break;
		case V_OCSP_CERTSTATUS_REVOKED:
		        r = i2d_OCSP_REVOKEDINFO(a->revoked,NULL);
			if (pp)
			        {
				p=*pp;
			        M_ASN1_I2D_put_IMP_opt(a->revoked,
						       i2d_OCSP_REVOKEDINFO, 
						       a->tag);
				}
		        break;

		}
	if (pp && *pp) *pp=p;
	return(r);
	}

OCSP_CERTSTATUS *d2i_OCSP_CERTSTATUS(OCSP_CERTSTATUS **a,
				     unsigned char **pp,
				     long length)
	{
	int tag, xclass, error=0;
	long len;
	unsigned char *p, *q, t;
	OCSP_CERTSTATUS* ret=NULL;

	if ((a == NULL) || ((*a) == NULL))
		{ 
		if ((ret=(OCSP_CERTSTATUS*)OCSP_CERTSTATUS_new()) == NULL) 
		        goto err; 
		}
	else	ret=(*a);
	p=*pp;
	ret->tag = (*p & ~(V_ASN1_CONSTRUCTED | V_ASN1_CONTEXT_SPECIFIC));
	switch (ret->tag)
	        {
		case V_OCSP_CERTSTATUS_GOOD:
		case V_OCSP_CERTSTATUS_UNKNOWN:
		        ret->revoked = NULL;
			q=p;
			ASN1_get_object(&p,&len,&tag,&xclass,length);
			if (len) 
                                {
				error = ASN1_R_BAD_TYPE;
				goto err;
				}
		        break;
		case V_OCSP_CERTSTATUS_REVOKED:
			q=p;
			ASN1_get_object(&q,&len,&tag,&xclass,length);
		        t=*p;
			*p=(t&~V_ASN1_PRIMATIVE_TAG)|V_ASN1_SEQUENCE;
		        q=p; 
			if (d2i_OCSP_REVOKEDINFO(&ret->revoked,
						 &p,length) == NULL)
			        goto err;
			*q=t;
			if ((p-q) != (len+2))
                                {
				error = ASN1_R_BAD_TYPE;
				goto err;
				}
		        break;
	        default:
		        ASN1err(ASN1_F_D2I_OCSP_CERTSTATUS,ASN1_R_BAD_TYPE);
		        break;
		}
	*pp=p;
	if (a != NULL) (*a)=ret;
	return(ret);
err:
	ASN1err(ASN1_F_D2I_OCSP_CERTSTATUS,error); 
	asn1_add_error(*pp,(int)(q- *pp)); 
	if ((ret != NULL) && ((a == NULL) || (*a != ret))) 
	        OCSP_CERTSTATUS_free(ret); 
	return(NULL);
	}

int i2a_OCSP_CERTSTATUS(BIO *bp, OCSP_CERTSTATUS* a)
        {
	switch (a->tag)
		{
		case V_OCSP_CERTSTATUS_GOOD:
			BIO_puts(bp, "CertStatus: good");
		        break;
		case V_OCSP_CERTSTATUS_REVOKED:
			BIO_puts(bp, "CertStatus: revoked");
			i2a_OCSP_REVOKEDINFO(bp, a->revoked);
		        break;
		case V_OCSP_CERTSTATUS_UNKNOWN:
			BIO_puts(bp, "CertStatus: unknown");
		        break;
		}
	return 1;
	}

OCSP_SINGLERESP *OCSP_SINGLERESP_new(void)
	{
	ASN1_CTX c;
	OCSP_SINGLERESP *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_SINGLERESP);
	M_ASN1_New(ret->certId, OCSP_CERTID_new);
	M_ASN1_New(ret->certStatus, OCSP_CERTSTATUS_new);
	M_ASN1_New(ret->thisUpdate, ASN1_GENERALIZEDTIME_new);
	ret->nextUpdate = NULL;
	ret->singleExtensions = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_SINGLERESP_NEW);
	}
	
void OCSP_SINGLERESP_free(OCSP_SINGLERESP *a)
	{
	if (a == NULL) return;
	OCSP_CERTID_free(a->certId);
	OCSP_CERTSTATUS_free(a->certStatus);
	ASN1_GENERALIZEDTIME_free(a->thisUpdate);
	ASN1_GENERALIZEDTIME_free(a->nextUpdate);
	sk_X509_EXTENSION_pop_free(a->singleExtensions, X509_EXTENSION_free);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_SINGLERESP(OCSP_SINGLERESP *a, unsigned char **pp)
	{
	int v1=0,v2=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->certId, i2d_OCSP_CERTID);
	M_ASN1_I2D_len(a->certStatus, i2d_OCSP_CERTSTATUS);
	M_ASN1_I2D_len(a->thisUpdate, i2d_ASN1_GENERALIZEDTIME);
	M_ASN1_I2D_len_EXP_opt(a->nextUpdate, i2d_ASN1_GENERALIZEDTIME, 0, v1);
	M_ASN1_I2D_len_EXP_SEQUENCE_opt_type(X509_EXTENSION,
	     a->singleExtensions, i2d_X509_EXTENSION, 1, V_ASN1_SEQUENCE, v2);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->certId, i2d_OCSP_CERTID);
	M_ASN1_I2D_put(a->certStatus, i2d_OCSP_CERTSTATUS);
	M_ASN1_I2D_put(a->thisUpdate, i2d_ASN1_GENERALIZEDTIME);
	M_ASN1_I2D_put_EXP_opt(a->nextUpdate, i2d_ASN1_GENERALIZEDTIME, 0, v1);
	M_ASN1_I2D_put_EXP_SEQUENCE_opt_type(X509_EXTENSION,
	     a->singleExtensions, i2d_X509_EXTENSION, 1, V_ASN1_SEQUENCE, v2);
	M_ASN1_I2D_finish();
	}

OCSP_SINGLERESP *d2i_OCSP_SINGLERESP(OCSP_SINGLERESP **a,
				     unsigned char **pp,
				     long length)
	{
	M_ASN1_D2I_vars(a,OCSP_SINGLERESP *,OCSP_SINGLERESP_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->certId, d2i_OCSP_CERTID);
	M_ASN1_D2I_get(ret->certStatus, d2i_OCSP_CERTSTATUS);
	M_ASN1_D2I_get(ret->thisUpdate, d2i_ASN1_GENERALIZEDTIME);
	M_ASN1_D2I_get_EXP_opt(ret->nextUpdate, d2i_ASN1_GENERALIZEDTIME, 0);
	/* there is no M_ASN1_D2I_get_EXP_seq*, so had to use set here*/
	M_ASN1_D2I_get_EXP_set_opt_type(X509_EXTENSION, ret->singleExtensions, 
	   d2i_X509_EXTENSION, X509_EXTENSION_free, 1, V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a,OCSP_SINGLERESP_free,ASN1_F_D2I_OCSP_SINGLERESP);
	}

int i2a_OCSP_SINGLERESP(BIO *bp, OCSP_SINGLERESP* a)
        {
	int /* XXX i, */ j=3;
	i2a_OCSP_CERTID(bp, a->certId);
	i2a_OCSP_CERTSTATUS(bp, a->certStatus);
	if (!ASN1_GENERALIZEDTIME_print(bp, a->thisUpdate)) return 0;
	if (a->nextUpdate) 
	        {
		if (!ASN1_GENERALIZEDTIME_print(bp, a->nextUpdate)) return 0;
		j++;
		}
#ifdef UNDEF
	/* XXX need generic extension print method or need to register
	 * ocsp extensions with existing extension handler mechanism,
	 * invoke i2a callbacks.
	 */
	if (a->singleExtensions != NULL)
		{
		for (i=0; i<sk_X509_EXTENSION_num(a->singleExtensions); i++)
			if (sk_X509_EXTENSION_value(a->singleExtensions,i) != NULL)
				i2a_X509_EXTENSION(bp, 
				  sk_X509_EXTENSION_value(a->singleExtensions,i));
		j+=sk_X509_EXTENSION_num(a->singleExtensions);
		}
#endif
	return j;
	}

OCSP_CRLID *OCSP_CRLID_new(void)
	{
	ASN1_CTX c;
	OCSP_CRLID *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_CRLID);
	ret->crlUrl = NULL;
	ret->crlNum = NULL;
	ret->crlTime = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_CRLID_NEW);
	}
	
void OCSP_CRLID_free(OCSP_CRLID *a)
	{
	if (a == NULL) return;
	ASN1_IA5STRING_free(a->crlUrl);
	ASN1_INTEGER_free(a->crlNum);
	ASN1_GENERALIZEDTIME_free(a->crlTime);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_CRLID(OCSP_CRLID *a,
		   unsigned char **pp)
	{
	int v1=0,v2=0,v3=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len_EXP_opt(a->crlUrl, i2d_ASN1_IA5STRING, 0, v1);
	M_ASN1_I2D_len_EXP_opt(a->crlNum, i2d_ASN1_INTEGER, 1, v2);
	M_ASN1_I2D_len_EXP_opt(a->crlTime, i2d_ASN1_GENERALIZEDTIME, 2, v3);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put_EXP_opt(a->crlUrl, i2d_ASN1_IA5STRING, 0, v1);
	M_ASN1_I2D_put_EXP_opt(a->crlNum, i2d_ASN1_INTEGER, 1, v2);
	M_ASN1_I2D_put_EXP_opt(a->crlTime, i2d_ASN1_GENERALIZEDTIME, 2, v3);
	M_ASN1_I2D_finish();
	}

OCSP_CRLID *d2i_OCSP_CRLID(OCSP_CRLID **a,
			   unsigned char **pp,
			   long length)
	{
	M_ASN1_D2I_vars(a,OCSP_CRLID *,OCSP_CRLID_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get_EXP_opt(ret->crlUrl, d2i_ASN1_IA5STRING, 0);
	M_ASN1_D2I_get_EXP_opt(ret->crlNum, d2i_ASN1_INTEGER, 1);
	M_ASN1_D2I_get_EXP_opt(ret->crlTime, d2i_ASN1_GENERALIZEDTIME, 2);
	M_ASN1_D2I_Finish(a,OCSP_CRLID_free,ASN1_F_D2I_OCSP_CRLID);
	}

int i2a_OCSP_CRLID(BIO *bp, OCSP_CRLID* a)
        {
	int i = 0;
	char buf[1024];
	if (a->crlUrl && ASN1_STRING_print(bp, (ASN1_STRING*)a->crlUrl)) i++;
	if (a->crlNum && a2i_ASN1_INTEGER(bp, a->crlNum, buf, sizeof buf)) i++;
	if (a->crlTime && ASN1_GENERALIZEDTIME_print(bp, a->crlTime)) i++;
	return i;
	}

OCSP_SERVICELOC *OCSP_SERVICELOC_new(void)
	{
	ASN1_CTX c;
	OCSP_SERVICELOC *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_SERVICELOC);
	M_ASN1_New(ret->issuer, X509_NAME_new);
	ret->locator = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_SERVICELOC_NEW);
	}
	
void OCSP_SERVICELOC_free(OCSP_SERVICELOC *a)
	{
	if (a == NULL) return;
	X509_NAME_free(a->issuer);
	sk_ACCESS_DESCRIPTION_pop_free(a->locator, ACCESS_DESCRIPTION_free);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_SERVICELOC(OCSP_SERVICELOC *a,
			unsigned char **pp)
	{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->issuer, i2d_X509_NAME);
	M_ASN1_I2D_len_SEQUENCE_opt_type(ACCESS_DESCRIPTION, 
			 a->locator, i2d_ACCESS_DESCRIPTION);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->issuer, i2d_X509_NAME);
	M_ASN1_I2D_put_SEQUENCE_opt_type(ACCESS_DESCRIPTION,
			 a->locator, i2d_ACCESS_DESCRIPTION);
	M_ASN1_I2D_finish();
	}

OCSP_SERVICELOC *d2i_OCSP_SERVICELOC(OCSP_SERVICELOC **a,
				     unsigned char **pp,
				     long length)
	{
	M_ASN1_D2I_vars(a,OCSP_SERVICELOC *,OCSP_SERVICELOC_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->issuer, d2i_X509_NAME);
	M_ASN1_D2I_get_seq_opt_type(ACCESS_DESCRIPTION, ret->locator,
		    d2i_ACCESS_DESCRIPTION,ACCESS_DESCRIPTION_free);
	M_ASN1_D2I_Finish(a,OCSP_SERVICELOC_free,ASN1_F_D2I_OCSP_SERVICELOC);
	}

int i2a_OCSP_SERVICELOC(BIO *bp,
			OCSP_SERVICELOC* a)
        {
	int i;
	X509_NAME_print(bp, a->issuer, 16);
	if (!a->locator) return 1;
	for (i=0; i<sk_ACCESS_DESCRIPTION_num(a->locator); i++)
		i2a_ACCESS_DESCRIPTION(bp,
			     sk_ACCESS_DESCRIPTION_value(a->locator,i));
	return i+2;
	}
