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

#include <openssl/bio.h>
#include <openssl/asn1_mac.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
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

IMPLEMENT_STACK_OF(OCSP_ONEREQ)
IMPLEMENT_ASN1_SET_OF(OCSP_ONEREQ)

OCSP_REQINFO *OCSP_REQINFO_new(void)
	{
	OCSP_REQINFO *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret, OCSP_REQINFO);
	ret->version = NULL;
	ret->requestorName = NULL;
	ret->requestList = NULL;
	ret->requestExtensions = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_REQINFO_NEW);
	}

void OCSP_REQINFO_free(OCSP_REQINFO *a)
	{
	if (a == NULL) return;
	ASN1_INTEGER_free(a->version);
	GENERAL_NAME_free(a->requestorName);
	sk_OCSP_ONEREQ_pop_free(a->requestList, OCSP_ONEREQ_free);
	sk_X509_EXTENSION_pop_free(a->requestExtensions, X509_EXTENSION_free);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_REQINFO(OCSP_REQINFO *a,
		     unsigned char **pp)
	{
	int v1=0,v2=0,v3=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len_EXP_opt(a->version,i2d_ASN1_INTEGER,0,v1);
	M_ASN1_I2D_len_EXP_opt(a->requestorName,i2d_GENERAL_NAME,1,v2);
	M_ASN1_I2D_len_SEQUENCE_type(OCSP_ONEREQ,
		     a->requestList, i2d_OCSP_ONEREQ);
	M_ASN1_I2D_len_EXP_SEQUENCE_opt_type(X509_EXTENSION,
	     a->requestExtensions, i2d_X509_EXTENSION,2,V_ASN1_SEQUENCE,v3);

	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put_EXP_opt(a->version,i2d_ASN1_INTEGER,0,v1);
	M_ASN1_I2D_put_EXP_opt(a->requestorName,i2d_GENERAL_NAME,1,v2);
	M_ASN1_I2D_put_SEQUENCE_type(OCSP_ONEREQ,a->requestList,i2d_OCSP_ONEREQ);
	M_ASN1_I2D_put_EXP_SEQUENCE_opt_type(X509_EXTENSION,a->requestExtensions,i2d_X509_EXTENSION,2,V_ASN1_SEQUENCE,v3);

	M_ASN1_I2D_finish();
	}

OCSP_REQINFO *d2i_OCSP_REQINFO(OCSP_REQINFO **a,
			       unsigned char **pp,
			       long length)
	{
	M_ASN1_D2I_vars(a,OCSP_REQINFO *,OCSP_REQINFO_new);

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
	M_ASN1_D2I_get_EXP_opt(ret->requestorName,d2i_GENERAL_NAME,1);
	M_ASN1_D2I_get_seq_type(OCSP_ONEREQ, ret->requestList,
				d2i_OCSP_ONEREQ,OCSP_ONEREQ_free);
	/* there is no M_ASN1_D2I_get_EXP_seq* code, so
	   we're using the set version */
	M_ASN1_D2I_get_EXP_set_opt_type(X509_EXTENSION,
		ret->requestExtensions,d2i_X509_EXTENSION,
		X509_EXTENSION_free,2,V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a,OCSP_REQINFO_free,ASN1_F_D2I_OCSP_REQINFO);
	}

int i2a_OCSP_REQINFO(BIO *bp,
		     OCSP_REQINFO* a)
        {
	int i, j=1;
	if (a->version == NULL) BIO_puts(bp, "0");
	else i2a_ASN1_INTEGER(bp, a->version);
	if (a->requestorName != NULL) 
		{
		j++;
#ifdef UNDEF
		i2a_GENERAL_NAME(bp, a->requestorName); /* does not exist */
#endif
		}
	if (a->requestList != NULL)
		{
		for (i=0; i<sk_OCSP_ONEREQ_num(a->requestList); i++)
			if (sk_OCSP_ONEREQ_value(a->requestList,i) != NULL)
				i2a_OCSP_ONEREQ(bp, 
				      sk_OCSP_ONEREQ_value(a->requestList,i));
		j+=sk_OCSP_ONEREQ_num(a->requestList);
		}
	j+=OCSP_extensions_print(bp, a->requestExtensions,
				 "Request Extensions");
	return j;
	}

OCSP_REQUEST *OCSP_REQUEST_new(void)
	{
	ASN1_CTX c;
	OCSP_REQUEST *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_REQUEST);
	M_ASN1_New(ret->tbsRequest, OCSP_REQINFO_new);
	ret->optionalSignature = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_REQUEST_NEW);
	}
	
void OCSP_REQUEST_free(OCSP_REQUEST *a)
	{
	if (a == NULL) return;
	OCSP_REQINFO_free(a->tbsRequest);
	OCSP_SIGNATURE_free(a->optionalSignature);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_REQUEST(OCSP_REQUEST *a,
		     unsigned char **pp)
	{
	int v=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->tbsRequest, i2d_OCSP_REQINFO);
	M_ASN1_I2D_len_EXP_opt(a->optionalSignature, i2d_OCSP_SIGNATURE, 0, v);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->tbsRequest, i2d_OCSP_REQINFO); 
	M_ASN1_I2D_put_EXP_opt(a->optionalSignature, i2d_OCSP_SIGNATURE, 0, v);
	M_ASN1_I2D_finish();
	}

OCSP_REQUEST *d2i_OCSP_REQUEST(OCSP_REQUEST **a,
			       unsigned char **pp,
			       long length)
	{
	M_ASN1_D2I_vars(a,OCSP_REQUEST *,OCSP_REQUEST_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->tbsRequest, d2i_OCSP_REQINFO);
	M_ASN1_D2I_get_EXP_opt(ret->optionalSignature, d2i_OCSP_SIGNATURE, 0);
	M_ASN1_D2I_Finish(a,OCSP_REQUEST_free,ASN1_F_D2I_OCSP_REQUEST);
	}

int i2a_OCSP_REQUEST(BIO *bp,
		     OCSP_REQUEST* a)
        {
	i2a_OCSP_REQINFO(bp, a->tbsRequest);
	i2a_OCSP_SIGNATURE(bp, a->optionalSignature);
	return a->optionalSignature ? 2 : 1;
	}

OCSP_ONEREQ *OCSP_ONEREQ_new(void)
	{
	ASN1_CTX c;
	OCSP_ONEREQ *ret=NULL;

	M_ASN1_New_Malloc(ret, OCSP_ONEREQ);
	M_ASN1_New(ret->reqCert, OCSP_CERTID_new);
	ret->singleRequestExtensions = NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_OCSP_ONEREQ_NEW);
	}
	
void OCSP_ONEREQ_free(OCSP_ONEREQ *a)
	{
	if (a == NULL) return;
	OCSP_CERTID_free(a->reqCert);
	sk_X509_EXTENSION_pop_free(a->singleRequestExtensions, X509_EXTENSION_free);
	OPENSSL_free((char *)a);
	}

int i2d_OCSP_ONEREQ(OCSP_ONEREQ *a,
		    unsigned char **pp)
	{
	int v=0;
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->reqCert, i2d_OCSP_CERTID);
	M_ASN1_I2D_len_EXP_SEQUENCE_opt_type(X509_EXTENSION,
	     a->singleRequestExtensions, i2d_X509_EXTENSION, 0,
	     V_ASN1_SEQUENCE, v);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->reqCert, i2d_OCSP_CERTID);
	M_ASN1_I2D_put_EXP_SEQUENCE_opt_type(X509_EXTENSION,
	     a->singleRequestExtensions, i2d_X509_EXTENSION, 0,
	     V_ASN1_SEQUENCE, v);
	M_ASN1_I2D_finish();
	}

OCSP_ONEREQ *d2i_OCSP_ONEREQ(OCSP_ONEREQ **a,
			     unsigned char **pp,
			     long length)
	{
	M_ASN1_D2I_vars(a,OCSP_ONEREQ *,OCSP_ONEREQ_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->reqCert, d2i_OCSP_CERTID);
	/* there is no M_ASN1_D2I_get_EXP_seq* code, so
	   we're using the set version */
	M_ASN1_D2I_get_EXP_set_opt_type(X509_EXTENSION,
		ret->singleRequestExtensions, d2i_X509_EXTENSION,
		X509_EXTENSION_free, 0, V_ASN1_SEQUENCE);
	M_ASN1_D2I_Finish(a,OCSP_ONEREQ_free,ASN1_F_D2I_OCSP_ONEREQ);
	}

int i2a_OCSP_ONEREQ(BIO *bp,
		    OCSP_ONEREQ* a)
        {
	i2a_OCSP_CERTID(bp, a->reqCert);
#ifdef UNDEF
	/* XXX need generic extension print method or need to register
	 * ocsp extensions with existing extension handler mechanism,
	 * invoke i2a callbacks.
	 */
	if (a->singleRequestExtensions != NULL)
		{
		for (i=0; i<sk_X509_EXTENSION_num(a->singleRequestExtensions); i++)
			if (sk_X509_EXTENSION_value(a->singleRequestExtensions,i) != NULL)
			  i2a_X509_EXTENSION(bp, 
				     sk_X509_EXTENSION_value(
				        a->singleRequestExtensions, i));
		j+=sk_X509_EXTENSION_num(a->singleRequestExtensions);
		}
#endif
	return 1;
	}
