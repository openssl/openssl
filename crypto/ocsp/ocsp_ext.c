/* ocsp_ext.c */
/* Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project. */

/* History:
   This file was transfered to Richard Levitte from CertCo by Kathy
   Weinhold in mid-spring 2000 to be included in OpenSSL or released
   as a patch kit. */

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

#include <stdio.h>
#include <cryptlib.h>
#include <openssl/objects.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>
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

/* also CRL Entry Extensions */

ASN1_STRING *ASN1_STRING_encode(ASN1_STRING *s, int (*i2d)(), 
				char *data, STACK_OF(ASN1_OBJECT) *sk)
        {
	int i;
	unsigned char *p, *b = NULL;

	if (data)
	        {
		if ((i=i2d(data,NULL)) <= 0) goto err;
		if (!(b=p=(unsigned char*)OPENSSL_malloc((unsigned int)i)))
			goto err;
	        if (i2d(data, &p) <= 0) goto err;
		}
	else if (sk)
	        {
		if ((i=i2d_ASN1_SET_OF_ASN1_OBJECT(sk,NULL,i2d,V_ASN1_SEQUENCE,
				   V_ASN1_UNIVERSAL,IS_SEQUENCE))<=0) goto err;
		if (!(b=p=(unsigned char*)OPENSSL_malloc((unsigned int)i)))
			goto err;
		if (i2d_ASN1_SET_OF_ASN1_OBJECT(sk,&p,i2d,V_ASN1_SEQUENCE,
				 V_ASN1_UNIVERSAL,IS_SEQUENCE)<=0) goto err;
		}
	else
		{
		OCSPerr(OCSP_F_ASN1_STRING_ENCODE,OCSP_R_BAD_DATA);
		goto err;
		}
	if (!s && !(s = ASN1_STRING_new())) goto err;
	if (!(ASN1_STRING_set(s, b, i))) goto err;
	OPENSSL_free(b);
	return s;
err:
	if (b) OPENSSL_free(b);
	return NULL;
	}

X509_EXTENSION *OCSP_nonce_new(void *p, unsigned int len)
        {
	X509_EXTENSION *x=NULL;
	if (!(x = X509_EXTENSION_new())) goto err;
	if (!(x->object = OBJ_nid2obj(NID_id_pkix_OCSP_Nonce))) goto err;
	if (!(ASN1_OCTET_STRING_set(x->value, p, len))) goto err;
	return x;
err:
	if (x) X509_EXTENSION_free(x);
	return NULL;
	}

X509_EXTENSION *OCSP_crlID_new(char *url, long *n, char *tim)
        {
	X509_EXTENSION *x = NULL;
	OCSP_CRLID *cid = NULL;
	
	if (!(cid = OCSP_CRLID_new())) goto err;
	if (url)
	        {
		if (!(cid->crlUrl = ASN1_IA5STRING_new())) goto err;
		if (!(ASN1_STRING_set(cid->crlUrl, url, -1))) goto err;
		}
	if (n)
	        {
		if (!(cid->crlNum = ASN1_INTEGER_new())) goto err;
		if (!(ASN1_INTEGER_set(cid->crlNum, *n))) goto err;
		}
	if (tim)
	        {
		if (!(cid->crlTime = ASN1_GENERALIZEDTIME_new())) goto err;
		if (!(ASN1_GENERALIZEDTIME_set_string(cid->crlTime, tim))) 
		        goto err;
		}
	if (!(x = X509_EXTENSION_new())) goto err;
	if (!(x->object = OBJ_nid2obj(NID_id_pkix_OCSP_CrlID))) goto err;
	if (!(ASN1_STRING_encode(x->value,i2d_OCSP_CRLID,(char*)cid,NULL)))
	        goto err;
	OCSP_CRLID_free(cid);
	return x;
err:
	if (x) X509_EXTENSION_free(x);
	if (cid) OCSP_CRLID_free(cid);
	return NULL;
	}

/*   AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER */
X509_EXTENSION *OCSP_accept_responses_new(char **oids)
        {
	int nid;
	STACK_OF(ASN1_OBJECT) *sk = NULL;
	ASN1_OBJECT *o = NULL;
        X509_EXTENSION *x = NULL;

	if (!(sk = sk_ASN1_OBJECT_new(NULL))) goto err;
	while (oids && *oids)
	        {
		if ((nid=OBJ_txt2nid(*oids))!=NID_undef&&(o=OBJ_nid2obj(nid))) 
		        sk_ASN1_OBJECT_push(sk, o);
		oids++;
		}
	if (!(x = X509_EXTENSION_new())) goto err;
	if (!(x->object = OBJ_nid2obj(NID_id_pkix_OCSP_acceptableResponses)))
		goto err;
	if (!(ASN1_STRING_encode(x->value,i2d_ASN1_OBJECT,NULL,sk)))
	        goto err;
	sk_ASN1_OBJECT_pop_free(sk, ASN1_OBJECT_free);
	return x;
err:
	if (x) X509_EXTENSION_free(x);
	if (sk) sk_ASN1_OBJECT_pop_free(sk, ASN1_OBJECT_free);
	return NULL;
        }

/*  ArchiveCutoff ::= GeneralizedTime */
X509_EXTENSION *OCSP_archive_cutoff_new(char* tim)
        {
	X509_EXTENSION *x=NULL;
	ASN1_GENERALIZEDTIME *gt = NULL;

	if (!(gt = ASN1_GENERALIZEDTIME_new())) goto err;
	if (!(ASN1_GENERALIZEDTIME_set_string(gt, tim))) goto err;
	if (!(x = X509_EXTENSION_new())) goto err;
	if (!(x->object=OBJ_nid2obj(NID_id_pkix_OCSP_archiveCutoff)))goto err;
	if (!(ASN1_STRING_encode(x->value,i2d_ASN1_GENERALIZEDTIME,
				 (char*)gt,NULL))) goto err;
	ASN1_GENERALIZEDTIME_free(gt);
	return x;
err:
	if (gt) ASN1_GENERALIZEDTIME_free(gt);
	if (x) X509_EXTENSION_free(x);
	return NULL;
	}

/* per ACCESS_DESCRIPTION parameter are oids, of which there are currently
 * two--NID_ad_ocsp, NID_id_ad_caIssuers--and GeneralName value.  This
 * method forces NID_ad_ocsp and uniformResourceLocator [6] IA5String.
 */
X509_EXTENSION *OCSP_url_svcloc_new(X509_NAME* issuer, char **urls)
        {
	X509_EXTENSION *x = NULL;
	ASN1_IA5STRING *ia5 = NULL;
	OCSP_SERVICELOC *sloc = NULL;
	ACCESS_DESCRIPTION *ad = NULL;
	
	if (!(sloc = OCSP_SERVICELOC_new())) goto err;
	if (!(sloc->issuer = X509_NAME_dup(issuer))) goto err;
	if (urls && *urls && !(sloc->locator = sk_ACCESS_DESCRIPTION_new(NULL))) goto err;
	while (urls && *urls)
	        {
		if (!(ad = ACCESS_DESCRIPTION_new())) goto err;
		if (!(ad->method=OBJ_nid2obj(NID_ad_OCSP))) goto err;
		if (!(ad->location = GENERAL_NAME_new())) goto err;
	        if (!(ia5 = ASN1_IA5STRING_new())) goto err;
		if (!ASN1_STRING_set((ASN1_STRING*)ia5, *urls, -1)) goto err;
		ad->location->type = GEN_URI;
		ad->location->d.ia5 = ia5;
		if (!sk_ACCESS_DESCRIPTION_push(sloc->locator, ad)) goto err;
		urls++;
		}
	if (!(x = X509_EXTENSION_new())) goto err;
	if (!(x->object = OBJ_nid2obj(NID_id_pkix_OCSP_serviceLocator))) 
	        goto err;
	if (!(ASN1_STRING_encode(x->value, i2d_OCSP_SERVICELOC,
				 (char*)sloc, NULL))) goto err;
	OCSP_SERVICELOC_free(sloc);
	return x;
err:
	if (x) X509_EXTENSION_free(x);
	if (sloc) OCSP_SERVICELOC_free(sloc);
	return NULL;
	}

int OCSP_extensions_print(BIO *bp,
			  STACK_OF(X509_EXTENSION) *sk,
			  char *title)
        {
	int i;
	if (!sk) return 1;
	if (BIO_printf(bp, "%s:\n", title) <= 0) return 0; 
	for (i=0; i<sk_X509_EXTENSION_num(sk); i++)
	        OCSP_extension_print(bp, sk_X509_EXTENSION_value(sk,i), 4);
	return sk_X509_EXTENSION_num(sk);
	}

int OCSP_extension_print(BIO *bp,
			 X509_EXTENSION *x,
			 int ind)
        {
	int i, j;
	STACK_OF(ASN1_OBJECT) *sk = NULL;
	unsigned char *p;
	OCSP_CRLID *crlid = NULL;
	OCSP_SERVICELOC *sloc = NULL;
	ASN1_GENERALIZEDTIME *gt = NULL;

	if (!x) return 1;
	switch (OBJ_obj2nid(x->object))
	        {
		case NID_id_pkix_OCSP_Nonce:
		        if (BIO_printf(bp, "%*snonce: ", ind, "") <= 0) 
			        goto err;
			if (M_ASN1_OCTET_STRING_print(bp, x->value) <= 0)
			        goto err;
			if (BIO_write(bp, "\n", 1) <= 0) goto err;
		        break;
		case NID_id_pkix_OCSP_CrlID:
		        if (BIO_printf(bp, "%*scrlId:\n", ind, "") <= 0) 
			        goto err;
		        p = x->value->data;
		        if (!(d2i_OCSP_CRLID(&crlid, &p, x->value->length)))
			        goto err;
			if (!OCSP_CRLID_print(bp, crlid, (2*ind))) goto err;
			OCSP_CRLID_free(crlid);
		        break;
		case NID_id_pkix_OCSP_acceptableResponses:
		        if (BIO_printf(bp, 
				      "%*sacceptable responses: ", 
				      ind, "") <= 0)
			        goto err;
		        p = x->value->data;
		        if (!(d2i_ASN1_SET_OF_ASN1_OBJECT(&sk, &p, x->value->length, 
					   d2i_ASN1_OBJECT, 
					   ASN1_OBJECT_free,
					   V_ASN1_SEQUENCE, 
					   V_ASN1_UNIVERSAL)))
			        goto err;
			for (i = 0; i < sk_ASN1_OBJECT_num(sk); i++)
			        {
		                j=OBJ_obj2nid(sk_ASN1_OBJECT_value(sk,i));
		                if (BIO_printf(bp," %s ",
					       (j == NID_undef)?"UNKNOWN":
					                   OBJ_nid2ln(j)) <= 0)
				          goto err;
				}
			if (BIO_write(bp, "\n", 1) <= 0) goto err;
			sk_ASN1_OBJECT_pop_free(sk, ASN1_OBJECT_free);
		        break;
		case NID_id_pkix_OCSP_archiveCutoff:
		        if (BIO_printf(bp, "%*sarchive cutoff: ", ind, "")<=0)
			        goto err;
		        p = x->value->data;
			if (!d2i_ASN1_GENERALIZEDTIME(&gt, &p, 
						      x->value->length))
			        goto err;
			if (!ASN1_GENERALIZEDTIME_print(bp, gt)) goto err;
			if (BIO_write(bp, "\n", 1) <= 0) goto err;
			ASN1_GENERALIZEDTIME_free(gt);
		        break;
		case NID_id_pkix_OCSP_serviceLocator:
		  if (BIO_printf(bp, "%*sservice locator:\n", ind, "") <= 0)
			        goto err;
		        p = x->value->data;
			if (!d2i_OCSP_SERVICELOC(&sloc, &p, 
						 x->value->length))
			        goto err;
			if (!OCSP_SERVICELOC_print(bp,sloc,(2*ind))) goto err;
			OCSP_SERVICELOC_free(sloc);
		        break;
	        case NID_undef:
	        default:
		        if (BIO_printf(bp,"%*sunrecognized oid: ",ind,"") <= 0)
			        goto err;
		        break;
		}
	return 1;
err:
	return 0;
	}
