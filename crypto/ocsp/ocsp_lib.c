/* ocsp_lib.c */
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
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>
#include <openssl/ocsp.h>

static STACK_OF(X509_EXTENSION) *ext_dup(STACK_OF(X509_EXTENSION) *fr)
	{
	int i;
	STACK_OF(X509_EXTENSION) *to = NULL;

	if (!(to = sk_X509_EXTENSION_dup(fr)))
	        goto err;
	for (i = 0; i < sk_X509_EXTENSION_num(fr); i++)
		{
	        sk_X509_EXTENSION_set(to, i,
	              X509_EXTENSION_dup(sk_X509_EXTENSION_value(fr, i)));
		if (! sk_X509_EXTENSION_value(to, i))
		        goto err;
		}
	return to;
err:
	if (to) sk_X509_EXTENSION_pop_free(to, X509_EXTENSION_free);
	return NULL;
	}

OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst, 
			      X509_NAME *issuerName, 
			      ASN1_BIT_STRING* issuerKey, 
			      ASN1_INTEGER *serialNumber)
        {
	int nid;
        unsigned int i;
	X509_ALGOR *alg;
	OCSP_CERTID *cid = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];
	EVP_MD_CTX ctx;

	if (!(cid = OCSP_CERTID_new())) goto err;

	alg = cid->hashAlgorithm;
	if (alg->algorithm != NULL) ASN1_OBJECT_free(alg->algorithm);
	if ((nid = EVP_MD_type(dgst)) == NID_undef)
	        {
		OCSPerr(OCSP_F_CERT_ID_NEW,OCSP_R_UNKNOWN_NID);
		goto err;
		}
	if (!(alg->algorithm=OBJ_nid2obj(nid))) goto err;
	if ((alg->parameter=ASN1_TYPE_new()) == NULL) goto err;
	alg->parameter->type=V_ASN1_NULL;

	if (!X509_NAME_digest(issuerName, dgst, md, &i)) goto digerr;
	if (!(ASN1_OCTET_STRING_set(cid->issuerNameHash, md, i))) goto err;

	/* Calculate the issuerKey hash, excluding tag and length */
	EVP_DigestInit(&ctx,dgst);
	EVP_DigestUpdate(&ctx,issuerKey->data, issuerKey->length);
	EVP_DigestFinal(&ctx,md,&i);

	if (!(ASN1_OCTET_STRING_set(cid->issuerKeyHash, md, i))) goto err;
	
	if (cid->serialNumber != NULL) ASN1_INTEGER_free(cid->serialNumber);
	if (!(cid->serialNumber = ASN1_INTEGER_dup(serialNumber))) goto err;
	return cid;
digerr:
	OCSPerr(OCSP_F_CERT_ID_NEW,OCSP_R_DIGEST_ERR);
err:
	if (cid) OCSP_CERTID_free(cid);
	return NULL;
	}

OCSP_CERTSTATUS *OCSP_cert_status_new(int status, int reason, char *tim)
        {
	OCSP_REVOKEDINFO *ri;
	OCSP_CERTSTATUS *cs = NULL;

	if (!(cs = OCSP_CERTSTATUS_new())) goto err;
	if ((cs->type = status) == V_OCSP_CERTSTATUS_REVOKED)
	        {
		if (!time)
		        {
		        OCSPerr(OCSP_F_CERT_STATUS_NEW,OCSP_R_REVOKED_NO_TIME);
			goto err;
		        }
		if (!(cs->value.revoked = ri = OCSP_REVOKEDINFO_new())) goto err;
		if (!ASN1_GENERALIZEDTIME_set_string(ri->revocationTime,tim))
			goto err;	
		if (reason != OCSP_REVOKED_STATUS_NOSTATUS)
		        {
			if (!(ri->revocationReason = ASN1_ENUMERATED_new())) 
			        goto err;
			if (!(ASN1_ENUMERATED_set(ri->revocationReason, 
						  reason)))
			        goto err;	
			}
		}
	return cs;
err:
	if (cs) OCSP_CERTSTATUS_free(cs);
	return NULL;
	}

OCSP_REQUEST *OCSP_request_new(X509_NAME* name,
			       STACK_OF(X509_EXTENSION) *extensions)
        {
	OCSP_REQUEST *req = NULL;

	if ((req = OCSP_REQUEST_new()) == NULL) goto err;
	if (name) /* optional */
	        {
		if (!(req->tbsRequest->requestorName=GENERAL_NAME_new()))
		        goto err;
		req->tbsRequest->requestorName->type = GEN_DIRNAME;
		req->tbsRequest->requestorName->d.dirn = X509_NAME_dup(name);
		}
	if (!(req->tbsRequest->requestList = sk_OCSP_ONEREQ_new(NULL))) goto err;
	if (extensions && 
	    (!(req->tbsRequest->requestExtensions = ext_dup(extensions))))
	        goto err;
	return req;
err:
	if (req) OCSP_REQUEST_free(req);
	return NULL;
	}

int OCSP_request_add(OCSP_REQUEST             *req,
		     OCSP_CERTID              *cid,
		     STACK_OF(X509_EXTENSION) *extensions)
        {
	OCSP_ONEREQ *one = NULL;

	if (!(one = OCSP_ONEREQ_new())) goto err;
	if (one->reqCert) OCSP_CERTID_free(one->reqCert);
	if (!(one->reqCert = OCSP_CERTID_dup(cid))) goto err;
	if (extensions&&(!(one->singleRequestExtensions=ext_dup(extensions))))
	        goto err;
	if (!sk_OCSP_ONEREQ_push(req->tbsRequest->requestList, one)) goto err;
	return 1;
err:
	if (one) OCSP_ONEREQ_free(one);
	return 0;
        }

int OCSP_request_sign(OCSP_REQUEST   *req,
		      EVP_PKEY       *key,
		      const EVP_MD   *dgst,
		      STACK_OF(X509) *certs)
        {
	int i;
	OCSP_SIGNATURE *sig;

	if (!(req->optionalSignature = sig = OCSP_SIGNATURE_new())) goto err;
	if (!OCSP_REQUEST_sign(req, key, dgst)) goto err;
	if (certs)
	        {
	        if (!(sig->certs = sk_X509_dup(certs))) goto err;
	        for (i = 0; i < sk_X509_num(sig->certs); i++)
	                {
			sk_X509_set(sig->certs, i, 
		               X509_dup(sk_X509_value(certs,i)));
		        if (! sk_X509_value(sig->certs, i))
			      goto err;
		        }
		}
	return 1;
err:
	if (req->optionalSignature)
	        {
		OCSP_SIGNATURE_free(req->optionalSignature);
		req->optionalSignature = NULL;
		}
	return 0;
	}

OCSP_BASICRESP *OCSP_basic_response_new(int type,
					X509* cert,
					STACK_OF(X509_EXTENSION) *extensions)
        {
	time_t t;
	OCSP_RESPID *rid;
        ASN1_BIT_STRING *bs;
	OCSP_BASICRESP *rsp = NULL;
	unsigned char md[SHA_DIGEST_LENGTH];
	
	if (!(rsp = OCSP_BASICRESP_new())) goto err;
	rid = rsp->tbsResponseData->responderId;
	switch (rid->type = type)
	        {
		case V_OCSP_RESPID_NAME:
		        /* cert is user cert */
		        if (!(rid->value.byName =
			          X509_NAME_dup(X509_get_subject_name(cert))))
				goto err;
		        break;
		case V_OCSP_RESPID_KEY:
		        /* cert is issuer cert */
			/* SHA-1 hash of responder's public key
                         * (excluding the tag and length fields)
			 */
		        bs = cert->cert_info->key->public_key;
		        SHA1(ASN1_STRING_data((ASN1_STRING*)bs), 
			     ASN1_STRING_length((ASN1_STRING*)bs), md);
			if (!(rid->value.byKey = ASN1_OCTET_STRING_new()))
				goto err;
			if (!(ASN1_OCTET_STRING_set(rid->value.byKey,
						    md, sizeof md)))
				goto err;
		        break;
		default:
		        OCSPerr(OCSP_F_BASIC_RESPONSE_NEW,OCSP_R_BAD_TAG);
			goto err;
		        break;
		}
	time(&t);
	if (!(ASN1_GENERALIZEDTIME_set(rsp->tbsResponseData->producedAt, t)))
		goto err;
	if (!(rsp->tbsResponseData->responses = sk_OCSP_SINGLERESP_new(NULL))) goto err;
	if (extensions && (!(rsp->tbsResponseData->responseExtensions = 
			                      ext_dup(extensions))))
		goto err;
	return rsp;
err:
	if (rsp) OCSP_BASICRESP_free(rsp);
	return NULL;
	}

int OCSP_basic_response_add(OCSP_BASICRESP           *rsp,
			    OCSP_CERTID              *cid,
			    OCSP_CERTSTATUS          *cst,
			    char                     *this,
			    char                     *next,
			    STACK_OF(X509_EXTENSION) *extensions)
        {
	OCSP_SINGLERESP *single = NULL;

	if (!(single = OCSP_SINGLERESP_new())) goto err;
	if (single->certId) OCSP_CERTID_free(single->certId);
	if (!(single->certId = OCSP_CERTID_dup(cid))) goto err;
	if (single->certStatus) OCSP_CERTSTATUS_free(single->certStatus);
	if (!(single->certStatus = OCSP_CERTSTATUS_dup(cst))) goto err;
	if (!ASN1_GENERALIZEDTIME_set_string(single->thisUpdate,this))goto err;
	if (next)
                { 
		if (!(single->nextUpdate = ASN1_GENERALIZEDTIME_new()))
		        goto err;
		if (!ASN1_GENERALIZEDTIME_set_string(single->nextUpdate,next))
	                goto err;
		}
	if (extensions && (!(single->singleExtensions = ext_dup(extensions))))
	        goto err;
	if (!sk_OCSP_SINGLERESP_push(rsp->tbsResponseData->responses,single)) goto err;
	return 1;
err:
	if (single) OCSP_SINGLERESP_free(single);
	return 0;
	}

int OCSP_basic_response_sign(OCSP_BASICRESP *brsp, 
			     EVP_PKEY       *key,
			     const EVP_MD   *dgst,
			     STACK_OF(X509) *certs)
        {
	int i;

	/* Right now, I think that not doing double hashing is the right
	   thing.	-- Richard Levitte */
	if (!OCSP_BASICRESP_sign(brsp, key, dgst, 0)) goto err;
	if (certs)
	        {
	        if (!(brsp->certs = sk_X509_dup(certs))) goto err;
	        for (i = 0; i < sk_X509_num(brsp->certs); i++)
	                {
			sk_X509_set(brsp->certs, i,
		               X509_dup(sk_X509_value(certs, i)));
		        if (! sk_X509_value(brsp->certs, i))
				goto err;
		        }
		}
	return 1;
err:
	return 0;
	}

OCSP_RESPONSE *OCSP_response_new(int status,
				 int nid,
				 int (*i2d)(),
				 char *data)
        {
        OCSP_RESPONSE *rsp = NULL;

	if (!(rsp = OCSP_RESPONSE_new())) goto err;
	if (!(ASN1_ENUMERATED_set(rsp->responseStatus, status))) goto err;
	if (!(rsp->responseBytes = OCSP_RESPBYTES_new())) goto err;
	if (rsp->responseBytes->responseType) ASN1_OBJECT_free(rsp->responseBytes->responseType);
	if (!(rsp->responseBytes->responseType = OBJ_nid2obj(nid))) goto err;
	if (!ASN1_STRING_encode((ASN1_STRING*)rsp->responseBytes->response,
				i2d, data, NULL)) goto err;
	return rsp;
err:
	if (rsp) OCSP_RESPONSE_free(rsp);
	return NULL;
	}

char* ocspResponseStatus2string(long s)
        {
	static struct { long t; char *m; } ts[6]= { 
	        { OCSP_RESPONSE_STATUS_SUCCESSFULL, "successful" },
	        { OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, "malformedrequest" },
	        { OCSP_RESPONSE_STATUS_INTERNALERROR, "internalerror" },
	        { OCSP_RESPONSE_STATUS_TRYLATER, "trylater" },
	        { OCSP_RESPONSE_STATUS_SIGREQUIRED, "sigrequired" },
	        { OCSP_RESPONSE_STATUS_UNAUTHORIZED, "unauthorized" } }, *p;
	for (p=ts; p < &ts[sizeof ts/sizeof ts[0]]; p++)
	        if (p->t == s)
		         return p->m;
	return "(UNKNOWN)";
	} 

char* ocspCertStatus2string(long s)
        {
	static struct { long t; char *m; } ts[3]= { 
	        { V_OCSP_CERTSTATUS_GOOD, "good" },
	        { V_OCSP_CERTSTATUS_REVOKED, "revoked" },
	        { V_OCSP_CERTSTATUS_UNKNOWN, "unknown" } }, *p;
	for (p=ts; p < &ts[sizeof ts/sizeof ts[0]]; p++)
	        if (p->t == s)
		         return p->m;
	return "(UNKNOWN)";
	} 

char * cRLReason2string(long s)
        {
	static struct { long t; char *m; } ts[8]= { 
	  { OCSP_REVOKED_STATUS_UNSPECIFIED, "unspecified" },
          { OCSP_REVOKED_STATUS_KEYCOMPROMISE, "keyCompromise" },
          { OCSP_REVOKED_STATUS_CACOMPROMISE, "cACompromise" },
          { OCSP_REVOKED_STATUS_AFFILIATIONCHANGED, "affiliationChanged" },
          { OCSP_REVOKED_STATUS_SUPERSEDED, "superseded" },
          { OCSP_REVOKED_STATUS_CESSATIONOFOPERATION, "cessationOfOperation" },
          { OCSP_REVOKED_STATUS_CERTIFICATEHOLD, "certificateHold" },
          { OCSP_REVOKED_STATUS_REMOVEFROMCRL, "removeFromCRL" } }, *p;
	for (p=ts; p < &ts[sizeof ts/sizeof ts[0]]; p++)
	        if (p->t == s)
		         return p->m;
	return "(UNKNOWN)";
	} 

static int i2a_GENERAL_NAME(bp,n)
BIO *bp; 
GENERAL_NAME *n;
	{
	int j;
        char *p;

	if (n == NULL) return(0);

	switch (n->type)
		{

	case GEN_DIRNAME:
	        X509_NAME_print(bp,n->d.dirn,16);
		break;

	case GEN_EMAIL:
	case GEN_DNS:
	case GEN_URI:
	case GEN_IPADD:
		p=(char *)n->d.ip->data;
		for (j=n->d.ip->length;j>0;j--)
			{
			if ((*p >= ' ') && (*p <= '~'))
			        BIO_printf(bp,"%c",*p);
			else if (*p & 0x80)
			        BIO_printf(bp,"\\0x%02X",*p);
			else if ((unsigned char)*p == 0xf7)
			        BIO_printf(bp,"^?");
			else	BIO_printf(bp,"^%c",*p+'@');
			p++;
			}
		break;

	case GEN_RID:
	        i2a_ASN1_OBJECT(bp, n->d.rid);
		break;

	/* XXX these are legit, need to support at some time... */
	case GEN_OTHERNAME:
	case GEN_X400:
	case GEN_EDIPARTY:
	default:
	        return 0;
		}

	return 1;
	}

int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE* o)
        {
	int i, j, n;
	long l;
	char *s;
	unsigned char *p;
	OCSP_CERTID *cid = NULL;
	OCSP_BASICRESP *br = NULL;
	OCSP_RESPDATA  *rd = NULL;
	OCSP_CERTSTATUS *cst = NULL;
	OCSP_REVOKEDINFO *rev = NULL;
	OCSP_SINGLERESP *single = NULL;
	OCSP_RESPBYTES *rb = o->responseBytes;

	l=ASN1_ENUMERATED_get(o->responseStatus);
	if (BIO_printf(bp,"OCSP Response Status: %s (0x%x)\n", 
		       ocspResponseStatus2string(l), l) <= 0) goto err;
	if (rb == NULL) return 1;
	i=OBJ_obj2nid(rb->responseType);
        if (BIO_printf(bp,"OCSP Response Bytes Response Type: %s",
		       (i == NID_undef)?"UNKNOWN":OBJ_nid2sn(i)) <= 0)
	        goto err;
	if (i != NID_id_pkix_OCSP_basic) 
	        {
		BIO_printf(bp," (unknown response type)\n");
		return 1;
		}
	p = ASN1_STRING_data(rb->response);
	i = ASN1_STRING_length(rb->response);
	if (!(d2i_OCSP_BASICRESP(&br, &p, i))) goto err;
	rd = br->tbsResponseData;
	l=ASN1_INTEGER_get(rd->version);
	if (BIO_printf(bp,"\nBasic Response Data Version: %lu (0x%lx)\n",
		       l+1,l) <= 0) goto err;
	if (BIO_printf(bp,"Basic Response Data Responder Id: ") <= 0) goto err;
	i2a_OCSP_RESPID(bp, rd->responderId);
	if (BIO_printf(bp,"\nBasic Response Data Produced At: ")<=0) goto err;
	if (!ASN1_GENERALIZEDTIME_print(bp, rd->producedAt)) goto err;
	if (BIO_printf(bp,"\nBasic Response Data Responses:\n") <= 0) goto err;
	for (i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++)
	        {
		if (! sk_OCSP_SINGLERESP_value(rd->responses, i)) continue;
		single = sk_OCSP_SINGLERESP_value(rd->responses, i);
		cid = single->certId;
		j=OBJ_obj2nid(cid->hashAlgorithm->algorithm);
		if (BIO_printf(bp,"    Cert Id:") <= 0) goto err;
		if (BIO_printf(bp,"\n%8sHash Algorithm: %s","",
			       (j == NID_undef)?"UNKNOWN":OBJ_nid2ln(j)) <= 0)
		        goto err;
		if (BIO_write(bp,"\n        Issuer Name Hash: ",27) <= 0)
		        goto err;
		i2a_ASN1_STRING(bp, cid->issuerNameHash, V_ASN1_OCTET_STRING);
		if (BIO_write(bp,"\n        Issuer Key Hash: ",26) <= 0) 
		        goto err;
		i2a_ASN1_STRING(bp, cid->issuerKeyHash, V_ASN1_OCTET_STRING);
		if (BIO_write(bp,"\n        Serial Number: ",24) <= 0) 
		        goto err;
		if (!i2a_ASN1_INTEGER(bp, cid->serialNumber)) 
		        goto err;
		cst = single->certStatus;
		if (BIO_printf(bp,"\n    Cert Status: %s (0x%x)",
			       ocspCertStatus2string(cst->type), cst->type) <= 0)
		        goto err;
		if (cst->type == V_OCSP_CERTSTATUS_REVOKED)
		        {
		        rev = cst->value.revoked;
			if (BIO_printf(bp, "\n    Revocation Time: ") <= 0) 
			        goto err;
			if (!ASN1_GENERALIZEDTIME_print(bp, 
							rev->revocationTime)) 
				goto err;
			if (rev->revocationReason) 
			        {
				l=ASN1_ENUMERATED_get(rev->revocationReason);
				if (BIO_printf(bp, 
					 "\n    Revocation Reason: %s (0x%x)",
					       cRLReason2string(l), l) <= 0)
				        goto err;
				}
			}
		if (BIO_printf(bp,"\n    This Update: ") <= 0) goto err;
		if (!ASN1_GENERALIZEDTIME_print(bp, single->thisUpdate)) 
			goto err;
		if (single->nextUpdate)
		        {
			if (BIO_printf(bp,"\n    Next Update: ") <= 0)goto err;
			if (!ASN1_GENERALIZEDTIME_print(bp,single->nextUpdate))
				goto err;
			}
		if (!BIO_write(bp,"\n",1)) goto err;
		if (!OCSP_extensions_print(bp, single->singleExtensions,
					   "Basic Response Single Extensions"))
		        goto err;
		}
	if (!OCSP_extensions_print(bp, rd->responseExtensions,
				   "Basic Response Extensions")) goto err;
	i=OBJ_obj2nid(br->signatureAlgorithm->algorithm);
	if (BIO_printf(bp,"Basic Response Signature Algorithm: %s",
		       (i == NID_undef)?"UNKNOWN":OBJ_nid2ln(i)) <= 0)
	        goto err;
	n=br->signature->length;
	s=(char *)br->signature->data;
	for (i=0; i<n; i++)
		{
		if ((i%18) == 0)
		if (BIO_write(bp,"\n        ",9) <= 0) goto err;
		if (BIO_printf(bp,"%02x%s",(unsigned char)s[i],
			((i+1) == n)?"":":") <= 0) goto err;
		}
	if (BIO_write(bp,"\n",1) != 1) goto err;
	if (br->certs)
	        {
		for (i=0; i<sk_X509_num(br->certs); i++)
			if (sk_X509_value(br->certs,i) != NULL) {
				X509_print(bp, sk_X509_value(br->certs,i));
				PEM_write_bio_X509(bp,sk_X509_value(br->certs,i));
			}
		}
	return 1;
err:
	return 0;
	}

int OCSP_CRLID_print(BIO *bp, OCSP_CRLID *a, int ind)
        {
	if (a->crlUrl)
	        {
		if (!BIO_printf(bp, "%*scrlUrl: ", ind, "")) goto err;
		if (!ASN1_STRING_print(bp, (ASN1_STRING*)a->crlUrl)) goto err;
		if (!BIO_write(bp, "\n", 1)) goto err;
		}
	if (a->crlNum)
	        {
		if (!BIO_printf(bp, "%*scrlNum: ", ind, "")) goto err;
		if (!i2a_ASN1_INTEGER(bp, a->crlNum)) goto err;
		if (!BIO_write(bp, "\n", 1)) goto err;
		}
	if (a->crlTime)
	        {
		if (!BIO_printf(bp, "%*scrlTime: ", ind, "")) goto err;
		if (!ASN1_GENERALIZEDTIME_print(bp, a->crlTime)) goto err;
		if (!BIO_write(bp, "\n", 1)) goto err;
		}
	return 1;
err:
	return 0;
	}

int OCSP_SERVICELOC_print(BIO *bp, OCSP_SERVICELOC* a, int ind)
        {
	int i, j;
	ACCESS_DESCRIPTION *ad;

        if (BIO_printf(bp, "%*sissuer: ", ind, "") <= 0) goto err;
        if (X509_NAME_print(bp, a->issuer, 16) <= 0) goto err;
        if (BIO_printf(bp, "\n", 1) <= 0) goto err;

		/* Service locator is optional */
		if (a->locator != NULL) {
			if (BIO_printf(bp, "%*slocator:\n", ind, "") <= 0) goto err;
			for (i = 0; i < sk_ACCESS_DESCRIPTION_num(a->locator); i++)
	        {
				ad = sk_ACCESS_DESCRIPTION_value(a->locator,i);
				if (BIO_printf(bp, "%*smethod: ", (2*ind), "") <= 0) 
					goto err;
				j=OBJ_obj2nid(ad->method);
				if (BIO_printf(bp,"%s", (j == NID_undef)?"UNKNOWN":
							   OBJ_nid2ln(j)) <= 0)
					goto err;
				if (BIO_printf(bp, "\n%*sname: ", (2*ind), "") <= 0) 
					goto err;
				if (i2a_GENERAL_NAME(bp, ad->location) <= 0) goto err;
				if (BIO_write(bp, "\n", 1) <= 0) goto err;
			}
		}
	return 1;
err:
	return 0;
	}

/* XXX assumes certs in signature are sorted root to leaf XXX */
int OCSP_request_verify(OCSP_REQUEST *req, EVP_PKEY *pkey)
        {
	STACK_OF(X509) *sk;

	if (!req->optionalSignature) return 0;
	if (pkey == NULL)
	        {
	        if (!(sk = req->optionalSignature->certs)) return 0;
		if (!(pkey=X509_get_pubkey(sk_X509_value(sk, sk_X509_num(sk)-1))))
		        {
		        OCSPerr(OCSP_F_REQUEST_VERIFY,OCSP_R_NO_PUBLIC_KEY);
			return 0;
		        }
		}
	return OCSP_REQUEST_verify(req, pkey);
        }

int OCSP_response_verify(OCSP_RESPONSE *rsp, EVP_PKEY *pkey)
        {
	int i, r;
	unsigned char *p;
	OCSP_RESPBYTES *rb;
	OCSP_BASICRESP *br = NULL;

	if ((rb = rsp->responseBytes) == NULL) 
	        {
		OCSPerr(OCSP_F_RESPONSE_VERIFY,OCSP_R_NO_RESPONSE_DATA);
                return 0;
		}
	if (OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic) 
	        {
		OCSPerr(OCSP_F_RESPONSE_VERIFY,OCSP_R_BAD_TAG);
                return 0;
		}
	p = ASN1_STRING_data(rb->response);
	i = ASN1_STRING_length(rb->response);
	if (!(d2i_OCSP_BASICRESP(&br, &p, i))) return 0;
	r = OCSP_basic_response_verify(br, pkey);
	OCSP_BASICRESP_free(br);
	return r;
        }

int OCSP_basic_response_verify(OCSP_BASICRESP *rsp, EVP_PKEY *pkey)
        {
	STACK_OF(X509) *sk;
	int ret;

	if (!rsp->signature) 
	        {
		OCSPerr(OCSP_F_BASIC_RESPONSE_VERIFY,OCSP_R_NO_SIGNATURE);
                return 0;
		}
	if (pkey == NULL)
	        {
	        if (!(sk = rsp->certs))
		        {
		        OCSPerr(OCSP_F_BASIC_RESPONSE_VERIFY,OCSP_R_NO_CERTIFICATE);
			return 0;
			}
		if (!(pkey=X509_get_pubkey(sk_X509_value(sk, sk_X509_num(sk)-1))))
		        {
		        OCSPerr(OCSP_F_BASIC_RESPONSE_VERIFY,OCSP_R_NO_PUBLIC_KEY);
			return 0;
		        }
		}
	ret = OCSP_BASICRESP_verify(rsp, pkey, 0);
	return ret;
        }
