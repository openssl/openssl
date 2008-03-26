/* crypto/cms/cms_ess.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include "cms_lcl.h"
#include "asn1_locl.h"

DECLARE_ASN1_ITEM(CMS_ReceiptRequest)

IMPLEMENT_ASN1_FUNCTIONS(CMS_ReceiptRequest)

/* ESS services: for now just Signed Receipt related */

int CMS_get1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest **prr)
	{
	ASN1_STRING *str;
	CMS_ReceiptRequest *rr = NULL;
	if (prr)
		*prr = NULL;
	str = CMS_signed_get0_data_by_OBJ(si,
				OBJ_nid2obj(NID_id_smime_aa_receiptRequest),
					-3, V_ASN1_SEQUENCE);
	if (!str)
		return 0;

	rr = ASN1_item_unpack(str, ASN1_ITEM_rptr(CMS_ReceiptRequest));
	if (!rr)
		return -1;
	if (prr)
		*prr = rr;
	else
		CMS_ReceiptRequest_free(rr);
	return 1;
	}

CMS_ReceiptRequest *CMS_ReceiptRequest_create0(unsigned char *id, int idlen,
				int allorfirst,
				STACK_OF(GENERAL_NAMES) *receiptList,
				STACK_OF(GENERAL_NAMES) *receiptsTo)
	{
	CMS_ReceiptRequest *rr = NULL;

	rr = CMS_ReceiptRequest_new();
	if (!rr)
		goto merr;
	if (id)
		ASN1_STRING_set0(rr->signedContentIdentifier, id, idlen);
	else
		{
		if (!ASN1_STRING_set(rr->signedContentIdentifier, NULL, 32))
			goto merr;
		if (RAND_pseudo_bytes(rr->signedContentIdentifier->data, 32) 
					<= 0)
			goto err;
		}

	sk_GENERAL_NAMES_pop_free(rr->receiptsTo, GENERAL_NAMES_free);
	rr->receiptsTo = receiptsTo;

	if (receiptList)
		{
		rr->receiptsFrom->type = 1;
		rr->receiptsFrom->d.receiptList = receiptList;
		}
	else
		{
		rr->receiptsFrom->type = 0;
		rr->receiptsFrom->d.allOrFirstTier = allorfirst;
		}

	return rr;

	merr:
	CMSerr(CMS_F_CMS_RECEIPTREQUEST_CREATE0, ERR_R_MALLOC_FAILURE);

	err:
	if (rr)
		CMS_ReceiptRequest_free(rr);

	return NULL;
	
	}

int CMS_add1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest *rr)
	{
	unsigned char *rrder = NULL;
	int rrderlen, r = 0;

	rrderlen = i2d_CMS_ReceiptRequest(rr, &rrder);
	if (rrderlen < 0)
		goto merr;

	if (!CMS_signed_add1_attr_by_NID(si, NID_id_smime_aa_receiptRequest,
					V_ASN1_SEQUENCE, rrder, rrderlen))
		goto merr;

	r = 1;

	merr:
	if (!r)
		CMSerr(CMS_F_CMS_ADD1_RECEIPTREQUEST, ERR_R_MALLOC_FAILURE);

	if (rrder)
		OPENSSL_free(rrder);

	return r;
	
	}

void CMS_ReceiptRequest_get0_values(CMS_ReceiptRequest *rr,
					ASN1_STRING **pcid,
					int *pallorfirst,
					STACK_OF(GENERAL_NAMES) **plist,
					STACK_OF(GENERAL_NAMES) **prto)
	{
	if (pcid)
		*pcid = rr->signedContentIdentifier;
	if (rr->receiptsFrom->type == 0)
		{
		if (pallorfirst)
			*pallorfirst = (int)rr->receiptsFrom->d.allOrFirstTier;
		if (plist)
			*plist = NULL;
		}
	else
		{
		if (pallorfirst)
			*pallorfirst = -1;
		if (plist)
			*plist = rr->receiptsFrom->d.receiptList;
		}
	if (prto)
		*prto = rr->receiptsTo;
	}



