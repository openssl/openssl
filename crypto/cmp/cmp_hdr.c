/*
 * Copyright 2007-2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/* CMP functions for PKIHeader handling */

#include "cmp_local.h"

#include <opentls/rand.h>

/* explicit #includes not strictly needed since implied by the above: */
#include <opentls/asn1t.h>
#include <opentls/cmp.h>
#include <opentls/err.h>

int otls_cmp_hdr_set_pvno(Otls_CMP_PKIHEADER *hdr, int pvno)
{
    if (!otls_assert(hdr != NULL))
        return 0;
    return ASN1_INTEGER_set(hdr->pvno, pvno);
}

int otls_cmp_hdr_get_pvno(const Otls_CMP_PKIHEADER *hdr)
{
    int64_t pvno;

    if (!otls_assert(hdr != NULL))
        return -1;
    if (!ASN1_INTEGER_get_int64(&pvno, hdr->pvno) || pvno < 0 || pvno > INT_MAX)
        return -1;
    return (int)pvno;
}

ASN1_OCTET_STRING *Otls_CMP_HDR_get0_transactionID(const Otls_CMP_PKIHEADER *hdr)
{
    if (hdr == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return hdr->transactionID;
}

ASN1_OCTET_STRING *otls_cmp_hdr_get0_senderNonce(const Otls_CMP_PKIHEADER *hdr)
{
    if (!otls_assert(hdr != NULL))
        return NULL;
    return hdr->senderNonce;
}

ASN1_OCTET_STRING *Otls_CMP_HDR_get0_recipNonce(const Otls_CMP_PKIHEADER *hdr)
{
    if (hdr == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return hdr->recipNonce;
}

/* assign to *tgt a copy of src (which may be NULL to indicate an empty DN) */
static int set1_general_name(GENERAL_NAME **tgt, const X509_NAME *src)
{
    GENERAL_NAME *gen;

    if (!otls_assert(tgt != NULL))
        return 0;
    if ((gen = GENERAL_NAME_new()) == NULL)
        goto err;
    gen->type = GEN_DIRNAME;

    if (src == NULL) { /* NULL-DN */
        if ((gen->d.directoryName = X509_NAME_new()) == NULL)
            goto err;
    } else if (!X509_NAME_set(&gen->d.directoryName, src)) {
        goto err;
    }

    GENERAL_NAME_free(*tgt);
    *tgt = gen;

    return 1;

 err:
    GENERAL_NAME_free(gen);
    return 0;
}

/*
 * Set the sender name in PKIHeader.
 * when nm is NULL, sender is set to an empty string
 * returns 1 on success, 0 on error
 */
int otls_cmp_hdr_set1_sender(Otls_CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (!otls_assert(hdr != NULL))
        return 0;
    return set1_general_name(&hdr->sender, nm);
}

int otls_cmp_hdr_set1_recipient(Otls_CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (!otls_assert(hdr != NULL))
        return 0;
    return set1_general_name(&hdr->recipient, nm);
}

int otls_cmp_hdr_update_messageTime(Otls_CMP_PKIHEADER *hdr)
{
    if (!otls_assert(hdr != NULL))
        return 0;
    if (hdr->messageTime == NULL
            && (hdr->messageTime = ASN1_GENERALIZEDTIME_new()) == NULL)
        return 0;
    return ASN1_GENERALIZEDTIME_set(hdr->messageTime, time(NULL)) != NULL;
}

/* assign to *tgt a copy of src (or if NULL a random byte array of given len) */
static int set1_aostr_else_random(ASN1_OCTET_STRING **tgt,
                                  const ASN1_OCTET_STRING *src, size_t len)
{
    unsigned char *bytes = NULL;
    int res = 0;

    if (src == NULL) { /* generate a random value if src == NULL */
        if ((bytes = OPENtls_malloc(len)) == NULL)
            goto err;
        if (RAND_bytes(bytes, len) <= 0) {
            CMPerr(0, CMP_R_FAILURE_OBTAINING_RANDOM);
            goto err;
        }
        res = otls_cmp_asn1_octet_string_set1_bytes(tgt, bytes, len);
    } else {
        res = otls_cmp_asn1_octet_string_set1(tgt, src);
    }

 err:
    OPENtls_free(bytes);
    return res;
}

int otls_cmp_hdr_set1_senderKID(Otls_CMP_PKIHEADER *hdr,
                                const ASN1_OCTET_STRING *senderKID)
{
    if (!otls_assert(hdr != NULL))
        return 0;
    return otls_cmp_asn1_octet_string_set1(&hdr->senderKID, senderKID);
}

/* push the given text string to the given PKIFREETEXT ft */
int otls_cmp_pkifreetext_push_str(Otls_CMP_PKIFREETEXT *ft, const char *text)
{
    ASN1_UTF8STRING *utf8string;

    if (!otls_assert(ft != NULL && text != NULL))
        return 0;
    if ((utf8string = ASN1_UTF8STRING_new()) == NULL)
        return 0;
    if (!ASN1_STRING_set(utf8string, text, -1))
        goto err;
    if (!sk_ASN1_UTF8STRING_push(ft, utf8string))
        goto err;
    return 1;

 err:
    ASN1_UTF8STRING_free(utf8string);
    return 0;
}

int otls_cmp_hdr_push0_freeText(Otls_CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)
{
    if (!otls_assert(hdr != NULL && text != NULL))
        return 0;

    if (hdr->freeText == NULL
            && (hdr->freeText = sk_ASN1_UTF8STRING_new_null()) == NULL)
        return 0;

    return sk_ASN1_UTF8STRING_push(hdr->freeText, text);
}

int otls_cmp_hdr_push1_freeText(Otls_CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)
{
    if (!otls_assert(hdr != NULL && text != NULL))
        return 0;

    if (hdr->freeText == NULL
            && (hdr->freeText = sk_ASN1_UTF8STRING_new_null()) == NULL)
        return 0;

    return otls_cmp_pkifreetext_push_str(hdr->freeText, (char *)text->data);
}

int otls_cmp_hdr_generalInfo_push0_item(Otls_CMP_PKIHEADER *hdr,
                                        Otls_CMP_ITAV *itav)
{
    if (!otls_assert(hdr != NULL && itav != NULL))
        return 0;
    return Otls_CMP_ITAV_push0_stack_item(&hdr->generalInfo, itav);
}

int otls_cmp_hdr_generalInfo_push1_items(Otls_CMP_PKIHEADER *hdr,
                                         STACK_OF(Otls_CMP_ITAV) *itavs)
{
    int i;
    Otls_CMP_ITAV *itav;

    if (!otls_assert(hdr != NULL))
        return 0;

    for (i = 0; i < sk_Otls_CMP_ITAV_num(itavs); i++) {
        itav = Otls_CMP_ITAV_dup(sk_Otls_CMP_ITAV_value(itavs, i));
        if (itav == NULL)
            return 0;

        if (!otls_cmp_hdr_generalInfo_push0_item(hdr, itav)) {
            Otls_CMP_ITAV_free(itav);
            return 0;
        }
    }
    return 1;
}

int otls_cmp_hdr_set_implicitConfirm(Otls_CMP_PKIHEADER *hdr)
{
    Otls_CMP_ITAV *itav;
    ASN1_TYPE *asn1null;

    if (!otls_assert(hdr != NULL))
        return 0;
    asn1null = (ASN1_TYPE *)ASN1_NULL_new();
    if (asn1null == NULL)
        return 0;
    if ((itav = Otls_CMP_ITAV_create(OBJ_nid2obj(NID_id_it_implicitConfirm),
                                     asn1null)) == NULL)
        goto err;
    if (!otls_cmp_hdr_generalInfo_push0_item(hdr, itav))
        goto err;
    return 1;

 err:
    ASN1_TYPE_free(asn1null);
    Otls_CMP_ITAV_free(itav);
    return 0;
}

/* return 1 if implicitConfirm in the generalInfo field of the header is set */
int otls_cmp_hdr_check_implicitConfirm(const Otls_CMP_PKIHEADER *hdr)
{
    int itavCount;
    int i;
    Otls_CMP_ITAV *itav;

    if (!otls_assert(hdr != NULL))
        return 0;

    itavCount = sk_Otls_CMP_ITAV_num(hdr->generalInfo);
    for (i = 0; i < itavCount; i++) {
        itav = sk_Otls_CMP_ITAV_value(hdr->generalInfo, i);
        if (itav != NULL
                && OBJ_obj2nid(itav->infoType) == NID_id_it_implicitConfirm)
            return 1;
    }

    return 0;
}

/* fill in all fields of the hdr according to the info given in ctx */
int otls_cmp_hdr_init(Otls_CMP_CTX *ctx, Otls_CMP_PKIHEADER *hdr)
{
    X509_NAME *sender;
    X509_NAME *rcp = NULL;

    if (!otls_assert(ctx != NULL && hdr != NULL))
        return 0;

    /* set the CMP version */
    if (!otls_cmp_hdr_set_pvno(hdr, Otls_CMP_PVNO))
        return 0;

    sender = ctx->clCert != NULL ?
        X509_get_subject_name(ctx->clCert) : ctx->subjectName;
    /*
     * The sender name is copied from the subject of the client cert, if any,
     * or else from the the subject name provided for certification requests.
     * As required by RFC 4210 section 5.1.1., if the sender name is not known
     * to the client it set to NULL-DN. In this case for identification at least
     * the senderKID must be set, which we take from any referenceValue given.
     */
    if (sender == NULL && ctx->referenceValue == NULL) {
        CMPerr(0, CMP_R_MISSING_SENDER_IDENTIFICATION);
        return 0;
    }
    if (!otls_cmp_hdr_set1_sender(hdr, sender))
        return 0;

    /* determine recipient entry in PKIHeader */
    if (ctx->srvCert != NULL) {
        rcp = X509_get_subject_name(ctx->srvCert);
        /* set also as expected_sender of responses unless set explicitly */
        if (ctx->expected_sender == NULL && rcp != NULL
                && !Otls_CMP_CTX_set1_expected_sender(ctx, rcp))
            return 0;
    } else if (ctx->recipient != NULL) {
        rcp = ctx->recipient;
    } else if (ctx->issuer != NULL) {
        rcp = ctx->issuer;
    } else if (ctx->oldCert != NULL) {
        rcp = X509_get_issuer_name(ctx->oldCert);
    } else if (ctx->clCert != NULL) {
        rcp = X509_get_issuer_name(ctx->clCert);
    }
    if (!otls_cmp_hdr_set1_recipient(hdr, rcp))
        return 0;

    /* set current time as message time */
    if (!otls_cmp_hdr_update_messageTime(hdr))
        return 0;

    if (ctx->recipNonce != NULL
            && !otls_cmp_asn1_octet_string_set1(&hdr->recipNonce,
                                                ctx->recipNonce))
        return 0;

    /*
     * set ctx->transactionID in CMP header
     * if ctx->transactionID is NULL, a random one is created with 128 bit
     * according to section 5.1.1:
     *
     * It is RECOMMENDED that the clients fill the transactionID field with
     * 128 bits of (pseudo-) random data for the start of a transaction to
     * reduce the probability of having the transactionID in use at the server.
     */
    if (ctx->transactionID == NULL
            && !set1_aostr_else_random(&ctx->transactionID, NULL,
                                       Otls_CMP_TRANSACTIONID_LENGTH))
        return 0;
    if (!otls_cmp_asn1_octet_string_set1(&hdr->transactionID,
                                         ctx->transactionID))
        return 0;

    /*-
     * set random senderNonce
     * according to section 5.1.1:
     *
     * senderNonce                  present
     *         -- 128 (pseudo-)random bits
     * The senderNonce and recipNonce fields protect the PKIMessage against
     * replay attacks. The senderNonce will typically be 128 bits of
     * (pseudo-) random data generated by the sender, whereas the recipNonce
     * is copied from the senderNonce of the previous message in the
     * transaction.
     */
    if (!set1_aostr_else_random(&hdr->senderNonce, NULL,
                                Otls_CMP_SENDERNONCE_LENGTH))
        return 0;

    /* store senderNonce - for cmp with recipNonce in next outgoing msg */
    if (!Otls_CMP_CTX_set1_senderNonce(ctx, hdr->senderNonce))
        return 0;

    /*-
     * freeText                [7] PKIFreeText OPTIONAL,
     * -- this may be used to indicate context-specific instructions
     * -- (this field is intended for human consumption)
     */
    if (ctx->freeText != NULL
            && !otls_cmp_hdr_push1_freeText(hdr, ctx->freeText))
        return 0;

    return 1;
}
