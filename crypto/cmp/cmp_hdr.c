/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* CMP functions for PKIHeader handling */

#include "cmp_local.h"

#include <openssl/rand.h>

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/err.h>

int ossl_cmp_hdr_set_pvno(OSSL_CMP_PKIHEADER *hdr, int pvno)
{
    if (!ossl_assert(hdr != NULL))
        return 0;
    return ASN1_INTEGER_set(hdr->pvno, pvno);
}

int ossl_cmp_hdr_get_pvno(const OSSL_CMP_PKIHEADER *hdr)
{
    int64_t pvno;

    if (!ossl_assert(hdr != NULL))
        return -1;
    if (!ASN1_INTEGER_get_int64(&pvno, hdr->pvno) || pvno < 0 || pvno > INT_MAX)
        return -1;
    return (int)pvno;
}

ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_transactionID(const OSSL_CMP_PKIHEADER *hdr)
{
    if (hdr == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return hdr->transactionID;
}

ASN1_OCTET_STRING *ossl_cmp_hdr_get0_senderNonce(const OSSL_CMP_PKIHEADER *hdr)
{
    if (!ossl_assert(hdr != NULL))
        return NULL;
    return hdr->senderNonce;
}

ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_recipNonce(const OSSL_CMP_PKIHEADER *hdr)
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

    if (!ossl_assert(tgt != NULL))
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
int ossl_cmp_hdr_set1_sender(OSSL_CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (!ossl_assert(hdr != NULL))
        return 0;
    return set1_general_name(&hdr->sender, nm);
}

int ossl_cmp_hdr_set1_recipient(OSSL_CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (!ossl_assert(hdr != NULL))
        return 0;
    return set1_general_name(&hdr->recipient, nm);
}

int ossl_cmp_hdr_update_messageTime(OSSL_CMP_PKIHEADER *hdr)
{
    if (!ossl_assert(hdr != NULL))
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
        if ((bytes = OPENSSL_malloc(len)) == NULL)
            goto err;
        if (RAND_bytes(bytes, len) <= 0) {
            CMPerr(0, CMP_R_FAILURE_OBTAINING_RANDOM);
            goto err;
        }
        res = ossl_cmp_asn1_octet_string_set1_bytes(tgt, bytes, len);
    } else {
        res = ossl_cmp_asn1_octet_string_set1(tgt, src);
    }

 err:
    OPENSSL_free(bytes);
    return res;
}

int ossl_cmp_hdr_set1_senderKID(OSSL_CMP_PKIHEADER *hdr,
                                const ASN1_OCTET_STRING *senderKID)
{
    if (!ossl_assert(hdr != NULL))
        return 0;
    return ossl_cmp_asn1_octet_string_set1(&hdr->senderKID, senderKID);
}

/* push the given text string to the given PKIFREETEXT ft */
int ossl_cmp_pkifreetext_push_str(OSSL_CMP_PKIFREETEXT *ft, const char *text)
{
    ASN1_UTF8STRING *utf8string;

    if (!ossl_assert(ft != NULL && text != NULL))
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

int ossl_cmp_hdr_push0_freeText(OSSL_CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)
{
    if (!ossl_assert(hdr != NULL && text != NULL))
        return 0;

    if (hdr->freeText == NULL
            && (hdr->freeText = sk_ASN1_UTF8STRING_new_null()) == NULL)
        return 0;

    return sk_ASN1_UTF8STRING_push(hdr->freeText, text);
}

int ossl_cmp_hdr_push1_freeText(OSSL_CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)
{
    if (!ossl_assert(hdr != NULL && text != NULL))
        return 0;

    if (hdr->freeText == NULL
            && (hdr->freeText = sk_ASN1_UTF8STRING_new_null()) == NULL)
        return 0;

    return ossl_cmp_pkifreetext_push_str(hdr->freeText, (char *)text->data);
}

int ossl_cmp_hdr_generalInfo_push0_item(OSSL_CMP_PKIHEADER *hdr,
                                        OSSL_CMP_ITAV *itav)
{
    if (!ossl_assert(hdr != NULL && itav != NULL))
        return 0;
    return OSSL_CMP_ITAV_push0_stack_item(&hdr->generalInfo, itav);
}

int ossl_cmp_hdr_generalInfo_push1_items(OSSL_CMP_PKIHEADER *hdr,
                                         STACK_OF(OSSL_CMP_ITAV) *itavs)
{
    int i;
    OSSL_CMP_ITAV *itav;

    if (!ossl_assert(hdr != NULL))
        return 0;

    for (i = 0; i < sk_OSSL_CMP_ITAV_num(itavs); i++) {
        itav = OSSL_CMP_ITAV_dup(sk_OSSL_CMP_ITAV_value(itavs, i));
        if (itav == NULL)
            return 0;

        if (!ossl_cmp_hdr_generalInfo_push0_item(hdr, itav)) {
            OSSL_CMP_ITAV_free(itav);
            return 0;
        }
    }
    return 1;
}

int ossl_cmp_hdr_set_implicitConfirm(OSSL_CMP_PKIHEADER *hdr)
{
    OSSL_CMP_ITAV *itav;
    ASN1_TYPE *asn1null;

    if (!ossl_assert(hdr != NULL))
        return 0;
    asn1null = (ASN1_TYPE *)ASN1_NULL_new();
    if (asn1null == NULL)
        return 0;
    if ((itav = OSSL_CMP_ITAV_create(OBJ_nid2obj(NID_id_it_implicitConfirm),
                                     asn1null)) == NULL)
        goto err;
    if (!ossl_cmp_hdr_generalInfo_push0_item(hdr, itav))
        goto err;
    return 1;

 err:
    ASN1_TYPE_free(asn1null);
    OSSL_CMP_ITAV_free(itav);
    return 0;
}

/* return 1 if implicitConfirm in the generalInfo field of the header is set */
int ossl_cmp_hdr_check_implicitConfirm(const OSSL_CMP_PKIHEADER *hdr)
{
    int itavCount;
    int i;
    OSSL_CMP_ITAV *itav;

    if (!ossl_assert(hdr != NULL))
        return 0;

    itavCount = sk_OSSL_CMP_ITAV_num(hdr->generalInfo);
    for (i = 0; i < itavCount; i++) {
        itav = sk_OSSL_CMP_ITAV_value(hdr->generalInfo, i);
        if (itav != NULL
                && OBJ_obj2nid(itav->infoType) == NID_id_it_implicitConfirm)
            return 1;
    }

    return 0;
}

/* fill in all fields of the hdr according to the info given in ctx */
int ossl_cmp_hdr_init(OSSL_CMP_CTX *ctx, OSSL_CMP_PKIHEADER *hdr)
{
    X509_NAME *sender;
    X509_NAME *rcp = NULL;

    if (!ossl_assert(ctx != NULL && hdr != NULL))
        return 0;

    /* set the CMP version */
    if (!ossl_cmp_hdr_set_pvno(hdr, OSSL_CMP_PVNO))
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
    if (!ossl_cmp_hdr_set1_sender(hdr, sender))
        return 0;

    /* determine recipient entry in PKIHeader */
    if (ctx->srvCert != NULL) {
        rcp = X509_get_subject_name(ctx->srvCert);
        /* set also as expected_sender of responses unless set explicitly */
        if (ctx->expected_sender == NULL && rcp != NULL
                && !OSSL_CMP_CTX_set1_expected_sender(ctx, rcp))
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
    if (!ossl_cmp_hdr_set1_recipient(hdr, rcp))
        return 0;

    /* set current time as message time */
    if (!ossl_cmp_hdr_update_messageTime(hdr))
        return 0;

    if (ctx->recipNonce != NULL
            && !ossl_cmp_asn1_octet_string_set1(&hdr->recipNonce,
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
                                       OSSL_CMP_TRANSACTIONID_LENGTH))
        return 0;
    if (!ossl_cmp_asn1_octet_string_set1(&hdr->transactionID,
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
                                OSSL_CMP_SENDERNONCE_LENGTH))
        return 0;

    /* store senderNonce - for cmp with recipNonce in next outgoing msg */
    if (!OSSL_CMP_CTX_set1_senderNonce(ctx, hdr->senderNonce))
        return 0;

    /*-
     * freeText                [7] PKIFreeText OPTIONAL,
     * -- this may be used to indicate context-specific instructions
     * -- (this field is intended for human consumption)
     */
    if (ctx->freeText != NULL
            && !ossl_cmp_hdr_push1_freeText(hdr, ctx->freeText))
        return 0;

    return 1;
}
