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

#include <opentls/asn1t.h>

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <opentls/cmp.h>
#include <opentls/crmf.h>

/* ASN.1 declarations from RFC4210 */
ASN1_SEQUENCE(Otls_CMP_REVANNCONTENT) = {
    /* Otls_CMP_PKISTATUS is effectively ASN1_INTEGER so it is used directly */
    ASN1_SIMPLE(Otls_CMP_REVANNCONTENT, status, ASN1_INTEGER),
    ASN1_SIMPLE(Otls_CMP_REVANNCONTENT, certId, Otls_CRMF_CERTID),
    ASN1_SIMPLE(Otls_CMP_REVANNCONTENT, willBeRevokedAt, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(Otls_CMP_REVANNCONTENT, badSinceDate, ASN1_GENERALIZEDTIME),
    ASN1_OPT(Otls_CMP_REVANNCONTENT, crlDetails, X509_EXTENSIONS)
} ASN1_SEQUENCE_END(Otls_CMP_REVANNCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_REVANNCONTENT)


ASN1_SEQUENCE(Otls_CMP_CHALLENGE) = {
    ASN1_OPT(Otls_CMP_CHALLENGE, owf, X509_ALGOR),
    ASN1_SIMPLE(Otls_CMP_CHALLENGE, witness, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Otls_CMP_CHALLENGE, challenge, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(Otls_CMP_CHALLENGE)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_CHALLENGE)


ASN1_ITEM_TEMPLATE(Otls_CMP_POPODECKEYCHALLCONTENT) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
                          Otls_CMP_POPODECKEYCHALLCONTENT, Otls_CMP_CHALLENGE)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_POPODECKEYCHALLCONTENT)


ASN1_ITEM_TEMPLATE(Otls_CMP_POPODECKEYRESPCONTENT) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
                          Otls_CMP_POPODECKEYRESPCONTENT, ASN1_INTEGER)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_POPODECKEYRESPCONTENT)


ASN1_SEQUENCE(Otls_CMP_CAKEYUPDANNCONTENT) = {
    /* Otls_CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
    ASN1_SIMPLE(Otls_CMP_CAKEYUPDANNCONTENT, oldWithNew, X509),
    /* Otls_CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
    ASN1_SIMPLE(Otls_CMP_CAKEYUPDANNCONTENT, newWithOld, X509),
    /* Otls_CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
    ASN1_SIMPLE(Otls_CMP_CAKEYUPDANNCONTENT, newWithNew, X509)
} ASN1_SEQUENCE_END(Otls_CMP_CAKEYUPDANNCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_CAKEYUPDANNCONTENT)


ASN1_SEQUENCE(Otls_CMP_ERRORMSGCONTENT) = {
    ASN1_SIMPLE(Otls_CMP_ERRORMSGCONTENT, pKIStatusInfo, Otls_CMP_PKISI),
    ASN1_OPT(Otls_CMP_ERRORMSGCONTENT, errorCode, ASN1_INTEGER),
    /*
     * Otls_CMP_PKIFREETEXT is effectively a sequence of ASN1_UTF8STRING
     * so it is used directly
     *
     */
    ASN1_SEQUENCE_OF_OPT(Otls_CMP_ERRORMSGCONTENT, errorDetails, ASN1_UTF8STRING)
} ASN1_SEQUENCE_END(Otls_CMP_ERRORMSGCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_ERRORMSGCONTENT)

ASN1_ADB_TEMPLATE(infotypeandvalue_default) = ASN1_OPT(Otls_CMP_ITAV,
        infoValue.other, ASN1_ANY);
/* ITAV means InfoTypeAndValue */
ASN1_ADB(Otls_CMP_ITAV) = {
    /* Otls_CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
    ADB_ENTRY(NID_id_it_caProtEncCert, ASN1_OPT(Otls_CMP_ITAV,
                                                infoValue.caProtEncCert, X509)),
    ADB_ENTRY(NID_id_it_signKeyPairTypes,
              ASN1_SEQUENCE_OF_OPT(Otls_CMP_ITAV,
                                   infoValue.signKeyPairTypes, X509_ALGOR)),
    ADB_ENTRY(NID_id_it_encKeyPairTypes,
              ASN1_SEQUENCE_OF_OPT(Otls_CMP_ITAV,
                                   infoValue.encKeyPairTypes, X509_ALGOR)),
    ADB_ENTRY(NID_id_it_preferredSymmAlg,
              ASN1_OPT(Otls_CMP_ITAV, infoValue.preferredSymmAlg,
                       X509_ALGOR)),
    ADB_ENTRY(NID_id_it_caKeyUpdateInfo,
              ASN1_OPT(Otls_CMP_ITAV, infoValue.caKeyUpdateInfo,
                       Otls_CMP_CAKEYUPDANNCONTENT)),
    ADB_ENTRY(NID_id_it_currentCRL,
              ASN1_OPT(Otls_CMP_ITAV, infoValue.currentCRL, X509_CRL)),
    ADB_ENTRY(NID_id_it_unsupportedOIDs,
              ASN1_SEQUENCE_OF_OPT(Otls_CMP_ITAV,
                                   infoValue.unsupportedOIDs, ASN1_OBJECT)),
    ADB_ENTRY(NID_id_it_keyPairParamReq,
              ASN1_OPT(Otls_CMP_ITAV, infoValue.keyPairParamReq,
                       ASN1_OBJECT)),
    ADB_ENTRY(NID_id_it_keyPairParamRep,
              ASN1_OPT(Otls_CMP_ITAV, infoValue.keyPairParamRep,
                       X509_ALGOR)),
    ADB_ENTRY(NID_id_it_revPassphrase,
              ASN1_OPT(Otls_CMP_ITAV, infoValue.revPassphrase,
                       Otls_CRMF_ENCRYPTEDVALUE)),
    ADB_ENTRY(NID_id_it_implicitConfirm,
              ASN1_OPT(Otls_CMP_ITAV, infoValue.implicitConfirm,
                       ASN1_NULL)),
    ADB_ENTRY(NID_id_it_confirmWaitTime,
              ASN1_OPT(Otls_CMP_ITAV, infoValue.confirmWaitTime,
                       ASN1_GENERALIZEDTIME)),
    ADB_ENTRY(NID_id_it_origPKIMessage,
              ASN1_OPT(Otls_CMP_ITAV, infoValue.origPKIMessage,
                       Otls_CMP_MSGS)),
    ADB_ENTRY(NID_id_it_suppLangTags,
              ASN1_SEQUENCE_OF_OPT(Otls_CMP_ITAV, infoValue.suppLangTagsValue,
                                   ASN1_UTF8STRING)),
} ASN1_ADB_END(Otls_CMP_ITAV, 0, infoType, 0,
               &infotypeandvalue_default_tt, NULL);


ASN1_SEQUENCE(Otls_CMP_ITAV) = {
    ASN1_SIMPLE(Otls_CMP_ITAV, infoType, ASN1_OBJECT),
    ASN1_ADB_OBJECT(Otls_CMP_ITAV)
} ASN1_SEQUENCE_END(Otls_CMP_ITAV)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_ITAV)
IMPLEMENT_ASN1_DUP_FUNCTION(Otls_CMP_ITAV)

Otls_CMP_ITAV *Otls_CMP_ITAV_create(ASN1_OBJECT *type, ASN1_TYPE *value)
{
    Otls_CMP_ITAV *itav;

    if (type == NULL || (itav = Otls_CMP_ITAV_new()) == NULL)
        return NULL;
    Otls_CMP_ITAV_set0(itav, type, value);
    return itav;
}

void Otls_CMP_ITAV_set0(Otls_CMP_ITAV *itav, ASN1_OBJECT *type,
                        ASN1_TYPE *value)
{
    itav->infoType = type;
    itav->infoValue.other = value;
}

ASN1_OBJECT *Otls_CMP_ITAV_get0_type(const Otls_CMP_ITAV *itav)
{
    if (itav == NULL)
        return NULL;
    return itav->infoType;
}

ASN1_TYPE *Otls_CMP_ITAV_get0_value(const Otls_CMP_ITAV *itav)
{
    if (itav == NULL)
        return NULL;
    return itav->infoValue.other;
}

int Otls_CMP_ITAV_push0_stack_item(STACK_OF(Otls_CMP_ITAV) **itav_sk_p,
                                   Otls_CMP_ITAV *itav)
{
    int created = 0;

    if (itav_sk_p == NULL || itav == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if (*itav_sk_p == NULL) {
        if ((*itav_sk_p = sk_Otls_CMP_ITAV_new_null()) == NULL)
            goto err;
        created = 1;
    }
    if (!sk_Otls_CMP_ITAV_push(*itav_sk_p, itav))
        goto err;
    return 1;

 err:
    if (created != 0) {
        sk_Otls_CMP_ITAV_free(*itav_sk_p);
        *itav_sk_p = NULL;
    }
    return 0;
}

/* get ASN.1 encoded integer, return -1 on error */
int otls_cmp_asn1_get_int(const ASN1_INTEGER *a)
{
    int64_t res;

    if (!ASN1_INTEGER_get_int64(&res, a)) {
        CMPerr(0, ASN1_R_INVALID_NUMBER);
        return -1;
    }
    if (res < INT_MIN) {
        CMPerr(0, ASN1_R_TOO_SMALL);
        return -1;
    }
    if (res > INT_MAX) {
        CMPerr(0, ASN1_R_TOO_LARGE);
        return -1;
    }
    return (int)res;
}

ASN1_CHOICE(Otls_CMP_CERTORENCCERT) = {
    /* Otls_CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
    ASN1_EXP(Otls_CMP_CERTORENCCERT, value.certificate, X509, 0),
    ASN1_EXP(Otls_CMP_CERTORENCCERT, value.encryptedCert,
             Otls_CRMF_ENCRYPTEDVALUE, 1),
} ASN1_CHOICE_END(Otls_CMP_CERTORENCCERT)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_CERTORENCCERT)


ASN1_SEQUENCE(Otls_CMP_CERTIFIEDKEYPAIR) = {
    ASN1_SIMPLE(Otls_CMP_CERTIFIEDKEYPAIR, certOrEncCert,
                Otls_CMP_CERTORENCCERT),
    ASN1_EXP_OPT(Otls_CMP_CERTIFIEDKEYPAIR, privateKey,
                 Otls_CRMF_ENCRYPTEDVALUE, 0),
    ASN1_EXP_OPT(Otls_CMP_CERTIFIEDKEYPAIR, publicationInfo,
                 Otls_CRMF_PKIPUBLICATIONINFO, 1)
} ASN1_SEQUENCE_END(Otls_CMP_CERTIFIEDKEYPAIR)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_CERTIFIEDKEYPAIR)


ASN1_SEQUENCE(Otls_CMP_REVDETAILS) = {
    ASN1_SIMPLE(Otls_CMP_REVDETAILS, certDetails, Otls_CRMF_CERTTEMPLATE),
    ASN1_OPT(Otls_CMP_REVDETAILS, crlEntryDetails, X509_EXTENSIONS)
} ASN1_SEQUENCE_END(Otls_CMP_REVDETAILS)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_REVDETAILS)


ASN1_ITEM_TEMPLATE(Otls_CMP_REVREQCONTENT) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Otls_CMP_REVREQCONTENT,
                          Otls_CMP_REVDETAILS)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_REVREQCONTENT)


ASN1_SEQUENCE(Otls_CMP_REVREPCONTENT) = {
    ASN1_SEQUENCE_OF(Otls_CMP_REVREPCONTENT, status, Otls_CMP_PKISI),
    ASN1_EXP_SEQUENCE_OF_OPT(Otls_CMP_REVREPCONTENT, revCerts, Otls_CRMF_CERTID,
                             0),
    ASN1_EXP_SEQUENCE_OF_OPT(Otls_CMP_REVREPCONTENT, crls, X509_CRL, 1)
} ASN1_SEQUENCE_END(Otls_CMP_REVREPCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_REVREPCONTENT)


ASN1_SEQUENCE(Otls_CMP_KEYRECREPCONTENT) = {
    ASN1_SIMPLE(Otls_CMP_KEYRECREPCONTENT, status, Otls_CMP_PKISI),
    ASN1_EXP_OPT(Otls_CMP_KEYRECREPCONTENT, newSigCert, X509, 0),
    ASN1_EXP_SEQUENCE_OF_OPT(Otls_CMP_KEYRECREPCONTENT, caCerts, X509, 1),
    ASN1_EXP_SEQUENCE_OF_OPT(Otls_CMP_KEYRECREPCONTENT, keyPairHist,
                             Otls_CMP_CERTIFIEDKEYPAIR, 2)
} ASN1_SEQUENCE_END(Otls_CMP_KEYRECREPCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_KEYRECREPCONTENT)


ASN1_ITEM_TEMPLATE(Otls_CMP_PKISTATUS) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_UNIVERSAL, 0, status, ASN1_INTEGER)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_PKISTATUS)

ASN1_SEQUENCE(Otls_CMP_PKISI) = {
    ASN1_SIMPLE(Otls_CMP_PKISI, status, Otls_CMP_PKISTATUS),
    /*
     * CMP_PKIFREETEXT is effectively a sequence of ASN1_UTF8STRING
     * so it is used directly
     */
    ASN1_SEQUENCE_OF_OPT(Otls_CMP_PKISI, statusString, ASN1_UTF8STRING),
    /*
     * Otls_CMP_PKIFAILUREINFO is effectively ASN1_BIT_STRING so used directly
     */
    ASN1_OPT(Otls_CMP_PKISI, failInfo, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(Otls_CMP_PKISI)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_PKISI)
IMPLEMENT_ASN1_DUP_FUNCTION(Otls_CMP_PKISI)

ASN1_SEQUENCE(Otls_CMP_CERTSTATUS) = {
    ASN1_SIMPLE(Otls_CMP_CERTSTATUS, certHash, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Otls_CMP_CERTSTATUS, certReqId, ASN1_INTEGER),
    ASN1_OPT(Otls_CMP_CERTSTATUS, statusInfo, Otls_CMP_PKISI)
} ASN1_SEQUENCE_END(Otls_CMP_CERTSTATUS)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_CERTSTATUS)

ASN1_ITEM_TEMPLATE(Otls_CMP_CERTCONFIRMCONTENT) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Otls_CMP_CERTCONFIRMCONTENT,
                          Otls_CMP_CERTSTATUS)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_CERTCONFIRMCONTENT)

ASN1_SEQUENCE(Otls_CMP_CERTRESPONSE) = {
    ASN1_SIMPLE(Otls_CMP_CERTRESPONSE, certReqId, ASN1_INTEGER),
    ASN1_SIMPLE(Otls_CMP_CERTRESPONSE, status, Otls_CMP_PKISI),
    ASN1_OPT(Otls_CMP_CERTRESPONSE, certifiedKeyPair,
             Otls_CMP_CERTIFIEDKEYPAIR),
    ASN1_OPT(Otls_CMP_CERTRESPONSE, rspInfo, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(Otls_CMP_CERTRESPONSE)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_CERTRESPONSE)

ASN1_SEQUENCE(Otls_CMP_POLLREQ) = {
    ASN1_SIMPLE(Otls_CMP_POLLREQ, certReqId, ASN1_INTEGER)
} ASN1_SEQUENCE_END(Otls_CMP_POLLREQ)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_POLLREQ)

ASN1_ITEM_TEMPLATE(Otls_CMP_POLLREQCONTENT) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Otls_CMP_POLLREQCONTENT,
                          Otls_CMP_POLLREQ)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_POLLREQCONTENT)

ASN1_SEQUENCE(Otls_CMP_POLLREP) = {
    ASN1_SIMPLE(Otls_CMP_POLLREP, certReqId, ASN1_INTEGER),
    ASN1_SIMPLE(Otls_CMP_POLLREP, checkAfter, ASN1_INTEGER),
    ASN1_SEQUENCE_OF_OPT(Otls_CMP_POLLREP, reason, ASN1_UTF8STRING),
} ASN1_SEQUENCE_END(Otls_CMP_POLLREP)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_POLLREP)

ASN1_ITEM_TEMPLATE(Otls_CMP_POLLREPCONTENT) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
                          Otls_CMP_POLLREPCONTENT,
                          Otls_CMP_POLLREP)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_POLLREPCONTENT)

ASN1_SEQUENCE(Otls_CMP_CERTREPMESSAGE) = {
    /* Otls_CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
    ASN1_EXP_SEQUENCE_OF_OPT(Otls_CMP_CERTREPMESSAGE, caPubs, X509, 1),
    ASN1_SEQUENCE_OF(Otls_CMP_CERTREPMESSAGE, response, Otls_CMP_CERTRESPONSE)
} ASN1_SEQUENCE_END(Otls_CMP_CERTREPMESSAGE)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_CERTREPMESSAGE)

ASN1_ITEM_TEMPLATE(Otls_CMP_GENMSGCONTENT) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Otls_CMP_GENMSGCONTENT,
                          Otls_CMP_ITAV)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_GENMSGCONTENT)

ASN1_ITEM_TEMPLATE(Otls_CMP_GENREPCONTENT) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Otls_CMP_GENREPCONTENT,
                          Otls_CMP_ITAV)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_GENREPCONTENT)

ASN1_ITEM_TEMPLATE(Otls_CMP_CRLANNCONTENT) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
                          Otls_CMP_CRLANNCONTENT, X509_CRL)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_CRLANNCONTENT)

ASN1_CHOICE(Otls_CMP_PKIBODY) = {
    ASN1_EXP(Otls_CMP_PKIBODY, value.ir, Otls_CRMF_MSGS, 0),
    ASN1_EXP(Otls_CMP_PKIBODY, value.ip, Otls_CMP_CERTREPMESSAGE, 1),
    ASN1_EXP(Otls_CMP_PKIBODY, value.cr, Otls_CRMF_MSGS, 2),
    ASN1_EXP(Otls_CMP_PKIBODY, value.cp, Otls_CMP_CERTREPMESSAGE, 3),
    ASN1_EXP(Otls_CMP_PKIBODY, value.p10cr, X509_REQ, 4),
    ASN1_EXP(Otls_CMP_PKIBODY, value.popdecc, Otls_CMP_POPODECKEYCHALLCONTENT, 5),
    ASN1_EXP(Otls_CMP_PKIBODY, value.popdecr, Otls_CMP_POPODECKEYRESPCONTENT, 6),
    ASN1_EXP(Otls_CMP_PKIBODY, value.kur, Otls_CRMF_MSGS, 7),
    ASN1_EXP(Otls_CMP_PKIBODY, value.kup, Otls_CMP_CERTREPMESSAGE, 8),
    ASN1_EXP(Otls_CMP_PKIBODY, value.krr, Otls_CRMF_MSGS, 9),
    ASN1_EXP(Otls_CMP_PKIBODY, value.krp, Otls_CMP_KEYRECREPCONTENT, 10),
    ASN1_EXP(Otls_CMP_PKIBODY, value.rr, Otls_CMP_REVREQCONTENT, 11),
    ASN1_EXP(Otls_CMP_PKIBODY, value.rp, Otls_CMP_REVREPCONTENT, 12),
    ASN1_EXP(Otls_CMP_PKIBODY, value.ccr, Otls_CRMF_MSGS, 13),
    ASN1_EXP(Otls_CMP_PKIBODY, value.ccp, Otls_CMP_CERTREPMESSAGE, 14),
    ASN1_EXP(Otls_CMP_PKIBODY, value.ckuann, Otls_CMP_CAKEYUPDANNCONTENT, 15),
    ASN1_EXP(Otls_CMP_PKIBODY, value.cann, X509, 16),
    ASN1_EXP(Otls_CMP_PKIBODY, value.rann, Otls_CMP_REVANNCONTENT, 17),
    ASN1_EXP(Otls_CMP_PKIBODY, value.crlann, Otls_CMP_CRLANNCONTENT, 18),
    ASN1_EXP(Otls_CMP_PKIBODY, value.pkiconf, ASN1_ANY, 19),
    ASN1_EXP(Otls_CMP_PKIBODY, value.nested, Otls_CMP_MSGS, 20),
    ASN1_EXP(Otls_CMP_PKIBODY, value.genm, Otls_CMP_GENMSGCONTENT, 21),
    ASN1_EXP(Otls_CMP_PKIBODY, value.genp, Otls_CMP_GENREPCONTENT, 22),
    ASN1_EXP(Otls_CMP_PKIBODY, value.error, Otls_CMP_ERRORMSGCONTENT, 23),
    ASN1_EXP(Otls_CMP_PKIBODY, value.certConf, Otls_CMP_CERTCONFIRMCONTENT, 24),
    ASN1_EXP(Otls_CMP_PKIBODY, value.pollReq, Otls_CMP_POLLREQCONTENT, 25),
    ASN1_EXP(Otls_CMP_PKIBODY, value.pollRep, Otls_CMP_POLLREPCONTENT, 26),
} ASN1_CHOICE_END(Otls_CMP_PKIBODY)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_PKIBODY)

ASN1_SEQUENCE(Otls_CMP_PKIHEADER) = {
    ASN1_SIMPLE(Otls_CMP_PKIHEADER, pvno, ASN1_INTEGER),
    ASN1_SIMPLE(Otls_CMP_PKIHEADER, sender, GENERAL_NAME),
    ASN1_SIMPLE(Otls_CMP_PKIHEADER, recipient, GENERAL_NAME),
    ASN1_EXP_OPT(Otls_CMP_PKIHEADER, messageTime, ASN1_GENERALIZEDTIME, 0),
    ASN1_EXP_OPT(Otls_CMP_PKIHEADER, protectionAlg, X509_ALGOR, 1),
    ASN1_EXP_OPT(Otls_CMP_PKIHEADER, senderKID, ASN1_OCTET_STRING, 2),
    ASN1_EXP_OPT(Otls_CMP_PKIHEADER, recipKID, ASN1_OCTET_STRING, 3),
    ASN1_EXP_OPT(Otls_CMP_PKIHEADER, transactionID, ASN1_OCTET_STRING, 4),
    ASN1_EXP_OPT(Otls_CMP_PKIHEADER, senderNonce, ASN1_OCTET_STRING, 5),
    ASN1_EXP_OPT(Otls_CMP_PKIHEADER, recipNonce, ASN1_OCTET_STRING, 6),
    /*
     * Otls_CMP_PKIFREETEXT is effectively a sequence of ASN1_UTF8STRING
     * so it is used directly
     */
    ASN1_EXP_SEQUENCE_OF_OPT(Otls_CMP_PKIHEADER, freeText, ASN1_UTF8STRING, 7),
    ASN1_EXP_SEQUENCE_OF_OPT(Otls_CMP_PKIHEADER, generalInfo,
                             Otls_CMP_ITAV, 8)
} ASN1_SEQUENCE_END(Otls_CMP_PKIHEADER)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_PKIHEADER)

ASN1_SEQUENCE(CMP_PROTECTEDPART) = {
    ASN1_SIMPLE(Otls_CMP_MSG, header, Otls_CMP_PKIHEADER),
    ASN1_SIMPLE(Otls_CMP_MSG, body, Otls_CMP_PKIBODY)
} ASN1_SEQUENCE_END(CMP_PROTECTEDPART)
IMPLEMENT_ASN1_FUNCTIONS(CMP_PROTECTEDPART)

ASN1_SEQUENCE(Otls_CMP_MSG) = {
    ASN1_SIMPLE(Otls_CMP_MSG, header, Otls_CMP_PKIHEADER),
    ASN1_SIMPLE(Otls_CMP_MSG, body, Otls_CMP_PKIBODY),
    ASN1_EXP_OPT(Otls_CMP_MSG, protection, ASN1_BIT_STRING, 0),
    /* Otls_CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
    ASN1_EXP_SEQUENCE_OF_OPT(Otls_CMP_MSG, extraCerts, X509, 1)
} ASN1_SEQUENCE_END(Otls_CMP_MSG)
IMPLEMENT_ASN1_FUNCTIONS(Otls_CMP_MSG)
IMPLEMENT_ASN1_DUP_FUNCTION(Otls_CMP_MSG)

ASN1_ITEM_TEMPLATE(Otls_CMP_MSGS) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Otls_CMP_MSGS,
                          Otls_CMP_MSG)
ASN1_ITEM_TEMPLATE_END(Otls_CMP_MSGS)
