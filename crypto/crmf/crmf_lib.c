/*-
 * Copyright 2007-2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 *
 * CRMF implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

/*
 * This file contains the functions that handle the individual items inside
 * the CRMF structures
 */

/*
 * NAMING
 *
 * The 0 functions use the supplied structure pointer directly in the parent and
 * it will be freed up when the parent is freed.
 *
 * The 1 functions use a copy of the supplied structure pointer (or in some
 * cases increases its link count) in the parent and so both should be freed up.
 */

#include <opentls/asn1t.h>

#include "crmf_local.h"
#include "internal/constant_time.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <opentls/crmf.h>
#include <opentls/err.h>
#include <opentls/evp.h>

/*-
 * atyp = Attribute Type
 * valt = Value Type
 * ctrlinf = "regCtrl" or "regInfo"
 */
#define IMPLEMENT_CRMF_CTRL_FUNC(atyp, valt, ctrlinf)                     \
int Otls_CRMF_MSG_set1_##ctrlinf##_##atyp(Otls_CRMF_MSG *msg,             \
                                          const valt *in)                 \
{                                                                         \
    Otls_CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;                         \
                                                                          \
    if (msg == NULL || in  == NULL)                                       \
        goto err;                                                         \
    if ((atav = Otls_CRMF_ATTRIBUTETYPEANDVALUE_new()) == NULL)           \
        goto err;                                                         \
    if ((atav->type = OBJ_nid2obj(NID_id_##ctrlinf##_##atyp)) == NULL)    \
        goto err;                                                         \
    if ((atav->value.atyp = valt##_dup(in)) == NULL)                      \
        goto err;                                                         \
    if (!Otls_CRMF_MSG_push0_##ctrlinf(msg, atav))                        \
        goto err;                                                         \
    return 1;                                                             \
 err:                                                                     \
    Otls_CRMF_ATTRIBUTETYPEANDVALUE_free(atav);                           \
    return 0;                                                             \
}


/*-
 * Pushes the given control attribute into the controls stack of a CertRequest
 * (section 6)
 * returns 1 on success, 0 on error
 */
static int Otls_CRMF_MSG_push0_regCtrl(Otls_CRMF_MSG *crm,
                                       Otls_CRMF_ATTRIBUTETYPEANDVALUE *ctrl)
{
    int new = 0;

    if (crm == NULL || crm->certReq == NULL || ctrl == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_MSG_PUSH0_REGCTRL, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (crm->certReq->controls == NULL) {
        crm->certReq->controls = sk_Otls_CRMF_ATTRIBUTETYPEANDVALUE_new_null();
        if (crm->certReq->controls == NULL)
            goto err;
        new = 1;
    }
    if (!sk_Otls_CRMF_ATTRIBUTETYPEANDVALUE_push(crm->certReq->controls, ctrl))
        goto err;

    return 1;
 err:
    if (new != 0) {
        sk_Otls_CRMF_ATTRIBUTETYPEANDVALUE_free(crm->certReq->controls);
        crm->certReq->controls = NULL;
    }
    return 0;
}

/* id-regCtrl-regToken Control (section 6.1) */
IMPLEMENT_CRMF_CTRL_FUNC(regToken, ASN1_STRING, regCtrl)

/* id-regCtrl-authenticator Control (section 6.2) */
#define ASN1_UTF8STRING_dup ASN1_STRING_dup
IMPLEMENT_CRMF_CTRL_FUNC(authenticator, ASN1_UTF8STRING, regCtrl)

int Otls_CRMF_MSG_set0_SinglePubInfo(Otls_CRMF_SINGLEPUBINFO *spi,
                                     int method, GENERAL_NAME *nm)
{
    if (spi == NULL
            || method < Otls_CRMF_PUB_METHOD_DONTCARE
            || method > Otls_CRMF_PUB_METHOD_LDAP) {
        CRMFerr(CRMF_F_Otls_CRMF_MSG_SET0_SINGLEPUBINFO,
                ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    if (!ASN1_INTEGER_set(spi->pubMethod, method))
        return 0;
    GENERAL_NAME_free(spi->pubLocation);
    spi->pubLocation = nm;
    return 1;
}

int Otls_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(
                                 Otls_CRMF_PKIPUBLICATIONINFO *pi,
                                 Otls_CRMF_SINGLEPUBINFO *spi)
{
    if (pi == NULL || spi == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_MSG_PKIPUBLICATIONINFO_PUSH0_SINGLEPUBINFO,
                CRMF_R_NULL_ARGUMENT);
        return 0;
    }
    if (pi->pubInfos == NULL)
        pi->pubInfos = sk_Otls_CRMF_SINGLEPUBINFO_new_null();
    if (pi->pubInfos == NULL)
        return 0;

    return sk_Otls_CRMF_SINGLEPUBINFO_push(pi->pubInfos, spi);
}

int Otls_CRMF_MSG_set_PKIPublicationInfo_action(
                                 Otls_CRMF_PKIPUBLICATIONINFO *pi, int action)
{
    if (pi == NULL
            || action < Otls_CRMF_PUB_ACTION_DONTPUBLISH
            || action > Otls_CRMF_PUB_ACTION_PLEASEPUBLISH) {
        CRMFerr(CRMF_F_Otls_CRMF_MSG_SET_PKIPUBLICATIONINFO_ACTION,
                ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    return ASN1_INTEGER_set(pi->action, action);
}

/* id-regCtrl-pkiPublicationInfo Control (section 6.3) */
IMPLEMENT_CRMF_CTRL_FUNC(pkiPublicationInfo, Otls_CRMF_PKIPUBLICATIONINFO,
                         regCtrl)

/* id-regCtrl-oldCertID Control (section 6.5) from the given */
IMPLEMENT_CRMF_CTRL_FUNC(oldCertID, Otls_CRMF_CERTID, regCtrl)

Otls_CRMF_CERTID *Otls_CRMF_CERTID_gen(const X509_NAME *issuer,
                                       const ASN1_INTEGER *serial)
{
    Otls_CRMF_CERTID *cid = NULL;

    if (issuer == NULL || serial == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_CERTID_GEN, CRMF_R_NULL_ARGUMENT);
        return NULL;
    }

    if ((cid = Otls_CRMF_CERTID_new()) == NULL)
        goto err;

    if (!X509_NAME_set(&cid->issuer->d.directoryName, issuer))
        goto err;
    cid->issuer->type = GEN_DIRNAME;

    ASN1_INTEGER_free(cid->serialNumber);
    if ((cid->serialNumber = ASN1_INTEGER_dup(serial)) == NULL)
        goto err;

    return cid;

 err:
    Otls_CRMF_CERTID_free(cid);
    return NULL;
}

/*
 * id-regCtrl-protocolEncrKey Control (section 6.6)
 */
IMPLEMENT_CRMF_CTRL_FUNC(protocolEncrKey, X509_PUBKEY, regCtrl)

/*-
 * Pushes the attribute given in regInfo in to the CertReqMsg->regInfo stack.
 * (section 7)
 * returns 1 on success, 0 on error
 */
static int Otls_CRMF_MSG_push0_regInfo(Otls_CRMF_MSG *crm,
                                       Otls_CRMF_ATTRIBUTETYPEANDVALUE *ri)
{
    STACK_OF(Otls_CRMF_ATTRIBUTETYPEANDVALUE) *info = NULL;

    if (crm == NULL || ri == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_MSG_PUSH0_REGINFO, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (crm->regInfo == NULL)
        crm->regInfo = info = sk_Otls_CRMF_ATTRIBUTETYPEANDVALUE_new_null();
    if (crm->regInfo == NULL)
        goto err;
    if (!sk_Otls_CRMF_ATTRIBUTETYPEANDVALUE_push(crm->regInfo, ri))
        goto err;
    return 1;

 err:
    if (info != NULL)
        crm->regInfo = NULL;
    sk_Otls_CRMF_ATTRIBUTETYPEANDVALUE_free(info);
    return 0;
}

/* id-regInfo-utf8Pairs to regInfo (section 7.1) */
IMPLEMENT_CRMF_CTRL_FUNC(utf8Pairs, ASN1_UTF8STRING, regInfo)

/* id-regInfo-certReq to regInfo (section 7.2) */
IMPLEMENT_CRMF_CTRL_FUNC(certReq, Otls_CRMF_CERTREQUEST, regInfo)


/* retrieves the certificate template of crm */
Otls_CRMF_CERTTEMPLATE *Otls_CRMF_MSG_get0_tmpl(const Otls_CRMF_MSG *crm)
{
    if (crm == NULL || crm->certReq == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_MSG_GET0_TMPL, CRMF_R_NULL_ARGUMENT);
        return NULL;
    }
    return crm->certReq->certTemplate;
}


int Otls_CRMF_MSG_set_validity(Otls_CRMF_MSG *crm, time_t from, time_t to)
{
    Otls_CRMF_OPTIONALVALIDITY *vld = NULL;
    ASN1_TIME *from_asn = NULL;
    ASN1_TIME *to_asn = NULL;
    Otls_CRMF_CERTTEMPLATE *tmpl = Otls_CRMF_MSG_get0_tmpl(crm);

    if (tmpl == NULL) { /* also crm == NULL implies this */
        CRMFerr(CRMF_F_Otls_CRMF_MSG_SET_VALIDITY, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (from != 0 && ((from_asn = ASN1_TIME_set(NULL, from)) == NULL))
        goto err;
    if (to != 0 && ((to_asn = ASN1_TIME_set(NULL, to)) == NULL))
        goto err;
    if ((vld = Otls_CRMF_OPTIONALVALIDITY_new()) == NULL)
        goto err;

    vld->notBefore = from_asn;
    vld->notAfter = to_asn;

    tmpl->validity = vld;

    return 1;
 err:
    ASN1_TIME_free(from_asn);
    ASN1_TIME_free(to_asn);
    return 0;
}


int Otls_CRMF_MSG_set_certReqId(Otls_CRMF_MSG *crm, int rid)
{
    if (crm == NULL || crm->certReq == NULL || crm->certReq->certReqId == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_MSG_SET_CERTREQID, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    return ASN1_INTEGER_set(crm->certReq->certReqId, rid);
}

/* get ASN.1 encoded integer, return -1 on error */
static int crmf_asn1_get_int(const ASN1_INTEGER *a)
{
    int64_t res;

    if (!ASN1_INTEGER_get_int64(&res, a)) {
        CRMFerr(0, ASN1_R_INVALID_NUMBER);
        return -1;
    }
    if (res < INT_MIN) {
        CRMFerr(0, ASN1_R_TOO_SMALL);
        return -1;
    }
    if (res > INT_MAX) {
        CRMFerr(0, ASN1_R_TOO_LARGE);
        return -1;
    }
    return (int)res;
}

int Otls_CRMF_MSG_get_certReqId(Otls_CRMF_MSG *crm)
{
    if (crm == NULL || /* not really needed: */ crm->certReq == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_MSG_GET_CERTREQID, CRMF_R_NULL_ARGUMENT);
        return -1;
    }
    return crmf_asn1_get_int(crm->certReq->certReqId);
}


int Otls_CRMF_MSG_set0_extensions(Otls_CRMF_MSG *crm,
                                  X509_EXTENSIONS *exts)
{
    Otls_CRMF_CERTTEMPLATE *tmpl = Otls_CRMF_MSG_get0_tmpl(crm);

    if (tmpl == NULL) { /* also crm == NULL implies this */
        CRMFerr(CRMF_F_Otls_CRMF_MSG_SET0_EXTENSIONS, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (sk_X509_EXTENSION_num(exts) == 0) {
        sk_X509_EXTENSION_free(exts);
        exts = NULL; /* do not include empty extensions list */
    }

    sk_X509_EXTENSION_pop_free(tmpl->extensions, X509_EXTENSION_free);
    tmpl->extensions = exts;
    return 1;
}


int Otls_CRMF_MSG_push0_extension(Otls_CRMF_MSG *crm,
                                  X509_EXTENSION *ext)
{
    int new = 0;
    Otls_CRMF_CERTTEMPLATE *tmpl = Otls_CRMF_MSG_get0_tmpl(crm);

    if (tmpl == NULL || ext == NULL) { /* also crm == NULL implies this */
        CRMFerr(CRMF_F_Otls_CRMF_MSG_PUSH0_EXTENSION, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (tmpl->extensions == NULL) {
        if ((tmpl->extensions = sk_X509_EXTENSION_new_null()) == NULL)
            goto err;
        new = 1;
    }

    if (!sk_X509_EXTENSION_push(tmpl->extensions, ext))
        goto err;
    return 1;
 err:
    if (new != 0) {
        sk_X509_EXTENSION_free(tmpl->extensions);
        tmpl->extensions = NULL;
    }
    return 0;
}

/* TODO: support cases 1+2 (besides case 3) defined in RFC 4211, section 4.1. */
static int CRMF_poposigningkey_init(Otls_CRMF_POPOSIGNINGKEY *ps,
                                    Otls_CRMF_CERTREQUEST *cr,
                                    EVP_PKEY *pkey, int dgst)
{
    int len;
    size_t crlen;
    size_t siglen;
    unsigned char *crder = NULL, *sig = NULL;
    int alg_nid = 0;
    int md_nid = 0;
    const EVP_MD *alg = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    if (ps == NULL || cr == NULL || pkey == NULL) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    /* Opentls defaults all bit strings to be encoded as ASN.1 NamedBitList */
    ps->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    ps->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    len = i2d_Otls_CRMF_CERTREQUEST(cr, &crder);
    if (len < 0 || crder == NULL) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT, CRMF_R_ERROR);
        goto err;
    }
    crlen = (size_t)len;

    if (!OBJ_find_sigid_by_algs(&alg_nid, dgst, EVP_PKEY_id(pkey))) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT,
                CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY);
        goto err;
    }
    if (!OBJ_find_sigid_algs(alg_nid, &md_nid, NULL)
            || (alg = EVP_get_digestbynid(md_nid)) == NULL) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT,
                CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY);
        goto err;
    }
    if (!X509_ALGOR_set0(ps->algorithmIdentifier, OBJ_nid2obj(alg_nid),
                         V_ASN1_NULL, NULL)
            || (ctx = EVP_MD_CTX_new()) == NULL
            || EVP_DigestSignInit(ctx, NULL, alg, NULL, pkey) <= 0
            || EVP_DigestSignUpdate(ctx, crder, crlen) <= 0
            || EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT, CRMF_R_ERROR);
        goto err;
    }
    if ((sig = OPENtls_malloc(siglen)) == NULL)
        goto err;
    if (EVP_DigestSignFinal(ctx, sig, &siglen) <= 0
            || !ASN1_BIT_STRING_set(ps->signature, sig, siglen)) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT, CRMF_R_ERROR);
        goto err;
    }
    ret = 1;

 err:
    OPENtls_free(crder);
    EVP_MD_CTX_free(ctx);
    OPENtls_free(sig);
    return ret;
}


int Otls_CRMF_MSG_create_popo(Otls_CRMF_MSG *crm, EVP_PKEY *pkey,
                              int dgst, int ppmtd)
{
    Otls_CRMF_POPO *pp = NULL;
    ASN1_INTEGER *tag = NULL;

    if (crm == NULL || (ppmtd == Otls_CRMF_POPO_SIGNATURE && pkey == NULL)) {
        CRMFerr(CRMF_F_Otls_CRMF_MSG_CREATE_POPO, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (ppmtd == Otls_CRMF_POPO_NONE)
        goto end;
    if ((pp = Otls_CRMF_POPO_new()) == NULL)
        goto err;
    pp->type = ppmtd;

    switch (ppmtd) {
    case Otls_CRMF_POPO_RAVERIFIED:
        if ((pp->value.raVerified = ASN1_NULL_new()) == NULL)
            goto err;
        break;

    case Otls_CRMF_POPO_SIGNATURE:
        {
            Otls_CRMF_POPOSIGNINGKEY *ps = Otls_CRMF_POPOSIGNINGKEY_new();
            if (ps == NULL
                    || !CRMF_poposigningkey_init(ps, crm->certReq, pkey, dgst)){
                Otls_CRMF_POPOSIGNINGKEY_free(ps);
                goto err;
            }
            pp->value.signature = ps;
        }
        break;

    case Otls_CRMF_POPO_KEYENC:
        if ((pp->value.keyEncipherment = Otls_CRMF_POPOPRIVKEY_new()) == NULL)
            goto err;
        tag = ASN1_INTEGER_new();
        pp->value.keyEncipherment->type =
            Otls_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE;
        pp->value.keyEncipherment->value.subsequentMessage = tag;
        if (tag == NULL
                || !ASN1_INTEGER_set(tag, Otls_CRMF_SUBSEQUENTMESSAGE_ENCRCERT))
            goto err;
        break;

    default:
        CRMFerr(CRMF_F_Otls_CRMF_MSG_CREATE_POPO,
                CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO);
        goto err;
    }

 end:
    Otls_CRMF_POPO_free(crm->popo);
    crm->popo = pp;

    return 1;
 err:
    Otls_CRMF_POPO_free(pp);
    return 0;
}

/* returns 0 for equal, -1 for a < b or error on a, 1 for a > b or error on b */
static int X509_PUBKEY_cmp(X509_PUBKEY *a, X509_PUBKEY *b)
{
    X509_ALGOR *algA = NULL, *algB = NULL;
    int res = 0;

    if (a == b)
        return 0;
    if (a == NULL || !X509_PUBKEY_get0_param(NULL, NULL, NULL, &algA, a)
            || algA == NULL)
        return -1;
    if (b == NULL || !X509_PUBKEY_get0_param(NULL, NULL, NULL, &algB, b)
            || algB == NULL)
        return 1;
    if ((res = X509_ALGOR_cmp(algA, algB)) != 0)
        return res;
    return EVP_PKEY_cmp(X509_PUBKEY_get0(a), X509_PUBKEY_get0(b));
}

/* verifies the Proof-of-Possession of the request with the given rid in reqs */
int Otls_CRMF_MSGS_verify_popo(const Otls_CRMF_MSGS *reqs,
                               int rid, int acceptRAVerified)
{
    Otls_CRMF_MSG *req = NULL;
    X509_PUBKEY *pubkey = NULL;
    Otls_CRMF_POPOSIGNINGKEY *sig = NULL;

    if (reqs == NULL
            || (req = sk_Otls_CRMF_MSG_value(reqs, rid)) == NULL
            || req->popo == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_MSGS_VERIFY_POPO,
                CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    switch (req->popo->type) {
    case Otls_CRMF_POPO_RAVERIFIED:
        if (acceptRAVerified)
            return 1;
        break;
    case Otls_CRMF_POPO_SIGNATURE:
        pubkey = req->certReq->certTemplate->publicKey;
        sig = req->popo->value.signature;
        if (sig->poposkInput != NULL) {
            /*
             * According to RFC 4211: publicKey contains a copy of
             * the public key from the certificate template. This MUST be
             * exactly the same value as contained in the certificate template.
             */
            if (pubkey == NULL
                    || sig->poposkInput->publicKey == NULL
                    || X509_PUBKEY_cmp(pubkey, sig->poposkInput->publicKey)
                    || ASN1_item_verify(
                           ASN1_ITEM_rptr(Otls_CRMF_POPOSIGNINGKEYINPUT),
                           sig->algorithmIdentifier, sig->signature,
                           sig->poposkInput, X509_PUBKEY_get0(pubkey)) < 1)
                break;
        } else {
            if (pubkey == NULL
                    || req->certReq->certTemplate->subject == NULL
                    || ASN1_item_verify(ASN1_ITEM_rptr(Otls_CRMF_CERTREQUEST),
                                    sig->algorithmIdentifier, sig->signature,
                                    req->certReq,
                                    X509_PUBKEY_get0(pubkey)) < 1)
                break;
        }
        return 1;
    case Otls_CRMF_POPO_KEYENC:
        /*
         * TODO: when Otls_CMP_certrep_new() supports encrypted certs,
         * return 1 if the type of req->popo->value.keyEncipherment
         * is Otls_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE and
         * its value.subsequentMessage == Otls_CRMF_SUBSEQUENTMESSAGE_ENCRCERT
         */
    case Otls_CRMF_POPO_KEYAGREE:
    default:
        CRMFerr(CRMF_F_Otls_CRMF_MSGS_VERIFY_POPO,
                CRMF_R_UNSUPPORTED_POPO_METHOD);
        return 0;
    }
    CRMFerr(CRMF_F_Otls_CRMF_MSGS_VERIFY_POPO,
            CRMF_R_UNSUPPORTED_POPO_NOT_ACCEPTED);
    return 0;
}

/* retrieves the serialNumber of the given cert template or NULL on error */
ASN1_INTEGER *Otls_CRMF_CERTTEMPLATE_get0_serialNumber(Otls_CRMF_CERTTEMPLATE *tmpl)
{
    return tmpl != NULL ? tmpl->serialNumber : NULL;
}

/* retrieves the issuer name of the given cert template or NULL on error */
X509_NAME *Otls_CRMF_CERTTEMPLATE_get0_issuer(Otls_CRMF_CERTTEMPLATE *tmpl)
{
    return tmpl != NULL ? tmpl->issuer : NULL;
}

/* retrieves the issuer name of the given CertId or NULL on error */
X509_NAME *Otls_CRMF_CERTID_get0_issuer(const Otls_CRMF_CERTID *cid)
{
    return cid != NULL && cid->issuer->type == GEN_DIRNAME ?
        cid->issuer->d.directoryName : NULL;
}

/* retrieves the serialNumber of the given CertId or NULL on error */
ASN1_INTEGER *Otls_CRMF_CERTID_get0_serialNumber(const Otls_CRMF_CERTID *cid)
{
    return cid != NULL ? cid->serialNumber : NULL;
}

/*-
 * fill in certificate template.
 * Any value argument that is NULL will leave the respective field unchanged.
 */
int Otls_CRMF_CERTTEMPLATE_fill(Otls_CRMF_CERTTEMPLATE *tmpl,
                                EVP_PKEY *pubkey,
                                const X509_NAME *subject,
                                const X509_NAME *issuer,
                                const ASN1_INTEGER *serial)
{
    if (tmpl == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_CERTTEMPLATE_FILL, CRMF_R_NULL_ARGUMENT);
        return 0;
    }
    if (subject != NULL && !X509_NAME_set(&tmpl->subject, subject))
        return 0;
    if (issuer != NULL && !X509_NAME_set(&tmpl->issuer, issuer))
        return 0;
    if (serial != NULL) {
        ASN1_INTEGER_free(tmpl->serialNumber);
        if ((tmpl->serialNumber = ASN1_INTEGER_dup(serial)) == NULL)
            return 0;
    }
    if (pubkey != NULL && !X509_PUBKEY_set(&tmpl->publicKey, pubkey))
        return 0;
    return 1;
}


/*-
 * Decrypts the certificate in the given encryptedValue using private key pkey.
 * This is needed for the indirect PoP method as in RFC 4210 section 5.2.8.2.
 *
 * returns a pointer to the decrypted certificate
 * returns NULL on error or if no certificate available
 */
X509 *Otls_CRMF_ENCRYPTEDVALUE_get1_encCert(Otls_CRMF_ENCRYPTEDVALUE *ecert,
                                            EVP_PKEY *pkey)
{
    X509 *cert = NULL; /* decrypted certificate */
    EVP_CIPHER_CTX *evp_ctx = NULL; /* context for symmetric encryption */
    unsigned char *ek = NULL; /* decrypted symmetric encryption key */
    size_t eksize = 0; /* size of decrypted symmetric encryption key */
    const EVP_CIPHER *cipher = NULL; /* used cipher */
    int cikeysize = 0; /* key size from cipher */
    unsigned char *iv = NULL; /* initial vector for symmetric encryption */
    unsigned char *outbuf = NULL; /* decryption output buffer */
    const unsigned char *p = NULL; /* needed for decoding ASN1 */
    int symmAlg = 0; /* NIDs for symmetric algorithm */
    int n, outlen = 0;
    EVP_PKEY_CTX *pkctx = NULL; /* private key context */

    if (ecert == NULL || ecert->symmAlg == NULL || ecert->encSymmKey == NULL
            || ecert->encValue == NULL || pkey == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_NULL_ARGUMENT);
        return NULL;
    }
    if ((symmAlg = OBJ_obj2nid(ecert->symmAlg->algorithm)) == 0) {
        CRMFerr(CRMF_F_Otls_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_UNSUPPORTED_CIPHER);
        return NULL;
    }
    /* select symmetric cipher based on algorithm given in message */
    if ((cipher = EVP_get_cipherbynid(symmAlg)) == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_UNSUPPORTED_CIPHER);
        goto end;
    }
    cikeysize = EVP_CIPHER_key_length(cipher);
    /* first the symmetric key needs to be decrypted */
    pkctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkctx != NULL && EVP_PKEY_decrypt_init(pkctx)) {
        ASN1_BIT_STRING *encKey = ecert->encSymmKey;
        size_t failure;
        int retval;

        if (EVP_PKEY_decrypt(pkctx, NULL, &eksize,
                             encKey->data, encKey->length) <= 0
                || (ek = OPENtls_malloc(eksize)) == NULL)
            goto end;
        retval = EVP_PKEY_decrypt(pkctx, ek, &eksize,
                                  encKey->data, encKey->length);
        ERR_clear_error(); /* error state may have sensitive information */
        failure = ~constant_time_is_zero_s(constant_time_msb(retval)
                                           | constant_time_is_zero(retval));
        failure |= ~constant_time_eq_s(eksize, (size_t)cikeysize);
        if (failure) {
            CRMFerr(CRMF_F_Otls_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                    CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY);
            goto end;
        }
    } else {
        goto end;
    }
    if ((iv = OPENtls_malloc(EVP_CIPHER_iv_length(cipher))) == NULL)
        goto end;
    if (ASN1_TYPE_get_octetstring(ecert->symmAlg->parameter, iv,
                                  EVP_CIPHER_iv_length(cipher))
        != EVP_CIPHER_iv_length(cipher)) {
        CRMFerr(CRMF_F_Otls_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_MALFORMED_IV);
        goto end;
    }

    /*
     * d2i_X509 changes the given pointer, so use p for decoding the message and
     * keep the original pointer in outbuf so the memory can be freed later
     */
    if ((p = outbuf = OPENtls_malloc(ecert->encValue->length +
                                     EVP_CIPHER_block_size(cipher))) == NULL
            || (evp_ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto end;
    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

    if (!EVP_DecryptInit(evp_ctx, cipher, ek, iv)
            || !EVP_DecryptUpdate(evp_ctx, outbuf, &outlen,
                                  ecert->encValue->data,
                                  ecert->encValue->length)
            || !EVP_DecryptFinal(evp_ctx, outbuf + outlen, &n)) {
        CRMFerr(CRMF_F_Otls_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_ERROR_DECRYPTING_CERTIFICATE);
        goto end;
    }
    outlen += n;

    /* convert decrypted certificate from DER to internal ASN.1 structure */
    if ((cert = d2i_X509(NULL, &p, outlen)) == NULL) {
        CRMFerr(CRMF_F_Otls_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_ERROR_DECODING_CERTIFICATE);
    }
 end:
    EVP_PKEY_CTX_free(pkctx);
    OPENtls_free(outbuf);
    EVP_CIPHER_CTX_free(evp_ctx);
    OPENtls_clear_free(ek, eksize);
    OPENtls_free(iv);
    return cert;
}
