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

/* CMP functions for PKIMessage construction */

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <opentls/asn1t.h>
#include <opentls/cmp.h>
#include <opentls/crmf.h>
#include <opentls/err.h>
#include <opentls/x509.h>

Otls_CMP_PKIHEADER *Otls_CMP_MSG_get0_header(const Otls_CMP_MSG *msg)
{
    if (msg == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return msg->header;
}

const char *otls_cmp_bodytype_to_string(int type)
{
    static const char *type_names[] = {
        "IR", "IP", "CR", "CP", "P10CR",
        "POPDECC", "POPDECR", "KUR", "KUP",
        "KRR", "KRP", "RR", "RP", "CCR", "CCP",
        "CKUANN", "CANN", "RANN", "CRLANN", "PKICONF", "NESTED",
        "GENM", "GENP", "ERROR", "CERTCONF", "POLLREQ", "POLLREP",
    };

    if (type < 0 || type > Otls_CMP_PKIBODY_TYPE_MAX)
        return "illegal body type";
    return type_names[type];
}

int otls_cmp_msg_set_bodytype(Otls_CMP_MSG *msg, int type)
{
    if (!otls_assert(msg != NULL && msg->body != NULL))
        return 0;

    msg->body->type = type;
    return 1;
}

int otls_cmp_msg_get_bodytype(const Otls_CMP_MSG *msg)
{
    if (!otls_assert(msg != NULL && msg->body != NULL))
        return -1;

    return msg->body->type;
}

/* Add an extension to the referenced extension stack, which may be NULL */
static int add1_extension(X509_EXTENSIONS **pexts, int nid, int crit, void *ex)
{
    X509_EXTENSION *ext;
    int res;

    if (!otls_assert(pexts != NULL)) /* pointer to var must not be NULL */
        return 0;

    if ((ext = X509V3_EXT_i2d(nid, crit, ex)) == NULL)
        return 0;

    res = X509v3_add_ext(pexts, ext, 0) != NULL;
    X509_EXTENSION_free(ext);
    return res;
}

/* Add a CRL revocation reason code to extension stack, which may be NULL */
static int add_crl_reason_extension(X509_EXTENSIONS **pexts, int reason_code)
{
    ASN1_ENUMERATED *val = ASN1_ENUMERATED_new();
    int res = 0;

    if (val != NULL && ASN1_ENUMERATED_set(val, reason_code))
        res = add1_extension(pexts, NID_crl_reason, 0 /* non-critical */, val);
    ASN1_ENUMERATED_free(val);
    return res;
}

Otls_CMP_MSG *otls_cmp_msg_create(Otls_CMP_CTX *ctx, int bodytype)
{
    Otls_CMP_MSG *msg = NULL;

    if (!otls_assert(ctx != NULL))
        return NULL;

    if ((msg = Otls_CMP_MSG_new()) == NULL)
        return NULL;
    if (!otls_cmp_hdr_init(ctx, msg->header)
            || !otls_cmp_msg_set_bodytype(msg, bodytype))
        goto err;
    if (ctx->geninfo_ITAVs != NULL
            && !otls_cmp_hdr_generalInfo_push1_items(msg->header,
                                                     ctx->geninfo_ITAVs))
        goto err;

    switch (bodytype) {
    case Otls_CMP_PKIBODY_IR:
    case Otls_CMP_PKIBODY_CR:
    case Otls_CMP_PKIBODY_KUR:
        if ((msg->body->value.ir = Otls_CRMF_MSGS_new()) == NULL)
            goto err;
        return msg;

    case Otls_CMP_PKIBODY_P10CR:
        if (ctx->p10CSR == NULL) {
            CMPerr(0, CMP_R_ERROR_CREATING_P10CR);
            goto err;
        }
        if ((msg->body->value.p10cr = X509_REQ_dup(ctx->p10CSR)) == NULL)
            goto err;
        return msg;

    case Otls_CMP_PKIBODY_IP:
    case Otls_CMP_PKIBODY_CP:
    case Otls_CMP_PKIBODY_KUP:
        if ((msg->body->value.ip = Otls_CMP_CERTREPMESSAGE_new()) == NULL)
            goto err;
        return msg;

    case Otls_CMP_PKIBODY_RR:
        if ((msg->body->value.rr = sk_Otls_CMP_REVDETAILS_new_null()) == NULL)
            goto err;
        return msg;
    case Otls_CMP_PKIBODY_RP:
        if ((msg->body->value.rp = Otls_CMP_REVREPCONTENT_new()) == NULL)
            goto err;
        return msg;

    case Otls_CMP_PKIBODY_CERTCONF:
        if ((msg->body->value.certConf =
             sk_Otls_CMP_CERTSTATUS_new_null()) == NULL)
            goto err;
        return msg;
    case Otls_CMP_PKIBODY_PKICONF:
        if ((msg->body->value.pkiconf = ASN1_TYPE_new()) == NULL)
            goto err;
        ASN1_TYPE_set(msg->body->value.pkiconf, V_ASN1_NULL, NULL);
        return msg;

    case Otls_CMP_PKIBODY_POLLREQ:
        if ((msg->body->value.pollReq = sk_Otls_CMP_POLLREQ_new_null()) == NULL)
            goto err;
        return msg;
    case Otls_CMP_PKIBODY_POLLREP:
        if ((msg->body->value.pollRep = sk_Otls_CMP_POLLREP_new_null()) == NULL)
            goto err;
        return msg;

    case Otls_CMP_PKIBODY_GENM:
    case Otls_CMP_PKIBODY_GENP:
        if ((msg->body->value.genm = sk_Otls_CMP_ITAV_new_null()) == NULL)
            goto err;
        return msg;

    case Otls_CMP_PKIBODY_ERROR:
        if ((msg->body->value.error = Otls_CMP_ERRORMSGCONTENT_new()) == NULL)
            goto err;
        return msg;

    default:
        CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
        goto err;
    }

 err:
    Otls_CMP_MSG_free(msg);
    return NULL;
}

#define HAS_SAN(ctx) \
    (sk_GENERAL_NAME_num((ctx)->subjectAltNames) > 0 \
         || Otls_CMP_CTX_reqExtensions_have_SAN(ctx) == 1)

static X509_NAME *determine_subj(Otls_CMP_CTX *ctx, X509 *refcert,
                                 int bodytype)
{
    if (ctx->subjectName != NULL)
        return ctx->subjectName;

    if (refcert != NULL
            && (bodytype == Otls_CMP_PKIBODY_KUR || !HAS_SAN(ctx)))
        /*
         * For KUR, copy subjectName from reference certificate.
         * For IR or CR, do the same only if there is no subjectAltName.
         */
        return X509_get_subject_name(refcert);
    return NULL;
}

/*
 * Create CRMF certificate request message for IR/CR/KUR
 * returns a pointer to the Otls_CRMF_MSG on success, NULL on error
 */
static Otls_CRMF_MSG *crm_new(Otls_CMP_CTX *ctx, int bodytype,
                              int rid, EVP_PKEY *rkey)
{
    Otls_CRMF_MSG *crm = NULL;
    X509 *refcert = ctx->oldCert != NULL ? ctx->oldCert : ctx->clCert;
    /* refcert defaults to current client cert */
    STACK_OF(GENERAL_NAME) *default_sans = NULL;
    X509_NAME *subject = determine_subj(ctx, refcert, bodytype);
    int crit = ctx->setSubjectAltNameCritical || subject == NULL;
    /* RFC5280: subjectAltName MUST be critical if subject is null */
    X509_EXTENSIONS *exts = NULL;

    if (rkey == NULL
            || (bodytype == Otls_CMP_PKIBODY_KUR && refcert == NULL)) {
        CMPerr(0, CMP_R_INVALID_ARGS);
        return NULL;
    }
    if ((crm = Otls_CRMF_MSG_new()) == NULL)
        return NULL;
    if (!Otls_CRMF_MSG_set_certReqId(crm, rid)
            /*
             * fill certTemplate, corresponding to CertificationRequestInfo
             * of PKCS#10. The rkey param cannot be NULL so far -
             * it could be NULL if centralized key creation was supported
             */
            || !Otls_CRMF_CERTTEMPLATE_fill(Otls_CRMF_MSG_get0_tmpl(crm), rkey,
                                            subject, ctx->issuer,
                                            NULL/* serial */))
        goto err;
    if (ctx->days != 0) {
        time_t notBefore, notAfter;

        notBefore = time(NULL);
        notAfter = notBefore + 60 * 60 * 24 * ctx->days;
        if (!Otls_CRMF_MSG_set_validity(crm, notBefore, notAfter))
            goto err;
    }

    /* extensions */
    if (refcert != NULL && !ctx->SubjectAltName_nodefault)
        default_sans = X509V3_get_d2i(X509_get0_extensions(refcert),
                                      NID_subject_alt_name, NULL, NULL);
    /* exts are copied from ctx to allow reuse */
    if (ctx->reqExtensions != NULL) {
        exts = sk_X509_EXTENSION_deep_copy(ctx->reqExtensions,
                                           X509_EXTENSION_dup,
                                           X509_EXTENSION_free);
        if (exts == NULL)
            goto err;
    }
    if (sk_GENERAL_NAME_num(ctx->subjectAltNames) > 0
            && !add1_extension(&exts, NID_subject_alt_name,
                               crit, ctx->subjectAltNames))
        goto err;
    if (!HAS_SAN(ctx) && default_sans != NULL
            && !add1_extension(&exts, NID_subject_alt_name, crit, default_sans))
        goto err;
    if (ctx->policies != NULL
            && !add1_extension(&exts, NID_certificate_policies,
                               ctx->setPoliciesCritical, ctx->policies))
        goto err;
    if (!Otls_CRMF_MSG_set0_extensions(crm, exts))
        goto err;
    exts = NULL;
    /* end fill certTemplate, now set any controls */

    /* for KUR, set OldCertId according to D.6 */
    if (bodytype == Otls_CMP_PKIBODY_KUR) {
        Otls_CRMF_CERTID *cid =
            Otls_CRMF_CERTID_gen(X509_get_issuer_name(refcert),
                                 X509_get_serialNumber(refcert));
        int ret;

        if (cid == NULL)
            goto err;
        ret = Otls_CRMF_MSG_set1_regCtrl_oldCertID(crm, cid);
        Otls_CRMF_CERTID_free(cid);
        if (ret == 0)
            goto err;
    }

    goto end;

 err:
    Otls_CRMF_MSG_free(crm);
    crm = NULL;

 end:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    sk_GENERAL_NAME_pop_free(default_sans, GENERAL_NAME_free);
    return crm;
}

Otls_CMP_MSG *otls_cmp_certReq_new(Otls_CMP_CTX *ctx, int type, int err_code)
{
    EVP_PKEY *rkey;
    EVP_PKEY *privkey;
    Otls_CMP_MSG *msg;
    Otls_CRMF_MSG *crm = NULL;

    if (!otls_assert(ctx != NULL))
        return NULL;

    rkey = Otls_CMP_CTX_get0_newPkey(ctx, 0);
    if (rkey == NULL)
        return NULL;
    privkey = Otls_CMP_CTX_get0_newPkey(ctx, 1);

    if (type != Otls_CMP_PKIBODY_IR && type != Otls_CMP_PKIBODY_CR
            && type != Otls_CMP_PKIBODY_KUR && type != Otls_CMP_PKIBODY_P10CR) {
        CMPerr(0, CMP_R_INVALID_ARGS);
        return NULL;
    }

    if ((msg = otls_cmp_msg_create(ctx, type)) == NULL)
        goto err;

    /* header */
    if (ctx->implicitConfirm && !otls_cmp_hdr_set_implicitConfirm(msg->header))
        goto err;

    /* body */
    /* For P10CR the content has already been set in Otls_CMP_MSG_create */
    if (type != Otls_CMP_PKIBODY_P10CR) {
        if (ctx->popoMethod == Otls_CRMF_POPO_SIGNATURE && privkey == NULL) {
            CMPerr(0, CMP_R_MISSING_PRIVATE_KEY);
            goto err;
        }
        if ((crm = crm_new(ctx, type, Otls_CMP_CERTREQID, rkey)) == NULL
                || !Otls_CRMF_MSG_create_popo(crm, privkey, ctx->digest,
                                              ctx->popoMethod)
                /* value.ir is same for cr and kur */
                || !sk_Otls_CRMF_MSG_push(msg->body->value.ir, crm))
            goto err;
        crm = NULL;
        /* TODO: here optional 2nd certreqmsg could be pushed to the stack */
    }

    if (!otls_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, err_code);
    Otls_CRMF_MSG_free(crm);
    Otls_CMP_MSG_free(msg);
    return NULL;
}

Otls_CMP_MSG *otls_cmp_certRep_new(Otls_CMP_CTX *ctx, int bodytype,
                                   int certReqId, Otls_CMP_PKISI *si,
                                   X509 *cert, STACK_OF(X509) *chain,
                                   STACK_OF(X509) *caPubs, int encrypted,
                                   int unprotectedErrors)
{
    Otls_CMP_MSG *msg = NULL;
    Otls_CMP_CERTREPMESSAGE *repMsg = NULL;
    Otls_CMP_CERTRESPONSE *resp = NULL;
    int status = -1;

    if (!otls_assert(ctx != NULL && si != NULL))
        return NULL;

    if ((msg = otls_cmp_msg_create(ctx, bodytype)) == NULL)
        goto err;
    repMsg = msg->body->value.ip; /* value.ip is same for cp and kup */

    /* header */
    if (ctx->implicitConfirm && !otls_cmp_hdr_set_implicitConfirm(msg->header))
        goto err;

    /* body */
    if ((resp = Otls_CMP_CERTRESPONSE_new()) == NULL)
        goto err;
    Otls_CMP_PKISI_free(resp->status);
    if ((resp->status = Otls_CMP_PKISI_dup(si)) == NULL
            || !ASN1_INTEGER_set(resp->certReqId, certReqId))
        goto err;

    status = otls_cmp_pkisi_get_pkistatus(resp->status);
    if (status != Otls_CMP_PKISTATUS_rejection
            && status != Otls_CMP_PKISTATUS_waiting && cert != NULL) {
        if (encrypted) {
            CMPerr(0, CMP_R_INVALID_ARGS);
            goto err;
        }

        if ((resp->certifiedKeyPair = Otls_CMP_CERTIFIEDKEYPAIR_new())
            == NULL)
            goto err;
        resp->certifiedKeyPair->certOrEncCert->type =
            Otls_CMP_CERTORENCCERT_CERTIFICATE;
        if (!X509_up_ref(cert))
            goto err;
        resp->certifiedKeyPair->certOrEncCert->value.certificate = cert;
    }

    if (!sk_Otls_CMP_CERTRESPONSE_push(repMsg->response, resp))
        goto err;
    resp = NULL;
    /* TODO: here optional 2nd certrep could be pushed to the stack */

    if (bodytype == Otls_CMP_PKIBODY_IP && caPubs != NULL
            && (repMsg->caPubs = X509_chain_up_ref(caPubs)) == NULL)
        goto err;
    if (chain != NULL
            && !otls_cmp_sk_X509_add1_certs(msg->extraCerts, chain, 0, 1, 0))
        goto err;

    if (!unprotectedErrors
            || otls_cmp_pkisi_get_pkistatus(si) != Otls_CMP_PKISTATUS_rejection)
        if (!otls_cmp_msg_protect(ctx, msg))
            goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_CERTREP);
    Otls_CMP_CERTRESPONSE_free(resp);
    Otls_CMP_MSG_free(msg);
    return NULL;
}

Otls_CMP_MSG *otls_cmp_rr_new(Otls_CMP_CTX *ctx)
{
    Otls_CMP_MSG *msg = NULL;
    Otls_CMP_REVDETAILS *rd;

    if (!otls_assert(ctx != NULL && ctx->oldCert != NULL))
        return NULL;

    if ((rd = Otls_CMP_REVDETAILS_new()) == NULL)
        goto err;

    /* Fill the template from the contents of the certificate to be revoked */
    if (!Otls_CRMF_CERTTEMPLATE_fill(rd->certDetails,
                                     NULL/* pubkey would be redundant */,
                                     NULL/* subject would be redundant */,
                                     X509_get_issuer_name(ctx->oldCert),
                                     X509_get_serialNumber(ctx->oldCert)))
        goto err;

    /* revocation reason code is optional */
    if (ctx->revocationReason != CRL_REASON_NONE
            && !add_crl_reason_extension(&rd->crlEntryDetails,
                                         ctx->revocationReason))
        goto err;

    if ((msg = otls_cmp_msg_create(ctx, Otls_CMP_PKIBODY_RR)) == NULL)
        goto err;

    if (!sk_Otls_CMP_REVDETAILS_push(msg->body->value.rr, rd))
        goto err;
    rd = NULL;

    /*
     * TODO: the Revocation Passphrase according to section 5.3.19.9 could be
     *       set here if set in ctx
     */

    if (!otls_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_RR);
    Otls_CMP_MSG_free(msg);
    Otls_CMP_REVDETAILS_free(rd);
    return NULL;
}

Otls_CMP_MSG *otls_cmp_rp_new(Otls_CMP_CTX *ctx, Otls_CMP_PKISI *si,
                              Otls_CRMF_CERTID *cid, int unprot_err)
{
    Otls_CMP_REVREPCONTENT *rep = NULL;
    Otls_CMP_PKISI *si1 = NULL;
    Otls_CRMF_CERTID *cid_copy = NULL;
    Otls_CMP_MSG *msg = NULL;

    if (!otls_assert(ctx != NULL && si != NULL && cid != NULL))
        return NULL;

    if ((msg = otls_cmp_msg_create(ctx, Otls_CMP_PKIBODY_RP)) == NULL)
        goto err;
    rep = msg->body->value.rp;

    if ((si1 = Otls_CMP_PKISI_dup(si)) == NULL)
        goto err;

    if (!sk_Otls_CMP_PKISI_push(rep->status, si1)) {
        Otls_CMP_PKISI_free(si1);
        goto err;
    }

    if ((rep->revCerts = sk_Otls_CRMF_CERTID_new_null()) == NULL)
        goto err;
    if ((cid_copy = Otls_CRMF_CERTID_dup(cid)) == NULL)
        goto err;
    if (!sk_Otls_CRMF_CERTID_push(rep->revCerts, cid_copy)) {
        Otls_CRMF_CERTID_free(cid_copy);
        goto err;
    }

    if (!unprot_err
            || otls_cmp_pkisi_get_pkistatus(si) != Otls_CMP_PKISTATUS_rejection)
        if (!otls_cmp_msg_protect(ctx, msg))
            goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_RP);
    Otls_CMP_MSG_free(msg);
    return NULL;
}

Otls_CMP_MSG *otls_cmp_pkiconf_new(Otls_CMP_CTX *ctx)
{
    Otls_CMP_MSG *msg;

    if (!otls_assert(ctx != NULL))
        return NULL;

    if ((msg = otls_cmp_msg_create(ctx, Otls_CMP_PKIBODY_PKICONF)) == NULL)
        goto err;
    if (otls_cmp_msg_protect(ctx, msg))
        return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_PKICONF);
    Otls_CMP_MSG_free(msg);
    return NULL;
}

int otls_cmp_msg_gen_push0_ITAV(Otls_CMP_MSG *msg, Otls_CMP_ITAV *itav)
{
    int bodytype;

    if (!otls_assert(msg != NULL && itav != NULL))
        return 0;

    bodytype = otls_cmp_msg_get_bodytype(msg);
    if (bodytype != Otls_CMP_PKIBODY_GENM
            && bodytype != Otls_CMP_PKIBODY_GENP) {
        CMPerr(0, CMP_R_INVALID_ARGS);
        return 0;
    }

    /* value.genp has the same structure, so this works for genp as well */
    return Otls_CMP_ITAV_push0_stack_item(&msg->body->value.genm, itav);
}

int otls_cmp_msg_gen_push1_ITAVs(Otls_CMP_MSG *msg,
                                 STACK_OF(Otls_CMP_ITAV) *itavs)
{
    int i;
    Otls_CMP_ITAV *itav = NULL;

    if (!otls_assert(msg != NULL))
        return 0;

    for (i = 0; i < sk_Otls_CMP_ITAV_num(itavs); i++) {
        if ((itav = Otls_CMP_ITAV_dup(sk_Otls_CMP_ITAV_value(itavs,i))) == NULL)
            return 0;
        if (!otls_cmp_msg_gen_push0_ITAV(msg, itav)) {
            Otls_CMP_ITAV_free(itav);
            return 0;
        }
    }
    return 1;
}

/*
 * Creates a new General Message/Response with an empty itav stack
 * returns a pointer to the PKIMessage on success, NULL on error
 */
static Otls_CMP_MSG *gen_new(Otls_CMP_CTX *ctx, int body_type, int err_code)
{
    Otls_CMP_MSG *msg = NULL;

    if (!otls_assert(ctx != NULL))
        return NULL;

    if ((msg = otls_cmp_msg_create(ctx, body_type)) == NULL)
        return NULL;

    if (ctx->genm_ITAVs != NULL
            && !otls_cmp_msg_gen_push1_ITAVs(msg, ctx->genm_ITAVs))
        goto err;

    if (!otls_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, err_code);
    Otls_CMP_MSG_free(msg);
    return NULL;
}

Otls_CMP_MSG *otls_cmp_genm_new(Otls_CMP_CTX *ctx)
{
    return gen_new(ctx, Otls_CMP_PKIBODY_GENM, CMP_R_ERROR_CREATING_GENM);
}

Otls_CMP_MSG *otls_cmp_genp_new(Otls_CMP_CTX *ctx)
{
    return gen_new(ctx, Otls_CMP_PKIBODY_GENP, CMP_R_ERROR_CREATING_GENP);
}

Otls_CMP_MSG *otls_cmp_error_new(Otls_CMP_CTX *ctx, Otls_CMP_PKISI *si,
                                 int errorCode,
                                 Otls_CMP_PKIFREETEXT *errorDetails,
                                 int unprotected)
{
    Otls_CMP_MSG *msg = NULL;

    if (!otls_assert(ctx != NULL && si != NULL))
        return NULL;

    if ((msg = otls_cmp_msg_create(ctx, Otls_CMP_PKIBODY_ERROR)) == NULL)
        goto err;

    Otls_CMP_PKISI_free(msg->body->value.error->pKIStatusInfo);
    if ((msg->body->value.error->pKIStatusInfo = Otls_CMP_PKISI_dup(si))
        == NULL)
        goto err;
    if (errorCode >= 0) {
        if ((msg->body->value.error->errorCode = ASN1_INTEGER_new()) == NULL)
            goto err;
        if (!ASN1_INTEGER_set(msg->body->value.error->errorCode, errorCode))
            goto err;
    }
    if (errorDetails != NULL)
        if ((msg->body->value.error->errorDetails =
            sk_ASN1_UTF8STRING_deep_copy(errorDetails, ASN1_STRING_dup,
                                         ASN1_STRING_free)) == NULL)
            goto err;

    if (!unprotected && !otls_cmp_msg_protect(ctx, msg))
        goto err;
    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_ERROR);
    Otls_CMP_MSG_free(msg);
    return NULL;
}

/*
 * Otls_CMP_CERTSTATUS_set_certHash() calculates a hash of the certificate,
 * using the same hash algorithm as is used to create and verify the
 * certificate signature, and places the hash into the certHash field of a
 * Otls_CMP_CERTSTATUS structure. This is used in the certConf message,
 * for example, to confirm that the certificate was received successfully.
 */
int otls_cmp_certstatus_set_certHash(Otls_CMP_CERTSTATUS *certStatus,
                                     const X509 *cert)
{
    unsigned int len;
    unsigned char hash[EVP_MAX_MD_SIZE];
    int md_NID;
    const EVP_MD *md = NULL;

    if (!otls_assert(certStatus != NULL && cert != NULL))
        return 0;

    /*-
     * select hash algorithm, as stated in Appendix F. Compilable ASN.1 defs:
     * the hash of the certificate, using the same hash algorithm
     * as is used to create and verify the certificate signature
     */
    if (OBJ_find_sigid_algs(X509_get_signature_nid(cert), &md_NID, NULL)
            && (md = EVP_get_digestbynid(md_NID)) != NULL) {
        if (!X509_digest(cert, md, hash, &len))
            goto err;
        if (!otls_cmp_asn1_octet_string_set1_bytes(&certStatus->certHash, hash,
                                                   len))
            goto err;
    } else {
        CMPerr(0, CMP_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }

    return 1;
 err:
    CMPerr(0, CMP_R_ERROR_SETTING_CERTHASH);
    return 0;
}

/*
 * TODO: handle potential 2nd certificate when signing and encrypting
 * certificates have been requested/received
 */
Otls_CMP_MSG *otls_cmp_certConf_new(Otls_CMP_CTX *ctx, int fail_info,
                                    const char *text)
{
    Otls_CMP_MSG *msg = NULL;
    Otls_CMP_CERTSTATUS *certStatus = NULL;
    Otls_CMP_PKISI *sinfo;

    if (!otls_assert(ctx != NULL && ctx->newCert != NULL))
        return NULL;

    if ((unsigned)fail_info > Otls_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN) {
        CMPerr(0, CMP_R_FAIL_INFO_OUT_OF_RANGE);
        return NULL;
    }

    if ((msg = otls_cmp_msg_create(ctx, Otls_CMP_PKIBODY_CERTCONF)) == NULL)
        goto err;

    if ((certStatus = Otls_CMP_CERTSTATUS_new()) == NULL)
        goto err;
    /* consume certStatus into msg right away so it gets deallocated with msg */
    if (!sk_Otls_CMP_CERTSTATUS_push(msg->body->value.certConf, certStatus))
        goto err;
    /* set the ID of the certReq */
    if (!ASN1_INTEGER_set(certStatus->certReqId, Otls_CMP_CERTREQID))
        goto err;
    /*
     * the hash of the certificate, using the same hash algorithm
     * as is used to create and verify the certificate signature
     */
    if (!otls_cmp_certstatus_set_certHash(certStatus, ctx->newCert))
        goto err;
    /*
     * For any particular CertStatus, omission of the statusInfo field
     * indicates ACCEPTANCE of the specified certificate.  Alternatively,
     * explicit status details (with respect to acceptance or rejection) MAY
     * be provided in the statusInfo field, perhaps for auditing purposes at
     * the CA/RA.
     */
    sinfo = fail_info != 0 ?
        otls_cmp_statusinfo_new(Otls_CMP_PKISTATUS_rejection, fail_info, text) :
        otls_cmp_statusinfo_new(Otls_CMP_PKISTATUS_accepted, 0, text);
    if (sinfo == NULL)
        goto err;
    certStatus->statusInfo = sinfo;

    if (!otls_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_CERTCONF);
    Otls_CMP_MSG_free(msg);
    return NULL;
}

Otls_CMP_MSG *otls_cmp_pollReq_new(Otls_CMP_CTX *ctx, int crid)
{
    Otls_CMP_MSG *msg = NULL;
    Otls_CMP_POLLREQ *preq = NULL;

    if (!otls_assert(ctx != NULL))
        return NULL;

    if ((msg = otls_cmp_msg_create(ctx, Otls_CMP_PKIBODY_POLLREQ)) == NULL)
        goto err;

    /* TODO: support multiple cert request IDs to poll */
    if ((preq = Otls_CMP_POLLREQ_new()) == NULL
            || !ASN1_INTEGER_set(preq->certReqId, crid)
            || !sk_Otls_CMP_POLLREQ_push(msg->body->value.pollReq, preq))
        goto err;

    preq = NULL;
    if (!otls_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_POLLREQ);
    Otls_CMP_POLLREQ_free(preq);
    Otls_CMP_MSG_free(msg);
    return NULL;
}

Otls_CMP_MSG *otls_cmp_pollRep_new(Otls_CMP_CTX *ctx, int crid,
                                   int64_t poll_after)
{
    Otls_CMP_MSG *msg;
    Otls_CMP_POLLREP *prep;

    if (!otls_assert(ctx != NULL))
        return NULL;

    if ((msg = otls_cmp_msg_create(ctx, Otls_CMP_PKIBODY_POLLREP)) == NULL)
        goto err;
    if ((prep = Otls_CMP_POLLREP_new()) == NULL)
        goto err;
    if (!sk_Otls_CMP_POLLREP_push(msg->body->value.pollRep, prep))
        goto err;
    if (!ASN1_INTEGER_set(prep->certReqId, crid))
        goto err;
    if (!ASN1_INTEGER_set_int64(prep->checkAfter, poll_after))
        goto err;

    if (!otls_cmp_msg_protect(ctx, msg))
        goto err;
    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_POLLREP);
    Otls_CMP_MSG_free(msg);
    return NULL;
}

/*-
 * returns the status field of the RevRepContent with the given
 * request/sequence id inside a revocation response.
 * RevRepContent has the revocation statuses in same order as they were sent in
 * RevReqContent.
 * returns NULL on error
 */
Otls_CMP_PKISI *
otls_cmp_revrepcontent_get_pkistatusinfo(Otls_CMP_REVREPCONTENT *rrep, int rsid)
{
    Otls_CMP_PKISI *status;

    if (!otls_assert(rrep != NULL))
        return NULL;

    if ((status = sk_Otls_CMP_PKISI_value(rrep->status, rsid)) != NULL)
        return status;

    CMPerr(0, CMP_R_PKISTATUSINFO_NOT_FOUND);
    return NULL;
}

/*
 * returns the CertId field in the revCerts part of the RevRepContent
 * with the given request/sequence id inside a revocation response.
 * RevRepContent has the CertIds in same order as they were sent in
 * RevReqContent.
 * returns NULL on error
 */
Otls_CRMF_CERTID *
otls_cmp_revrepcontent_get_CertId(Otls_CMP_REVREPCONTENT *rrep, int rsid)
{
    Otls_CRMF_CERTID *cid = NULL;

    if (!otls_assert(rrep != NULL))
        return NULL;

    if ((cid = sk_Otls_CRMF_CERTID_value(rrep->revCerts, rsid)) != NULL)
        return cid;

    CMPerr(0, CMP_R_CERTID_NOT_FOUND);
    return NULL;
}

static int suitable_rid(const ASN1_INTEGER *certReqId, int rid)
{
    int trid;

    if (rid == -1)
        return 1;

    trid = otls_cmp_asn1_get_int(certReqId);

    if (trid == -1) {
        CMPerr(0, CMP_R_BAD_REQUEST_ID);
        return 0;
    }
    return rid == trid;
}

static void add_expected_rid(int rid)
{
    char str[DECIMAL_SIZE(rid) + 1];

    BIO_snprintf(str, sizeof(str), "%d", rid);
    ERR_add_error_data(2, "expected certReqId = ", str);
}

/*
 * returns a pointer to the PollResponse with the given CertReqId
 * (or the first one in case -1) inside a PollRepContent
 * returns NULL on error or if no suitable PollResponse available
 */
Otls_CMP_POLLREP *
otls_cmp_pollrepcontent_get0_pollrep(const Otls_CMP_POLLREPCONTENT *prc,
                                     int rid)
{
    Otls_CMP_POLLREP *pollRep = NULL;
    int i;

    if (!otls_assert(prc != NULL))
        return NULL;

    for (i = 0; i < sk_Otls_CMP_POLLREP_num(prc); i++) {
        pollRep = sk_Otls_CMP_POLLREP_value(prc, i);
        if (suitable_rid(pollRep->certReqId, rid))
            return pollRep;
    }

    CMPerr(0, CMP_R_CERTRESPONSE_NOT_FOUND);
    add_expected_rid(rid);
    return NULL;
}

/*
 * returns a pointer to the CertResponse with the given CertReqId
 * (or the first one in case -1) inside a CertRepMessage
 * returns NULL on error or if no suitable CertResponse available
 */
Otls_CMP_CERTRESPONSE *
otls_cmp_certrepmessage_get0_certresponse(const Otls_CMP_CERTREPMESSAGE *crm,
                                          int rid)
{
    Otls_CMP_CERTRESPONSE *crep = NULL;
    int i;

    if (!otls_assert(crm != NULL && crm->response != NULL))
        return NULL;

    for (i = 0; i < sk_Otls_CMP_CERTRESPONSE_num(crm->response); i++) {
        crep = sk_Otls_CMP_CERTRESPONSE_value(crm->response, i);
        if (suitable_rid(crep->certReqId, rid))
            return crep;
    }

    CMPerr(0, CMP_R_CERTRESPONSE_NOT_FOUND);
    add_expected_rid(rid);
    return NULL;
}

/*
 * CMP_CERTRESPONSE_get1_certificate() attempts to retrieve the returned
 * certificate from the given certResponse B<crep>.
 * Uses the privkey in case of indirect POP from B<ctx>.
 * Returns a pointer to a copy of the found certificate, or NULL if not found.
 */
X509 *otls_cmp_certresponse_get1_certificate(EVP_PKEY *privkey,
                                             const Otls_CMP_CERTRESPONSE *crep)
{
    Otls_CMP_CERTORENCCERT *coec;
    X509 *crt = NULL;

    if (!otls_assert(crep != NULL))
        return NULL;

    if (crep->certifiedKeyPair
            && (coec = crep->certifiedKeyPair->certOrEncCert) != NULL) {
        switch (coec->type) {
        case Otls_CMP_CERTORENCCERT_CERTIFICATE:
            crt = X509_dup(coec->value.certificate);
            break;
        case Otls_CMP_CERTORENCCERT_ENCRYPTEDCERT:
            /* cert encrypted for indirect PoP; RFC 4210, 5.2.8.2 */
            if (privkey == NULL) {
                CMPerr(0, CMP_R_MISSING_PRIVATE_KEY);
                return NULL;
            }
            crt =
                Otls_CRMF_ENCRYPTEDVALUE_get1_encCert(coec->value.encryptedCert,
                                                      privkey);
            break;
        default:
            CMPerr(0, CMP_R_UNKNOWN_CERT_TYPE);
            return NULL;
        }
    }
    if (crt == NULL)
        CMPerr(0, CMP_R_CERTIFICATE_NOT_FOUND);
    return crt;
}

Otls_CMP_MSG *otls_cmp_msg_load(const char *file)
{
    Otls_CMP_MSG *msg = NULL;
    BIO *bio = NULL;

    if (!otls_assert(file != NULL))
        return NULL;

    if ((bio = BIO_new_file(file, "rb")) == NULL)
        return NULL;
    msg = Otls_d2i_CMP_MSG_bio(bio, NULL);
    BIO_free(bio);
    return msg;
}
