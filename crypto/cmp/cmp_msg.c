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

/* CMP functions for PKIMessage construction */

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/err.h>
#include <openssl/x509.h>

OSSL_CMP_PKIHEADER *OSSL_CMP_MSG_get0_header(const OSSL_CMP_MSG *msg)
{
    if (msg == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return msg->header;
}

const char *ossl_cmp_bodytype_to_string(int type)
{
    static const char *type_names[] = {
        "IR", "IP", "CR", "CP", "P10CR",
        "POPDECC", "POPDECR", "KUR", "KUP",
        "KRR", "KRP", "RR", "RP", "CCR", "CCP",
        "CKUANN", "CANN", "RANN", "CRLANN", "PKICONF", "NESTED",
        "GENM", "GENP", "ERROR", "CERTCONF", "POLLREQ", "POLLREP",
    };

    if (type < 0 || type > OSSL_CMP_PKIBODY_TYPE_MAX)
        return "illegal body type";
    return type_names[type];
}

int ossl_cmp_msg_set_bodytype(OSSL_CMP_MSG *msg, int type)
{
    if (!ossl_assert(msg != NULL && msg->body != NULL))
        return 0;

    msg->body->type = type;
    return 1;
}

int ossl_cmp_msg_get_bodytype(const OSSL_CMP_MSG *msg)
{
    if (!ossl_assert(msg != NULL && msg->body != NULL))
        return -1;

    return msg->body->type;
}

/* Add an extension to the referenced extension stack, which may be NULL */
static int add1_extension(X509_EXTENSIONS **pexts, int nid, int crit, void *ex)
{
    X509_EXTENSION *ext;
    int res;

    if (!ossl_assert(pexts != NULL)) /* pointer to var must not be NULL */
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

OSSL_CMP_MSG *ossl_cmp_msg_create(OSSL_CMP_CTX *ctx, int bodytype)
{
    OSSL_CMP_MSG *msg = NULL;

    if (!ossl_assert(ctx != NULL))
        return NULL;

    if ((msg = OSSL_CMP_MSG_new()) == NULL)
        return NULL;
    if (!ossl_cmp_hdr_init(ctx, msg->header)
            || !ossl_cmp_msg_set_bodytype(msg, bodytype))
        goto err;
    if (ctx->geninfo_ITAVs != NULL
            && !ossl_cmp_hdr_generalInfo_push1_items(msg->header,
                                                     ctx->geninfo_ITAVs))
        goto err;

    switch (bodytype) {
    case OSSL_CMP_PKIBODY_IR:
    case OSSL_CMP_PKIBODY_CR:
    case OSSL_CMP_PKIBODY_KUR:
        if ((msg->body->value.ir = OSSL_CRMF_MSGS_new()) == NULL)
            goto err;
        return msg;

    case OSSL_CMP_PKIBODY_P10CR:
        if (ctx->p10CSR == NULL) {
            CMPerr(0, CMP_R_ERROR_CREATING_P10CR);
            goto err;
        }
        if ((msg->body->value.p10cr = X509_REQ_dup(ctx->p10CSR)) == NULL)
            goto err;
        return msg;

    case OSSL_CMP_PKIBODY_IP:
    case OSSL_CMP_PKIBODY_CP:
    case OSSL_CMP_PKIBODY_KUP:
        if ((msg->body->value.ip = OSSL_CMP_CERTREPMESSAGE_new()) == NULL)
            goto err;
        return msg;

    case OSSL_CMP_PKIBODY_RR:
        if ((msg->body->value.rr = sk_OSSL_CMP_REVDETAILS_new_null()) == NULL)
            goto err;
        return msg;
    case OSSL_CMP_PKIBODY_RP:
        if ((msg->body->value.rp = OSSL_CMP_REVREPCONTENT_new()) == NULL)
            goto err;
        return msg;

    case OSSL_CMP_PKIBODY_CERTCONF:
        if ((msg->body->value.certConf =
             sk_OSSL_CMP_CERTSTATUS_new_null()) == NULL)
            goto err;
        return msg;
    case OSSL_CMP_PKIBODY_PKICONF:
        if ((msg->body->value.pkiconf = ASN1_TYPE_new()) == NULL)
            goto err;
        ASN1_TYPE_set(msg->body->value.pkiconf, V_ASN1_NULL, NULL);
        return msg;

    case OSSL_CMP_PKIBODY_POLLREQ:
        if ((msg->body->value.pollReq = sk_OSSL_CMP_POLLREQ_new_null()) == NULL)
            goto err;
        return msg;
    case OSSL_CMP_PKIBODY_POLLREP:
        if ((msg->body->value.pollRep = sk_OSSL_CMP_POLLREP_new_null()) == NULL)
            goto err;
        return msg;

    case OSSL_CMP_PKIBODY_GENM:
    case OSSL_CMP_PKIBODY_GENP:
        if ((msg->body->value.genm = sk_OSSL_CMP_ITAV_new_null()) == NULL)
            goto err;
        return msg;

    case OSSL_CMP_PKIBODY_ERROR:
        if ((msg->body->value.error = OSSL_CMP_ERRORMSGCONTENT_new()) == NULL)
            goto err;
        return msg;

    default:
        CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
        goto err;
    }

 err:
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

#define HAS_SAN(ctx) \
    (sk_GENERAL_NAME_num((ctx)->subjectAltNames) > 0 \
         || OSSL_CMP_CTX_reqExtensions_have_SAN(ctx) == 1)

static X509_NAME *determine_subj(OSSL_CMP_CTX *ctx, X509 *refcert,
                                 int bodytype)
{
    if (ctx->subjectName != NULL)
        return ctx->subjectName;

    if (refcert != NULL
            && (bodytype == OSSL_CMP_PKIBODY_KUR || !HAS_SAN(ctx)))
        /*
         * For KUR, copy subjectName from reference certificate.
         * For IR or CR, do the same only if there is no subjectAltName.
         */
        return X509_get_subject_name(refcert);
    return NULL;
}

/*
 * Create CRMF certificate request message for IR/CR/KUR
 * returns a pointer to the OSSL_CRMF_MSG on success, NULL on error
 */
static OSSL_CRMF_MSG *crm_new(OSSL_CMP_CTX *ctx, int bodytype,
                              int rid, EVP_PKEY *rkey)
{
    OSSL_CRMF_MSG *crm = NULL;
    X509 *refcert = ctx->oldCert != NULL ? ctx->oldCert : ctx->clCert;
    /* refcert defaults to current client cert */
    STACK_OF(GENERAL_NAME) *default_sans = NULL;
    X509_NAME *subject = determine_subj(ctx, refcert, bodytype);
    int crit = ctx->setSubjectAltNameCritical || subject == NULL;
    /* RFC5280: subjectAltName MUST be critical if subject is null */
    X509_EXTENSIONS *exts = NULL;

    if (rkey == NULL
            || (bodytype == OSSL_CMP_PKIBODY_KUR && refcert == NULL)) {
        CMPerr(0, CMP_R_INVALID_ARGS);
        return NULL;
    }
    if ((crm = OSSL_CRMF_MSG_new()) == NULL)
        return NULL;
    if (!OSSL_CRMF_MSG_set_certReqId(crm, rid)
            /*
             * fill certTemplate, corresponding to CertificationRequestInfo
             * of PKCS#10. The rkey param cannot be NULL so far -
             * it could be NULL if centralized key creation was supported
             */
            || !OSSL_CRMF_CERTTEMPLATE_fill(OSSL_CRMF_MSG_get0_tmpl(crm), rkey,
                                            subject, ctx->issuer,
                                            NULL/* serial */))
        goto err;
    if (ctx->days != 0) {
        time_t notBefore, notAfter;

        notBefore = time(NULL);
        notAfter = notBefore + 60 * 60 * 24 * ctx->days;
        if (!OSSL_CRMF_MSG_set_validity(crm, notBefore, notAfter))
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
    if (!OSSL_CRMF_MSG_set0_extensions(crm, exts))
        goto err;
    exts = NULL;
    /* end fill certTemplate, now set any controls */

    /* for KUR, set OldCertId according to D.6 */
    if (bodytype == OSSL_CMP_PKIBODY_KUR) {
        OSSL_CRMF_CERTID *cid =
            OSSL_CRMF_CERTID_gen(X509_get_issuer_name(refcert),
                                 X509_get_serialNumber(refcert));
        int ret;

        if (cid == NULL)
            goto err;
        ret = OSSL_CRMF_MSG_set1_regCtrl_oldCertID(crm, cid);
        OSSL_CRMF_CERTID_free(cid);
        if (ret == 0)
            goto err;
    }

    goto end;

 err:
    OSSL_CRMF_MSG_free(crm);
    crm = NULL;

 end:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    sk_GENERAL_NAME_pop_free(default_sans, GENERAL_NAME_free);
    return crm;
}

OSSL_CMP_MSG *ossl_cmp_certReq_new(OSSL_CMP_CTX *ctx, int type, int err_code)
{
    EVP_PKEY *rkey;
    EVP_PKEY *privkey;
    OSSL_CMP_MSG *msg;
    OSSL_CRMF_MSG *crm = NULL;

    if (!ossl_assert(ctx != NULL))
        return NULL;

    rkey = OSSL_CMP_CTX_get0_newPkey(ctx, 0);
    if (rkey == NULL)
        return NULL;
    privkey = OSSL_CMP_CTX_get0_newPkey(ctx, 1);

    if (type != OSSL_CMP_PKIBODY_IR && type != OSSL_CMP_PKIBODY_CR
            && type != OSSL_CMP_PKIBODY_KUR && type != OSSL_CMP_PKIBODY_P10CR) {
        CMPerr(0, CMP_R_INVALID_ARGS);
        return NULL;
    }

    if ((msg = ossl_cmp_msg_create(ctx, type)) == NULL)
        goto err;

    /* header */
    if (ctx->implicitConfirm && !ossl_cmp_hdr_set_implicitConfirm(msg->header))
        goto err;

    /* body */
    /* For P10CR the content has already been set in OSSL_CMP_MSG_create */
    if (type != OSSL_CMP_PKIBODY_P10CR) {
        if (ctx->popoMethod == OSSL_CRMF_POPO_SIGNATURE && privkey == NULL) {
            CMPerr(0, CMP_R_MISSING_PRIVATE_KEY);
            goto err;
        }
        if ((crm = crm_new(ctx, type, OSSL_CMP_CERTREQID, rkey)) == NULL
                || !OSSL_CRMF_MSG_create_popo(crm, privkey, ctx->digest,
                                              ctx->popoMethod)
                /* value.ir is same for cr and kur */
                || !sk_OSSL_CRMF_MSG_push(msg->body->value.ir, crm))
            goto err;
        crm = NULL;
        /* TODO: here optional 2nd certreqmsg could be pushed to the stack */
    }

    if (!ossl_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, err_code);
    OSSL_CRMF_MSG_free(crm);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

OSSL_CMP_MSG *ossl_cmp_certRep_new(OSSL_CMP_CTX *ctx, int bodytype,
                                   int certReqId, OSSL_CMP_PKISI *si,
                                   X509 *cert, STACK_OF(X509) *chain,
                                   STACK_OF(X509) *caPubs, int encrypted,
                                   int unprotectedErrors)
{
    OSSL_CMP_MSG *msg = NULL;
    OSSL_CMP_CERTREPMESSAGE *repMsg = NULL;
    OSSL_CMP_CERTRESPONSE *resp = NULL;
    int status = -1;

    if (!ossl_assert(ctx != NULL && si != NULL))
        return NULL;

    if ((msg = ossl_cmp_msg_create(ctx, bodytype)) == NULL)
        goto err;
    repMsg = msg->body->value.ip; /* value.ip is same for cp and kup */

    /* header */
    if (ctx->implicitConfirm && !ossl_cmp_hdr_set_implicitConfirm(msg->header))
        goto err;

    /* body */
    if ((resp = OSSL_CMP_CERTRESPONSE_new()) == NULL)
        goto err;
    OSSL_CMP_PKISI_free(resp->status);
    if ((resp->status = OSSL_CMP_PKISI_dup(si)) == NULL
            || !ASN1_INTEGER_set(resp->certReqId, certReqId))
        goto err;

    status = ossl_cmp_pkisi_get_pkistatus(resp->status);
    if (status != OSSL_CMP_PKISTATUS_rejection
            && status != OSSL_CMP_PKISTATUS_waiting && cert != NULL) {
        if (encrypted) {
            CMPerr(0, CMP_R_INVALID_ARGS);
            goto err;
        }

        if ((resp->certifiedKeyPair = OSSL_CMP_CERTIFIEDKEYPAIR_new())
            == NULL)
            goto err;
        resp->certifiedKeyPair->certOrEncCert->type =
            OSSL_CMP_CERTORENCCERT_CERTIFICATE;
        if (!X509_up_ref(cert))
            goto err;
        resp->certifiedKeyPair->certOrEncCert->value.certificate = cert;
    }

    if (!sk_OSSL_CMP_CERTRESPONSE_push(repMsg->response, resp))
        goto err;
    resp = NULL;
    /* TODO: here optional 2nd certrep could be pushed to the stack */

    if (bodytype == OSSL_CMP_PKIBODY_IP && caPubs != NULL
            && (repMsg->caPubs = X509_chain_up_ref(caPubs)) == NULL)
        goto err;
    if (chain != NULL
            && !ossl_cmp_sk_X509_add1_certs(msg->extraCerts, chain, 0, 1, 0))
        goto err;

    if (!unprotectedErrors
            || ossl_cmp_pkisi_get_pkistatus(si) != OSSL_CMP_PKISTATUS_rejection)
        if (!ossl_cmp_msg_protect(ctx, msg))
            goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_CERTREP);
    OSSL_CMP_CERTRESPONSE_free(resp);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

OSSL_CMP_MSG *ossl_cmp_rr_new(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_MSG *msg = NULL;
    OSSL_CMP_REVDETAILS *rd;

    if (!ossl_assert(ctx != NULL && ctx->oldCert != NULL))
        return NULL;

    if ((rd = OSSL_CMP_REVDETAILS_new()) == NULL)
        goto err;

    /* Fill the template from the contents of the certificate to be revoked */
    if (!OSSL_CRMF_CERTTEMPLATE_fill(rd->certDetails,
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

    if ((msg = ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_RR)) == NULL)
        goto err;

    if (!sk_OSSL_CMP_REVDETAILS_push(msg->body->value.rr, rd))
        goto err;
    rd = NULL;

    /*
     * TODO: the Revocation Passphrase according to section 5.3.19.9 could be
     *       set here if set in ctx
     */

    if (!ossl_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_RR);
    OSSL_CMP_MSG_free(msg);
    OSSL_CMP_REVDETAILS_free(rd);
    return NULL;
}

OSSL_CMP_MSG *ossl_cmp_rp_new(OSSL_CMP_CTX *ctx, OSSL_CMP_PKISI *si,
                              OSSL_CRMF_CERTID *cid, int unprot_err)
{
    OSSL_CMP_REVREPCONTENT *rep = NULL;
    OSSL_CMP_PKISI *si1 = NULL;
    OSSL_CRMF_CERTID *cid_copy = NULL;
    OSSL_CMP_MSG *msg = NULL;

    if (!ossl_assert(ctx != NULL && si != NULL && cid != NULL))
        return NULL;

    if ((msg = ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_RP)) == NULL)
        goto err;
    rep = msg->body->value.rp;

    if ((si1 = OSSL_CMP_PKISI_dup(si)) == NULL)
        goto err;

    if (!sk_OSSL_CMP_PKISI_push(rep->status, si1)) {
        OSSL_CMP_PKISI_free(si1);
        goto err;
    }

    if ((rep->revCerts = sk_OSSL_CRMF_CERTID_new_null()) == NULL)
        goto err;
    if ((cid_copy = OSSL_CRMF_CERTID_dup(cid)) == NULL)
        goto err;
    if (!sk_OSSL_CRMF_CERTID_push(rep->revCerts, cid_copy)) {
        OSSL_CRMF_CERTID_free(cid_copy);
        goto err;
    }

    if (!unprot_err
            || ossl_cmp_pkisi_get_pkistatus(si) != OSSL_CMP_PKISTATUS_rejection)
        if (!ossl_cmp_msg_protect(ctx, msg))
            goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_RP);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

OSSL_CMP_MSG *ossl_cmp_pkiconf_new(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_MSG *msg;

    if (!ossl_assert(ctx != NULL))
        return NULL;

    if ((msg = ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_PKICONF)) == NULL)
        goto err;
    if (ossl_cmp_msg_protect(ctx, msg))
        return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_PKICONF);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

int ossl_cmp_msg_gen_push0_ITAV(OSSL_CMP_MSG *msg, OSSL_CMP_ITAV *itav)
{
    int bodytype;

    if (!ossl_assert(msg != NULL && itav != NULL))
        return 0;

    bodytype = ossl_cmp_msg_get_bodytype(msg);
    if (bodytype != OSSL_CMP_PKIBODY_GENM
            && bodytype != OSSL_CMP_PKIBODY_GENP) {
        CMPerr(0, CMP_R_INVALID_ARGS);
        return 0;
    }

    /* value.genp has the same structure, so this works for genp as well */
    return OSSL_CMP_ITAV_push0_stack_item(&msg->body->value.genm, itav);
}

int ossl_cmp_msg_gen_push1_ITAVs(OSSL_CMP_MSG *msg,
                                 STACK_OF(OSSL_CMP_ITAV) *itavs)
{
    int i;
    OSSL_CMP_ITAV *itav = NULL;

    if (!ossl_assert(msg != NULL))
        return 0;

    for (i = 0; i < sk_OSSL_CMP_ITAV_num(itavs); i++) {
        if ((itav = OSSL_CMP_ITAV_dup(sk_OSSL_CMP_ITAV_value(itavs,i))) == NULL)
            return 0;
        if (!ossl_cmp_msg_gen_push0_ITAV(msg, itav)) {
            OSSL_CMP_ITAV_free(itav);
            return 0;
        }
    }
    return 1;
}

/*
 * Creates a new General Message/Response with an empty itav stack
 * returns a pointer to the PKIMessage on success, NULL on error
 */
static OSSL_CMP_MSG *gen_new(OSSL_CMP_CTX *ctx, int body_type, int err_code)
{
    OSSL_CMP_MSG *msg = NULL;

    if (!ossl_assert(ctx != NULL))
        return NULL;

    if ((msg = ossl_cmp_msg_create(ctx, body_type)) == NULL)
        return NULL;

    if (ctx->genm_ITAVs != NULL
            && !ossl_cmp_msg_gen_push1_ITAVs(msg, ctx->genm_ITAVs))
        goto err;

    if (!ossl_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, err_code);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

OSSL_CMP_MSG *ossl_cmp_genm_new(OSSL_CMP_CTX *ctx)
{
    return gen_new(ctx, OSSL_CMP_PKIBODY_GENM, CMP_R_ERROR_CREATING_GENM);
}

OSSL_CMP_MSG *ossl_cmp_genp_new(OSSL_CMP_CTX *ctx)
{
    return gen_new(ctx, OSSL_CMP_PKIBODY_GENP, CMP_R_ERROR_CREATING_GENP);
}

OSSL_CMP_MSG *ossl_cmp_error_new(OSSL_CMP_CTX *ctx, OSSL_CMP_PKISI *si,
                                 int errorCode,
                                 OSSL_CMP_PKIFREETEXT *errorDetails,
                                 int unprotected)
{
    OSSL_CMP_MSG *msg = NULL;

    if (!ossl_assert(ctx != NULL && si != NULL))
        return NULL;

    if ((msg = ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_ERROR)) == NULL)
        goto err;

    OSSL_CMP_PKISI_free(msg->body->value.error->pKIStatusInfo);
    if ((msg->body->value.error->pKIStatusInfo = OSSL_CMP_PKISI_dup(si))
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

    if (!unprotected && !ossl_cmp_msg_protect(ctx, msg))
        goto err;
    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_ERROR);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

/*
 * OSSL_CMP_CERTSTATUS_set_certHash() calculates a hash of the certificate,
 * using the same hash algorithm as is used to create and verify the
 * certificate signature, and places the hash into the certHash field of a
 * OSSL_CMP_CERTSTATUS structure. This is used in the certConf message,
 * for example, to confirm that the certificate was received successfully.
 */
int ossl_cmp_certstatus_set_certHash(OSSL_CMP_CERTSTATUS *certStatus,
                                     const X509 *cert)
{
    unsigned int len;
    unsigned char hash[EVP_MAX_MD_SIZE];
    int md_NID;
    const EVP_MD *md = NULL;

    if (!ossl_assert(certStatus != NULL && cert != NULL))
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
        if (!ossl_cmp_asn1_octet_string_set1_bytes(&certStatus->certHash, hash,
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
OSSL_CMP_MSG *ossl_cmp_certConf_new(OSSL_CMP_CTX *ctx, int fail_info,
                                    const char *text)
{
    OSSL_CMP_MSG *msg = NULL;
    OSSL_CMP_CERTSTATUS *certStatus = NULL;
    OSSL_CMP_PKISI *sinfo;

    if (!ossl_assert(ctx != NULL && ctx->newCert != NULL))
        return NULL;

    if ((unsigned)fail_info > OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN) {
        CMPerr(0, CMP_R_FAIL_INFO_OUT_OF_RANGE);
        return NULL;
    }

    if ((msg = ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_CERTCONF)) == NULL)
        goto err;

    if ((certStatus = OSSL_CMP_CERTSTATUS_new()) == NULL)
        goto err;
    /* consume certStatus into msg right away so it gets deallocated with msg */
    if (!sk_OSSL_CMP_CERTSTATUS_push(msg->body->value.certConf, certStatus))
        goto err;
    /* set the ID of the certReq */
    if (!ASN1_INTEGER_set(certStatus->certReqId, OSSL_CMP_CERTREQID))
        goto err;
    /*
     * the hash of the certificate, using the same hash algorithm
     * as is used to create and verify the certificate signature
     */
    if (!ossl_cmp_certstatus_set_certHash(certStatus, ctx->newCert))
        goto err;
    /*
     * For any particular CertStatus, omission of the statusInfo field
     * indicates ACCEPTANCE of the specified certificate.  Alternatively,
     * explicit status details (with respect to acceptance or rejection) MAY
     * be provided in the statusInfo field, perhaps for auditing purposes at
     * the CA/RA.
     */
    sinfo = fail_info != 0 ?
        ossl_cmp_statusinfo_new(OSSL_CMP_PKISTATUS_rejection, fail_info, text) :
        ossl_cmp_statusinfo_new(OSSL_CMP_PKISTATUS_accepted, 0, text);
    if (sinfo == NULL)
        goto err;
    certStatus->statusInfo = sinfo;

    if (!ossl_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_CERTCONF);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

OSSL_CMP_MSG *ossl_cmp_pollReq_new(OSSL_CMP_CTX *ctx, int crid)
{
    OSSL_CMP_MSG *msg = NULL;
    OSSL_CMP_POLLREQ *preq = NULL;

    if (!ossl_assert(ctx != NULL))
        return NULL;

    if ((msg = ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_POLLREQ)) == NULL)
        goto err;

    /* TODO: support multiple cert request IDs to poll */
    if ((preq = OSSL_CMP_POLLREQ_new()) == NULL
            || !ASN1_INTEGER_set(preq->certReqId, crid)
            || !sk_OSSL_CMP_POLLREQ_push(msg->body->value.pollReq, preq))
        goto err;

    preq = NULL;
    if (!ossl_cmp_msg_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_POLLREQ);
    OSSL_CMP_POLLREQ_free(preq);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

OSSL_CMP_MSG *ossl_cmp_pollRep_new(OSSL_CMP_CTX *ctx, int crid,
                                   int64_t poll_after)
{
    OSSL_CMP_MSG *msg;
    OSSL_CMP_POLLREP *prep;

    if (!ossl_assert(ctx != NULL))
        return NULL;

    if ((msg = ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_POLLREP)) == NULL)
        goto err;
    if ((prep = OSSL_CMP_POLLREP_new()) == NULL)
        goto err;
    if (!sk_OSSL_CMP_POLLREP_push(msg->body->value.pollRep, prep))
        goto err;
    if (!ASN1_INTEGER_set(prep->certReqId, crid))
        goto err;
    if (!ASN1_INTEGER_set_int64(prep->checkAfter, poll_after))
        goto err;

    if (!ossl_cmp_msg_protect(ctx, msg))
        goto err;
    return msg;

 err:
    CMPerr(0, CMP_R_ERROR_CREATING_POLLREP);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

/*-
 * returns the status field of the RevRepContent with the given
 * request/sequence id inside a revocation response.
 * RevRepContent has the revocation statuses in same order as they were sent in
 * RevReqContent.
 * returns NULL on error
 */
OSSL_CMP_PKISI *
ossl_cmp_revrepcontent_get_pkistatusinfo(OSSL_CMP_REVREPCONTENT *rrep, int rsid)
{
    OSSL_CMP_PKISI *status;

    if (!ossl_assert(rrep != NULL))
        return NULL;

    if ((status = sk_OSSL_CMP_PKISI_value(rrep->status, rsid)) != NULL)
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
OSSL_CRMF_CERTID *
ossl_cmp_revrepcontent_get_CertId(OSSL_CMP_REVREPCONTENT *rrep, int rsid)
{
    OSSL_CRMF_CERTID *cid = NULL;

    if (!ossl_assert(rrep != NULL))
        return NULL;

    if ((cid = sk_OSSL_CRMF_CERTID_value(rrep->revCerts, rsid)) != NULL)
        return cid;

    CMPerr(0, CMP_R_CERTID_NOT_FOUND);
    return NULL;
}

static int suitable_rid(const ASN1_INTEGER *certReqId, int rid)
{
    int trid;

    if (rid == -1)
        return 1;

    trid = ossl_cmp_asn1_get_int(certReqId);

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
OSSL_CMP_POLLREP *
ossl_cmp_pollrepcontent_get0_pollrep(const OSSL_CMP_POLLREPCONTENT *prc,
                                     int rid)
{
    OSSL_CMP_POLLREP *pollRep = NULL;
    int i;

    if (!ossl_assert(prc != NULL))
        return NULL;

    for (i = 0; i < sk_OSSL_CMP_POLLREP_num(prc); i++) {
        pollRep = sk_OSSL_CMP_POLLREP_value(prc, i);
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
OSSL_CMP_CERTRESPONSE *
ossl_cmp_certrepmessage_get0_certresponse(const OSSL_CMP_CERTREPMESSAGE *crm,
                                          int rid)
{
    OSSL_CMP_CERTRESPONSE *crep = NULL;
    int i;

    if (!ossl_assert(crm != NULL && crm->response != NULL))
        return NULL;

    for (i = 0; i < sk_OSSL_CMP_CERTRESPONSE_num(crm->response); i++) {
        crep = sk_OSSL_CMP_CERTRESPONSE_value(crm->response, i);
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
X509 *ossl_cmp_certresponse_get1_certificate(EVP_PKEY *privkey,
                                             const OSSL_CMP_CERTRESPONSE *crep)
{
    OSSL_CMP_CERTORENCCERT *coec;
    X509 *crt = NULL;

    if (!ossl_assert(crep != NULL))
        return NULL;

    if (crep->certifiedKeyPair
            && (coec = crep->certifiedKeyPair->certOrEncCert) != NULL) {
        switch (coec->type) {
        case OSSL_CMP_CERTORENCCERT_CERTIFICATE:
            crt = X509_dup(coec->value.certificate);
            break;
        case OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT:
            /* cert encrypted for indirect PoP; RFC 4210, 5.2.8.2 */
            if (privkey == NULL) {
                CMPerr(0, CMP_R_MISSING_PRIVATE_KEY);
                return NULL;
            }
            crt =
                OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(coec->value.encryptedCert,
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

OSSL_CMP_MSG *ossl_cmp_msg_load(const char *file)
{
    OSSL_CMP_MSG *msg = NULL;
    BIO *bio = NULL;

    if (!ossl_assert(file != NULL))
        return NULL;

    if ((bio = BIO_new_file(file, "rb")) == NULL)
        return NULL;
    msg = OSSL_d2i_CMP_MSG_bio(bio, NULL);
    BIO_free(bio);
    return msg;
}
