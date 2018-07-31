/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP implementation by
 * Martin Peylo, Miikka Viljanen, David von Oheimb, and Tobias Pankert.
 */

#include <openssl/cmp.h>
#include "cmp_int.h"
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>

typedef OSSL_CMP_MSG *(*cmp_srv_process_cb_t)
                      (OSSL_CMP_SRV_CTX *ctx, const OSSL_CMP_MSG *msg);

/*
 * this structure is used to store the context for the CMP mock server
 * partly using OpenSSL ASN.1 types in order to ease handling it - such ASN.1
 * entries must be given first, in same order as ASN1_SEQUENCE(OSSL_CMP_SRV_CTX)
 */
struct OSSL_cmp_srv_ctx_st {
    X509 *certOut;              /* Certificate to be returned in cp/ip/kup */
    STACK_OF(X509) *chainOut;   /* Cert chain useful to validate certOut */
    STACK_OF(X509) *caPubsOut;  /* caPubs for ip */
    OSSL_CMP_PKISI *pkiStatusOut; /* PKI Status Info to be returned */
    OSSL_CMP_MSG *certReq;      /* ir/cr/p10cr/kur saved in case of polling */
    int certReqId;              /* id saved in case of polling */
    OSSL_CMP_CTX *ctx;          /* client cmp context, partly reused for srv */
    unsigned int pollCount;     /* Number of polls before cert response */
    long checkAfterTime;        /* time to wait for the next poll in seconds */
    int grantImplicitConfirm;   /* Grant implicit confirmation if requested */
    int sendError;              /* Always send error if true */
    int sendUnprotectedErrors;  /* Send error and rejection msgs uprotected */
    int acceptUnprotectedRequests; /* Accept unprotected request messages */
    int acceptRAVerified;       /* Accept ir/cr/kur with POPO RAVerified */
    int encryptcert;            /* Encrypt certs in cert response message */
    /* callbacks for message processing */
    cmp_srv_process_cb_t process_ir_cb;
    cmp_srv_process_cb_t process_cr_cb;
    cmp_srv_process_cb_t process_p10cr_cb;
    cmp_srv_process_cb_t process_kur_cb;
    cmp_srv_process_cb_t process_rr_cb;
    cmp_srv_process_cb_t process_certconf_cb;
    cmp_srv_process_cb_t process_error_cb;
    cmp_srv_process_cb_t process_pollreq_cb;
    cmp_srv_process_cb_t process_genm_cb;

} /* OSSL_CMP_SRV_CTX */ ;

ASN1_SEQUENCE(OSSL_CMP_SRV_CTX) = {
    ASN1_OPT(OSSL_CMP_SRV_CTX, certOut, X509),
        ASN1_SEQUENCE_OF_OPT(OSSL_CMP_SRV_CTX, chainOut, X509),
        ASN1_SEQUENCE_OF_OPT(OSSL_CMP_SRV_CTX, caPubsOut, X509),
        ASN1_SIMPLE(OSSL_CMP_SRV_CTX, pkiStatusOut, OSSL_CMP_PKISI),
        ASN1_OPT(OSSL_CMP_SRV_CTX, certReq, OSSL_CMP_MSG)
} ASN1_SEQUENCE_END(OSSL_CMP_SRV_CTX)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(OSSL_CMP_SRV_CTX)

void OSSL_CMP_SRV_CTX_delete(OSSL_CMP_SRV_CTX *srv_ctx)
{
    if (srv_ctx == NULL)
        return;
    OSSL_CMP_CTX_delete(srv_ctx->ctx);
    srv_ctx->ctx = NULL;
    OSSL_CMP_SRV_CTX_free(srv_ctx);
}

OSSL_CMP_CTX *OSSL_CMP_SRV_CTX_get0_ctx(OSSL_CMP_SRV_CTX *srv_ctx)
{
    if (srv_ctx == NULL)
        return NULL;
    return srv_ctx->ctx;
}

int OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(OSSL_CMP_SRV_CTX *srv_ctx,
                                                int value)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->grantImplicitConfirm = value ? 1 : 0;
    return 1;
}

int OSSL_CMP_SRV_CTX_set_accept_unprotected(OSSL_CMP_SRV_CTX *srv_ctx,
                                            int value)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->acceptUnprotectedRequests = value ? 1 : 0;
    return 1;
}

int OSSL_CMP_SRV_CTX_set_send_unprotected_errors(OSSL_CMP_SRV_CTX *srv_ctx,
                                                 int value)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->sendUnprotectedErrors = value ? 1 : 0;
    return 1;
}

int OSSL_CMP_SRV_CTX_set_statusInfo(OSSL_CMP_SRV_CTX *srv_ctx, int status,
                                    unsigned long failInfo, const char *text)
{
    if (srv_ctx == NULL)
        return 0;
    OSSL_CMP_PKISI_free(srv_ctx->pkiStatusOut);
    return (srv_ctx->pkiStatusOut =
            OSSL_CMP_statusInfo_new(status, failInfo, text))
           != NULL;
}

int OSSL_CMP_SRV_CTX_set1_certOut(OSSL_CMP_SRV_CTX *srv_ctx, X509 *cert)
{
    if (srv_ctx == NULL)
        return 0;
    X509_free(srv_ctx->certOut);
    if (X509_up_ref(cert)) {
        srv_ctx->certOut = cert;
        return 1;
    }
    srv_ctx->certOut = NULL;
    return 0;
}

int OSSL_CMP_SRV_CTX_set1_chainOut(OSSL_CMP_SRV_CTX *srv_ctx,
                                   STACK_OF(X509) *chain)
{
    if (srv_ctx == NULL || chain == NULL)
        return 0;
    sk_X509_pop_free(srv_ctx->chainOut, X509_free);
    return (srv_ctx->chainOut = X509_chain_up_ref(chain)) != NULL;
}

int OSSL_CMP_SRV_CTX_set1_caPubsOut(OSSL_CMP_SRV_CTX *srv_ctx,
                                    STACK_OF(X509) *caPubs)
{
    if (srv_ctx == NULL || caPubs == NULL)
        return 0;
    sk_X509_pop_free(srv_ctx->caPubsOut, X509_free);
    return (srv_ctx->caPubsOut = X509_chain_up_ref(caPubs)) != NULL;
}

int OSSL_CMP_SRV_CTX_set_send_error(OSSL_CMP_SRV_CTX *srv_ctx, int error)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->sendError = error ? 1 : 0;
    return 1;
}

int OSSL_CMP_SRV_CTX_set_checkAfterTime(OSSL_CMP_SRV_CTX *srv_ctx, long tim)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->checkAfterTime = tim;
    return 1;
}

int OSSL_CMP_SRV_CTX_set_pollCount(OSSL_CMP_SRV_CTX *srv_ctx, int count)
{
    if (srv_ctx == NULL || count < 0)
        return 0;
    srv_ctx->pollCount = count;
    return 1;
}

int OSSL_CMP_SRV_CTX_set_accept_raverified(OSSL_CMP_SRV_CTX *srv_ctx,
                                           int raverified)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->acceptRAVerified = raverified ? 1 : 0;
    return 1;
}

static int cmp_verify_popo(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *msg)
{
    if (srv_ctx == NULL || msg == NULL || msg->body == NULL) {
        CMPerr(CMP_F_CMP_VERIFY_POPO, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if (msg->body->type == OSSL_CMP_PKIBODY_P10CR) {
        X509_REQ *req = msg->body->value.p10cr;
        if (X509_REQ_verify(req, X509_REQ_get0_pubkey(req)) > 0)
            return 1;
        CMPerr(CMP_F_CMP_VERIFY_POPO, CMP_R_REQUEST_NOT_ACCEPTED);
        return 0;
    }

    return OSSL_CRMF_MSGS_verify_popo(msg->body->value.ir,
                                      OSSL_CMP_CERTREQID,
                                      srv_ctx->acceptRAVerified);
}

/*
 * Processes an ir/cr/p10cr/kur and returns a certification response.
 * Only handles the first certification request contained in certReq
 * returns an ip/cp/kup on success and NULL on error
 */
static OSSL_CMP_MSG *CMP_process_cert_request(OSSL_CMP_SRV_CTX *srv_ctx,
                                              const OSSL_CMP_MSG *certReq)
{
    OSSL_CMP_MSG *msg = NULL;
    OSSL_CMP_PKISI *si = NULL;
    X509 *certOut = NULL;
    STACK_OF(X509) *chainOut = NULL, *caPubs = NULL;
    OSSL_CRMF_MSG *crm = NULL;
    int bodytype;
    if (srv_ctx == NULL || certReq == NULL) {
        CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_INVALID_ARGS);
        return NULL;
    }
    switch (certReq->body->type) {
    case OSSL_CMP_PKIBODY_P10CR:
    case OSSL_CMP_PKIBODY_CR:
        bodytype = OSSL_CMP_PKIBODY_CP;
        break;
    case OSSL_CMP_PKIBODY_IR:
        bodytype = OSSL_CMP_PKIBODY_IP;
        break;
    case OSSL_CMP_PKIBODY_KUR:
        bodytype = OSSL_CMP_PKIBODY_KUP;
        break;
    default:
        CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_UNEXPECTED_PKIBODY);
        return NULL;
    }

    if (certReq->body->type == OSSL_CMP_PKIBODY_P10CR) {
        srv_ctx->certReqId = OSSL_CMP_CERTREQID;
    } else {
        if ((crm =
             sk_OSSL_CRMF_MSG_value(certReq->body->value.cr, 0)) == NULL) {
            CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_CERTREQMSG_NOT_FOUND);
            return NULL;
        }
        srv_ctx->certReqId = OSSL_CRMF_MSG_get_certReqId(crm);
    }

    if (!cmp_verify_popo(srv_ctx, certReq)) {
        /* Proof of possession could not be verified */
        if ((si = OSSL_CMP_statusInfo_new(OSSL_CMP_PKISTATUS_rejection,
                                          1 << OSSL_CMP_PKIFAILUREINFO_badPOP,
                                          NULL)) == NULL)
            goto oom;
    } else if (srv_ctx->pollCount > 0) {
        srv_ctx->pollCount--;
        if ((si = OSSL_CMP_statusInfo_new(OSSL_CMP_PKISTATUS_waiting, 0, NULL))
            == NULL)
            goto oom;
        OSSL_CMP_MSG_free(srv_ctx->certReq);
        if ((srv_ctx->certReq = OSSL_CMP_MSG_dup((OSSL_CMP_MSG *)certReq))
            == NULL)
            goto oom;
    } else {
        certOut = srv_ctx->certOut;
        chainOut = srv_ctx->chainOut;
        caPubs = srv_ctx->caPubsOut;
        if (OSSL_CMP_MSG_check_implicitConfirm((OSSL_CMP_MSG *) certReq) &&
            srv_ctx->grantImplicitConfirm)
            OSSL_CMP_CTX_set_option(srv_ctx->ctx,
                                    OSSL_CMP_CTX_OPT_IMPLICITCONFIRM, 1);
        if ((si = OSSL_CMP_PKISI_dup(srv_ctx->pkiStatusOut)) == NULL)
            goto oom;
    }

    msg = OSSL_CMP_certrep_new(srv_ctx->ctx, bodytype, srv_ctx->certReqId, si,
                               certOut, chainOut, caPubs, srv_ctx->encryptcert,
                               srv_ctx->sendUnprotectedErrors);
    if (msg == NULL)
        CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_ERROR_CREATING_CERTREP);

    OSSL_CMP_PKISI_free(si);
    return msg;

 oom:
    CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_OUT_OF_MEMORY);
    OSSL_CMP_PKISI_free(si);
    return NULL;
}

static OSSL_CMP_MSG *process_rr(OSSL_CMP_SRV_CTX *srv_ctx,
                                const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *msg;
    OSSL_CMP_REVDETAILS *details;
    OSSL_CRMF_CERTID *certId;
    OSSL_CRMF_CERTTEMPLATE *tmpl;
    X509_NAME *issuer;
    ASN1_INTEGER *serial;

    if (srv_ctx == NULL || req == NULL) {
        CMPerr(CMP_F_PROCESS_RR, CMP_R_NULL_ARGUMENT);
        return NULL;
    }

    if ((details = sk_OSSL_CMP_REVDETAILS_value(req->body->value.rr,
                                                OSSL_CMP_REVREQSID)) == NULL) {
        CMPerr(CMP_F_PROCESS_RR, CMP_R_ERROR_PROCESSING_MSG);
        return NULL;
    }

    /* accept revocation only for the certificate we send in ir/cr/kur */
    tmpl = details->certDetails;
    issuer = OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl);
    serial = OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl);
    if (X509_NAME_cmp(issuer, X509_get_issuer_name(srv_ctx->certOut)) != 0 ||
        ASN1_INTEGER_cmp(serial,
                         X509_get0_serialNumber(srv_ctx->certOut)) != 0) {
        CMPerr(CMP_F_PROCESS_RR, CMP_R_REQUEST_NOT_ACCEPTED);
        return NULL;
    }

    if ((certId = OSSL_CRMF_CERTID_gen(issuer, serial)) == NULL) {
        CMPerr(CMP_F_PROCESS_RR, CMP_R_OUT_OF_MEMORY);
        return NULL;
    }

    if ((msg = OSSL_CMP_rp_new(srv_ctx->ctx, srv_ctx->pkiStatusOut, certId,
                               srv_ctx->sendUnprotectedErrors)) == NULL)
        CMPerr(CMP_F_PROCESS_RR, CMP_R_ERROR_CREATING_RR);
    return msg;
}

static OSSL_CMP_MSG *process_certConf(OSSL_CMP_SRV_CTX *srv_ctx,
                                      const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *msg = NULL;
    OSSL_CMP_CERTSTATUS *status = NULL;
    ASN1_OCTET_STRING *tmp = NULL;
    int res = -1;
    int num = sk_OSSL_CMP_CERTSTATUS_num(req->body->value.certConf);

    if (num == 0) {
        OSSL_CMP_err(srv_ctx->ctx, "certificate rejected by client");
    } else {
        if (num > 1)
            OSSL_CMP_warn(srv_ctx->ctx,
                     "All CertStatus but the first will be ignored");
        status = sk_OSSL_CMP_CERTSTATUS_value(req->body->value.certConf,
                                              OSSL_CMP_CERTREQID);
    }

    if (status != NULL) {
        /* check cert request id */
        if (ASN1_INTEGER_get(status->certReqId) != srv_ctx->certReqId) {
            CMPerr(CMP_F_PROCESS_CERTCONF, CMP_R_UNEXPECTED_REQUEST_ID);
            return NULL;
        }

        /* check cert hash by recalculating it in place */
        tmp = status->certHash;
        status->certHash = NULL;
        if (CMP_CERTSTATUS_set_certHash(status, srv_ctx->certOut))
            res = status->certHash == NULL ? 0 /* avoiding SCA false positive */
                  : ASN1_OCTET_STRING_cmp(tmp, status->certHash) == 0;
        ASN1_OCTET_STRING_free(status->certHash);
        status->certHash = tmp;
        if (res == -1)
            return NULL;
        if (!res) {
            CMPerr(CMP_F_PROCESS_CERTCONF, CMP_R_WRONG_CERT_HASH);
            return NULL;
        }

        if (status->statusInfo != NULL) {
            char *tmpbuf = OPENSSL_malloc(OSSL_CMP_PKISI_BUFLEN);
            if (tmpbuf == NULL)
                goto oom;
            OSSL_CMP_info(srv_ctx->ctx, "certificate rejected by client:");
            if (OSSL_CMP_PKISI_snprint(status->statusInfo, tmpbuf,
                                       OSSL_CMP_PKISI_BUFLEN) != NULL)
                OSSL_CMP_info(srv_ctx->ctx, tmpbuf);
            OPENSSL_free(tmpbuf);
        }
    }

    if ((msg = OSSL_CMP_pkiconf_new(srv_ctx->ctx)) == NULL) {
        CMPerr(CMP_F_PROCESS_CERTCONF, CMP_R_ERROR_CREATING_PKICONF);
        return NULL;
    }

    return msg;

 oom:
    CMPerr(CMP_F_PROCESS_CERTCONF, CMP_R_OUT_OF_MEMORY);
    return NULL;
}

static OSSL_CMP_MSG *process_error(OSSL_CMP_SRV_CTX *srv_ctx,
                                   const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *msg = OSSL_CMP_pkiconf_new(srv_ctx->ctx);

    if (msg == NULL) {
        CMPerr(CMP_F_PROCESS_ERROR, CMP_R_ERROR_CREATING_PKICONF);
        return NULL;
    }

    return msg;
}

static OSSL_CMP_MSG *process_pollReq(OSSL_CMP_SRV_CTX *srv_ctx,
                                     const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *msg = NULL;
    if (!srv_ctx || !srv_ctx->certReq) {
        CMPerr(CMP_F_PROCESS_POLLREQ, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    if (srv_ctx->pollCount == 0) {
        if ((msg = CMP_process_cert_request(srv_ctx, srv_ctx->certReq)) == NULL)
            CMPerr(CMP_F_PROCESS_POLLREQ, CMP_R_ERROR_PROCESSING_CERTREQ);
    } else {
        srv_ctx->pollCount--;
        if ((msg = OSSL_CMP_pollRep_new(srv_ctx->ctx, srv_ctx->certReqId,
                                        srv_ctx->checkAfterTime)) == NULL)
            CMPerr(CMP_F_PROCESS_POLLREQ, CMP_R_ERROR_CREATING_POLLREP);
    }
    return msg;
}

/*
 * Processes genm and creates a genp message mirroring the contents of the
 * incoming message
 */
static OSSL_CMP_MSG *process_genm(OSSL_CMP_SRV_CTX *srv_ctx,
                                  const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *msg = NULL;
    STACK_OF(OSSL_CMP_ITAV) *tmp = NULL;

    if (srv_ctx == NULL || srv_ctx->ctx == NULL || req == NULL) {
        CMPerr(CMP_F_PROCESS_GENM, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    /* Back up potential genm_itavs */
    tmp = srv_ctx->ctx->genm_itavs;
    srv_ctx->ctx->genm_itavs = req->body->value.genm;
    if ((msg = OSSL_CMP_genp_new(srv_ctx->ctx)) == NULL)
        CMPerr(CMP_F_PROCESS_GENM, CMP_R_OUT_OF_MEMORY);
    /* restore genm_itavs */
    srv_ctx->ctx->genm_itavs = tmp;
    return msg;
}

/*
 * Determines whether missing protection is allowed
 */
static int unprotected_exception(const OSSL_CMP_CTX *ctx,
                                 int accept_unprotected_requests,
                                 const OSSL_CMP_MSG *req)
{
    if (accept_unprotected_requests) {
        OSSL_CMP_warn(ctx, "ignoring missing protection of request message");
        return 1;
    }
    if (req->body->type == OSSL_CMP_PKIBODY_ERROR && ctx->unprotectedErrors) {
        OSSL_CMP_warn(ctx, "ignoring missing protection of error message");
        return 1;
    }
    return 0;
}

/*
 * Mocks the server/responder.
 * srv_ctx is the context of the server
 * returns 1 if a message was created and 0 on error
 */
static int process_request(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req,
                           OSSL_CMP_MSG **rsp)
{
    cmp_srv_process_cb_t process_cb = NULL;
    OSSL_CMP_CTX *ctx;

    if (srv_ctx == NULL || srv_ctx->ctx == NULL || req == NULL || rsp == NULL) {
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx = srv_ctx->ctx;
    *rsp = NULL;

    if (req->header->sender->type != GEN_DIRNAME) {
        CMPerr(CMP_F_PROCESS_REQUEST,
               CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED);
        return 0;
    }
    if (!X509_NAME_set(&ctx->recipient, req->header->sender->d.directoryName)) {
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    if (OSSL_CMP_MSG_check_received(ctx, req,
                                      srv_ctx->acceptUnprotectedRequests,
                                      unprotected_exception) < 0) {
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE);
        return 0;
    }
    if (srv_ctx->sendError) {
        if ((*rsp = OSSL_CMP_error_new(ctx, srv_ctx->pkiStatusOut, -1, NULL,
                                       srv_ctx->sendUnprotectedErrors)))
            return 1;
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_ERROR_CREATING_ERROR);
        return 0;
    }

    switch (req->body->type) {
    case OSSL_CMP_PKIBODY_IR:
        process_cb = srv_ctx->process_ir_cb;
        break;
    case OSSL_CMP_PKIBODY_CR:
        process_cb = srv_ctx->process_cr_cb;
        break;
    case OSSL_CMP_PKIBODY_P10CR:
        process_cb = srv_ctx->process_p10cr_cb;
        break;
    case OSSL_CMP_PKIBODY_KUR:
        process_cb = srv_ctx->process_kur_cb;
        break;
    case OSSL_CMP_PKIBODY_POLLREQ:
        process_cb = srv_ctx->process_pollreq_cb;
        break;
    case OSSL_CMP_PKIBODY_RR:
        process_cb = srv_ctx->process_rr_cb;
        break;
    case OSSL_CMP_PKIBODY_ERROR:
        process_cb = srv_ctx->process_error_cb;
        break;
    case OSSL_CMP_PKIBODY_CERTCONF:
        process_cb = srv_ctx->process_certconf_cb;
        break;
    case OSSL_CMP_PKIBODY_GENM:
        process_cb = srv_ctx->process_genm_cb;
        break;
    default:
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_UNEXPECTED_PKIBODY);
        break;
    }
    if (process_cb == NULL)
        return 0;
    if ((*rsp = process_cb(srv_ctx, req)) == NULL)
        return 0;

    return 1;
}

/*
 * Mocks the server connection. Works similar to OSSL_CMP_MSG_http_perform.
 * A OSSL_CMP_SRV_CTX must be set as transfer_cb_arg
 * returns 0 on success and else a CMP error reason code defined in cmp.h
 */
int OSSL_CMP_mock_server_perform(OSSL_CMP_CTX *cmp_ctx, const OSSL_CMP_MSG *req,
                                 OSSL_CMP_MSG **rsp)
{
    OSSL_CMP_MSG *srv_req = NULL, *srv_rsp = NULL;
    OSSL_CMP_SRV_CTX *srv_ctx = NULL;
    int error = 0;

    if (cmp_ctx == NULL || req == NULL || rsp == NULL)
        return CMP_R_NULL_ARGUMENT;
    *rsp = NULL;

    if ((srv_ctx = OSSL_CMP_CTX_get_transfer_cb_arg(cmp_ctx)) == NULL)
        return CMP_R_ERROR_TRANSFERRING_OUT;

    /* OSSL_CMP_MSG_dup en- and decodes ASN.1, used for checking encoding */
    if ((srv_req = OSSL_CMP_MSG_dup((OSSL_CMP_MSG *)req)) == NULL)
        error = CMP_R_ERROR_DECODING_MESSAGE;

    if (process_request(srv_ctx, srv_req, &srv_rsp) == 0) {
        OSSL_CMP_PKISI *si;
        const char *data;
        int flags = 0;
        unsigned long err = ERR_peek_error_line_data(NULL, NULL, &data, &flags);
        if ((si = OSSL_CMP_statusInfo_new(OSSL_CMP_PKISTATUS_rejection,
                                     /* TODO make failure bits more specific */
                                     1 << OSSL_CMP_PKIFAILUREINFO_badRequest,
                                     NULL))) {
            srv_rsp = OSSL_CMP_error_new(cmp_ctx, si,
                                         err != 0 ? ERR_GET_REASON(err): -1,
                                         CMP_PKIFREETEXT_push_str(NULL,
                                            flags&ERR_TXT_STRING ? data : NULL),
                                         srv_ctx->sendUnprotectedErrors);
            OSSL_CMP_PKISI_free(si);
        } else {
            error = CMP_R_ERROR_PROCESSING_MSG;
        }
        goto end;
    }

    /* OSSL_CMP_MSG_dup en- and decodes ASN.1, used for checking encoding */
    if ((*rsp = OSSL_CMP_MSG_dup(srv_rsp)) == NULL) {
        error = CMP_R_ERROR_DECODING_MESSAGE;
        goto end;
    }

 end:
    OSSL_CMP_MSG_free(srv_req);
    OSSL_CMP_MSG_free(srv_rsp);

    return error;
}

/*
 * creates and initializes a OSSL_CMP_SRV_CTX structure
 * returns pointer to created CMP_SRV_ on success, NULL on error
 */
OSSL_CMP_SRV_CTX *OSSL_CMP_SRV_CTX_create(void)
{
    OSSL_CMP_SRV_CTX *ctx = NULL;
    if ((ctx = OSSL_CMP_SRV_CTX_new()) == NULL)
        goto oom;
    ctx->certReqId = -1;
    if ((ctx->ctx = OSSL_CMP_CTX_create()) == NULL)
        goto oom;
    ctx->pollCount = 0;
    ctx->checkAfterTime = 1;
    ctx->grantImplicitConfirm = 0;
    ctx->sendError = 0;
    ctx->sendUnprotectedErrors = 0;
    ctx->acceptUnprotectedRequests = 0;
    ctx->encryptcert = 0;
    ctx->acceptRAVerified = 0;
    ctx->certReqId = OSSL_CMP_CERTREQID;
    ctx->process_ir_cb = CMP_process_cert_request;
    ctx->process_cr_cb = CMP_process_cert_request;
    ctx->process_p10cr_cb = CMP_process_cert_request;
    ctx->process_kur_cb = CMP_process_cert_request;
    ctx->process_certconf_cb = process_certConf;
    ctx->process_error_cb = process_error;
    ctx->process_rr_cb = process_rr;
    ctx->process_pollreq_cb = process_pollReq;
    ctx->process_genm_cb = process_genm;
    return ctx;
 oom:
    CMPerr(CMP_F_OSSL_CMP_SRV_CTX_CREATE, CMP_R_OUT_OF_MEMORY);
    OSSL_CMP_SRV_CTX_free(ctx);
    return NULL;
}
