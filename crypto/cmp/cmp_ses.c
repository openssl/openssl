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
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#include <string.h>

#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#define sleep(x) Sleep((x) * 1000)
#endif

#include "cmp_int.h"

/*
 * table used to translate PKIMessage body type number into a printable string
 */
static char *V_CMP_TABLE[] = {
    "IR",
    "IP",
    "CR",
    "CP",
    "P10CR",
    "POPDECC",
    "POPDECR",
    "KUR",
    "KUP",
    "KRR",
    "KRP",
    "RR",
    "RP",
    "CCR",
    "CCP",
    "CKUANN",
    "CANN",
    "RANN",
    "CRLANN",
    "PKICONF",
    "NESTED",
    "GENM",
    "GENP",
    "ERROR",
    "CERTCONF",
    "POLLREQ",
    "POLLREP",
};

/*
 * internal function
 *
 * adds error data of the given OSSL_CMP_MSG
 */
static void message_add_error_data(OSSL_CMP_MSG *msg)
{
    char *buf;
    int bt = OSSL_CMP_MSG_get_bodytype(msg);

    switch (bt) {
    case OSSL_CMP_PKIBODY_ERROR:
        if ((buf = OPENSSL_malloc(OSSL_CMP_PKISI_BUFLEN)) != NULL) {
            if (OSSL_CMP_PKISI_snprint(msg->body->value.error->
                                       pKIStatusInfo,
                                       buf, OSSL_CMP_PKISI_BUFLEN) != 0)
                ERR_add_error_data(1, buf);
            OPENSSL_free(buf);
        }
        break;
    case -1:
        ERR_add_error_data(1, "got no message, or invalid type '-1'");
        break;
    default:
        if (bt<0 || (size_t) bt >= sizeof(V_CMP_TABLE)/sizeof(V_CMP_TABLE[0])) {
            ERR_add_error_data(1, "got invalid message type out of sane range");
        } else {
            ERR_add_error_data(3, "got unexpected message type '",
                                  V_CMP_TABLE[bt], "'");
        }
        break;
    }
}

#define IS_ENOLLMENT(t) (t == OSSL_CMP_PKIBODY_IP || \
                         t == OSSL_CMP_PKIBODY_CP || t == OSSL_CMP_PKIBODY_KUP)

/*
 * evaluate whether there's an standard-violating exception configured for
 * handling unprotected errors
 */
static int unprotected_exception(const OSSL_CMP_CTX *ctx, int expected_type,
                                 const OSSL_CMP_MSG *rep)
{
    int exception = 0;
    int rcvd_type = OSSL_CMP_MSG_get_bodytype(rep);

    if (ctx->unprotectedErrors) {
        if (rcvd_type == OSSL_CMP_PKIBODY_ERROR) {
            OSSL_CMP_warn(ctx, "ignoring missing protection of error response");
            exception = 1;
        }
        if (rcvd_type == OSSL_CMP_PKIBODY_RP &&
            OSSL_CMP_PKISI_PKIStatus_get(
            CMP_REVREPCONTENT_PKIStatusInfo_get(rep->body->value.rp,
                                                OSSL_CMP_REVREQSID))
                == OSSL_CMP_PKISTATUS_rejection) {
            OSSL_CMP_warn(ctx,
                          "ignoring missing protection of revocation response message with rejection status");
            exception = 1;
        }
        if (rcvd_type == OSSL_CMP_PKIBODY_PKICONF) {
            OSSL_CMP_warn(ctx,
                          "ignoring missing protection of PKI Confirmation message");
            exception = 1;
        }
        if (rcvd_type == expected_type && IS_ENOLLMENT(rcvd_type)) {
            OSSL_CMP_CERTREPMESSAGE *crepmsg = rep->body->value.ip;
            OSSL_CMP_CERTRESPONSE *crep =
                CMP_CERTREPMESSAGE_certResponse_get0(crepmsg, -1);
            if (sk_OSSL_CMP_CERTRESPONSE_num(crepmsg->response) > 1) {
                /* a specific error could be misleading here */
                return 0;
            }
            /*
             * TODO: handle multiple CertResponses in CertRepMsg, in case
             *       multiple requests have been sent -->  GitHub issue#67
             */
            if (crep == NULL) {
                /* a specific error could be misleading here */
                return 0;
            }
            if (OSSL_CMP_PKISI_PKIStatus_get(crep->status) ==
                OSSL_CMP_PKISTATUS_rejection) {
                OSSL_CMP_warn(ctx,
                              "ignoring missing protection of CertRepMessage with rejection status");
                exception = 1;
            }
        }
    }
    return exception;
}


/*
 * internal function
 *
 * performs the generic aspects of sending a request and receiving a response
 * returns 1 on success, 0 on error
 * Regardless of success, caller is responsible for freeing *rep (unless NULL).
 */
static int send_receive_check(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req,
                              const char *type_string, int func,
                              OSSL_CMP_MSG **rep, int expected_type,
                              int not_received)
{
    int msgtimeout = ctx->msgtimeout; /* backup original value */
    int err, rcvd_type;

    if ((expected_type == OSSL_CMP_PKIBODY_POLLREP ||
         IS_ENOLLMENT(expected_type))
        && ctx->totaltimeout != 0) { /* total timeout is not infinite */
        long time_left = (long)(ctx->end_time - time(NULL));
        if (time_left <= 0) {
            CMPerr(CMP_F_SEND_RECEIVE_CHECK, CMP_R_TOTAL_TIMEOUT);
            return 0;
        }
        if (ctx->msgtimeout == 0 || time_left < ctx->msgtimeout)
            ctx->msgtimeout = time_left;
    }

    OSSL_CMP_printf(ctx, OSSL_CMP_FL_INFO, "sending %s", type_string);
    if (ctx->transfer_cb != NULL)
        err = (ctx->transfer_cb)(ctx, req, rep);
        /* may produce, e.g., CMP_R_ERROR_TRANSFERRING_OUT
         *                 or CMP_R_ERROR_TRANSFERRING_IN
         * DO NOT DELETE the two error reason codes in this comment, they are
         * for mkerr.pl
         */
    else
        err = CMP_R_ERROR_SENDING_REQUEST;
    ctx->msgtimeout = msgtimeout; /* restore original value */

    if (err != 0) {
        CMPerr(CMP_F_SEND_RECEIVE_CHECK, err);
        if (err == CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE ||
            err == CMP_R_READ_TIMEOUT ||
            err == CMP_R_ERROR_DECODING_MESSAGE)
            CMPerr(func, not_received);
        else {
            CMPerr(func, CMP_R_ERROR_SENDING_REQUEST);
            CMP_add_error_data(type_string);
        }
        *rep = NULL;
        return 0;
    }

    OSSL_CMP_info(ctx, "got response");
    if((rcvd_type = OSSL_CMP_MSG_check_received(ctx, *rep, expected_type,
                                                unprotected_exception)) < 0)
        return 0;

    /* catch if received message type isn't one of expected ones (e.g. error) */
    if (rcvd_type != expected_type &&
        /* as an answer to polling, there could be IP/CP/KUP */
        !(expected_type == OSSL_CMP_PKIBODY_POLLREP && IS_ENOLLMENT(rcvd_type))) {
        CMPerr(CMP_F_SEND_RECEIVE_CHECK,
               rcvd_type == OSSL_CMP_PKIBODY_ERROR ? CMP_R_RECEIVED_ERROR :
               CMP_R_UNEXPECTED_PKIBODY); /* in next line for mkerr.pl */
        message_add_error_data(*rep);
        return 0;
    }

    return 1;
}

/*
 * internal function
 *
 * When a 'waiting' PKIStatus has been received, this function is used to
 * attempt to poll for a response message.
 *
 * A total timeout may have been set in the context.  The function will continue
 * to poll until the timeout is reached and then poll a last time even when that
 * is before the "checkAfter" sent by the server. If ctx->totaltimeout is 0, the
 * timeout is disabled.
 *
 * returns 1 on success, returns received PKIMESSAGE in *msg argument
 * returns 0 on error or when timeout is reached without a received message
 *
 * TODO: handle multiple poll requests for multiple certificates
 *       --> GitHub issue#67
 */
static int pollForResponse(OSSL_CMP_CTX *ctx, long rid, OSSL_CMP_MSG **out)
{
    OSSL_CMP_MSG *preq = NULL;
    OSSL_CMP_MSG *prep = NULL;
    OSSL_CMP_POLLREP *pollRep = NULL;

    OSSL_CMP_info(ctx,
                  "received 'waiting' PKIStatus, starting to poll for response");
    for (;;) {
        if ((preq = OSSL_CMP_pollReq_new(ctx, rid)) == NULL)
            goto err;

        if (!send_receive_check(ctx, preq, "pollReq", CMP_F_POLLFORRESPONSE,
                                &prep, OSSL_CMP_PKIBODY_POLLREP,
                                CMP_R_POLLREP_NOT_RECEIVED))
             goto err;

        /* handle potential pollRep */
        if (OSSL_CMP_MSG_get_bodytype(prep) == OSSL_CMP_PKIBODY_POLLREP) {
            long checkAfter;
            OSSL_CMP_POLLREPCONTENT *prc = prep->body->value.pollRep;
            /*
             * TODO: handle multiple PollRepContent elements, in case
             *       multiple requests have been sent -->  GitHub issue#67
             */
            if (sk_OSSL_CMP_POLLREP_num(prc) > 1) {
                CMPerr(CMP_F_POLLFORRESPONSE,
                       CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED);
                goto err;
            }
            if ((pollRep = CMP_POLLREPCONTENT_pollRep_get0(prc, rid)) == NULL)
                goto err;
            checkAfter = ASN1_INTEGER_get(pollRep->checkAfter);
            if (checkAfter < 0) {
                CMPerr(CMP_F_POLLFORRESPONSE,
                       CMP_R_RECEIVED_NEGATIVE_CHECKAFTER_IN_POLLREP);
                goto err;
            }
            /* TODO: print OPTIONAL reason (PKIFreeText) from message */
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_INFO,
                            "received polling response, waiting checkAfter =  "
                            "%ld sec before next polling request", checkAfter);

            if (ctx->totaltimeout != 0) { /* total timeout is not infinite */
                const int exp = 5; /* expected max time per msg round trip */
                long time_left = (long)(ctx->end_time - exp - time(NULL));
                if (time_left <= 0) {
                    CMPerr(CMP_F_POLLFORRESPONSE, CMP_R_TOTAL_TIMEOUT);
                    goto err;
                }
                if (time_left < checkAfter) {
                    checkAfter = time_left;
                    /* poll one last time just when timeout was reached */
                }
            }

            OSSL_CMP_MSG_free(preq);
            preq = NULL;
            OSSL_CMP_MSG_free(prep);
            prep = NULL;
            sleep((unsigned int)checkAfter);
        } else {
            OSSL_CMP_info(ctx, "got ip/cp/kup after polling");
            break;
        }
    }
    if (prep == NULL)
        goto err;

    OSSL_CMP_MSG_free(preq);
    *out = prep;

    return 1;
 err:
    OSSL_CMP_MSG_free(preq);
    OSSL_CMP_MSG_free(prep);
    return 0;
}

/*
 * internal function, but exported just for testing
 *
 * send certConf for IR, CR or KUR sequences and check response
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_exchange_certConf(OSSL_CMP_CTX *ctx, int failure, const char *txt)
{
    OSSL_CMP_MSG *certConf = NULL;
    OSSL_CMP_MSG *PKIconf = NULL;
    int success = 0;

    /* check if all necessary options are set done by OSSL_CMP_certConf_new */
    /* create Certificate Confirmation - certConf */
    if ((certConf = OSSL_CMP_certConf_new(ctx, failure, txt)) == NULL)
        goto err;

    success = send_receive_check(ctx, certConf, "certConf",
                                 CMP_F_OSSL_CMP_EXCHANGE_CERTCONF, &PKIconf,
                                 OSSL_CMP_PKIBODY_PKICONF,
                                 CMP_R_PKICONF_NOT_RECEIVED);

 err:
    OSSL_CMP_MSG_free(certConf);
    OSSL_CMP_MSG_free(PKIconf);
    return success;
}

/*
 * internal function, but exported just for testing
 * icurrently unused
 *
 * send given error and check response
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_exchange_error(OSSL_CMP_CTX *ctx, int status, int failure,
                            const char *txt)
{
    OSSL_CMP_MSG *error = NULL;
    OSSL_CMP_PKISI *si = NULL;
    OSSL_CMP_MSG *PKIconf = NULL;
    int success = 0;

    /* check if all necessary options are set is done in OSSL_CMP_error_new */
    /* create Error Message - error */
    if ((si = OSSL_CMP_statusInfo_new(status, 1 << failure, txt)) == NULL)
        goto err;
    if ((error = OSSL_CMP_error_new(ctx, si, -1, NULL, 0)) == NULL)
        goto err;

    success = send_receive_check(ctx, error, "error",
                                 CMP_F_OSSL_CMP_EXCHANGE_ERROR,
                                 &PKIconf, OSSL_CMP_PKIBODY_PKICONF,
                                 CMP_R_PKICONF_NOT_RECEIVED);

 err:
    OSSL_CMP_MSG_free(error);
    OSSL_CMP_PKISI_free(si);
    OSSL_CMP_MSG_free(PKIconf);
    return success;
}

/*
 * internal function
 *
 * saves error information from PKIStatusInfo field of a certresponse into ctx
 */
static int save_statusInfo(OSSL_CMP_CTX *ctx, OSSL_CMP_PKISI *si)
{
    int i;
    OSSL_CMP_PKIFREETEXT *ss;

    if (si == NULL)
        return 0;

    if ((ctx->lastPKIStatus = OSSL_CMP_PKISI_PKIStatus_get(si) < 0))
        return 0;

    if (!OSSL_CMP_CTX_set_failInfoCode(ctx, si->failInfo))
        return 0;

    sk_ASN1_UTF8STRING_pop_free(ctx->lastStatusString,ASN1_UTF8STRING_free);
    ctx->lastStatusString = NULL;

    if ((ctx->lastStatusString = sk_ASN1_UTF8STRING_new_null()) == NULL)
        return 0;
    ss = si->statusString;
    for (i = 0; i < sk_ASN1_UTF8STRING_num(ss); i++) {
        ASN1_UTF8STRING *str = sk_ASN1_UTF8STRING_value(ss, i);
        if (!sk_ASN1_UTF8STRING_push(ctx->lastStatusString,
                                     ASN1_STRING_dup(str)))
            return 0;
    }
    return 1;
}

/*
 * Retrieve a copy of the certificate, if any, from the given CertResponse.
 * Take into account PKIStatusInfo of CertResponse and report it on error.
 * returns NULL if not found or on error
 */
static X509 *get_cert_status(OSSL_CMP_CTX *ctx, int bodytype,
                             OSSL_CMP_CERTRESPONSE *crep)
{
    char *tempbuf;
    X509 *crt = NULL;
    if (ctx == NULL || crep == NULL)
        return NULL;

    switch (OSSL_CMP_PKISI_PKIStatus_get(crep->status)) {
    case OSSL_CMP_PKISTATUS_waiting:
        OSSL_CMP_err(ctx,
                     "received \"waiting\" status for cert when actually aiming to extract cert");
        CMPerr(CMP_F_GET_CERT_STATUS, CMP_R_ENCOUNTERED_WAITING);
        goto err;
    case OSSL_CMP_PKISTATUS_grantedWithMods:
        OSSL_CMP_warn(ctx, "received \"grantedWithMods\" for certificate");
        crt = CMP_CERTRESPONSE_get_certificate(ctx, crep);
        break;
    case OSSL_CMP_PKISTATUS_accepted:
        crt = CMP_CERTRESPONSE_get_certificate(ctx, crep);
        break;

        /* get all information in case of a rejection before going to error */
    case OSSL_CMP_PKISTATUS_rejection:
        OSSL_CMP_err(ctx, "received \"rejection\" status rather than cert");
        CMPerr(CMP_F_GET_CERT_STATUS, CMP_R_REQUEST_REJECTED_BY_CA);
        goto err;

    case OSSL_CMP_PKISTATUS_revocationWarning:
        OSSL_CMP_warn(ctx,
                      "received \"revocationWarning\" - a revocation of the cert is imminent");
        crt = CMP_CERTRESPONSE_get_certificate(ctx, crep);
        break;
    case OSSL_CMP_PKISTATUS_revocationNotification:
        OSSL_CMP_warn(ctx,
                      "received \"revocationNotification\" - a revocation of the cert has occurred");
        crt = CMP_CERTRESPONSE_get_certificate(ctx, crep);
        break;
    case OSSL_CMP_PKISTATUS_keyUpdateWarning:
        if (bodytype != OSSL_CMP_PKIBODY_KUR) {
            CMPerr(CMP_F_GET_CERT_STATUS, CMP_R_ENCOUNTERED_KEYUPDATEWARNING);
            goto err;
        }
        OSSL_CMP_warn(ctx,
                      "received \"keyUpdateWarning\" - update already done for the given oldCertId");
        crt = CMP_CERTRESPONSE_get_certificate(ctx, crep);
        break;
    default:
        OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                        "received unsupported PKIStatus %ld for certificate",
                        ctx->lastPKIStatus);
        CMPerr(CMP_F_GET_CERT_STATUS, CMP_R_ENCOUNTERED_UNSUPPORTED_PKISTATUS);
        goto err;
    }
    if (crt == NULL) {/* according to PKIStatus, we can expect a cert */
        CMPerr(CMP_F_GET_CERT_STATUS, CMP_R_CERTIFICATE_NOT_FOUND);
    }

    return crt;

 err:
    if ((tempbuf = OPENSSL_malloc(OSSL_CMP_PKISI_BUFLEN))) {
        if (OSSL_CMP_PKISI_snprint(crep->status, tempbuf,OSSL_CMP_PKISI_BUFLEN))
            ERR_add_error_data(1, tempbuf);
        OPENSSL_free(tempbuf);
    }
    return NULL;
}

/*
 * internal function
 *
 * performs the generic handling of certificate responses for IR/CR/KUR/P10CR
 * returns 1 on success, 0 on error
 * Regardless of success, caller is responsible for freeing *resp (unless NULL).
 */
static int cert_response(OSSL_CMP_CTX *ctx, long rid, OSSL_CMP_MSG **resp,
                         int func, int not_received)
{
    int failure = -1; /* no failure */
    const char *txt = NULL;
    OSSL_CMP_CERTREPMESSAGE *crepmsg;
    OSSL_CMP_CERTRESPONSE *crep;
    STACK_OF(X509) *extracerts;
    int ret = 1;

 retry:
    crepmsg = (*resp)->body->value.ip; /* same for cp and kup */
    if (sk_OSSL_CMP_CERTRESPONSE_num(crepmsg->response) > 1) {
        CMPerr(func, CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED);
        return 0;
    }
    /*
     * TODO handle multiple CertResponses in CertRepMsg (in case multiple
     * requests have been sent) -->  GitHub issue#67
     */
    crep = CMP_CERTREPMESSAGE_certResponse_get0(crepmsg, rid);
    if (crep == NULL)
        return 0;
    if (rid == -1)/* for OSSL_CMP_PKIBODY_P10CR learn CertReqId from response */
        rid = ASN1_INTEGER_get(crep->certReqId);

    if (OSSL_CMP_PKISI_PKIStatus_get(crep->status) ==
        OSSL_CMP_PKISTATUS_waiting){
        OSSL_CMP_MSG_free(*resp);
        if (pollForResponse(ctx, rid, resp)) {
            goto retry; /* got rp/cp/kup which might still indicate 'waiting' */
        } else {
            CMPerr(func, not_received);
            ERR_add_error_data(1,
                             "received 'waiting' pkistatus but polling failed");
            *resp = NULL;
            return 0;
        }
    }

    if (!save_statusInfo(ctx, crep->status))
        return 0;
    if ((ctx->newClCert = get_cert_status(ctx, (*resp)->body->type,
                                          crep)) == NULL) {
        CMP_add_error_data("cannot extract certificate from response");
        return 0;
    }

    /*
     * if the CMP server returned certificates in the caPubs field, copy them
     * to the context so that they can be retrieved if necessary
     */
    if (crepmsg->caPubs != NULL)
        OSSL_CMP_CTX_set1_caPubs(ctx, crepmsg->caPubs);

    /* copy received extraCerts to ctx->extraCertsIn so they can be retrieved */
    if ((extracerts = (*resp)->extraCerts) != NULL) {
        if (!OSSL_CMP_CTX_set1_extraCertsIn(ctx, extracerts) ||
        /*
         * merge them also into the untrusted certs, such that the peer does
         * not need to send them again (in this and any further transaction)
         */
            !OSSL_CMP_sk_X509_add1_certs(ctx->untrusted_certs, extracerts,
                                         0, 1/* no dups */))
            return 0;
    }

    if (!(X509_check_private_key(ctx->newClCert,
                                 ctx->newPkey != NULL ? ctx->newPkey
                                                      : ctx->pkey))) {
        failure = OSSL_CMP_PKIFAILUREINFO_incorrectData;
        txt = "public key in new certificate does not match our private key";
#if 0 /* better leave this for any ctx->certConf_cb to decide */
        (void)OSSL_CMP_exchange_error(ctx, OSSL_CMP_PKISTATUS_rejection,
                                      failure, txt);
        /*
         * cannot flag failure earlier as send_receive_check() indirectly calls
         * ERR_clear_error()
         */
        CMPerr(func, CMP_R_CERTIFICATE_NOT_ACCEPTED);
        ERR_add_error_data(1, txt);
        return 0;
#endif
    }

    /*
     * Execute the certification checking callback function possibly set in ctx,
     * which can determine whether to accept a newly enrolled certificate.
     * It may overrule the pre-decision reflected in 'failure' and '*txt'.
     */
    if (ctx->certConf_cb && (failure = ctx->certConf_cb(ctx, ctx->newClCert,
                                                        failure, &txt)) >= 0) {
        if (txt == NULL)
            txt = "CMP client application did not accept newly enrolled certificate";
    }

    /* TODO: better move certConf exchange to do_certreq_seq() such that
       also more low-level errors with CertReqMessages get reported to server */
    if (!ctx->disableConfirm && !OSSL_CMP_MSG_check_implicitConfirm(*resp))
        if (!OSSL_CMP_exchange_certConf(ctx, failure, txt))
            ret = 0;

    if (failure >= 0) {
        /*
         * cannot flag failure earlier because send_receive_check()
         * indirectly calls ERR_clear_error()
         */
        put_cert_verify_err(func);
        CMPerr(func, CMP_R_CERTIFICATE_NOT_ACCEPTED);
        ERR_add_error_data(1, "rejecting newly enrolled cert");
        if (txt != NULL)
            CMP_add_error_txt("; ", txt);
        return 0;
    }
    return ret;
}

/*
 * internal function
 *
 * Do the full sequence CR/IR/KUR/P10CR, CP/IP/KUP/CP,
 * certConf, PKIconf, and potential polling.
 *
 * All options need to be set in the context.
 *
 * TODO: another function to request two certificates at once should be created
 *
 * returns pointer to received certificate, or NULL if none was received
 */
static X509 *do_certreq_seq(OSSL_CMP_CTX *ctx, const char *type_string, int fn,
                            int req_type, int req_err, int rep_type, int rep_err)
{
    OSSL_CMP_MSG *req = NULL;
    OSSL_CMP_MSG *rep = NULL;
    long rid = (req_type == OSSL_CMP_PKIBODY_P10CR) ? -1 : OSSL_CMP_CERTREQID;
    X509 *result = NULL;

    if (ctx == NULL)
        return NULL;

    ctx->end_time = time(NULL) + ctx->totaltimeout;
    ctx->lastPKIStatus = -1;

    /* The check if all necessary options are set done by OSSL_CMP_certreq_new */
    if ((req = OSSL_CMP_certreq_new(ctx, req_type, req_err)) == NULL)
        goto err;

    if (!send_receive_check(ctx, req, type_string, fn, &rep, rep_type, rep_err))
        goto err;

    if (!cert_response(ctx, rid, &rep, fn, rep_err))
        goto err;

    result = ctx->newClCert;
 err:
    OSSL_CMP_MSG_free(req);
    OSSL_CMP_MSG_free(rep);

    /* print out OpenSSL and CMP errors via the log callback or OSSL_CMP_puts */
    if (result == NULL)
        ERR_print_errors_cb(CMP_CTX_error_cb, (void *)ctx);
    return result;
}

/*
 * do the full sequence for RR, including RR, RP, and potential polling
 *
 * All options need to be set in the context,
 * in particular oldCert, the certificate to be revoked.
 *
 * TODO: this function can only revoke one certificate so far,
 * should be possible for several according to 5.3.9
 *
 * The RFC is vague in which PKIStatus should be returned by the server, so we
 * take "accepted, "grantedWithMods", and "revocationWarning" as success,
 * "revocationNotification" is used by some CAs as an indication that the
 * certificate was already revoked, "rejection" as indication that the
 * revocation was rejected, and do not expect "waiting" or "keyUpdateWarning"
 * (which are handled as error).
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_exec_RR_ses(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_MSG *rr = NULL;
    OSSL_CMP_MSG *rp = NULL;
    OSSL_CMP_PKISI *si = NULL;
    int result = 0;

    if (ctx == NULL)
        return 0;

    ctx->lastPKIStatus = -1;

    /* check if all necessary options are set is done in OSSL_CMP_rr_new */
    /* create Revocation Request - ir */
    if ((rr = OSSL_CMP_rr_new(ctx)) == NULL)
        goto err;

    if (!send_receive_check(ctx, rr, "rr", CMP_F_OSSL_CMP_EXEC_RR_SES,
                            &rp, OSSL_CMP_PKIBODY_RP, CMP_R_RP_NOT_RECEIVED))
        goto err;

    /* evaluate PKIStatus field */
    si = CMP_REVREPCONTENT_PKIStatusInfo_get(rp->body->value.rp,
                                             OSSL_CMP_REVREQSID);
    if (!save_statusInfo(ctx, si))
        goto err;
    switch (OSSL_CMP_PKISI_PKIStatus_get(si)) {
    case OSSL_CMP_PKISTATUS_accepted:
        OSSL_CMP_info(ctx, "revocation accepted (PKIStatus=accepted)");
        result = 1;
        break;
    case OSSL_CMP_PKISTATUS_grantedWithMods:
        OSSL_CMP_info(ctx, "revocation accepted (PKIStatus=grantedWithMods)");
        result = 1;
        break;
    case OSSL_CMP_PKISTATUS_rejection:
        /* interpretation as warning or error depends on CA */
        OSSL_CMP_warn(ctx, "revocation rejected (PKIStatus=rejection)");
        CMPerr(CMP_F_OSSL_CMP_EXEC_RR_SES, CMP_R_REQUEST_REJECTED_BY_CA);
        goto err;
    case OSSL_CMP_PKISTATUS_revocationWarning:
        OSSL_CMP_info(ctx, "revocation accepted (PKIStatus=revocationWarning)");
        result = 1;
        break;
    case OSSL_CMP_PKISTATUS_revocationNotification:
        /* interpretation as warning or error depends on CA */
        OSSL_CMP_info(ctx,
                      "revocation accepted (PKIStatus=revocationNotification)");
        result = 1;
        break;
    case OSSL_CMP_PKISTATUS_waiting:
    case OSSL_CMP_PKISTATUS_keyUpdateWarning:
        CMPerr(CMP_F_OSSL_CMP_EXEC_RR_SES, CMP_R_UNEXPECTED_PKISTATUS);
        goto err;
    default:
        CMPerr(CMP_F_OSSL_CMP_EXEC_RR_SES, CMP_R_UNKNOWN_PKISTATUS);
        goto err;
    }

 err:

    /* print out OpenSSL and CMP errors via the log callback or OSSL_CMP_puts */
    if (result == 0) {
        char *tempbuf;
        if ((tempbuf = OPENSSL_malloc(OSSL_CMP_PKISI_BUFLEN)) != NULL) {
            if (OSSL_CMP_PKISI_snprint(si, tempbuf,
                                       OSSL_CMP_PKISI_BUFLEN))
                ERR_add_error_data(1, tempbuf);
            OPENSSL_free(tempbuf);
        }
        ERR_print_errors_cb(CMP_CTX_error_cb, (void *)ctx);
    }
    OSSL_CMP_MSG_free(rr);
    OSSL_CMP_MSG_free(rp);
    return result;
}

X509 *OSSL_CMP_exec_IR_ses(OSSL_CMP_CTX *ctx)
{
    return do_certreq_seq(ctx, "ir", CMP_F_OSSL_CMP_EXEC_IR_SES,
                          OSSL_CMP_PKIBODY_IR, CMP_R_ERROR_CREATING_IR,
                          OSSL_CMP_PKIBODY_IP, CMP_R_IP_NOT_RECEIVED);
}

X509 *OSSL_CMP_exec_CR_ses(OSSL_CMP_CTX *ctx)
{
    return do_certreq_seq(ctx, "cr", CMP_F_OSSL_CMP_EXEC_CR_SES,
                          OSSL_CMP_PKIBODY_CR, CMP_R_ERROR_CREATING_CR,
                          OSSL_CMP_PKIBODY_CP, CMP_R_CP_NOT_RECEIVED);
}

X509 *OSSL_CMP_exec_KUR_ses(OSSL_CMP_CTX *ctx)
{
    return do_certreq_seq(ctx, "kur", CMP_F_OSSL_CMP_EXEC_KUR_SES,
                          OSSL_CMP_PKIBODY_KUR, CMP_R_ERROR_CREATING_KUR,
                          OSSL_CMP_PKIBODY_KUP, CMP_R_KUP_NOT_RECEIVED);
}

X509 *OSSL_CMP_exec_P10CR_ses(OSSL_CMP_CTX *ctx)
{
    return do_certreq_seq(ctx, "p10cr", CMP_F_OSSL_CMP_EXEC_P10CR_SES,
                          OSSL_CMP_PKIBODY_P10CR, CMP_R_ERROR_CREATING_P10CR,
                          OSSL_CMP_PKIBODY_CP, CMP_R_CP_NOT_RECEIVED);
}

/*
 * Sends a general message to the server to request information specified in the
 * InfoType and Value (itav) given in the ctx->genm_itavs, see section 5.3.19
 * and E.5.
 *
 * returns pointer to stack of ITAVs received in the answer or NULL on error
 */
STACK_OF(OSSL_CMP_ITAV) *OSSL_CMP_exec_GENM_ses(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_MSG *genm = NULL;
    OSSL_CMP_MSG *genp = NULL;
    STACK_OF(OSSL_CMP_ITAV) *rcvd_itavs = NULL;

    if ((genm = OSSL_CMP_genm_new(ctx)) == NULL)
        goto err;

    if (!send_receive_check(ctx, genm, "genm",
                            CMP_F_OSSL_CMP_EXEC_GENM_SES, &genp,
                            OSSL_CMP_PKIBODY_GENP, CMP_R_GENP_NOT_RECEIVED))
         goto err;

    /* received stack of itavs not to be freed with the genp */
    rcvd_itavs = genp->body->value.genp;
    genp->body->value.genp = NULL;

 err:
    OSSL_CMP_MSG_free(genm);
    OSSL_CMP_MSG_free(genp);

    /* print out OpenSSL and CMP errors via the log callback or OSSL_CMP_puts */
    /* TODO: verify that !recv_itavs is necessarily an error */
    if (rcvd_itavs == NULL)
        ERR_print_errors_cb(CMP_CTX_error_cb, (void *)ctx);
    return rcvd_itavs;
}
