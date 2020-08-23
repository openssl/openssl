/*
 * Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Test CMP DER parsing.
 */

#include <openssl/bio.h>
#include <openssl/cmp.h>
#include "../crypto/cmp/cmp_local.h"
#include <openssl/err.h>
#include "fuzzer.h"
#include "rand.inc"

DEFINE_STACK_OF(OSSL_CMP_ITAV)

int FuzzerInitialize(ossl_unused int *unused__argc, ossl_unused char ***unused__argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    FuzzerSetRand();
    return 1;
}

static int num_responses;

static OSSL_CMP_MSG *transfer_cb(OSSL_CMP_CTX *ctx, ossl_unused const OSSL_CMP_MSG *unused__req)
{
    if (num_responses++ > 2)
        return NULL; /* prevent loops due to repeated pollRep */
    return OSSL_CMP_MSG_dup((OSSL_CMP_MSG *)
                            OSSL_CMP_CTX_get_transfer_cb_arg(ctx));
}

static int print_noop(ossl_unused const char *unused__func,
                      ossl_unused const char *unused__file,
                      ossl_unused int unused__line,
                      ossl_unused OSSL_CMP_severity unused__level,
                      ossl_unused const char *unused__msg)
{
    return 1;
}

static int allow_unprotected(ossl_unused const OSSL_CMP_CTX *unused__ctx,
                             ossl_unused const OSSL_CMP_MSG *unused__rep,
                             ossl_unused int unused__invalid_protection,
                             ossl_unused int unused__expected_type)
{
    return 1;
}

static void cmp_client_process_response(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)
{
    X509_NAME *name = X509_NAME_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();

    ctx->unprotectedSend = 1; /* satisfy ossl_cmp_msg_protect() */
    ctx->disableConfirm = 1; /* check just one response message */
    ctx->popoMethod = OSSL_CRMF_POPO_NONE; /* satisfy ossl_cmp_certReq_new() */
    ctx->oldCert = X509_new(); /* satisfy crm_new() and ossl_cmp_rr_new() */
    if (!OSSL_CMP_CTX_set1_secretValue(ctx, (unsigned char *)"",
                                       0) /* prevent too unspecific error */
            || ctx->oldCert == NULL
            || name == NULL || !X509_set_issuer_name(ctx->oldCert, name)
            || serial == NULL || !X509_set_serialNumber(ctx->oldCert, serial))
        goto err;

    (void)OSSL_CMP_CTX_set_transfer_cb(ctx, transfer_cb);
    (void)OSSL_CMP_CTX_set_transfer_cb_arg(ctx, msg);
    (void)OSSL_CMP_CTX_set_log_cb(ctx, print_noop);
    num_responses = 0;
    switch (msg->body != NULL ? msg->body->type : -1) {
    case OSSL_CMP_PKIBODY_IP:
        (void)OSSL_CMP_exec_IR_ses(ctx);
        break;
    case OSSL_CMP_PKIBODY_CP:
        (void)OSSL_CMP_exec_CR_ses(ctx);
        (void)OSSL_CMP_exec_P10CR_ses(ctx);
        break;
    case OSSL_CMP_PKIBODY_KUP:
        (void)OSSL_CMP_exec_KUR_ses(ctx);
        break;
    case OSSL_CMP_PKIBODY_POLLREP:
        ctx->status = OSSL_CMP_PKISTATUS_waiting;
        (void)OSSL_CMP_try_certreq(ctx, OSSL_CMP_PKIBODY_CR, NULL, NULL);
        break;
    case OSSL_CMP_PKIBODY_RP:
        (void)OSSL_CMP_exec_RR_ses(ctx);
        break;
    case OSSL_CMP_PKIBODY_GENP:
        sk_OSSL_CMP_ITAV_pop_free(OSSL_CMP_exec_GENM_ses(ctx),
                                  OSSL_CMP_ITAV_free);
        break;
    default:
        (void)ossl_cmp_msg_check_update(ctx, msg, allow_unprotected, 0);
        break;
    }
 err:
    X509_NAME_free(name);
    ASN1_INTEGER_free(serial);
}

static OSSL_CMP_PKISI *process_cert_request(ossl_unused OSSL_CMP_SRV_CTX *unused__srv_ctx,
                                            ossl_unused const OSSL_CMP_MSG *unused__cert_req,
                                            ossl_unused int unused__certReqId,
                                            ossl_unused const OSSL_CRMF_MSG *unused__crm,
                                            ossl_unused const X509_REQ *unused__p10cr,
                                            ossl_unused X509 **unused__certOut,
                                            ossl_unused STACK_OF(X509) **chainOut,
                                            ossl_unused STACK_OF(X509) **caPubs)
{
    CMPerr(0, CMP_R_ERROR_PROCESSING_MESSAGE);
    return NULL;
}

static OSSL_CMP_PKISI *process_rr(ossl_unused OSSL_CMP_SRV_CTX *unused__srv_ctx,
                                  ossl_unused const OSSL_CMP_MSG *unused__rr,
                                  ossl_unused const X509_NAME *unused__issuer,
                                  ossl_unused const ASN1_INTEGER *unused__serial)
{
    CMPerr(0, CMP_R_ERROR_PROCESSING_MESSAGE);
    return NULL;
}

static int process_genm(ossl_unused OSSL_CMP_SRV_CTX *unused__srv_ctx,
                        ossl_unused const OSSL_CMP_MSG *unused__genm,
                        ossl_unused const STACK_OF(OSSL_CMP_ITAV) *in,
                        ossl_unused STACK_OF(OSSL_CMP_ITAV) **out)
{
    CMPerr(0, CMP_R_ERROR_PROCESSING_MESSAGE);
    return 0;
}

static void process_error(ossl_unused OSSL_CMP_SRV_CTX *unused__srv_ctx,
                          ossl_unused const OSSL_CMP_MSG *unused__error,
                          ossl_unused const OSSL_CMP_PKISI *unused__statusInfo,
                          ossl_unused const ASN1_INTEGER *unused__errorCode,
                          ossl_unused const OSSL_CMP_PKIFREETEXT *unused__errorDetails)
{
    CMPerr(0, CMP_R_ERROR_PROCESSING_MESSAGE);
}

static int process_certConf(ossl_unused OSSL_CMP_SRV_CTX *unused__srv_ctx,
                            ossl_unused const OSSL_CMP_MSG *unused__certConf,
                            ossl_unused int unused__certReqId,
                            ossl_unused const ASN1_OCTET_STRING *unused__certHash,
                            ossl_unused const OSSL_CMP_PKISI *unused__si)
{
    CMPerr(0, CMP_R_ERROR_PROCESSING_MESSAGE);
    return 0;
}

static int process_pollReq(ossl_unused OSSL_CMP_SRV_CTX *unused__srv_ctx,
                           ossl_unused const OSSL_CMP_MSG *unused__pollReq,
                           ossl_unused int unused__certReqId,
                           ossl_unused OSSL_CMP_MSG **unused__certReq,
                           ossl_unused int64_t *unused__check_after)
{
    CMPerr(0, CMP_R_ERROR_PROCESSING_MESSAGE);
    return 0;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    OSSL_CMP_MSG *msg;
    BIO *in;

    if (len == 0)
        return 0;

    in = BIO_new(BIO_s_mem());
    OPENSSL_assert((size_t)BIO_write(in, buf, len) == len);
    msg = d2i_OSSL_CMP_MSG_bio(in, NULL);
    if (msg != NULL) {
        BIO *out = BIO_new(BIO_s_null());
        OSSL_CMP_SRV_CTX *srv_ctx = OSSL_CMP_SRV_CTX_new(NULL, NULL);
        OSSL_CMP_CTX *client_ctx = OSSL_CMP_CTX_new(NULL, NULL);

        i2d_OSSL_CMP_MSG_bio(out, msg);
        ASN1_item_print(out, (ASN1_VALUE *)msg, 4,
                        ASN1_ITEM_rptr(OSSL_CMP_MSG), NULL);
        BIO_free(out);

        if (client_ctx != NULL)
            cmp_client_process_response(client_ctx, msg);
        if (srv_ctx != NULL
            && OSSL_CMP_CTX_set_log_cb(OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv_ctx),
                                       print_noop)
            && OSSL_CMP_SRV_CTX_init(srv_ctx, NULL, process_cert_request,
                                     process_rr, process_genm, process_error,
                                     process_certConf, process_pollReq))
            OSSL_CMP_MSG_free(OSSL_CMP_SRV_process_request(srv_ctx, msg));

        OSSL_CMP_CTX_free(client_ctx);
        OSSL_CMP_SRV_CTX_free(srv_ctx);
        OSSL_CMP_MSG_free(msg);
    }

    BIO_free(in);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}
