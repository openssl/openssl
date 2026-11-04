/*
 * Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2020
 * Copyright Siemens AG 2015-2020
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "helpers/cmp_testlib.h"

typedef struct test_fixture {
    const char *test_case_name;
    int reason;
    int change_parameters_only;
    OSSL_CMP_SRV_CTX *srv_ctx;
    OSSL_CMP_MSG *req;
} CMP_SRV_TEST_FIXTURE;

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *default_null_provider = NULL, *provider = NULL;
static OSSL_CMP_MSG *request = NULL;
#define TEST_PBM_SECRET (const unsigned char *)"1234", 4

static void tear_down(CMP_SRV_TEST_FIXTURE *fixture)
{
    OSSL_CMP_SRV_CTX_free(fixture->srv_ctx);
    OPENSSL_free(fixture);
}

static CMP_SRV_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_SRV_TEST_FIXTURE *fixture;

    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))))
        return NULL;
    fixture->test_case_name = test_case_name;
    if (!TEST_ptr(fixture->srv_ctx = OSSL_CMP_SRV_CTX_new(libctx, NULL)))
        goto err;
    return fixture;

err:
    tear_down(fixture);
    return NULL;
}

static int dummy_errorCode = CMP_R_MULTIPLE_SAN_SOURCES; /* any reason code not about credential change */

static OSSL_CMP_PKISI *process_cert_request(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *cert_req,
    int certReqId,
    const OSSL_CRMF_MSG *crm,
    const X509_REQ *p10cr,
    X509 **certOut,
    STACK_OF(X509) **chainOut,
    STACK_OF(X509) **caPubs)
{
    ERR_raise(ERR_LIB_CMP, dummy_errorCode);
    return NULL;
}

static int delay_delivery(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req)
{
    return 1; /* always expect the client to poll */
}

static OSSL_CMP_MSG *poll_with_credential_case(CMP_SRV_TEST_FIXTURE *fixture,
    OSSL_CMP_CTX *client_ctx, const OSSL_CMP_PKIHEADER *first_hdr, OSSL_CMP_MSG *rsp)
{
    OSSL_CMP_MSG *poll_req = NULL;
    OSSL_CMP_PKISI *statusInfo;
    X509_NAME *sender = NULL;
    ASN1_OCTET_STRING *senderKID = NULL;

    if (!TEST_int_eq(OSSL_CMP_MSG_get_bodytype(rsp), OSSL_CMP_PKIBODY_ERROR)
        || !TEST_ptr(statusInfo = rsp->body->value.error->pKIStatusInfo)
        || !TEST_int_eq(ossl_cmp_pkisi_get_status(statusInfo), OSSL_CMP_PKISTATUS_waiting)
        /* prepare for next request with values from the first header; subject will determine sender */
        || !TEST_true(OSSL_CMP_CTX_set1_subjectName(client_ctx, first_hdr->sender->d.directoryName))
        || !TEST_true(OSSL_CMP_CTX_set1_transactionID(client_ctx, first_hdr->transactionID))
        || !TEST_true(ossl_cmp_ctx_set1_recipNonce(client_ctx, rsp->header->senderNonce))
        /* select PBM and set the secret; no need to set the reference value */
        || !TEST_true(OSSL_CMP_CTX_set1_secretValue(client_ctx, TEST_PBM_SECRET))
        || !TEST_ptr(first_hdr->protectionAlg)
        || !TEST_true(ossl_cmp_ctx_set1_protectionAlg(client_ctx, first_hdr->protectionAlg)))
        goto end;
    OSSL_CMP_MSG_free(rsp);
    rsp = NULL;

    if (!TEST_ptr(poll_req = ossl_cmp_pollReq_new(client_ctx, OSSL_CMP_CERTREQID)))
        goto end;
    if (first_hdr->senderKID != NULL
        && !TEST_true(ossl_cmp_hdr_set1_senderKID(poll_req->header, first_hdr->senderKID)))
        goto end;
    switch (fixture->reason) {
    case CMP_R_UNSUPPORTED_PKIBODY:
        break;
    case CMP_R_UNEXPECTED_SENDER:
        if (!TEST_ptr(sender = X509_NAME_new())
            || !TEST_true(X509_NAME_add_entry_by_txt(sender, "CN", MBSTRING_ASC,
                (const unsigned char *)"different sender", -1, -1, 0))
            || !TEST_true(ossl_cmp_hdr_set1_sender(poll_req->header, sender)))
            goto end;
        break;
    case CMP_R_ERROR_CREDENTIALS_CHANGED:
        if (!TEST_ptr(senderKID = ASN1_OCTET_STRING_new()) /* empty KID */
            || !TEST_true(ossl_cmp_hdr_set1_senderKID(poll_req->header, senderKID)))
            goto end;
        break;
    case CMP_R_ERROR_ALGORITHM_CHANGED:
        if (fixture->change_parameters_only) {
            /*
             * Remove the selected protection algorithm, so reprotection will use a fresh PBM salt.
             * Yet this does not change the algorithm itself, so the server should not complain on this.
             */
            if (!TEST_true(ossl_cmp_ctx_set1_protectionAlg(client_ctx, NULL)))
                goto end;
        } else {
            /* Removing protection is also treated as an algorithm change. */
            if (!TEST_true(OSSL_CMP_CTX_set_option(client_ctx, OSSL_CMP_OPT_UNPROTECTED_SEND, 1)))
                goto end;
        }
        break;
    default:
        TEST_error("invalid credential change case");
        goto end;
    }
    if (!TEST_true(ossl_cmp_msg_protect(client_ctx, poll_req))) /* adapt protection of the message */
        goto end;
    (void)TEST_ptr(rsp = OSSL_CMP_CTX_server_perform(client_ctx, poll_req));

end:
    OSSL_CMP_MSG_free(poll_req);
    X509_NAME_free(sender);
    ASN1_OCTET_STRING_free(senderKID);
    return rsp;
}

static int execute_test_handle_request(CMP_SRV_TEST_FIXTURE *fixture)
{
    OSSL_CMP_SRV_CTX *ctx = fixture->srv_ctx;
    OSSL_CMP_CTX *client_ctx;
    OSSL_CMP_CTX *cmp_ctx;
    char *dummy_custom_ctx = "@test_dummy", *custom_ctx;
    const OSSL_CMP_PKIHEADER *first_hdr = fixture->req->header;
    OSSL_CMP_MSG *rsp = NULL;
    OSSL_CMP_ERRORMSGCONTENT *errorContent;
    int use_polling = fixture->reason != dummy_errorCode;
    int expected_error = fixture->change_parameters_only ? CMP_R_UNSUPPORTED_PKIBODY : fixture->reason;
    int res = 0;

    if (!TEST_ptr(client_ctx = OSSL_CMP_CTX_new(libctx, NULL))
        || !TEST_true(OSSL_CMP_CTX_set_transfer_cb_arg(client_ctx, ctx)))
        goto end;

    if (!TEST_true(OSSL_CMP_SRV_CTX_init(ctx, dummy_custom_ctx,
            process_cert_request, NULL, NULL,
            NULL, NULL, NULL))
        || !TEST_true(OSSL_CMP_SRV_CTX_init_trans(ctx, use_polling ? delay_delivery : NULL, NULL))
        || !TEST_ptr(custom_ctx = OSSL_CMP_SRV_CTX_get0_custom_ctx(ctx))
        || !TEST_int_eq(strcmp(custom_ctx, dummy_custom_ctx), 0))
        goto end;

    if (!TEST_true(OSSL_CMP_SRV_CTX_set_send_unprotected_errors(ctx, 0))
        || !TEST_true(OSSL_CMP_SRV_CTX_set_accept_unprotected(ctx, 0))
        || !TEST_true(OSSL_CMP_SRV_CTX_set_accept_raverified(ctx, 1))
        || !TEST_true(OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(ctx, 1))
        || !TEST_true(OSSL_CMP_SRV_CTX_set_enforce_same_credentials(ctx, 1))
        || !TEST_ptr(cmp_ctx = OSSL_CMP_SRV_CTX_get0_cmp_ctx(ctx))
        || !OSSL_CMP_CTX_set1_referenceValue(cmp_ctx, (unsigned char *)"server", 6)
        || !OSSL_CMP_CTX_set1_secretValue(cmp_ctx, TEST_PBM_SECRET))
        goto end;

    if (!TEST_ptr(rsp = OSSL_CMP_CTX_server_perform(client_ctx, fixture->req)))
        goto end;
    if (use_polling && !TEST_ptr(rsp = poll_with_credential_case(fixture, client_ctx, first_hdr, rsp)))
        goto end;

    if (!TEST_int_eq(OSSL_CMP_MSG_get_bodytype(rsp), OSSL_CMP_PKIBODY_ERROR)
        || !TEST_ptr(errorContent = rsp->body->value.error)
        || !TEST_int_eq(ASN1_INTEGER_get(errorContent->errorCode), ERR_PACK(ERR_LIB_CMP, 0, expected_error)))
        goto end;

    res = 1;

end:
    OSSL_CMP_MSG_free(rsp);
    OSSL_CMP_CTX_free(client_ctx);
    return res;
}

static int test_handle_request_case(int credential_change_reason, int params_only)
{
    SETUP_TEST_FIXTURE(CMP_SRV_TEST_FIXTURE, set_up);
    fixture->req = request;
    fixture->reason = credential_change_reason;
    fixture->change_parameters_only = params_only;
    EXECUTE_TEST(execute_test_handle_request, tear_down);
    return result;
}

static int test_handle_request_no_credential_change(void)
{
    return test_handle_request_case(CMP_R_UNSUPPORTED_PKIBODY, 0);
}

static int test_handle_request(void)
{
    return test_handle_request_case(dummy_errorCode, 0);
}

static int test_handle_request_sender_change(void)
{
    return test_handle_request_case(CMP_R_UNEXPECTED_SENDER, 0);
}

static int test_handle_request_senderKID_change(void)
{
    return test_handle_request_case(CMP_R_ERROR_CREDENTIALS_CHANGED, 0);
}

static int test_handle_request_protection_parameters_change(void)
{
    return test_handle_request_case(CMP_R_ERROR_ALGORITHM_CHANGED, 1);
}

static int test_handle_request_protection_algorithm_change(void)
{
    return test_handle_request_case(CMP_R_ERROR_ALGORITHM_CHANGED, 0);
}

void cleanup_tests(void)
{
    OSSL_CMP_MSG_free(request);
    OSSL_PROVIDER_unload(default_null_provider);
    OSSL_PROVIDER_unload(provider);
    OSSL_LIB_CTX_free(libctx);
    return;
}

#define USAGE \
    "CR_protected_PBM_1234.der module_name [module_conf_file]\n"
OPT_TEST_DECLARE_USAGE(USAGE)

int setup_tests(void)
{
    const char *request_f;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(request_f = test_get_argument(0))) {
        TEST_error("usage: cmp_server_test %s", USAGE);
        return 0;
    }

    if (!test_arg_libctx(&libctx, &default_null_provider, &provider, 1, USAGE))
        return 0;

    if (!TEST_ptr(request = load_pkimsg(request_f, libctx))) {
        cleanup_tests();
        return 0;
    }

    /*
     * the below cases (indirectly) call
     * OSSL_CMP_SRV_CTX_new(),
     * OSSL_CMP_SRV_CTX_free(),
     * OSSL_CMP_CTX_server_perform(),
     * OSSL_CMP_SRV_process_request(),
     * OSSL_CMP_SRV_CTX_init(),
     * OSSL_CMP_SRV_CTX_get0_cmp_ctx(),
     * OSSL_CMP_SRV_CTX_get0_custom_ctx(),
     * OSSL_CMP_SRV_CTX_set_send_unprotected_errors(),
     * OSSL_CMP_SRV_CTX_set_accept_unprotected(),
     * OSSL_CMP_SRV_CTX_set_accept_raverified(), and
     * OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(), and
     * OSSL_CMP_SRV_CTX_set_enforce_same_credentials()
     */
    ADD_TEST(test_handle_request);
    ADD_TEST(test_handle_request_no_credential_change);
    ADD_TEST(test_handle_request_sender_change);
    ADD_TEST(test_handle_request_senderKID_change);
    ADD_TEST(test_handle_request_protection_parameters_change);
    ADD_TEST(test_handle_request_protection_algorithm_change);
    return 1;
}
