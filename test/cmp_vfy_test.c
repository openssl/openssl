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
 * CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.
 */

#include "cmptestlib.h"

static const char *server_f;
static const char *client_f;
static const char *endentity1_f;
static const char *endentity2_f;
static const char *root_f;
static const char *intermediate_f;
static const char *ir_protected_f;
static const char *ir_unprotected_f;
static const char *ip_waiting_f;

typedef struct test_fixture {
    const char *test_case_name;
    int expected;
    OSSL_CMP_CTX *cmp_ctx;
    OSSL_CMP_MSG *msg;
    X509 *cert;
} CMP_VFY_TEST_FIXTURE;

static CMP_VFY_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_VFY_TEST_FIXTURE *fixture;
    int setup_ok = 0;
    /* Allocate memory owned by the fixture, exit on error */
    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))))
        goto err;
    fixture->test_case_name = test_case_name;
    if (!TEST_ptr(fixture->cmp_ctx = OSSL_CMP_CTX_create()))
        goto err;

    setup_ok = 1;
 err:
    if (!setup_ok) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static void tear_down(CMP_VFY_TEST_FIXTURE *fixture)
{
    OSSL_CMP_MSG_free(fixture->msg);
    OSSL_CMP_CTX_delete(fixture->cmp_ctx);
    OPENSSL_free(fixture);
}

static time_t test_time_valid = 0, test_time_future = 0;

static X509 *srvcert = NULL;
static X509 *clcert = NULL;
/* chain */
static X509 *endentity1 = NULL, *endentity2 = NULL,
    *intermediate = NULL, *root = NULL;

static int execute_validation_test(CMP_VFY_TEST_FIXTURE *fixture)
{
    return TEST_int_eq(fixture->expected,
                       OSSL_CMP_validate_msg(fixture->cmp_ctx, fixture->msg));
}

static int execute_cmp_validate_cert_path_test(CMP_VFY_TEST_FIXTURE *fixture)
{
    return TEST_int_eq(fixture->expected,
                       OSSL_CMP_validate_cert_path(fixture->cmp_ctx,
                                              OSSL_CMP_CTX_get0_trustedStore
                                              (fixture->cmp_ctx), fixture->cert,
                                              0));
}

static int test_cmp_validate_msg_mac_alg_protection(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* secret value belonging to cmp-test/CMP_IP_waitingStatus_PBM.der */
    const unsigned char sec_1[] =
        { '9', 'p', 'p', '8', '-', 'b', '3', '5', 'i', '-', 'X', 'd', '3',
        'Q', '-', 'u', 'd', 'N', 'R'
    };
    fixture->expected = 1;

    if (!TEST_true
        (OSSL_CMP_CTX_set1_secretValue(fixture->cmp_ctx, sec_1, sizeof(sec_1)))
        || !TEST_ptr(fixture->msg = load_pkimsg(ip_waiting_f))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validation_test, tear_down);
    return result;
}

static int test_cmp_validate_msg_mac_alg_protection_bad(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    const unsigned char sec_bad[] =
        { '9', 'p', 'p', '8', '-', 'b', '3', '5', 'i', '-', 'X', 'd', '3',
        'Q', '-', 'u', 'd', 'N', 'r'
    };
    fixture->expected = 0;

    if (!TEST_true
        (OSSL_CMP_CTX_set1_secretValue(fixture->cmp_ctx, sec_bad,
                                       sizeof(sec_bad)))
        || !TEST_ptr(fixture->msg = load_pkimsg(ip_waiting_f))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validation_test, tear_down);
    return result;
}

static int test_cmp_validate_msg_signature(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 1;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f)) ||
        !TEST_true(OSSL_CMP_CTX_set1_srvCert(fixture->cmp_ctx, srvcert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validation_test, tear_down);
    return result;
}

static int test_cmp_validate_msg_signature_bad(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 0;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f)) ||
        !TEST_true(OSSL_CMP_CTX_set1_srvCert(fixture->cmp_ctx, clcert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validation_test, tear_down);
    return result;
}

static int test_cmp_validate_msg_signature_expected_sender(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 1;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f)) ||
        !TEST_true(OSSL_CMP_CTX_set1_srvCert(fixture->cmp_ctx, srvcert)) ||
        /* Set wrong expected sender name*/
        !TEST_true(OSSL_CMP_CTX_set1_expected_sender(fixture->cmp_ctx,
                                             X509_get_subject_name(srvcert)))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validation_test, tear_down);
    return result;
}

static int test_cmp_validate_msg_signature_unexpected_sender(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 0;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f)) ||
        !TEST_true(OSSL_CMP_CTX_set1_srvCert(fixture->cmp_ctx, srvcert)) ||
        /* Set wrong expected sender name*/
        !TEST_true(OSSL_CMP_CTX_set1_expected_sender(fixture->cmp_ctx,
                                                X509_get_subject_name(root)))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validation_test, tear_down);
    return result;
}


static int test_cmp_validate_msg_unprotected_request(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 0;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_unprotected_f))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validation_test, tear_down);
    return result;
}

static int test_cmp_validate_cert_path(void)
{
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE *trusted = NULL;
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->cert = endentity2;
    fixture->expected = 1;
    if (!TEST_ptr(untrusted = OSSL_CMP_CTX_get0_untrusted_certs(fixture->cmp_ctx)) ||
        !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, endentity1)) ||
        !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, intermediate)) ||
        !TEST_true(trusted = OSSL_CMP_CTX_get0_trustedStore(fixture->cmp_ctx)) ||
        !TEST_true(X509_STORE_add_cert(trusted, root))) {
        tear_down(fixture);
        fixture = NULL;
    } else {
        X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(trusted),
                                   test_time_valid);
    }
    EXECUTE_TEST(execute_cmp_validate_cert_path_test, tear_down);
    return result;
}

static int test_cmp_validate_cert_path_no_anchor(void)
{
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE *trusted = NULL;
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->cert = endentity2;
    fixture->expected = 0;
    if (!TEST_ptr(untrusted =
                  OSSL_CMP_CTX_get0_untrusted_certs(fixture->cmp_ctx)) ||
        !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, endentity1)) ||
        !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, intermediate)) ||
        !TEST_true(trusted = OSSL_CMP_CTX_get0_trustedStore(fixture->cmp_ctx)) ||
        /* Wrong anchor */
        !TEST_true(X509_STORE_add_cert(trusted, srvcert))) {
        tear_down(fixture);
        fixture = NULL;
    } else {
        X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(trusted),
                                   test_time_valid);
    }
    EXECUTE_TEST(execute_cmp_validate_cert_path_test, tear_down);
    return result;
}

static int test_cmp_validate_cert_path_expired(void)
{

    STACK_OF(X509) *untrusted = NULL;
    X509_STORE *trusted = NULL;
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->cert = endentity2;
    fixture->expected = 0;
    if (!TEST_ptr(untrusted =
                  OSSL_CMP_CTX_get0_untrusted_certs(fixture->cmp_ctx)) ||
        !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, endentity1)) ||
        !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, intermediate)) ||
        !TEST_true(trusted = OSSL_CMP_CTX_get0_trustedStore(fixture->cmp_ctx)) ||
        !TEST_true(X509_STORE_add_cert(trusted, root))) {
        tear_down(fixture);
        fixture = NULL;
    } else {
        X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(trusted),
                                   test_time_future);
    }
    EXECUTE_TEST(execute_cmp_validate_cert_path_test, tear_down);
    return result;
}

void cleanup_tests(void)
{
    X509_free(srvcert);
    X509_free(clcert);
    X509_free(endentity1);
    X509_free(endentity2);
    X509_free(intermediate);
    X509_free(root);
    return;
}

int setup_tests(void)
{
    /* Set test time stamps */
    struct tm ts = { 0 };
    ts.tm_year = 2018 - 1900;
    ts.tm_mon = 1;              /* February */
    ts.tm_mday = 18;
    test_time_valid = mktime(&ts); /* February 18th 2018 */
    ts.tm_year += 10;           /* February 18th 2028 */
    test_time_future = mktime(&ts);

    if (!TEST_ptr(server_f = test_get_argument(0)) ||
        !TEST_ptr(client_f = test_get_argument(1)) ||
        !TEST_ptr(endentity1_f = test_get_argument(2)) ||
        !TEST_ptr(endentity2_f = test_get_argument(3)) ||
        !TEST_ptr(root_f = test_get_argument(4)) ||
        !TEST_ptr(intermediate_f = test_get_argument(5)) ||
        !TEST_ptr(ir_protected_f = test_get_argument(6)) ||
        !TEST_ptr(ir_unprotected_f = test_get_argument(7)) ||
        !TEST_ptr(ip_waiting_f = test_get_argument(8))) {
        TEST_error("usage: cmp_vfy_test server.crt client.crt"
                   "EndEntity1.crt EndEntity2.crt"
                   "Root_CA.crt Intermediate_CA.crt"
                   "CMP_IR_protected.der CMP_IR_unprotected.der"
                   "IP_waitingStatus_PBM.der\n");
        return 0;
    }

    /* Load certificates for cert chain */
    if (!TEST_ptr(endentity1 = load_pem_cert(endentity1_f)) ||
        !TEST_ptr(endentity2 = load_pem_cert(endentity2_f)) ||
        !TEST_ptr(root = load_pem_cert(root_f)) ||
        !TEST_ptr(intermediate = load_pem_cert(intermediate_f)))
        return 0;

    /* Load certificates for message validation */
    if (!TEST_ptr(srvcert = load_pem_cert(server_f)) ||
        !TEST_ptr(clcert = load_pem_cert(client_f)))
        return 0;

    /* Message validation tests */
    ADD_TEST(test_cmp_validate_msg_signature);
    ADD_TEST(test_cmp_validate_msg_signature_bad);
    ADD_TEST(test_cmp_validate_msg_signature_expected_sender);
    ADD_TEST(test_cmp_validate_msg_signature_unexpected_sender);
    ADD_TEST(test_cmp_validate_msg_unprotected_request);
    ADD_TEST(test_cmp_validate_msg_mac_alg_protection);
    ADD_TEST(test_cmp_validate_msg_mac_alg_protection_bad);

    /* Cert path validation tests */
    ADD_TEST(test_cmp_validate_cert_path);
    ADD_TEST(test_cmp_validate_cert_path_expired);
    ADD_TEST(test_cmp_validate_cert_path_no_anchor);

    return 1;
}
