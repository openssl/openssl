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

static const char *server_cert_f;
static const char *pkcs10_f;

typedef struct test_fixture {
    const char *test_case_name;
    OSSL_CMP_CTX *cmp_ctx;
    /* for msg create tests */
    int bodytype;
    int err_code;
    /* for protection tests */
    OSSL_CMP_MSG *msg;
    int expected;               /* expected outcome */
    OSSL_CMP_PKISI *si;      /* for error and response messages */
} CMP_MSG_TEST_FIXTURE;

static unsigned char ref[CMP_TEST_REFVALUE_LENGTH];

static CMP_MSG_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_MSG_TEST_FIXTURE *fixture;
    int setup_ok = 0;
    /* Allocate memory owned by the fixture, exit on error */
    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))))
        goto err;
    fixture->test_case_name = test_case_name;

    if (!TEST_ptr(fixture->cmp_ctx = OSSL_CMP_CTX_create()) ||
        !TEST_true(OSSL_CMP_CTX_set_option(fixture->cmp_ctx,
                                      OSSL_CMP_CTX_OPT_UNPROTECTED_SEND, 1)) ||
        !TEST_true(OSSL_CMP_CTX_set1_referenceValue(fixture->cmp_ctx, ref,
                                               sizeof(ref))))
        goto err;

    setup_ok = 1;
 err:
    if (!setup_ok) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static void tear_down(CMP_MSG_TEST_FIXTURE *fixture)
{
    /* ERR_print_errors_fp(stderr);
       Free any memory owned by the fixture, etc. */
    OSSL_CMP_CTX_delete(fixture->cmp_ctx);
    OSSL_CMP_MSG_free(fixture->msg);
    OSSL_CMP_PKISI_free(fixture->si);
    OPENSSL_free(fixture);
}

static EVP_PKEY *newkey = NULL;
static X509 *cert = NULL;

#define EXECUTE_MSG_CREATION_TEST(expr) \
do { \
    OSSL_CMP_MSG *msg = NULL; \
    int good = fixture->expected ? \
            TEST_ptr(msg = expr) && TEST_true(valid_asn1_encoding(msg)) : \
            TEST_ptr_null(msg = expr); \
    OSSL_CMP_MSG_free(msg); \
    return good; \
} while(0)

/* The following tests call a cmp message creation function.
 * if fixture->expected != 0:
 *         returns 1 if the message is created and syntactically correct.
 * if fixture->expected == 0
 *         returns 1 if message creation returns NULL                         */
static int execute_certreq_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(OSSL_CMP_certreq_new(fixture->cmp_ctx,
                                              fixture->bodytype,
                                              fixture->err_code));
}

static int execute_errormsg_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(OSSL_CMP_error_new(fixture->cmp_ctx, fixture->si,
                                                 fixture->err_code,
                                                 NULL/* fixture->free_text */, 0));
}

static int execute_rr_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(OSSL_CMP_rr_new(fixture->cmp_ctx));
}

static int execute_certconf_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(OSSL_CMP_certConf_new
                              (fixture->cmp_ctx, fixture->err_code, NULL));
}

static int execute_genm_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(OSSL_CMP_genm_new(fixture->cmp_ctx));
}

static int execute_pollreq_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(OSSL_CMP_pollReq_new(fixture->cmp_ctx, 4711));
}

static int execute_pkimessage_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(OSSL_CMP_MSG_create
                              (fixture->cmp_ctx, fixture->bodytype));
}

static int test_cmp_create_ir_protection_set(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    unsigned char secret[16];
    fixture->bodytype = OSSL_CMP_PKIBODY_IR;
    fixture->err_code = CMP_R_ERROR_CREATING_IR;
    fixture->expected = 1;
    if (!TEST_int_eq(1, RAND_bytes(secret, sizeof(secret))) ||
        !TEST_true(OSSL_CMP_CTX_set_option(fixture->cmp_ctx,
                                      OSSL_CMP_CTX_OPT_UNPROTECTED_SEND, 0)) ||
        !TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey)) ||
        !TEST_true(OSSL_CMP_CTX_set1_secretValue(fixture->cmp_ctx, secret,
                                            sizeof(secret)))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_ir_protection_fails(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = OSSL_CMP_PKIBODY_IR;
    fixture->err_code = CMP_R_ERROR_CREATING_IR;
    fixture->expected = 0;
    if (!TEST_true(OSSL_CMP_CTX_set1_pkey(fixture->cmp_ctx, newkey)) ||
        !TEST_true(OSSL_CMP_CTX_set_option(fixture->cmp_ctx,
                                      OSSL_CMP_CTX_OPT_UNPROTECTED_SEND, 0)) ||
        !TEST_true(OSSL_CMP_CTX_set1_clCert(fixture->cmp_ctx, cert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_cr_without_key(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = OSSL_CMP_PKIBODY_CR;
    fixture->err_code = CMP_R_ERROR_CREATING_CR;
    fixture->expected = 0;
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_cr(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = OSSL_CMP_PKIBODY_CR;
    fixture->err_code = CMP_R_ERROR_CREATING_CR;
    fixture->expected = 1;
    if (!TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_certreq_with_invalid_bodytype(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = OSSL_CMP_PKIBODY_RR;
    fixture->err_code = CMP_R_ERROR_CREATING_IR;
    fixture->expected = 0;
    if (!TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_p10cr(void)
{
    X509_REQ *p10cr = NULL;

    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = OSSL_CMP_PKIBODY_P10CR;
    fixture->err_code = CMP_R_ERROR_CREATING_P10CR;
    fixture->expected = 1;
    if (!TEST_ptr(p10cr = load_csr(pkcs10_f)) ||
        !TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey)) ||
        !TEST_true(OSSL_CMP_CTX_set1_p10CSR(fixture->cmp_ctx, p10cr))) {
        tear_down(fixture);
        fixture = NULL;
    }
    X509_REQ_free(p10cr);
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_p10cr_null(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = OSSL_CMP_PKIBODY_P10CR;
    fixture->err_code = CMP_R_ERROR_CREATING_P10CR;
    fixture->expected = 0;
    if (!TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_kur(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = OSSL_CMP_PKIBODY_KUR;
    fixture->err_code = CMP_R_ERROR_CREATING_KUR;
    fixture->expected = 1;
    if (!TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey)) ||
        !TEST_true(OSSL_CMP_CTX_set1_oldClCert(fixture->cmp_ctx, cert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_kur_without_oldcert(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->bodytype = OSSL_CMP_PKIBODY_KUR;
    fixture->err_code = CMP_R_ERROR_CREATING_KUR;
    fixture->expected = 0;
    if (!TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_certconf(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->err_code = 12345;  /* TODO hardcoded */
    fixture->expected = 1;
    if (!TEST_true(OSSL_CMP_CTX_set1_newClCert(fixture->cmp_ctx, cert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certconf_create_test, tear_down);
    return result;
}

static int test_cmp_create_certconf_without_newclcert(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->err_code = 12345;  /* TODO hardcoded */
    fixture->expected = 0;
    if (!TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certconf_create_test, tear_down);
    return result;
}

static int test_cmp_create_error_msg(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->si = OSSL_CMP_statusInfo_new(OSSL_CMP_PKISTATUS_rejection,
                                     OSSL_CMP_PKIFAILUREINFO_systemFailure, NULL);
    fixture->err_code = -1;
    fixture->expected = 1;      /* Expected: Message creation is successful */
    if (!TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_errormsg_create_test, tear_down);
    return result;
}

static int test_cmp_create_error_msg_without_si(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->si = NULL;
    fixture->err_code = -1;
    fixture->expected = 0;      /* Expected: Message creation fails */
    if (!TEST_true(OSSL_CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_errormsg_create_test, tear_down);
    return result;
}

static int test_cmp_create_pollreq(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_pollreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_rr(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    if (!TEST_true(OSSL_CMP_CTX_set1_oldClCert(fixture->cmp_ctx, cert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_rr_create_test, tear_down);
    return result;
}

static int test_cmp_create_rr_without_oldcert(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->expected = 0;
    EXECUTE_TEST(execute_rr_create_test, tear_down);
    return result;
}

static int test_cmp_create_genm(void)
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    OSSL_CMP_ITAV *itv = NULL;

    OSSL_CMP_CTX_set_option(fixture->cmp_ctx, OSSL_CMP_CTX_OPT_UNPROTECTED_SEND, 1);
    fixture->expected = 1;
    if (!TEST_ptr
        (itv = OSSL_CMP_ITAV_gen(OBJ_nid2obj(NID_id_it_implicitConfirm), NULL))
        || !TEST_true(OSSL_CMP_CTX_genm_itav_push0(fixture->cmp_ctx, itv))) {
        OSSL_CMP_ITAV_free(itv);
        tear_down(fixture);
        fixture = NULL;
    }

    EXECUTE_TEST(execute_genm_create_test, tear_down);
    return result;
}

static int test_cmp_pkimessage_create(int bodytype)
{
    X509_REQ *p10cr = NULL;
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);

    switch (fixture->bodytype = bodytype) {
    case OSSL_CMP_PKIBODY_P10CR:
        fixture->expected = 1;
        if (!TEST_true(OSSL_CMP_CTX_set1_p10CSR(fixture->cmp_ctx,
                                                p10cr = load_csr(pkcs10_f)))) {
            tear_down(fixture);
            fixture = NULL;
        }
        X509_REQ_free(p10cr);
        break;
    case OSSL_CMP_PKIBODY_IR:
    case OSSL_CMP_PKIBODY_IP:
    case OSSL_CMP_PKIBODY_CR:
    case OSSL_CMP_PKIBODY_CP:
    case OSSL_CMP_PKIBODY_KUR:
    case OSSL_CMP_PKIBODY_KUP:
    case OSSL_CMP_PKIBODY_RR:
    case OSSL_CMP_PKIBODY_RP:
    case OSSL_CMP_PKIBODY_PKICONF:
    case OSSL_CMP_PKIBODY_GENM:
    case OSSL_CMP_PKIBODY_GENP:
    case OSSL_CMP_PKIBODY_ERROR:
    case OSSL_CMP_PKIBODY_CERTCONF:
    case OSSL_CMP_PKIBODY_POLLREQ:
    case OSSL_CMP_PKIBODY_POLLREP:
        fixture->expected = 1;
        break;
    default:
        fixture->expected = 0;
        break;
    }

    EXECUTE_TEST(execute_pkimessage_create_test, tear_down);
    return result;
}

void cleanup_tests(void)
{
    EVP_PKEY_free(newkey);
    X509_free(cert);
}

int setup_tests(void)
{
    if (!TEST_ptr(server_cert_f = test_get_argument(0)) ||
        !TEST_ptr(pkcs10_f = test_get_argument(1))) {
        TEST_error("usage: cmp_msg_test server.crt pkcs10.der\n");
        return 0;
    }

    if (!TEST_ptr(newkey = gen_rsa()) ||
        !TEST_ptr(cert =
                  load_pem_cert(server_cert_f)) ||
        !TEST_int_eq(1, RAND_bytes(ref, sizeof(ref))))
        return 0;

    /* Message creation tests */
    ADD_TEST(test_cmp_create_certreq_with_invalid_bodytype);
    ADD_TEST(test_cmp_create_ir_protection_fails);
    ADD_TEST(test_cmp_create_ir_protection_set);
    ADD_TEST(test_cmp_create_error_msg);
    ADD_TEST(test_cmp_create_error_msg_without_si);
    ADD_TEST(test_cmp_create_certconf);
    ADD_TEST(test_cmp_create_certconf_without_newclcert);
    ADD_TEST(test_cmp_create_kur);
    ADD_TEST(test_cmp_create_kur_without_oldcert);
    ADD_TEST(test_cmp_create_cr);
    ADD_TEST(test_cmp_create_cr_without_key);
    ADD_TEST(test_cmp_create_p10cr);
    ADD_TEST(test_cmp_create_p10cr_null);
    ADD_TEST(test_cmp_create_pollreq);
    ADD_TEST(test_cmp_create_rr);
    ADD_TEST(test_cmp_create_rr_without_oldcert);
    ADD_TEST(test_cmp_create_genm);
    ADD_ALL_TESTS_NOSUBTEST(test_cmp_pkimessage_create,
                            OSSL_CMP_PKIBODY_POLLREP + 1);

    return 1;
}
