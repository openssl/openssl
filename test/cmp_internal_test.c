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

#include "../crypto/cmp/cmp_int.h"

static const char *server_f;
static const char *ir_protected_f;
static const char *ir_unprotected_f;
static const char *ip_PBM_f;

/* Add test code as per
 * http://wiki.openssl.org/index.php/How_To_Write_Unit_Tests_For_OpenSSL#Style
 */
typedef struct test_fixture {
    const char *test_case_name;
    OSSL_CMP_CTX *cmp_ctx;
    /* for protection tests */
    OSSL_CMP_MSG *msg;
    OSSL_CMP_PKISI *si;      /* for error and response messages */
    ASN1_OCTET_STRING *secret;
    EVP_PKEY *privkey;
    EVP_PKEY *pubkey;
    unsigned char *mem;
    int memlen;
    int expected;
} CMP_INT_TEST_FIXTURE;

static CMP_INT_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_INT_TEST_FIXTURE *fixture;
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

static void tear_down(CMP_INT_TEST_FIXTURE *fixture)
{
    /* ERR_print_errors_fp(stderr);
       Free any memory owned by the fixture, etc. */
    OSSL_CMP_CTX_delete(fixture->cmp_ctx);
    OSSL_CMP_MSG_free(fixture->msg);
    ASN1_OCTET_STRING_free(fixture->secret);
    EVP_PKEY_free(fixture->privkey);
    EVP_PKEY_free(fixture->pubkey);
    OSSL_CMP_PKISI_free(fixture->si);

    OPENSSL_free(fixture->mem);
    OPENSSL_free(fixture);
}

static EVP_PKEY *loadedprivkey = NULL;
static EVP_PKEY *loadedpubkey = NULL;

static int execute_calc_protection_fails_test(CMP_INT_TEST_FIXTURE *fixture)
{
    ASN1_BIT_STRING *protection = NULL;
    int res = TEST_ptr_null(protection =
                            CMP_calc_protection(fixture->msg, fixture->secret,
                                                fixture->privkey));
    ASN1_BIT_STRING_free(protection);
    return res;
}

/* TODO internal test*/
static int execute_calc_protection_test(CMP_INT_TEST_FIXTURE *fixture)
{
    ASN1_BIT_STRING *protection = NULL;
    int res =
        TEST_ptr(protection = CMP_calc_protection(fixture->msg, fixture->secret,
                                                  fixture->privkey)) &&
        TEST_true(ASN1_STRING_cmp(protection,
                                  fixture->msg->protection) == 0);
    ASN1_BIT_STRING_free(protection);
    return res;
}

/* This function works similar to parts of CMP_verify_signature in cmp_vfy.c,
 * but without the need for a OSSL_CMP_CTX or a X509 certificate */
static int verify_signature(OSSL_CMP_MSG *msg,
                            ASN1_BIT_STRING *protection,
                            EVP_PKEY *pkey, int digest_nid)
{
    CMP_PROTECTEDPART prot_part;
    unsigned char *prot_part_der = NULL;
    int l;
    EVP_MD_CTX *ctx = NULL;
    int res;

    prot_part.header = OSSL_CMP_MSG_get0_header(msg);
    prot_part.body = msg->body;
    res =
        TEST_int_ge(l = i2d_CMP_PROTECTEDPART(&prot_part, &prot_part_der), 0) &&
        TEST_ptr(ctx = EVP_MD_CTX_create()) &&
        TEST_true(EVP_VerifyInit_ex
                  (ctx, (EVP_MD *)EVP_get_digestbynid(digest_nid), NULL))
        && TEST_true(EVP_VerifyUpdate(ctx, prot_part_der, l))
        && TEST_int_eq(EVP_VerifyFinal(ctx, protection->data,
                                       protection->length, pkey), 1);
    /* cleanup */
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(prot_part_der);
    return res;
}

/* Calls OSSL_CMP_calc_protection and verifies signature*/
static int execute_calc_protection_signature_test(CMP_INT_TEST_FIXTURE *
                                                  fixture)
{
    ASN1_BIT_STRING *protection = NULL;
    int ret = (TEST_ptr(protection =
                        CMP_calc_protection(fixture->msg, NULL,
                                                 fixture->privkey)) &&
               TEST_true(verify_signature(fixture->msg, protection,
                                           fixture->pubkey,
                                          fixture->cmp_ctx->digest)));
    ASN1_BIT_STRING_free(protection);
    return ret;
}

/* TODO TPa: find a way to set protection algorithm */
static int test_cmp_calc_protection_no_key_no_secret(void)
{
    SETUP_TEST_FIXTURE(CMP_INT_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_unprotected_f)) ||
        !TEST_ptr(fixture->msg->header->protectionAlg = X509_ALGOR_new())) {
        tear_down(fixture);
        fixture = NULL;
    }

    EXECUTE_TEST(execute_calc_protection_fails_test, tear_down);
    return result;
}

/* TODO TPa: find openssl-independent reference value */
static int test_cmp_calc_protection_pkey(void)
{
    SETUP_TEST_FIXTURE(CMP_INT_TEST_FIXTURE, set_up);
    fixture->pubkey = loadedpubkey;
    fixture->privkey = loadedprivkey;
    if (!TEST_true(EVP_PKEY_up_ref(loadedpubkey)) ||
        !TEST_true(EVP_PKEY_up_ref(loadedprivkey)) ||
        !TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_calc_protection_signature_test, tear_down);
    return result;
}

static int test_cmp_calc_protection_pbmac(void)
{
    SETUP_TEST_FIXTURE(CMP_INT_TEST_FIXTURE, set_up);
    unsigned char sec_insta[] = { 'i', 'n', 's', 't', 'a' };

    if (!TEST_ptr(fixture->secret = ASN1_OCTET_STRING_new()) ||
        !TEST_true(ASN1_OCTET_STRING_set
                   (fixture->secret, sec_insta, sizeof(sec_insta))) ||
        !TEST_ptr(fixture->msg = load_pkimsg(ip_PBM_f))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_calc_protection_test, tear_down);
    return result;
}

void cleanup_tests(void)
{
    EVP_PKEY_free(loadedprivkey);
    EVP_PKEY_free(loadedpubkey);
}

int setup_tests(void)
{
    if (!TEST_ptr(server_f = test_get_argument(0)) ||
        !TEST_ptr(ir_protected_f = test_get_argument(1)) ||
        !TEST_ptr(ir_unprotected_f = test_get_argument(2)) ||
        !TEST_ptr(ip_PBM_f = test_get_argument(3))) {
        TEST_error("usage: cmp_internal_test server.pem"
                   "IR_protected.der IR_unprotected.der IP_PBM.der\n");
        return 0;
    }

    if (!TEST_ptr(loadedprivkey = load_pem_key(server_f)))
        return 0;
    if (TEST_true(EVP_PKEY_up_ref(loadedprivkey)))
        loadedpubkey = loadedprivkey;

    /* Message protection tests */
    ADD_TEST(test_cmp_calc_protection_no_key_no_secret);
    ADD_TEST(test_cmp_calc_protection_pkey);
    ADD_TEST(test_cmp_calc_protection_pbmac);

    return 1;
}
