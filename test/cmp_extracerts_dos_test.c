/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Regression test for: CMP server unauthenticated memory/CPU DoS via
 * cached extraCerts on failed protection checks.
 *
 * Root cause (crypto/cmp/cmp_vfy.c, ossl_cmp_msg_check_update(), current
 * master as of this writing):
 *
 *   res = ossl_x509_add_certs_new(&ctx->untrusted, msg->extraCerts, ...);
 *   ...
 *   res = OSSL_CMP_validate_msg(ctx, msg) || (cb...);   // may be 0 (rejected)
 *
 *   if (ctx->noCacheExtraCerts)                          // <-- rollback is
 *       while (num_added-- > 0)                          //  gated on this
 *           X509_free(sk_X509_shift(ctx->untrusted));    //  flag only, NOT
 *                                                          //  on the
 *                                                          //  validation
 *                                                          //  result (res)
 *
 *   if (!res) { ...; return 0; }   // certs from a REJECTED msg are kept
 *
 * This test exercises ossl_cmp_msg_check_update() directly -- no sockets,
 * no HTTP server, no apps/cmp.c -- and asserts on the resulting size of
 * ctx->untrusted. It builds a genuinely PBM-protected OSSL_CMP_MSG using
 * the project's own internal message-creation function
 * (ossl_cmp_genm_new(), same one exercised in test/cmp_msg_test.c) so the
 * message is not hand-crafted to "look" rejectable -- it is rejected for a
 * real reason (the receiving ctx has no matching secret configured), the
 * same way OSSL_CMP_validate_msg() would reject any unauthenticated CMP
 * request in the field.
 *
 * Expected results:
 *   - BEFORE the fix: untrusted_count_after == untrusted_count_before + N
 *     (every rejected message's extraCerts persist)
 *   - AFTER the fix:  untrusted_count_after == untrusted_count_before
 *     (rejected messages leave no residue)
 */

#include "helpers/cmp_testlib.h"

#define NUM_REJECTED_REQUESTS 25 /* "attacker" sends this many distinct certs */

typedef struct test_fixture {
    const char *test_case_name;
    OSSL_CMP_CTX *server_ctx; /* long-lived ctx under test, mirrors srv_ctx->ctx */
} CMP_DOS_TEST_FIXTURE;

static OSSL_LIB_CTX *libctx = NULL;

static CMP_DOS_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_DOS_TEST_FIXTURE *fixture;

    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))))
        return NULL;
    fixture->test_case_name = test_case_name;

    if (!TEST_ptr(fixture->server_ctx = OSSL_CMP_CTX_new(libctx, NULL))) {
        OPENSSL_free(fixture);
        return NULL;
    }
    /*
     * Deliberately do NOT call OSSL_CMP_CTX_set1_secretValue() on the
     * server ctx. Per OSSL_CMP_validate_msg() (crypto/cmp/cmp_vfy.c):
     *   case NID_id_PasswordBasedMAC:
     *     if (ctx->secretValue == NULL) {
     *         ossl_cmp_info(ctx, "no secret available for verifying..");
     *         ERR_raise(ERR_LIB_CMP, CMP_R_ERROR_VALIDATING_PROTECTION);
     *         return 0;
     *     }
     * so every PBM-protected message this ctx receives is unconditionally
     * rejected -- a deterministic, content-independent rejection path that
     * models "missing or invalid protection" from the report's repro
     * steps, without needing to forge a bad MAC by hand.
     * ctx->noCacheExtraCerts is left at its default (0), exactly as in the
     * vulnerable deployment ("not setting -no_cache_extracerts").
     */
    return fixture;
}

static void tear_down(CMP_DOS_TEST_FIXTURE *fixture)
{
    if (fixture == NULL)
        return;
    OSSL_CMP_CTX_free(fixture->server_ctx);
    OPENSSL_free(fixture);
}

/* Generates a throwaway EC P-256 keypair; cheap, and key strength is
 * irrelevant to this test. */
static EVP_PKEY *generate_throwaway_keypair(void)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL)))
        return NULL;
    if (!TEST_int_gt(EVP_PKEY_keygen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_group_name(pctx, "P-256"), 0)
        || !TEST_int_gt(EVP_PKEY_generate(pctx, &pkey), 0))
        pkey = NULL;
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/*
 * Builds a minimal, self-signed, syntactically valid X509 with a unique
 * subject/issuer per index, so X509_ADD_FLAG_NO_DUP cannot collapse it
 * with any other generated cert (matching the report's exploitation
 * requirement of "unique certificates across requests").
 */
static X509 *generate_unique_self_signed_cert(EVP_PKEY *pkey, int index)
{
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    ASN1_INTEGER *serial = NULL;
    char cn[64];

    BIO_snprintf(cn, sizeof(cn), "attacker-cert-%d", index);

    if (!TEST_ptr(cert = X509_new())
        || !TEST_true(X509_set_version(cert, X509_VERSION_3)))
        goto err;

    if (!TEST_ptr(serial = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set(serial, 1000L + index))
        || !TEST_true(X509_set_serialNumber(cert, serial)))
        goto err;

    if (!TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(cert), 0))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(cert),
            60L * 60L * 24L * 365L)))
        goto err;

    if (!TEST_true(X509_set_pubkey(cert, pkey)))
        goto err;

    if (!TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            (unsigned char *)"cmp-dos-test",
            -1, -1, 0))
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (unsigned char *)cn,
            -1, -1, 0))
        || !TEST_true(X509_set_subject_name(cert, name))
        || !TEST_true(X509_set_issuer_name(cert, name)))
        goto err;

    if (!TEST_int_gt(X509_sign(cert, pkey, EVP_sha256()), 0))
        goto err;

    X509_NAME_free(name);
    ASN1_INTEGER_free(serial);
    return cert;

err:
    X509_NAME_free(name);
    ASN1_INTEGER_free(serial);
    X509_free(cert);
    return NULL;
}

/*
 * Builds a real, internally consistent, PBM-protected CMP GenMsg carrying
 * exactly one never-before-seen self-signed cert as its sole extraCert.
 * Uses a throwaway *client*-side OSSL_CMP_CTX purely to drive message
 * creation/protection (ossl_cmp_genm_new() both builds the body and calls
 * ossl_cmp_msg_protect() internally, same as in test/cmp_msg_test.c). The
 * client ctx's secret is intentionally never shared with the server ctx
 * under test, so the message is protected (syntactically well-formed,
 * non-empty protection field) but NOT verifiable by the receiver -- this
 * is what "missing or invalid protection" means for a real attacker who
 * has no credentials, not an empty/garbage protection field.
 */
static OSSL_CMP_MSG *build_rejectable_msg_with_unique_cert(int index)
{
    OSSL_CMP_CTX *client_ctx = NULL;
    OSSL_CMP_MSG *msg = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *fresh_cert = NULL;
    STACK_OF(X509) *extra = NULL;
    unsigned char ref[16], secret[16];

    if (!TEST_ptr(client_ctx = OSSL_CMP_CTX_new(libctx, NULL)))
        goto err;

    if (!TEST_ptr(pkey = generate_throwaway_keypair())
        || !TEST_ptr(fresh_cert = generate_unique_self_signed_cert(pkey, index)))
        goto err;

    if (!TEST_ptr(extra = sk_X509_new_null())
        || !TEST_true(sk_X509_push(extra, fresh_cert)))
        goto err;
    fresh_cert = NULL; /* ownership now with the stack */

    if (!TEST_true(OSSL_CMP_CTX_set1_extraCertsOut(client_ctx, extra)))
        goto err;

    /* PBM protection with a secret the server ctx will never be given */
    memset(ref, (unsigned char)(0xA0 + (index & 0x0F)), sizeof(ref));
    memset(secret, (unsigned char)(0x50 + (index & 0x0F)), sizeof(secret));
    if (!TEST_true(OSSL_CMP_CTX_set_option(client_ctx,
            OSSL_CMP_OPT_UNPROTECTED_SEND, 0))
        || !TEST_true(OSSL_CMP_CTX_set1_referenceValue(client_ctx, ref,
            sizeof(ref)))
        || !TEST_true(OSSL_CMP_CTX_set1_secretValue(client_ctx, secret,
            sizeof(secret))))
        goto err;

    /* GenMsg is the lightest standard body type for this purpose */
    if (!TEST_ptr(msg = ossl_cmp_genm_new(client_ctx)))
        goto err;

    sk_X509_pop_free(extra, X509_free);
    X509_free(fresh_cert);
    EVP_PKEY_free(pkey);
    OSSL_CMP_CTX_free(client_ctx);
    return msg;

err:
    sk_X509_pop_free(extra, X509_free);
    X509_free(fresh_cert);
    EVP_PKEY_free(pkey);
    OSSL_CMP_CTX_free(client_ctx);
    OSSL_CMP_MSG_free(msg);
    return NULL;
}

/*
 * Core assertion: N distinct rejected requests must not grow
 * server_ctx->untrusted at all.
 *
 * Before the fix this fails with e.g.:
 *   ERROR: untrusted count after (25) != count before (0)
 */
static int execute_no_unbounded_growth_test(CMP_DOS_TEST_FIXTURE *fixture)
{
    OSSL_CMP_CTX *server_ctx = fixture->server_ctx;
    int count_before, count_after, i;

    count_before = sk_X509_num(OSSL_CMP_CTX_get0_untrusted(server_ctx));
    if (count_before < 0)
        count_before = 0;

    for (i = 0; i < NUM_REJECTED_REQUESTS; i++) {
        OSSL_CMP_MSG *msg = build_rejectable_msg_with_unique_cert(i);
        int check_result;

        if (!TEST_ptr(msg))
            return 0;

        check_result = ossl_cmp_msg_check_update(server_ctx, msg, NULL, 0);
        OSSL_CMP_MSG_free(msg);

        if (!TEST_int_eq(check_result, 0)) {
            TEST_note("expected request #%d to be rejected (server ctx has"
                      " no matching PBM secret) but it was accepted -- test"
                      " setup is wrong, not exercising the rejection path",
                i);
            return 0;
        }
    }

    count_after = sk_X509_num(OSSL_CMP_CTX_get0_untrusted(server_ctx));
    if (count_after < 0)
        count_after = 0;

    if (!TEST_int_eq(count_after, count_before)) {
        TEST_note("server_ctx->untrusted grew from %d to %d after %d"
                  " rejected requests -- failed-request extraCerts caching"
                  " bug is present (see ossl_cmp_msg_check_update() in"
                  " crypto/cmp/cmp_vfy.c)",
            count_before, count_after,
            NUM_REJECTED_REQUESTS);
        return 0;
    }
    return 1;
}

/*
 * Single-request variant of the same check, useful in isolation since it
 * pins down that even ONE rejected request leaves no residue -- ruling out
 * X509_ADD_FLAG_NO_DUP coincidentally masking the bug in the N-request test.
 */
static int execute_single_rejected_request_test(CMP_DOS_TEST_FIXTURE *fixture)
{
    OSSL_CMP_CTX *server_ctx = fixture->server_ctx;
    OSSL_CMP_MSG *msg = build_rejectable_msg_with_unique_cert(999);
    int count_before, count_after;

    if (!TEST_ptr(msg))
        return 0;

    count_before = sk_X509_num(OSSL_CMP_CTX_get0_untrusted(server_ctx));
    if (count_before < 0)
        count_before = 0;

    if (!TEST_int_eq(ossl_cmp_msg_check_update(server_ctx, msg, NULL, 0), 0)) {
        OSSL_CMP_MSG_free(msg);
        return 0;
    }
    OSSL_CMP_MSG_free(msg);

    count_after = sk_X509_num(OSSL_CMP_CTX_get0_untrusted(server_ctx));
    if (count_after < 0)
        count_after = 0;

    return TEST_int_eq(count_after, count_before);
}

static int test_single_rejected_request_leaves_no_residue(void)
{
    SETUP_TEST_FIXTURE(CMP_DOS_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_single_rejected_request_test, tear_down);
    return result;
}

static int test_no_unbounded_growth_on_rejected_requests(void)
{
    SETUP_TEST_FIXTURE(CMP_DOS_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_no_unbounded_growth_test, tear_down);
    return result;
}

int setup_tests(void)
{
    ADD_TEST(test_single_rejected_request_leaves_no_residue);
    ADD_TEST(test_no_unbounded_growth_on_rejected_requests);
    return 1;
}
