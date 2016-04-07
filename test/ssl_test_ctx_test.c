/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Ideally, CONF should offer standard parsing methods and cover them
 * in tests. But since we have no CONF tests, we use a custom test for now.
 */

#include <stdio.h>

#include "e_os.h"
#include "ssl_test_ctx.h"
#include "testutil.h"
#include <openssl/e_os2.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>

static CONF *conf = NULL;

typedef struct ssl_test_ctx_test_fixture {
    const char *test_case_name;
    const char *test_section;
    /* Expected parsed configuration. */
    SSL_TEST_CTX *expected_ctx;
} SSL_TEST_CTX_TEST_FIXTURE;

/* Returns 1 if the contexts are equal, 0 otherwise. */
static int SSL_TEST_CTX_equal(SSL_TEST_CTX *ctx, SSL_TEST_CTX *ctx2)
{
    if (ctx->expected_result != ctx2->expected_result) {
        fprintf(stderr, "ExpectedResult mismatch: %s vs %s.\n",
                ssl_test_result_name(ctx->expected_result),
                ssl_test_result_name(ctx2->expected_result));
        return 0;
    }
    if (ctx->client_alert != ctx2->client_alert) {
        fprintf(stderr, "ClientAlert mismatch: %s vs %s.\n",
                ssl_alert_name(ctx->client_alert),
                ssl_alert_name(ctx2->client_alert));
        return 0;
    }
    if (ctx->server_alert != ctx2->server_alert) {
        fprintf(stderr, "ServerAlert mismatch: %s vs %s.\n",
                ssl_alert_name(ctx->server_alert),
                ssl_alert_name(ctx2->server_alert));
        return 0;
    }
    if (ctx->protocol != ctx2->protocol) {
        fprintf(stderr, "ClientAlert mismatch: %s vs %s.\n",
                ssl_protocol_name(ctx->protocol),
                ssl_protocol_name(ctx2->protocol));
        return 0;
    }
    if (ctx->client_verify_callback != ctx2->client_verify_callback) {
        fprintf(stderr, "ClientVerifyCallback mismatch: %s vs %s.\n",
                ssl_verify_callback_name(ctx->client_verify_callback),
                ssl_verify_callback_name(ctx2->client_verify_callback));
        return 0;
    }

    return 1;
}

static SSL_TEST_CTX_TEST_FIXTURE set_up(const char *const test_case_name)
{
    SSL_TEST_CTX_TEST_FIXTURE fixture;
    fixture.test_case_name = test_case_name;
    fixture.expected_ctx = SSL_TEST_CTX_new();
    OPENSSL_assert(fixture.expected_ctx != NULL);
    return fixture;
}

static int execute_test(SSL_TEST_CTX_TEST_FIXTURE fixture)
{
    int success = 0;

    SSL_TEST_CTX *ctx = SSL_TEST_CTX_create(conf, fixture.test_section);

    if (ctx == NULL) {
        fprintf(stderr, "Failed to parse good configuration %s.\n",
                fixture.test_section);
        goto err;
    }

    if (!SSL_TEST_CTX_equal(ctx, fixture.expected_ctx))
        goto err;

    success = 1;
 err:
    SSL_TEST_CTX_free(ctx);
    return success;
}

static int execute_failure_test(SSL_TEST_CTX_TEST_FIXTURE fixture)
{
    SSL_TEST_CTX *ctx = SSL_TEST_CTX_create(conf, fixture.test_section);

    if (ctx != NULL) {
        fprintf(stderr, "Parsing bad configuration %s succeeded.\n",
                fixture.test_section);
        SSL_TEST_CTX_free(ctx);
        return 0;
    }

    return 1;
}

static void tear_down(SSL_TEST_CTX_TEST_FIXTURE fixture)
{
    SSL_TEST_CTX_free(fixture.expected_ctx);
    ERR_print_errors_fp(stderr);
}

#define SETUP_SSL_TEST_CTX_TEST_FIXTURE()                       \
    SETUP_TEST_FIXTURE(SSL_TEST_CTX_TEST_FIXTURE, set_up)
#define EXECUTE_SSL_TEST_CTX_TEST()             \
    EXECUTE_TEST(execute_test, tear_down)
#define EXECUTE_SSL_TEST_CTX_FAILURE_TEST()             \
    EXECUTE_TEST(execute_failure_test, tear_down)

static int test_empty_configuration()
{
    SETUP_SSL_TEST_CTX_TEST_FIXTURE();
    fixture.test_section = "ssltest_default";
    fixture.expected_ctx->expected_result = SSL_TEST_SUCCESS;
    EXECUTE_SSL_TEST_CTX_TEST();
}

static int test_good_configuration()
{
    SETUP_SSL_TEST_CTX_TEST_FIXTURE();
    fixture.test_section = "ssltest_good";
    fixture.expected_ctx->expected_result = SSL_TEST_SERVER_FAIL;
    fixture.expected_ctx->client_alert = SSL_AD_UNKNOWN_CA;
    fixture.expected_ctx->server_alert = 0;  /* No alert. */
    fixture.expected_ctx->protocol = TLS1_1_VERSION;
    fixture.expected_ctx->client_verify_callback = SSL_TEST_VERIFY_REJECT_ALL,
    EXECUTE_SSL_TEST_CTX_TEST();
}

static const char *bad_configurations[] = {
    "ssltest_unknown_option",
    "ssltest_unknown_expected_result",
    "ssltest_unknown_alert",
    "ssltest_unknown_protocol",
    "ssltest_unknown_verify_callback",
};

static int test_bad_configuration(int idx)
{
        SETUP_SSL_TEST_CTX_TEST_FIXTURE();
        fixture.test_section = bad_configurations[idx];
        EXECUTE_SSL_TEST_CTX_FAILURE_TEST();
}

int main(int argc, char **argv)
{
    int result = 0;

    if (argc != 2)
        return 1;

    conf = NCONF_new(NULL);
    OPENSSL_assert(conf != NULL);

    /* argv[1] should point to test/ssl_test_ctx_test.conf */
    OPENSSL_assert(NCONF_load(conf, argv[1], NULL) > 0);


    ADD_TEST(test_empty_configuration);
    ADD_TEST(test_good_configuration);
    ADD_ALL_TESTS(test_bad_configuration, OSSL_NELEM(bad_configurations));

    result = run_tests(argv[0]);

    NCONF_free(conf);

    return result;
}
