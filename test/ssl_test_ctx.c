/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>

#include <openssl/e_os2.h>
#include <openssl/crypto.h>

#include "e_os.h"
#include "ssl_test_ctx.h"

/* True enums and other test configuration values that map to an int. */
typedef struct {
    const char *name;
    int value;
} test_enum;


__owur static int parse_enum(const test_enum *enums, size_t num_enums,
                             int *value, const char *name)
{
    size_t i;
    for (i = 0; i < num_enums; i++) {
        if (strcmp(enums[i].name, name) == 0) {
            *value = enums[i].value;
            return 1;
        }
    }
    return 0;
}

static const char *enum_name(const test_enum *enums, size_t num_enums,
                             int value)
{
    size_t i;
    for (i = 0; i < num_enums; i++) {
        if (enums[i].value == value) {
            return enums[i].name;
        }
    }
    return "InvalidValue";
}


/*******************/
/* ExpectedResult. */
/*******************/

static const test_enum ssl_test_results[] = {
    {"Success", SSL_TEST_SUCCESS},
    {"ServerFail", SSL_TEST_SERVER_FAIL},
    {"ClientFail", SSL_TEST_CLIENT_FAIL},
    {"InternalError", SSL_TEST_INTERNAL_ERROR},
};

__owur static int parse_expected_result(SSL_TEST_CTX *test_ctx, const char *value)
{
    int ret_value;
    if (!parse_enum(ssl_test_results, OSSL_NELEM(ssl_test_results),
                    &ret_value, value)) {
        return 0;
    }
    test_ctx->expected_result = ret_value;
    return 1;
}

const char *ssl_test_result_t_name(ssl_test_result_t result)
{
    return enum_name(ssl_test_results, OSSL_NELEM(ssl_test_results), result);
}

/******************************/
/* ClientAlert / ServerAlert. */
/******************************/

static const test_enum ssl_alerts[] = {
    {"UnknownCA", SSL_AD_UNKNOWN_CA},
};

__owur static int parse_alert(int *alert, const char *value)
{
    return parse_enum(ssl_alerts, OSSL_NELEM(ssl_alerts), alert, value);
}

__owur static int parse_client_alert(SSL_TEST_CTX *test_ctx, const char *value)
{
    return parse_alert(&test_ctx->client_alert, value);
}

__owur static int parse_server_alert(SSL_TEST_CTX *test_ctx, const char *value)
{
    return parse_alert(&test_ctx->server_alert, value);
}

const char *ssl_alert_name(int alert)
{
    return enum_name(ssl_alerts, OSSL_NELEM(ssl_alerts), alert);
}

/************/
/* Protocol */
/************/

static const test_enum ssl_protocols[] = {
     {"TLSv1.2", TLS1_2_VERSION},
     {"TLSv1.1", TLS1_1_VERSION},
     {"TLSv1", TLS1_VERSION},
     {"SSLv3", SSL3_VERSION},
};

__owur static int parse_protocol(SSL_TEST_CTX *test_ctx, const char *value)
{
    return parse_enum(ssl_protocols, OSSL_NELEM(ssl_protocols),
                      &test_ctx->protocol, value);
}

const char *ssl_protocol_name(int protocol)
{
    return enum_name(ssl_protocols, OSSL_NELEM(ssl_protocols), protocol);
}


/*************************************************************/
/* Known test options and their corresponding parse methods. */
/*************************************************************/

typedef struct {
    const char *name;
    int (*parse)(SSL_TEST_CTX *test_ctx, const char *value);
} ssl_test_ctx_option;

static const ssl_test_ctx_option ssl_test_ctx_options[] = {
    { "ExpectedResult", &parse_expected_result },
    { "ClientAlert", &parse_client_alert },
    { "ServerAlert", &parse_server_alert },
    { "Protocol", &parse_protocol },
};


/*
 * Since these methods are used to create tests, we use OPENSSL_assert liberally
 * for malloc failures and other internal errors.
 */
SSL_TEST_CTX *SSL_TEST_CTX_new()
{
    SSL_TEST_CTX *ret;
    ret = OPENSSL_zalloc(sizeof(*ret));
    OPENSSL_assert(ret != NULL);
    ret->expected_result = SSL_TEST_SUCCESS;
    return ret;
}

void SSL_TEST_CTX_free(SSL_TEST_CTX *ctx)
{
    OPENSSL_free(ctx);
}

SSL_TEST_CTX *SSL_TEST_CTX_create(const CONF *conf, const char *test_section)
{
    STACK_OF(CONF_VALUE) *sk_conf;
    SSL_TEST_CTX *ctx;
    int i;
    size_t j;

    sk_conf = NCONF_get_section(conf, test_section);
    OPENSSL_assert(sk_conf != NULL);

    ctx = SSL_TEST_CTX_new();
    OPENSSL_assert(ctx != NULL);

    for (i = 0; i < sk_CONF_VALUE_num(sk_conf); i++) {
        int found = 0;
        const CONF_VALUE *option = sk_CONF_VALUE_value(sk_conf, i);
        for (j = 0; j < OSSL_NELEM(ssl_test_ctx_options); j++) {
            if (strcmp(option->name, ssl_test_ctx_options[j].name) == 0) {
                if (!ssl_test_ctx_options[j].parse(ctx, option->value)) {
                    fprintf(stderr, "Bad value %s for option %s\n",
                            option->value, option->name);
                    goto err;
                }
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "Unknown test option: %s\n", option->name);
            goto err;
        }
    }

    goto done;

 err:
    SSL_TEST_CTX_free(ctx);
    ctx = NULL;
 done:
    return ctx;
}
