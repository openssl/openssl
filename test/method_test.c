/*
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 BaishanCloud. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>

#include "testutil.h"
#include "../ssl/ssl_local.h"
#include "ssltestlib.h"

static char *cert = NULL;
static char *pvk = NULL;

struct subtest {
	int min_version;
	int max_version;
	const SSL_METHOD* server_method;
	const SSL_METHOD* client_method;
};

#define SUBTEST_TLS1_2_VERSION	0
#define SUBTEST_TLS1_3_VERSION	1
#define SUBTEST_QUANTITY		2

static struct subtest subtests[] = {
	{ TLS1_VERSION, TLS1_2_VERSION, NULL, NULL }, 
	{ TLS1_VERSION, TLS1_3_VERSION, NULL, NULL }};

static int test_method(int test)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(), subtests[test].min_version, subtests[test].max_version, &sctx, &cctx, cert, pvk))
     || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)))
        goto end;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    if (!TEST_true(SSL_get_ssl_method(serverssl)->ssl_accept == ossl_statem_accept && SSL_get_ssl_method(serverssl)->ssl_connect == ssl_undefined_function &&
   	    		   SSL_get_ssl_method(clientssl)->ssl_accept == ssl_undefined_function && SSL_get_ssl_method(clientssl)->ssl_connect == ossl_statem_connect))
        goto end;

	if (!TEST_true(SSL_get_ssl_method(serverssl) == subtests[test].server_method && SSL_get_ssl_method(clientssl) == subtests[test].client_method))	
        goto end;
	
    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

int setup_tests(void)
{
	subtests[SUBTEST_TLS1_2_VERSION].server_method = tlsv1_2_server_method();
	subtests[SUBTEST_TLS1_2_VERSION].client_method = tlsv1_2_client_method();
	subtests[SUBTEST_TLS1_3_VERSION].server_method = tlsv1_3_server_method();
	subtests[SUBTEST_TLS1_3_VERSION].client_method = tlsv1_3_client_method();

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0)) || !TEST_ptr(pvk = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_method, SUBTEST_QUANTITY);
    return 1;
}
