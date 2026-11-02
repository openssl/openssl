/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "internal/ssl_unwrap.h"
#include "ssl_local.h"

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    SSL_CONNECTION *sc;
    SSL_SESSION *session;
} SESSION_ID_FIXTURE;

/*
 * Fail one explicitly armed lock and pass all other lock calls through. The
 * callback arms the next cache read, which is the final collision check.
 */
static CRYPTO_RWLOCK *read_lock_to_fail;

/* wraps */

int __real_CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock);
int __wrap_CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock);

int __wrap_CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock)
{
    if (lock != NULL && lock == read_lock_to_fail) {
        read_lock_to_fail = NULL;
        return 0;
    }

    return __real_CRYPTO_THREAD_read_lock(lock);
}

/* fault injection */

static void fail_next_read_lock(CRYPTO_RWLOCK *lock)
{
    assert_null(read_lock_to_fail);
    assert_non_null(lock);
    read_lock_to_fail = lock;
}

/* helpers */

static int generate_session_id_then_fail_cache_lock(SSL *ssl,
    unsigned char *id, unsigned int *id_len)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);

    memset(id, 0x5a, *id_len);
    fail_next_read_lock(sc->session_ctx->lock);
    return 1;
}

/* fixtures */

static int setup(void **state)
{
    SESSION_ID_FIXTURE *fixture = calloc(1, sizeof(*fixture));

    assert_non_null(fixture);
    fixture->ctx = SSL_CTX_new(TLS_server_method());
    assert_non_null(fixture->ctx);
    fixture->ssl = SSL_new(fixture->ctx);
    assert_non_null(fixture->ssl);
    fixture->sc = SSL_CONNECTION_FROM_SSL(fixture->ssl);
    assert_non_null(fixture->sc);
    fixture->session = SSL_SESSION_new();
    assert_non_null(fixture->session);

    fixture->sc->version = TLS1_2_VERSION;
    read_lock_to_fail = NULL;
    ERR_clear_error();
    *state = fixture;
    return 0;
}

static int teardown(void **state)
{
    SESSION_ID_FIXTURE *fixture = *state;

    assert_null(read_lock_to_fail);
    SSL_SESSION_free(fixture->session);
    SSL_free(fixture->ssl);
    SSL_CTX_free(fixture->ctx);
    free(fixture);
    ERR_clear_error();
    return 0;
}

static void test_generate_session_id_final_cache_lock_failure(void **state)
{
    SESSION_ID_FIXTURE *fixture = *state;
    unsigned long err;

    assert_true(SSL_set_generate_session_id(fixture->ssl,
        generate_session_id_then_fail_cache_lock));

    assert_false(ssl_generate_session_id(fixture->sc, fixture->session));
    /* Inspect the first error recorded for this failure. */
    err = ERR_peek_error();
    assert_true(ossl_statem_in_error(fixture->sc));
    assert_int_equal(ERR_GET_LIB(err), ERR_LIB_SSL);
    assert_int_equal(ERR_GET_REASON(err), ERR_R_INTERNAL_ERROR);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            test_generate_session_id_final_cache_lock_failure, setup,
            teardown),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
