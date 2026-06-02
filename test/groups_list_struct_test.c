/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/nelem.h"
#include "../ssl/ssl_local.h"
#include "testutil.h"

/*
 * Sentinel used by the default-keyshare path in tls1_set_groups_list when a
 * list ends up with groups but no explicit keyshares.  ksid_arr[0] is set to
 * 0 to tell downstream code "send a keyshare for the first supported group".
 */
#define KS_IMPLICIT 0

#define MAX_GROUPS 8
#define MAX_TUPLES 4

struct expected_state {
    const char *list;
    const char *groups[MAX_GROUPS];
    size_t groups_len;
    const char *keyshares[MAX_GROUPS];
    size_t keyshares_len;
    size_t tuples[MAX_TUPLES];
    size_t tuples_len;
};

static const struct expected_state expected_states[] = {
    {
        .list = "X25519/prime256v1:-X25519",
        .groups = { "secp256r1" }, .groups_len = 1,
        .keyshares = { "" }, .keyshares_len = 1,
        .tuples = { 1 }, .tuples_len = 1,
    },
    {
        .list = "*X25519/prime256v1/-X25519",
        .groups = { "secp256r1" }, .groups_len = 1,
        .keyshares = { "" }, .keyshares_len = 1,
        .tuples = { 1 }, .tuples_len = 1,
    },
    {
        .list = "X25519/secp256r1:secp384r1:secp521r1/*X448:-X25519/-X448",
        .groups = { "secp256r1", "secp384r1", "secp521r1" }, .groups_len = 3,
        .keyshares = { "" }, .keyshares_len = 1,
        .tuples = { 3 }, .tuples_len = 1,
    },
};

static int verify_groups(SSL_CTX *ctx, const struct expected_state *st)
{
    size_t j;

    if (!TEST_size_t_eq(ctx->ext.supportedgroups_len, st->groups_len))
        return 0;
    for (j = 0; j < st->groups_len; j++) {
        const char *got = tls1_group_id2name(ctx, ctx->ext.supportedgroups[j]);

        if (!TEST_ptr(got))
            return 0;
        if (!TEST_str_eq(got, st->groups[j]))
            return 0;
    }
    return 1;
}

static int verify_keyshares(SSL_CTX *ctx, const struct expected_state *st)
{
    size_t j;

    if (!TEST_size_t_eq(ctx->ext.keyshares_len, st->keyshares_len))
        return 0;
    for (j = 0; j < st->keyshares_len; j++) {
        if (st->keyshares[j][0] == '\0') {
            if (!TEST_uint_eq(ctx->ext.keyshares[j], KS_IMPLICIT))
                return 0;
        } else {
            const char *got = tls1_group_id2name(ctx, ctx->ext.keyshares[j]);

            if (!TEST_ptr(got))
                return 0;
            if (!TEST_str_eq(got, st->keyshares[j]))
                return 0;
        }
    }
    return 1;
}

static int verify_tuples(SSL_CTX *ctx, const struct expected_state *st)
{
    size_t j;
    size_t sum = 0;

    if (!TEST_size_t_eq(ctx->ext.tuples_len, st->tuples_len))
        return 0;
    for (j = 0; j < st->tuples_len; j++) {
        if (!TEST_size_t_eq(ctx->ext.tuples[j], st->tuples[j]))
            return 0;
        sum += ctx->ext.tuples[j];
    }

    if (!TEST_size_t_eq(sum, ctx->ext.supportedgroups_len))
        return 0;
    return 1;
}

static int test_groups_list_state(int i)
{
    int ok = 0;
    SSL_CTX *ctx = NULL;
    const struct expected_state *st = &expected_states[i];

    TEST_info("==> Verifying state for: %s", st->list);

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method())))
        goto end;
    if (!TEST_true(SSL_CTX_set1_groups_list(ctx, st->list)))
        goto end;

    if (!verify_groups(ctx, st))
        goto end;
    if (!verify_keyshares(ctx, st))
        goto end;
    if (!verify_tuples(ctx, st))
        goto end;

    ok = 1;
end:
    SSL_CTX_free(ctx);
    return ok;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_groups_list_state, OSSL_NELEM(expected_states));
    return 1;
}
