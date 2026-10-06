/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests for the TLS supported-groups list parser (tls1_set_groups_list()),
 * driven through the public SSL_CTX_set1_groups_list() entry point.
 *
 * The parser maintains three flat arrays and their bookkeeping in SSL_CTX:
 *   ctx->ext.supportedgroups[0..supportedgroups_len)  - groups, in order
 *   ctx->ext.tuples[0..tuples_len)                    - group count per tuple
 *   ctx->ext.keyshares[0..keyshares_len)              - keyshare group IDs
 * with the governing invariant that the per-tuple counts sum to the group
 * count: sum(tuples) == supportedgroups_len.  Those fields are not visible
 * through the public API, so we include ssl_local.h and check them directly.
 *
 * Several of the cases below are regressions for GitHub #31315, where the
 * remove-group path could leave tuples/keyshares out of step with the group
 * array (manifesting as an out-of-bounds read under a sanitizer).
 */

#include <openssl/ssl.h>
#include "internal/nelem.h"
#include "internal/tlsgroups.h"
#include "../ssl/ssl_local.h"
#include "testutil.h"

#define MAX_GROUPS 8
#define MAX_TUPLES 8
#define MAX_KS 8

/*
 * Sentinel used in ctx->ext.keyshares to mean "a single keyshare from the
 * first supported group" (set when no '*' prefix appears anywhere).
 */
#define KS_FIRST 0

typedef struct {
    const char *desc;
    const char *list; /* input passed to set1_groups_list */
    uint16_t groups[MAX_GROUPS]; /* expected groups, in order */
    size_t ngroups;
    size_t tuples[MAX_TUPLES]; /* expected per-tuple group counts */
    size_t ntuples;
    uint16_t keyshares[MAX_KS]; /* expected keyshares (KS_FIRST == 0) */
    size_t nkeyshares;
} TESTCASE;

static const TESTCASE cases[] = {
    /* --- Well-formed baselines --------------------------------------- */
    {
        "single tuple, two groups, implicit keyshare",
        "X25519:prime256v1",
        { OSSL_TLS_GROUP_ID_x25519, OSSL_TLS_GROUP_ID_secp256r1 },
        2,
        { 2 },
        1,
        { KS_FIRST },
        1,
    },
    {
        "two tuples, implicit keyshare",
        "X25519/prime256v1",
        { OSSL_TLS_GROUP_ID_x25519, OSSL_TLS_GROUP_ID_secp256r1 },
        2,
        { 1, 1 },
        2,
        { KS_FIRST },
        1,
    },
    {
        "explicit keyshare prefix",
        "*X25519:prime256v1",
        { OSSL_TLS_GROUP_ID_x25519, OSSL_TLS_GROUP_ID_secp256r1 },
        2,
        { 2 },
        1,
        { OSSL_TLS_GROUP_ID_x25519 },
        1,
    },

    /* --- #31315: removal that empties a *closed* tuple --------------- */
    {
        /*
         * -X25519 empties closed tuple 0; it must be excised and the
         * active-tuple counter shifted down (was: "1 group, 0 tuples").
         */
        "remove empties closed tuple (excision)",
        "X25519/prime256v1:-X25519",
        { OSSL_TLS_GROUP_ID_secp256r1 },
        1,
        { 1 },
        1,
        { KS_FIRST },
        1,
    },
    {
        /*
         * Removed group carried the keyshare and its tuple empties: the
         * keyshare must be dropped, not floated onto another tuple's group
         * (was: "1 group, tuples {1,1}", keyshare pointing at prime256v1).
         */
        "remove keyshared group empties tuple (drop, not float)",
        "*X25519/prime256v1/-X25519",
        { OSSL_TLS_GROUP_ID_secp256r1 },
        1,
        { 1 },
        1,
        { KS_FIRST },
        1,
    },
    {
        /*
         * Two removals, each emptying a distinct closed tuple (was:
         * "3 groups but tuple counts summing to 5").
         */
        "two removals empty two closed tuples",
        "X25519/secp256r1:secp384r1:secp521r1/*X448:-X25519/-X448",
        { OSSL_TLS_GROUP_ID_secp256r1, OSSL_TLS_GROUP_ID_secp384r1,
            OSSL_TLS_GROUP_ID_secp521r1 },
        3,
        { 3 },
        1,
        { KS_FIRST },
        1,
    },

    /* --- Removal from the *active* tuple (no excision) --------------- */
    {
        "remove empties the active tuple only",
        "X25519:-X25519",
        { 0 },
        0,
        { 0 },
        0,
        { 0 },
        0,
    },
    {
        "closed tuple intact, active tuple emptied and discarded",
        "X25519/prime256v1:-prime256v1",
        { OSSL_TLS_GROUP_ID_x25519 },
        1,
        { 1 },
        1,
        { KS_FIRST },
        1,
    },
    {
        "keyshared group removed from active tuple",
        "X25519/secp384r1/*X448:-X448",
        { OSSL_TLS_GROUP_ID_x25519, OSSL_TLS_GROUP_ID_secp384r1 },
        2,
        { 1, 1 },
        2,
        { KS_FIRST },
        1,
    },

    /* --- Legitimate keyshare retention (tuple not emptied) ----------- */
    {
        /*
         * Removing the keyshared X25519 from a tuple that still has
         * prime256v1: prime256v1's own keyshare is retained.
         */
        "remove one of two keyshares, tuple survives",
        "*X25519:*prime256v1:-X25519",
        { OSSL_TLS_GROUP_ID_secp256r1 },
        1,
        { 1 },
        1,
        { OSSL_TLS_GROUP_ID_secp256r1 },
        1,
    },

    /* --- Keyshare floats *within* its own (surviving, closed) tuple --- */
    {
        /*
         * X25519 carried the keyshare in closed tuple 0 {X25519,secp384r1};
         * removing it must float the keyshare to secp384r1 (the remaining
         * group of tuple 0), NOT to secp256r1 which is in tuple 1.
         */
        "keyshare floats to remaining group of same tuple",
        "*X25519:secp384r1/secp256r1:-X25519",
        { OSSL_TLS_GROUP_ID_secp384r1, OSSL_TLS_GROUP_ID_secp256r1 },
        2,
        { 1, 1 },
        2,
        { OSSL_TLS_GROUP_ID_secp384r1 },
        1,
    },
    {
        /*
         * Removed keyshared group is in the middle of tuple 0; its keyshare
         * floats to the tuple's first group (X25519), and tuple 1's own
         * keyshare (secp256r1) is untouched.  A float that escaped tuple 0
         * would corrupt this to a different keyshare set.
         */
        "mid-tuple keyshare floats to tuple head, not across tuples",
        "X25519:*X448:secp384r1 / *secp256r1:-X448",
        { OSSL_TLS_GROUP_ID_x25519, OSSL_TLS_GROUP_ID_secp384r1,
            OSSL_TLS_GROUP_ID_secp256r1 },
        3,
        { 2, 1 },
        2,
        { OSSL_TLS_GROUP_ID_x25519, OSSL_TLS_GROUP_ID_secp256r1 },
        2,
    },
};

/*
 * Assert every structural invariant the parser must maintain, from the parsed
 * state alone (independent of the specific input):
 *
 *  1. Partition:   sum(tuples[0..tuples_len)) == supportedgroups_len.
 *  2. No empty tuples survive the final compaction (every count > 0).
 *  3. Groups are distinct.
 *  4. Keyshares are either the lone "first group" sentinel {0}, or a set of
 *     distinct non-zero group IDs that appear as an ordered subsequence of
 *     the supported groups (never the sentinel mixed with real IDs).
 *
 * These are exactly the properties that were violated by GitHub #31315 (a
 * broken partition led to an out-of-bounds read in the remove path).
 */
static int check_invariants(SSL_CTX *ctx)
{
    size_t i, j, sum;
    int ok = 1;

    /* 1 + 2: partition, with no zero-count tuple left behind. */
    for (i = 0, sum = 0; i < ctx->ext.tuples_len; i++) {
        if (!TEST_size_t_gt(ctx->ext.tuples[i], 0)) {
            TEST_error("zero-count tuple at index %zu survived", i);
            ok = 0;
        }
        sum += ctx->ext.tuples[i];
    }
    if (!TEST_size_t_eq(sum, ctx->ext.supportedgroups_len))
        ok = 0;

    /* 3: groups distinct. */
    for (i = 0; i < ctx->ext.supportedgroups_len; i++)
        for (j = 0; j < i; j++)
            if (!TEST_uint_ne(ctx->ext.supportedgroups[i],
                    ctx->ext.supportedgroups[j]))
                ok = 0;

    /* 4: keyshare shape. */
    if (ctx->ext.keyshares_len == 1 && ctx->ext.keyshares[0] == KS_FIRST) {
        /* Sentinel form: a single implicit keyshare from the first group. */
    } else {
        size_t g = 0;

        for (i = 0; i < ctx->ext.keyshares_len; i++) {
            uint16_t ks = ctx->ext.keyshares[i];

            if (!TEST_uint_ne(ks, KS_FIRST)) { /* sentinel must be alone */
                ok = 0;
                continue;
            }
            for (j = 0; j < i; j++) /* distinct */
                if (!TEST_uint_ne(ks, ctx->ext.keyshares[j]))
                    ok = 0;
            while (g < ctx->ext.supportedgroups_len
                && ctx->ext.supportedgroups[g] != ks)
                g++; /* ordered subsequence */
            if (!TEST_size_t_lt(g, ctx->ext.supportedgroups_len)) {
                TEST_error("keyshare 0x%04X not an in-order group", ks);
                ok = 0;
                break;
            }
            g++;
        }
    }

    return ok;
}

static int run_case(int idx)
{
    const TESTCASE *tc = &cases[idx];
    SSL_CTX *ctx = NULL;
    int ret = 0;
    size_t i;

    TEST_info("case %d: %s  [\"%s\"]", idx, tc->desc, tc->list);

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method())))
        goto end;

    if (!TEST_int_eq(SSL_CTX_set1_groups_list(ctx, tc->list), 1))
        goto end;

    /* Groups: exact contents and order. */
    if (!TEST_size_t_eq(ctx->ext.supportedgroups_len, tc->ngroups))
        goto end;
    for (i = 0; i < tc->ngroups; i++)
        if (!TEST_uint_eq(ctx->ext.supportedgroups[i], tc->groups[i]))
            goto end;

    /* Tuples: exact per-tuple counts. */
    if (!TEST_size_t_eq(ctx->ext.tuples_len, tc->ntuples))
        goto end;
    for (i = 0; i < tc->ntuples; i++)
        if (!TEST_size_t_eq(ctx->ext.tuples[i], tc->tuples[i]))
            goto end;

    /* Keyshares: exact contents (KS_FIRST == 0 sentinel). */
    if (!TEST_size_t_eq(ctx->ext.keyshares_len, tc->nkeyshares))
        goto end;
    for (i = 0; i < tc->nkeyshares; i++)
        if (!TEST_uint_eq(ctx->ext.keyshares[i], tc->keyshares[i]))
            goto end;

    if (!check_invariants(ctx))
        goto end;

    ret = 1;
end:
    SSL_CTX_free(ctx);
    return ret;
}

/*
 * Synthetic edge-case forms.  We do not spell out the exact parsed result for
 * these (that would just re-derive the parser); instead we assert the parse
 * succeeds or fails as expected and, on success, that all invariants hold.
 * These deliberately stress the corners of the remove/dedup/keyshare paths.
 */
typedef struct {
    const char *list;
    int expect_ok; /* 1: parse succeeds; 0: syntax/parse error */
} EDGECASE;

static const EDGECASE edgecases[] = {
    /* --- valid, invariant-preserving corner cases --- */
    { "X25519", 1 },
    { "X25519:secp256r1:secp384r1:secp521r1:X448", 1 }, /* one full tuple */
    { "X25519/secp256r1/secp384r1/secp521r1/X448", 1 }, /* many tuples */
    { "*X25519:secp256r1", 1 },
    { "X25519:X25519", 1 }, /* dup within tuple */
    { "X25519/X25519", 1 }, /* dup across tuples */
    { "X25519:-secp384r1", 1 }, /* remove absent: no-op */
    { "X25519:-X25519", 1 }, /* empty the active tuple */
    { "X25519/secp256r1:-X25519", 1 }, /* excise closed tuple */
    { "X25519/secp256r1/secp384r1:-secp256r1", 1 }, /* excise middle tuple */
    { "X25519:secp256r1/secp384r1:-secp384r1", 1 }, /* empty active, discard */
    { "*X25519/prime256v1/-X25519", 1 }, /* #31315: drop, not float */
    { "X25519/secp256r1:secp384r1:secp521r1/*X448:-X25519/-X448", 1 }, /* #31315 */
    { "*X25519:*secp256r1:-X25519", 1 }, /* keyshare survives sibling */
    { "X25519/secp256r1:-X25519:secp384r1", 1 }, /* excise then refill */
    { "X25519:secp256r1:X448:-X25519:-X448", 1 }, /* multiple removals */
    { "?*BOGUS:X25519 / *secp256r1", 1 }, /* stacked prefix, unknown */
    { "X25519:?BOGUS:secp256r1", 1 }, /* ignore unknown mid-tuple */
    { "*X25519:DEFAULT:-secp256r1:-X448", 1 }, /* DEFAULT + removals */
    { "DEFAULT:-X25519:-?curveSM2:-?ffdhe2048:-?ffdhe3072", 1 },
    { "secp256r1:DEFAULT", 1 }, /* prepend then DEFAULT */

    /* --- expected syntax / parse errors --- */
    { "X25519//secp256r1", 0 }, /* empty tuple */
    { "X25519::secp256r1", 0 }, /* empty group */
    { ":X25519", 0 },
    { "X25519:", 0 },
    { "/X25519", 0 },
    { "X25519/", 0 },
    { "**X25519", 0 }, /* double keyshare prefix */
    { "??X25519", 0 },
    { "--X25519", 0 },
    { "X25519:NOTAREALGROUP", 0 }, /* unknown w/o '?' */
    { "-DEFAULT", 0 }, /* prefix on pseudo-group */
    { "?DEFAULT", 0 },
};

static int run_edge(int idx)
{
    const EDGECASE *tc = &edgecases[idx];
    SSL_CTX *ctx = NULL;
    int ret = 0, r;

    TEST_info("edge %d: [\"%s\"] expect %s", idx, tc->list,
        tc->expect_ok ? "ok" : "error");

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method())))
        goto end;

    r = SSL_CTX_set1_groups_list(ctx, tc->list);
    if (tc->expect_ok) {
        if (!TEST_int_eq(r, 1) || !check_invariants(ctx))
            goto end;
    } else {
        if (!TEST_int_eq(r, 0))
            goto end;
    }

    ret = 1;
end:
    SSL_CTX_free(ctx);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(run_case, (int)OSSL_NELEM(cases));
    ADD_ALL_TESTS(run_edge, (int)OSSL_NELEM(edgecases));
    return 1;
}
