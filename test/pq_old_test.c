/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Perf microbench for priority_queue.c (handle-based, parallel
 * elements[]).
 *
 * Build with -O2 -DNDEBUG for representative numbers; the default test
 * build also works but figures will be slower (asserts compiled in).
 *
 * Not wired into any test recipe -- run on demand:
 *   make test/pq_old_test && util/wrap.pl test/pq_old_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <openssl/crypto.h>
#include "internal/priority_queue.h"
#include "internal/time.h"
#include "internal/nelem.h"
#include "testutil.h"

#define TRIALS 10

/*
 * ossl_time_now() uses gettimeofday() -- 1 us resolution.  At small N the
 * timed region (a few hundred ns) often falls inside one tick and reads
 * 0.  Each trial therefore repeats its inner body until accumulated
 * elapsed exceeds MIN_ELAPSED_NS, then divides by the total ops actually
 * performed.
 */
#define MIN_ELAPSED_NS 100000.0

typedef struct old_elem_st {
    size_t value;
    size_t handle; /* returned by ossl_pqueue_push */
} OLD_ELEM;

static int old_cmp(const void *av, const void *bv)
{
    const OLD_ELEM *a = av;
    const OLD_ELEM *b = bv;

    return a->value < b->value ? -1 : a->value > b->value;
}

DEFINE_PRIORITY_QUEUE_OF(OLD_ELEM);

static double now_ns(void)
{
    return (double)ossl_time2ticks(ossl_time_now());
}

/* ------------------------------------------------------------------- */
/* Per-trial setup helpers                                             */
/* ------------------------------------------------------------------- */
static void fill_old(OLD_ELEM *e, size_t n, uint32_t seed)
{
    size_t i;

    test_random_seed(seed);
    for (i = 0; i < n; i++) {
        e[i].value = (size_t)test_random();
        e[i].handle = 0;
    }
}

static size_t *random_perm(size_t n, uint32_t seed)
{
    size_t *p = OPENSSL_malloc(n * sizeof(*p));
    size_t i;

    if (p == NULL)
        return NULL;
    for (i = 0; i < n; i++)
        p[i] = i;
    test_random_seed(seed);
    for (i = n - 1; i > 0; i--) {
        size_t j = (size_t)(test_random() % (i + 1));
        size_t tmp = p[i];

        p[i] = p[j];
        p[j] = tmp;
    }
    return p;
}

/* ------------------------------------------------------------------- */
/* Benchmarks                                                          */
/* ------------------------------------------------------------------- */
static double measure_push(OLD_ELEM *e, size_t n, int reserve)
{
    OSSL_PRIORITY_QUEUE_OLD_ELEM *pq = NULL;
    double ret = -1;
    double best = 1e30;
    int t;

    for (t = 0; t < TRIALS; t++) {
        double elapsed = 0, ns;
        size_t ops = 0;

        do {
            double t0, t1;
            size_t i;
            int ok = 1;

            fill_old(e, n, 0x1234u + (uint32_t)t);
            pq = ossl_pqueue_OLD_ELEM_new(old_cmp);
            if (pq == NULL)
                goto err;
            if (reserve && !ossl_pqueue_OLD_ELEM_reserve(pq, n))
                goto err;
            t0 = now_ns();
            for (i = 0; i < n; i++)
                ok &= ossl_pqueue_OLD_ELEM_push(pq, &e[i], &e[i].handle);
            t1 = now_ns();
            ossl_pqueue_OLD_ELEM_free(pq);
            pq = NULL;
            if (!ok)
                goto err;
            elapsed += t1 - t0;
            ops += n;
        } while (elapsed < MIN_ELAPSED_NS);
        ns = elapsed / (double)ops;
        if (ns < best)
            best = ns;
    }
    ret = best;
err:
    ossl_pqueue_OLD_ELEM_free(pq);
    return ret;
}

static double measure_pop(OLD_ELEM *e, size_t n)
{
    OSSL_PRIORITY_QUEUE_OLD_ELEM *pq = NULL;
    double ret = -1;
    double best = 1e30;
    int t;

    for (t = 0; t < TRIALS; t++) {
        double elapsed = 0, ns;
        size_t ops = 0;

        do {
            double t0, t1;
            size_t i;
            int ok = 1;

            fill_old(e, n, 0x1234u + (uint32_t)t);
            pq = ossl_pqueue_OLD_ELEM_new(old_cmp);
            if (pq == NULL)
                goto err;
            if (!ossl_pqueue_OLD_ELEM_reserve(pq, n))
                goto err;
            for (i = 0; i < n; i++)
                ok &= ossl_pqueue_OLD_ELEM_push(pq, &e[i], &e[i].handle);
            if (!ok)
                goto err;
            t0 = now_ns();
            for (i = 0; i < n; i++)
                ossl_pqueue_OLD_ELEM_pop(pq);
            t1 = now_ns();
            ossl_pqueue_OLD_ELEM_free(pq);
            pq = NULL;
            elapsed += t1 - t0;
            ops += n;
        } while (elapsed < MIN_ELAPSED_NS);
        ns = elapsed / (double)ops;
        if (ns < best)
            best = ns;
    }
    ret = best;
err:
    ossl_pqueue_OLD_ELEM_free(pq);
    return ret;
}

static double measure_remove(OLD_ELEM *e, size_t n)
{
    size_t *perm = NULL;
    OSSL_PRIORITY_QUEUE_OLD_ELEM *pq = NULL;
    double ret = -1;
    double best = 1e30;
    int t;

    perm = random_perm(n, 0xfeedu);
    if (perm == NULL)
        goto err;

    for (t = 0; t < TRIALS; t++) {
        double elapsed = 0, ns;
        size_t ops = 0;

        do {
            double t0, t1;
            size_t i;
            int ok = 1;

            fill_old(e, n, 0x1234u + (uint32_t)t);
            pq = ossl_pqueue_OLD_ELEM_new(old_cmp);
            if (pq == NULL)
                goto err;
            if (!ossl_pqueue_OLD_ELEM_reserve(pq, n))
                goto err;
            for (i = 0; i < n; i++)
                ok &= ossl_pqueue_OLD_ELEM_push(pq, &e[i], &e[i].handle);
            if (!ok)
                goto err;
            t0 = now_ns();
            for (i = 0; i < n; i++)
                ossl_pqueue_OLD_ELEM_remove(pq, e[perm[i]].handle);
            t1 = now_ns();
            ossl_pqueue_OLD_ELEM_free(pq);
            pq = NULL;
            elapsed += t1 - t0;
            ops += n;
        } while (elapsed < MIN_ELAPSED_NS);
        ns = elapsed / (double)ops;
        if (ns < best)
            best = ns;
    }
    ret = best;
err:
    ossl_pqueue_OLD_ELEM_free(pq);
    OPENSSL_free(perm);
    return ret;
}

/*
 * Steady state: queue holds ~N items.  Each cycle pops the top, mutates
 * its key to a fresh random value, and pushes the same element back.
 * The set of in-flight elements never changes -- only their keys -- so
 * the heap stays in a well-defined state without any wrap-around reinit.
 * 'fresh[]' is precomputed so PRNG cost is excluded from the timed loop.
 */
static double measure_steady(OLD_ELEM *e, size_t n, size_t cycles)
{
    size_t *fresh = NULL;
    OSSL_PRIORITY_QUEUE_OLD_ELEM *pq = NULL;
    double ret = -1;
    double best = 1e30;
    int t;

    fresh = OPENSSL_malloc(cycles * sizeof(*fresh));
    if (fresh == NULL)
        goto err;

    for (t = 0; t < TRIALS; t++) {
        double elapsed = 0, ns;
        size_t ops = 0;
        size_t c;

        test_random_seed(0x5678u + (uint32_t)t);
        for (c = 0; c < cycles; c++)
            fresh[c] = (size_t)test_random();

        do {
            double t0, t1;
            size_t i;
            int ok = 1;

            fill_old(e, n, 0x1234u + (uint32_t)t);
            pq = ossl_pqueue_OLD_ELEM_new(old_cmp);
            if (pq == NULL)
                goto err;
            if (!ossl_pqueue_OLD_ELEM_reserve(pq, n))
                goto err;
            for (i = 0; i < n; i++)
                ok &= ossl_pqueue_OLD_ELEM_push(pq, &e[i], &e[i].handle);
            if (!ok)
                goto err;

            t0 = now_ns();
            for (c = 0; c < cycles; c++) {
                OLD_ELEM *en = ossl_pqueue_OLD_ELEM_pop(pq);

                en->value = fresh[c];
                ok &= ossl_pqueue_OLD_ELEM_push(pq, en, &en->handle);
            }
            t1 = now_ns();
            ossl_pqueue_OLD_ELEM_free(pq);
            pq = NULL;
            if (!ok)
                goto err;
            elapsed += t1 - t0;
            ops += 2 * cycles;
        } while (elapsed < MIN_ELAPSED_NS);
        ns = elapsed / (double)ops;
        if (ns < best)
            best = ns;
    }
    ret = best;
err:
    ossl_pqueue_OLD_ELEM_free(pq);
    OPENSSL_free(fresh);
    return ret;
}

/*
 * Churn: queue holds N elements throughout.  Each cycle picks a random
 * live element by array index, removes it (mid-heap remove, not just
 * the top), assigns a fresh key, and pushes it back.  This is the
 * cancel-and-rearm pattern -- e.g. a timer wheel where a pending event
 * is cancelled and rescheduled at a new deadline.  Distinct from
 * steady_push_pop, which only ever touches the root.
 */
static double measure_churn(OLD_ELEM *e, size_t n, size_t cycles)
{
    size_t *fresh = NULL;
    size_t *idx = NULL;
    OSSL_PRIORITY_QUEUE_OLD_ELEM *pq = NULL;
    double ret = -1;
    double best = 1e30;
    int t;

    fresh = OPENSSL_malloc(cycles * sizeof(*fresh));
    idx = OPENSSL_malloc(cycles * sizeof(*idx));
    if (fresh == NULL || idx == NULL)
        goto err;

    for (t = 0; t < TRIALS; t++) {
        double elapsed = 0, ns;
        size_t ops = 0;
        size_t c;

        test_random_seed(0x9abcu + (uint32_t)t);
        for (c = 0; c < cycles; c++) {
            fresh[c] = (size_t)test_random();
            idx[c] = (size_t)(test_random() % n);
        }

        do {
            double t0, t1;
            size_t i;
            int ok = 1;

            fill_old(e, n, 0x1234u + (uint32_t)t);
            pq = ossl_pqueue_OLD_ELEM_new(old_cmp);
            if (pq == NULL)
                goto err;
            if (!ossl_pqueue_OLD_ELEM_reserve(pq, n))
                goto err;
            for (i = 0; i < n; i++)
                ok &= ossl_pqueue_OLD_ELEM_push(pq, &e[i], &e[i].handle);
            if (!ok)
                goto err;

            t0 = now_ns();
            for (c = 0; c < cycles; c++) {
                size_t j = idx[c];

                ossl_pqueue_OLD_ELEM_remove(pq, e[j].handle);
                e[j].value = fresh[c];
                ok &= ossl_pqueue_OLD_ELEM_push(pq, &e[j], &e[j].handle);
            }
            t1 = now_ns();
            ossl_pqueue_OLD_ELEM_free(pq);
            pq = NULL;
            if (!ok)
                goto err;
            elapsed += t1 - t0;
            ops += 2 * cycles;
        } while (elapsed < MIN_ELAPSED_NS);
        ns = elapsed / (double)ops;
        if (ns < best)
            best = ns;
    }
    ret = best;
err:
    ossl_pqueue_OLD_ELEM_free(pq);
    OPENSSL_free(fresh);
    OPENSSL_free(idx);
    return ret;
}

static void cell(double v)
{
    if (v < 0)
        printf(" %12s", "NaN");
    else
        printf(" %12.2f", v);
}

static size_t override_n;

static size_t cycles_for(size_t n)
{
    if (n <= 1024)
        return 100000;
    if (n <= 16384)
        return 50000;
    return 5000;
}

static int run_perf(void)
{
    static const size_t default_sizes[] = { 64, 1024, 16384, 262144 };
    static const size_t default_cycles[] = { 100000, 100000, 50000, 5000 };
    const size_t *sizes;
    const size_t *steady_cycles;
    const size_t *churn_cycles;
    size_t nsizes;
    size_t override_cycles;
    size_t s;

    if (override_n != 0) {
        sizes = &override_n;
        override_cycles = cycles_for(override_n);
        steady_cycles = &override_cycles;
        churn_cycles = &override_cycles;
        nsizes = 1;
    } else {
        sizes = default_sizes;
        steady_cycles = default_cycles;
        churn_cycles = default_cycles;
        nsizes = OSSL_NELEM(default_sizes);
    }

    printf("# priority_queue.c (handle-based) -- best of %d trials, ns/op\n",
        TRIALS);
    printf("# element size: %zu bytes\n", sizeof(OLD_ELEM));
    printf("# columns: 1=N 2=push_grow 3=push_reserved 4=pop_drain"
           " 5=remove_random 6=steady_push_pop 7=churn_rm_push\n");
    printf("# %-8s %12s %12s %12s %12s %12s %12s\n",
        "N", "push_grow", "push_resv", "pop_drain",
        "remove_rand", "steady", "churn");

    for (s = 0; s < nsizes; s++) {
        size_t n = sizes[s];
        OLD_ELEM *oe = OPENSSL_malloc(n * sizeof(*oe));

        if (!TEST_ptr(oe)) {
            OPENSSL_free(oe);
            return 0;
        }

        printf("%-10zu", n);
        cell(measure_push(oe, n, 0));
        cell(measure_push(oe, n, 1));
        cell(measure_pop(oe, n));
        cell(measure_remove(oe, n));
        cell(measure_steady(oe, n, steady_cycles[s]));
        cell(measure_churn(oe, n, churn_cycles[s]));
        printf("\n");
        fflush(stdout);

        OPENSSL_free(oe);
    }
    return 1;
}

OPT_TEST_DECLARE_USAGE("[N]\n")

int setup_tests(void)
{
    const char *arg;

    if (!test_skip_common_options())
        return 0;

    arg = test_get_argument(0);
    if (arg != NULL) {
        char *end;
        unsigned long long v = strtoull(arg, &end, 10);

        if (*arg == '\0' || *end != '\0' || v == 0) {
            TEST_error("N must be a positive integer");
            return 0;
        }
        override_n = (size_t)v;
    }

    ADD_TEST(run_perf);
    return 1;
}
