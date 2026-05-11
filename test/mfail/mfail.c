/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "mfail.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define MFAIL_HAVE_ASAN 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) && !defined(MFAIL_HAVE_ASAN)
#define MFAIL_HAVE_ASAN 1
#endif

#ifdef MFAIL_HAVE_ASAN
extern void __sanitizer_print_stack_trace(void);
#elif defined(__GLIBC__) || defined(__APPLE__)
#include <execinfo.h>
#define MFAIL_HAVE_BACKTRACE
#define MFAIL_BT_MAX 128
#endif

static struct {
    int installed;
    int skip_all;
    int skip_slow;
    int single_point;
    int start_point;
    int env_count;
    int slow_threshold;
    int print_bt;
    int mode;
    int phase;
    int seq;
    int next_point;
    int iter_index;
    int n;
    int total;
    int iterations;
    int started;
    int fail_after;
    int alloc_count;
    int triggered;
    int counting;
    int slow_skipped;
} mf;

static int env_is_true(const char *name)
{
    const char *value = getenv(name);
    return value != NULL && *value != '\0' && strcmp(value, "0") != 0;
}

static int env_int(const char *name, int dflt)
{
    const char *value = getenv(name);
    return (value != NULL && *value != '\0') ? atoi(value) : dflt;
}

static void mfail_print_bt(void)
{
#ifdef MFAIL_HAVE_ASAN
    fprintf(stderr, "# MFAIL_BT (failure injection point)\n");
    __sanitizer_print_stack_trace();
#elif defined(MFAIL_HAVE_BACKTRACE)
    void *buf[MFAIL_BT_MAX];
    char **syms;
    int n, i;

    n = backtrace(buf, MFAIL_BT_MAX);
    syms = backtrace_symbols(buf, n);
    if (syms == NULL)
        return;

    fprintf(stderr, "# MFAIL_BT (failure injection point)\n");
    /* Skip frame 0 (this function) */
    for (i = 1; i < n; i++)
        fprintf(stderr, "#   %s\n", syms[i]);

    free(syms);
#endif
}

static int should_fail(void)
{
    int idx;

    if (!mf.counting)
        return 0;

    idx = mf.alloc_count++;

    if (mf.fail_after < 0 || mf.triggered)
        return 0;
    if (idx == mf.fail_after) {
        mf.triggered = 1;
        if (mf.print_bt)
            mfail_print_bt();
        return 1;
    }
    return 0;
}

static void *mf_malloc(size_t num, const char *file, int line)
{
    if (num == 0)
        return NULL;
    if (should_fail())
        return NULL;
    return malloc(num);
}

static void *mf_realloc(void *addr, size_t num, const char *file, int line)
{
    if (addr == NULL)
        return mf_malloc(num, file, line);
    if (num == 0) {
        free(addr);
        return NULL;
    }
    if (should_fail())
        return NULL;
    return realloc(addr, num);
}

static void mf_free(void *addr, const char *file, int line)
{
    free(addr);
}

int mfail_install(int optional)
{
    if (mf.installed)
        return 1;
    if (env_is_true("OPENSSL_TEST_MFAIL_DISABLE"))
        return 0;

    mf.skip_all = env_is_true("OPENSSL_TEST_MFAIL_SKIP_ALL");
    mf.skip_slow = env_is_true("OPENSSL_TEST_MFAIL_SKIP_SLOW");
    mf.single_point = env_int("OPENSSL_TEST_MFAIL_POINT", -1);
    mf.start_point = env_int("OPENSSL_TEST_MFAIL_START", 0);
    mf.env_count = env_int("OPENSSL_TEST_MFAIL_COUNT", 0);
    mf.slow_threshold = env_int("OPENSSL_TEST_MFAIL_SLOW", 1000);
    mf.print_bt = env_is_true("OPENSSL_TEST_MFAIL_BACKTRACE");

    /* if optional and nothing configured, then no point installing hooks */
    if (optional && mf.env_count <= 0 && mf.single_point < 0)
        return 0;

    if (!CRYPTO_set_mem_functions(mf_malloc, mf_realloc, mf_free))
        return -1;

    mf.installed = 1;
    mf.fail_after = -1;
    return 1;
}

int mfail_is_installed(void)
{
    return mf.installed;
}

int mfail_env_skip_all(void)
{
    return !mf.installed || mf.skip_all;
}

int mfail_env_skip_slow(void)
{
    return !mf.installed || mf.skip_slow;
}

/* The i-th of n points distributed over [start, total), rotated by seq */
static int compute_point(int i, int total, int n, int seq, int start)
{
    int range = total - start;
    int stride_int, stride_rem_x2, stride_rnd, offset, p;

    if (range <= 0 || n <= 0)
        return start;

    stride_int = range / n;
    stride_rem_x2 = (range - stride_int * n) * 2;
    stride_rnd = stride_int + (stride_rem_x2 >= n ? 1 : 0);
    offset = (stride_rnd > 0) ? (seq % stride_rnd) : 0;

    p = (int)(((long)i * range + n / 2) / n) + offset;
    if (p >= range)
        p = range - 1;
    if (p < 0)
        p = 0;
    return start + p;
}

void mfail_init(int seq, int flags)
{
    mf.seq = seq;
    mf.iter_index = 0;
    mf.n = 0;
    mf.total = 0;
    mf.iterations = 0;
    mf.started = 0;
    mf.fail_after = -1;
    mf.alloc_count = 0;
    mf.triggered = 0;
    mf.counting = 0;
    mf.slow_skipped = 0;

    if (mf.single_point >= 0) {
        mf.mode = MFAIL_MODE_SINGLE;
    } else if ((flags & MFAIL_FLAG_COUNT) && mf.env_count > 0) {
        mf.mode = MFAIL_MODE_SAMPLED;
    } else {
        mf.mode = MFAIL_MODE_EXHAUSTIVE;
    }
    mf.phase = MFAIL_PHASE_COUNTING;
    mf.next_point = -1;
}

int mfail_has_next(void)
{
    if (mf.started) {
        mf.iterations++;
        switch (mf.phase) {
        case MFAIL_PHASE_COUNTING:
            mf.total = mf.alloc_count;
            if (mf.skip_slow && mf.total > mf.slow_threshold) {
                mf.slow_skipped = 1;
                mf.phase = MFAIL_PHASE_DONE;
                break;
            }
            if (mf.mode == MFAIL_MODE_SINGLE) {
                mf.phase = MFAIL_PHASE_INJECTING;
                mf.next_point = mf.single_point;
            } else if (mf.mode == MFAIL_MODE_EXHAUSTIVE) {
                if (mf.total > mf.start_point) {
                    mf.phase = MFAIL_PHASE_INJECTING;
                    mf.next_point = mf.start_point;
                } else {
                    mf.phase = MFAIL_PHASE_DONE;
                }
            } else { /* mf.mode is MFAIL_MODE_SAMPLED */
                mf.n = mf.env_count;
                if (mf.n > mf.total)
                    mf.n = mf.total;
                if (mf.n > 0 && mf.total > mf.start_point) {
                    mf.phase = MFAIL_PHASE_INJECTING;
                    mf.iter_index = 0;
                    mf.next_point = compute_point(0, mf.total, mf.n, mf.seq,
                        mf.start_point);
                } else {
                    mf.phase = MFAIL_PHASE_DONE;
                }
            }
            break;
        case MFAIL_PHASE_INJECTING:
            if (mf.mode == MFAIL_MODE_SINGLE) {
                mf.phase = MFAIL_PHASE_DONE;
            } else if (mf.mode == MFAIL_MODE_EXHAUSTIVE) {
                if (++mf.next_point >= mf.total)
                    mf.phase = MFAIL_PHASE_DONE;
            } else { /* SAMPLED */
                if (++mf.iter_index >= mf.n)
                    mf.phase = MFAIL_PHASE_DONE;
                else
                    mf.next_point = compute_point(mf.iter_index, mf.total,
                        mf.n, mf.seq, mf.start_point);
            }
            break;
        case MFAIL_PHASE_DONE:
        default:
            break;
        }
    } else {
        mf.started = 1;
    }

    if (mf.phase == MFAIL_PHASE_DONE)
        return 0;

    mf.alloc_count = 0;
    mf.counting = 0;
    mf.triggered = 0;
    mf.fail_after = (mf.phase == MFAIL_PHASE_INJECTING) ? mf.next_point : -1;
    return 1;
}

void mfail_start(void)
{
    mf.alloc_count = 0;
    mf.counting = 1;
}

void mfail_end(void)
{
    mf.counting = 0;
}

void mfail_arm_once(int point)
{
    mf.fail_after = point;
    mf.alloc_count = 0;
    mf.triggered = 0;
}

void mfail_disarm(void)
{
    mf.fail_after = -1;
    mf.alloc_count = 0;
    mf.triggered = 0;
}

int mfail_was_triggered(void)
{
    return mf.triggered;
}

int mfail_was_slow_skipped(void)
{
    return mf.slow_skipped;
}

int mfail_get_count(void)
{
    return mf.alloc_count;
}

int mfail_get_total(void)
{
    return mf.total;
}

int mfail_get_phase(void)
{
    return mf.phase;
}

int mfail_get_mode(void)
{
    return mf.mode;
}

int mfail_iterations(void)
{
    return mf.iterations;
}

int mfail_get_slow_threshold(void)
{
    return mf.slow_threshold;
}

int mfail_get_point(void)
{
    return (mf.phase == MFAIL_PHASE_INJECTING) ? mf.next_point : -1;
}
