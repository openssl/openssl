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
#include <limits.h>
#include <openssl/crypto.h>

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define MFAIL_HAVE_ASAN 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) && !defined(MFAIL_HAVE_ASAN)
#define MFAIL_HAVE_ASAN 1
#endif

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define MFAIL_HAVE_MSAN 1
#endif
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
    int count_only;
    int count_only_env;
    int sample_count;
    int slow_threshold;
    int print_bt;
    int no_watch;
    int watch_alloc;
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
    int no_check;
} mf;

struct mfw_block {
    void *ptr;
    size_t size;
    int num;
    const char *file;
    int line;
};

static struct {
    int active;
    int failed;
    int triggered;
    int leaks;
    int checked;
    int allocs;
    int frees;
    int nsecrets;
    struct {
        unsigned char *data;
        size_t len;
    } secrets[MFAIL_WATCH_MAX_SECRETS];
    struct mfw_block *blocks;
    size_t nblocks;
    size_t blocks_cap;
    MFAIL_LEAK leak[MFAIL_WATCH_MAX_LEAKS];
} mfw;

static int env_is_true(const char *name)
{
    const char *value = getenv(name);
    return value != NULL && *value != '\0' && strcmp(value, "0") != 0;
}

static int env_int(const char *name, int dflt)
{
    const char *value = getenv(name);
    unsigned long ul;

    if (value != NULL && *value != '\0'
        && OPENSSL_strtoul(value, NULL, 10, &ul) && ul <= INT_MAX)
        return (int)ul;
    return dflt;
}

static void mfail_print_bt(const char *what)
{
#ifdef MFAIL_HAVE_ASAN
    fprintf(stderr, "# MFAIL_BT (%s)\n", what);
    __sanitizer_print_stack_trace();
#elif defined(MFAIL_HAVE_BACKTRACE)
    void *buf[MFAIL_BT_MAX];
    char **syms;
    int n, i;

    n = backtrace(buf, MFAIL_BT_MAX);
    syms = backtrace_symbols(buf, n);
    if (syms == NULL)
        return;

    fprintf(stderr, "# MFAIL_BT (%s)\n", what);
    /* Skip frame 0 (this function) */
    for (i = 1; i < n; i++)
        fprintf(stderr, "#   %s\n", syms[i]);

    free(syms);
#endif
}

static int should_fail(const char *file)
{
    int idx;

    if (!mf.counting)
        return 0;
    /* skip if checking errors and file is not set (debug and error parts) */
    if (!mf.no_check && file == NULL)
        return 0;

    idx = mf.alloc_count++;

    if (mf.fail_after < 0 || mf.triggered)
        return 0;
    if (idx == mf.fail_after) {
        mf.triggered = 1;
        if (mfw.active)
            mfw.triggered = 1;
        if (mf.print_bt)
            mfail_print_bt("failure injection point");
        return 1;
    }
    return 0;
}

static void mfw_track(void *ptr, size_t size, const char *file, int line)
{
    struct mfw_block *b;

    if (mfw.nblocks == mfw.blocks_cap) {
        size_t cap = mfw.blocks_cap == 0 ? 256 : mfw.blocks_cap * 2;

        b = realloc(mfw.blocks, cap * sizeof(*b));
        if (b == NULL) {
            mfw.failed = 1;
            return;
        }
        mfw.blocks = b;
        mfw.blocks_cap = cap;
    }
    b = &mfw.blocks[mfw.nblocks++];
    b->ptr = ptr;
    b->size = size;
    b->num = mfw.allocs++;
    if (b->num == mf.watch_alloc) {
        char what[64];

        snprintf(what, sizeof(what), "watched allocation %d", b->num);
        mfail_print_bt(what);
    }
    b->file = file;
    b->line = line;
}

static int mfw_find_secret(const unsigned char *p, size_t size, size_t *offset)
{
    int i;

    for (i = 0; i < mfw.nsecrets; i++) {
        const unsigned char *s = mfw.secrets[i].data, *q = p;
        size_t len = mfw.secrets[i].len, left = size;

        while (left >= len
            && (q = memchr(q, s[0], left - len + 1)) != NULL) {
            if (memcmp(q, s, len) == 0) {
                *offset = q - p;
                return i;
            }
            q++;
            left = size - (q - p);
        }
    }
    return -1;
}

/* Search the block if it is tracked and stop tracking it */
static void mfw_release(void *ptr, const char *file, int line)
{
    size_t i, offset = 0;
    int secret;
    struct mfw_block *b = NULL;

    int free_num = mfw.frees++;

    /* most blocks are freed soon after they are allocated */
    for (i = mfw.nblocks; i > 0; i--) {
        if (mfw.blocks[i - 1].ptr == ptr) {
            b = &mfw.blocks[i - 1];
            break;
        }
    }
    if (b == NULL)
        return;

    mfw.checked++;
#ifdef MFAIL_HAVE_MSAN
    /* the block is searched as a whole and freed right after it */
    __msan_unpoison(ptr, b->size);
#endif
    secret = mfw_find_secret(ptr, b->size, &offset);
    if (secret >= 0) {
        if (mfw.leaks < MFAIL_WATCH_MAX_LEAKS) {
            MFAIL_LEAK *l = &mfw.leak[mfw.leaks];

            l->secret = secret;
            l->offset = offset;
            l->size = b->size;
            l->alloc_num = b->num;
            l->free_num = free_num;
            l->alloc_file = b->file;
            l->alloc_line = b->line;
            l->free_file = file;
            l->free_line = line;
            l->point = mf.triggered ? mf.fail_after : -1;
        }
        mfw.leaks++;
        if (mf.print_bt) {
            char what[80];

            snprintf(what, sizeof(what),
                "secret left by allocation %d in free %d", b->num, free_num);
            mfail_print_bt(what);
        }
    }
    *b = mfw.blocks[--mfw.nblocks];
}

static size_t mfw_block_size(void *ptr)
{
    size_t i;

    for (i = mfw.nblocks; i > 0; i--)
        if (mfw.blocks[i - 1].ptr == ptr)
            return mfw.blocks[i - 1].size;
    return 0;
}

static void *mf_malloc(size_t num, const char *file, int line)
{
    void *ret;

    if (num == 0)
        return NULL;
    if (should_fail(file))
        return NULL;
    ret = malloc(num);
    if (mfw.active && ret != NULL)
        mfw_track(ret, num, file, line);
    return ret;
}

static void mf_free(void *addr, const char *file, int line)
{
    if (mfw.active && addr != NULL)
        mfw_release(addr, file, line);
    free(addr);
}

static void *mf_realloc(void *addr, size_t num, const char *file, int line)
{
    void *ret;
    size_t old;

    if (addr == NULL)
        return mf_malloc(num, file, line);
    if (num == 0) {
        mf_free(addr, file, line);
        return NULL;
    }
    if (should_fail(file))
        return NULL;
    if (!mfw.active || (old = mfw_block_size(addr)) == 0)
        return realloc(addr, num);
    /* realloc() may free the old block, so move it here and search it */
    if ((ret = malloc(num)) == NULL)
        return NULL;
    memcpy(ret, addr, old < num ? old : num);
    mfw_release(addr, file, line);
    free(addr);
    mfw_track(ret, num, file, line);
    return ret;
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
    mf.count_only_env = env_is_true("OPENSSL_TEST_MFAIL_COUNT_ONLY");
    mf.slow_threshold = env_int("OPENSSL_TEST_MFAIL_SLOW", 1000);
    mf.print_bt = env_is_true("OPENSSL_TEST_MFAIL_BACKTRACE");
    /* searching of freed blocks reads uninitialised memory */
    mf.no_watch = env_is_true("OSSL_USE_VALGRIND");
    mf.watch_alloc = env_int("OPENSSL_TEST_MFAIL_WATCH_ALLOC", -1);

    /* if optional and nothing configured, then no point installing hooks */
    if (optional && mf.env_count <= 0 && mf.single_point < 0
        && !mf.count_only_env)
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

static void mfw_reset(void)
{
    mfw.failed = 0;
    mfw.triggered = 0;
    mfw.leaks = 0;
    mfw.checked = 0;
    mfw.allocs = 0;
    mfw.frees = 0;
    mfw.nblocks = 0;
}

int mfail_watch_secret(const void *secret, size_t len)
{
    unsigned char *copy;

    if (secret == NULL || len < MFAIL_WATCH_MIN_LEN)
        return 0;
    if (!mf.installed || mf.no_watch)
        return 1;
    if (mfw.active && mfw.nsecrets == MFAIL_WATCH_MAX_SECRETS)
        return 0;
    if ((copy = malloc(len)) == NULL)
        return 0;
    memcpy(copy, secret, len);
    if (!mfw.active) {
        mfw_reset();
        mfw.nsecrets = 0;
    }
    mfw.secrets[mfw.nsecrets].data = copy;
    mfw.secrets[mfw.nsecrets].len = len;
    mfw.nsecrets++;
    mfw.active = 1;
    return 1;
}

void mfail_watch_end(void)
{
    int i;

    if (!mfw.active)
        return;
    mfw.active = 0;
    for (i = 0; i < mfw.nsecrets; i++) {
        memset(mfw.secrets[i].data, 0, mfw.secrets[i].len);
        free(mfw.secrets[i].data);
    }
    mfw.nsecrets = 0;
    mfw.nblocks = 0;
}

int mfail_is_watching(void)
{
    return mfw.active;
}

int mfail_watch_get_leaks(void)
{
    return mfw.failed ? -1 : mfw.leaks;
}

int mfail_watch_get_checked(void)
{
    return mfw.checked;
}

int mfail_watch_was_triggered(void)
{
    return mfw.triggered;
}

const MFAIL_LEAK *mfail_watch_get_leak(int i)
{
    if (i < 0 || i >= mfw.leaks || i >= MFAIL_WATCH_MAX_LEAKS)
        return NULL;
    return &mfw.leak[i];
}

void mfail_init(int seq, int flags)
{
    mfail_init_ex(seq, flags, 0);
}

void mfail_init_ex(int seq, int flags, int count)
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
    mf.no_check = flags & MFAIL_FLAG_NO_CHECK;
    mf.count_only = mf.count_only_env || (flags & MFAIL_FLAG_COUNT_ONLY) != 0;
    /* env count overrides the requested per-test sample count */
    mf.sample_count = mf.env_count > 0 ? mf.env_count : count;

    if (mf.single_point >= 0) {
        mf.mode = MFAIL_MODE_SINGLE;
    } else if ((flags & MFAIL_FLAG_COUNT) && mf.sample_count > 0) {
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
            if (mf.count_only) {
                mf.phase = MFAIL_PHASE_DONE;
                break;
            }
            /* sampled runs are bounded, so slow-skip only applies otherwise */
            if (mf.skip_slow && mf.mode != MFAIL_MODE_SAMPLED
                && mf.total > mf.slow_threshold) {
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
                mf.n = mf.sample_count;
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
    /* do not carry the watch results over from the previous iteration */
    if (!mfw.active)
        mfw_reset();
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

int mfail_is_count_only(void)
{
    return mf.count_only;
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
