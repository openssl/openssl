/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#define _GNU_SOURCE

#include <assert.h>
#include <execinfo.h>
#include <stdbool.h>
#include <unistd.h>

#include "internal/common.h"
#include "internal/time.h"
#include "internal/threads_lock_contention.h"

#ifdef REPORT_RWLOCK_CONTENTION

# define BT_BUF_SIZE 1024

/*
 * Normally we would use a BIO here to do this, but we create locks during
 * library initalization, and creating a bio too early, creates a recursive set
 * of stack calls that leads us to call CRYPTO_thread_run_once while currently
 * executing the init routine for various run_once functions, which leads to
 * deadlock.  Avoid that by just using a FILE pointer.  Also note that we
 * directly use a pthread_mutex_t to protect access from mutltiple threads
 * to the contention log file.  We do this because we want to avoid use
 * of the CRYPTO_THREAD api so as to prevent recursive blocking reports.
 */
static FILE *contention_fp = NULL;
static CRYPTO_ONCE init_contention_fp = CRYPTO_ONCE_STATIC_INIT;
static int rwlock_count = 0;
pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
CRYPTO_THREAD_LOCAL thread_contention_data;

static void destroy_contention_data(void *data)
{
    OPENSSL_free(data);
}

struct stack_info {
    unsigned int nptrs;
    int write;
    OSSL_TIME start;
    OSSL_TIME duration;
    char **strings;
};

#  define STACKS_COUNT 32
struct stack_traces {
    int lock_depth;
    size_t idx;
    struct stack_info stacks[STACKS_COUNT];
};

#  ifdef FIPS_MODULE
#   define FIPS_SFX "-fips"
#  else
#   define FIPS_SFX ""
#  endif
static void init_contention_fp_once(void)
{
    contention_fp = fopen("lock-contention-log" FIPS_SFX ".txt", "w");
    if (contention_fp == NULL)
        fprintf(stderr, "Contention log file could not be opened, log will not be recorded\n");

    /*
     * Create a thread local key here to store our list of stack traces
     * to be printed when we unlock the lock we are holding
     */
    CRYPTO_THREAD_init_local(&thread_contention_data, destroy_contention_data);
    return;
}

static struct stack_traces *get_stack_traces(bool init)
{
    struct stack_traces *traces = CRYPTO_THREAD_get_local(&thread_contention_data);
    if (!traces && init) {
        traces = OPENSSL_zalloc(sizeof(*traces));
        CRYPTO_THREAD_set_local(&thread_contention_data, traces);
    }

    return traces;
}

static void print_stack_traces(struct stack_traces *traces, FILE *fptr)
{
    unsigned int j;

    pthread_mutex_lock(&log_lock);
    while (traces != NULL && traces->idx >= 1) {
        traces->idx--;
        fprintf(fptr, "lock blocked on %s for %zu usec at time %zu tid %d\n",
                traces->stacks[traces->idx].write == 1 ? "WRITE" : "READ",
                ossl_time2us(traces->stacks[traces->idx].duration),
                ossl_time2us(traces->stacks[traces->idx].start),
                gettid());
        if (traces->stacks[traces->idx].strings != NULL) {
            for (j = 0; j < traces->stacks[traces->idx].nptrs; j++)
                fprintf(fptr, "%s\n", traces->stacks[traces->idx].strings[j]);
            free(traces->stacks[traces->idx].strings);
        } else {
            fprintf(fptr, "No stack trace available\n");
        }
        fprintf(contention_fp, "\n");
    }
    pthread_mutex_unlock(&log_lock);
}

void ossl_init_rwlock_contention_data(void)
{
    CRYPTO_THREAD_run_once(&init_contention_fp, init_contention_fp_once);
    __atomic_add_fetch(&rwlock_count, 1, __ATOMIC_ACQ_REL);
}

void ossl_free_rwlock_contention_data(void)
{
    /*
     * Note: It's possible here that OpenSSL may allocate a lock and immediately
     * free it, in which case we would erroneously close the contention log
     * prior to the library going on to do more real work.  In practice
     * that never happens though, and since this is a debug facility
     * we don't worry about that here.
     */
    if (__atomic_add_fetch(&rwlock_count, -1, __ATOMIC_ACQ_REL) == 0) {
        fclose(contention_fp);
        contention_fp = NULL;
    }
}

int ossl_rwlock_rdlock(pthread_rwlock_t *lock)
{
    struct stack_traces *traces = get_stack_traces(true);

    traces->lock_depth++;
    if (pthread_rwlock_tryrdlock(lock)) {
        void *buffer[BT_BUF_SIZE];
        OSSL_TIME start, end;
        int ret;

        start = ossl_time_now();
        ret = pthread_rwlock_rdlock(lock);
        if (ret)
            return ret;
        end = ossl_time_now();
        traces->stacks[traces->idx].nptrs = backtrace(buffer, BT_BUF_SIZE);
        traces->stacks[traces->idx].strings = backtrace_symbols(buffer,
                                                                traces->stacks[traces->idx].nptrs);
        traces->stacks[traces->idx].duration = ossl_time_subtract(end, start);
        traces->stacks[traces->idx].start = start;
        traces->stacks[traces->idx].write = 0;
        traces->idx++;
        if (traces->idx >= STACKS_COUNT) {
            fprintf(stderr, "STACK RECORD OVERFLOW!\n");
            print_stack_traces(traces, contention_fp);
        }
    }

    return 0;
}

int ossl_rwlock_wrlock(pthread_rwlock_t *lock)
{
    struct stack_traces *traces = get_stack_traces(true);

    traces->lock_depth++;
    if (pthread_rwlock_trywrlock(lock)) {
        void *buffer[BT_BUF_SIZE];
        OSSL_TIME start, end;
        int ret;

        start = ossl_time_now();
        ret = pthread_rwlock_wrlock(lock);
        if (ret)
            return ret;
        end = ossl_time_now();
        traces->stacks[traces->idx].nptrs = backtrace(buffer, BT_BUF_SIZE);
        traces->stacks[traces->idx].strings = backtrace_symbols(buffer,
                                                                traces->stacks[traces->idx].nptrs);
        traces->stacks[traces->idx].duration = ossl_time_subtract(end, start);
        traces->stacks[traces->idx].start = start;
        traces->stacks[traces->idx].write = 1;
        traces->idx++;
        if (traces->idx >= STACKS_COUNT) {
            fprintf(stderr, "STACK RECORD OVERFLOW!\n");
            print_stack_traces(traces, contention_fp);
        }
    }

    return 0;
}

int ossl_rwlock_unlock(pthread_rwlock_t *lock)
{
    int ret;

    ret = pthread_rwlock_unlock(lock);
    if (ret)
        return ret;

    {
        struct stack_traces *traces = get_stack_traces(false);

        if (contention_fp == NULL)
            return 0;
        if (traces != NULL) {
            traces->lock_depth--;
            assert(traces->lock_depth >= 0);
            if (traces->lock_depth == 0)
                print_stack_traces(traces, contention_fp);
        }
    }

    return 0;
}

#endif
