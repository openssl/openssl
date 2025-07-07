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
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/uio.h>

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
static CRYPTO_ONCE init_contention_data_flag = CRYPTO_ONCE_STATIC_INIT;
pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
CRYPTO_THREAD_LOCAL thread_contention_data;

struct stack_info {
    unsigned int nptrs;
    int write;
    OSSL_TIME start;
    OSSL_TIME duration;
    char **strings;
};

#  define STACKS_COUNT 32
struct stack_traces {
    int fd;
    int lock_depth;
    size_t idx;
    struct stack_info stacks[STACKS_COUNT];
};

#  ifdef FIPS_MODULE
#   define FIPS_SFX "-fips"
#  else
#   define FIPS_SFX ""
#  endif
static void *init_contention_data(void)
{
    struct stack_traces *traces;
    char fname_fmt[] = "lock-contention-log" FIPS_SFX ".%d.txt";
    char fname[sizeof(fname_fmt) + sizeof(int) * 3];

    traces = OPENSSL_zalloc(sizeof(struct stack_traces));

    snprintf(fname, sizeof(fname), fname_fmt, gettid());

    traces->fd = open(fname, O_WRONLY | O_APPEND | O_CLOEXEC | O_CREAT, 0600);

    return traces;
}

static void destroy_contention_data(void *data)
{
    struct stack_traces *st = data;

    close(st->fd);
    OPENSSL_free(data);
}

static void init_contention_data_once(void)
{
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
        traces = init_contention_data();
        CRYPTO_THREAD_set_local(&thread_contention_data, traces);
    }

    return traces;
}

static void print_stack_traces(struct stack_traces *traces)
{
    unsigned int j;
    struct iovec *iov;
    int iovcnt;

    while (traces != NULL && traces->idx >= 1) {
        traces->idx--;
        dprintf(traces->fd,
                "lock blocked on %s for %zu usec at time %zu tid %d\n",
                traces->stacks[traces->idx].write == 1 ? "WRITE" : "READ",
                ossl_time2us(traces->stacks[traces->idx].duration),
                ossl_time2us(traces->stacks[traces->idx].start),
                gettid());
        if (traces->stacks[traces->idx].strings != NULL) {
            static const char lf = '\n';
            iovcnt = traces->stacks[traces->idx].nptrs * 2 + 1;
            iov = alloca(iovcnt * sizeof(*iov));
            for (j = 0; j < traces->stacks[traces->idx].nptrs; j++) {
                iov[2 * j].iov_base = traces->stacks[traces->idx].strings[j];
               iov[2 * j].iov_len = strlen(traces->stacks[traces->idx].strings[j]);
                iov[2 * j + 1].iov_base = (char *) &lf;
               iov[2 * j + 1].iov_len = 1;
            }
            iov[traces->stacks[traces->idx].nptrs * 2].iov_base = (char *) &lf;
            iov[traces->stacks[traces->idx].nptrs * 2].iov_len = 1;
        } else {
            static const char no_bt[] = "No stack trace available\n\n";
            iovcnt = 1;
            iov = alloca(iovcnt * sizeof(*iov));
            iov[0].iov_base = (char *) no_bt;
            iov[0].iov_len = sizeof(no_bt) - 1;
        }
        writev(traces->fd, iov, iovcnt);
        free(traces->stacks[traces->idx].strings);
    }
}

void ossl_init_rwlock_contention_data(void)
{
    CRYPTO_THREAD_run_once(&init_contention_data_flag, init_contention_data_once);
}

void ossl_free_rwlock_contention_data(void)
{
}

static int record_lock_contention(pthread_rwlock_t *lock,
                                  struct stack_traces *traces, bool write)
{
    void *buffer[BT_BUF_SIZE];
    OSSL_TIME start, end;
    int ret;

    start = ossl_time_now();
    ret = (write ? pthread_rwlock_wrlock : pthread_rwlock_rdlock)(lock);
    if (ret)
        return ret;
    end = ossl_time_now();
    traces->stacks[traces->idx].nptrs = backtrace(buffer, BT_BUF_SIZE);
    traces->stacks[traces->idx].strings = backtrace_symbols(buffer,
                                                            traces->stacks[traces->idx].nptrs);
    traces->stacks[traces->idx].duration = ossl_time_subtract(end, start);
    traces->stacks[traces->idx].start = start;
    traces->stacks[traces->idx].write = write;
    traces->idx++;
    if (traces->idx >= STACKS_COUNT) {
        fprintf(stderr, "STACK RECORD OVERFLOW!\n");
        print_stack_traces(traces);
    }

    return 0;
}

int ossl_rwlock_rdlock(pthread_rwlock_t *lock)
{
    struct stack_traces *traces = get_stack_traces(true);

    traces->lock_depth++;
    if (pthread_rwlock_tryrdlock(lock))
        return record_lock_contention(lock, traces, false);

    return 0;
}

int ossl_rwlock_wrlock(pthread_rwlock_t *lock)
{
    struct stack_traces *traces = get_stack_traces(true);

    traces->lock_depth++;
    if (pthread_rwlock_trywrlock(lock))
        return record_lock_contention(lock, traces, true);

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

        if (traces != NULL) {
            traces->lock_depth--;
            assert(traces->lock_depth >= 0);
            if (traces->lock_depth == 0)
                print_stack_traces(traces);
        }
    }

    return 0;
}

#endif
