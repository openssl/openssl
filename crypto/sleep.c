/*
 * Copyright 2022-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdbool.h>
#include <openssl/crypto.h>
#include "internal/e_os.h"
#include "internal/time.h"

/*
 * system-specific variants defining OSSL_sleep()
 *
 * ossl_sleep_millis/ossl_sleep_secs return a non-zero value if the underlying
 * sleep call has been interrupted and zero otherwise;  note that that does not
 * mean that the full delay duration has lapsed (as it may also be impacted
 * by the platform implementation sleep duration limits), just that there were
 * no interrupts.
 */
#if (defined(OPENSSL_SYS_UNIX) || defined(__DJGPP__)) && !defined(OPENSSL_USE_SLEEP_BUSYLOOP)

# if defined(OPENSSL_USE_USLEEP)                        \
    || defined(__DJGPP__)                               \
    || (defined(__TANDEM) && defined(_REENTRANT))

/*
 * usleep() was made obsolete by POSIX.1-2008, and nanosleep()
 * should be used instead.  However, nanosleep() isn't implemented
 * on the platforms given above, so we still use it for those.
 * Also, OPENSSL_USE_USLEEP can be defined to enable the use of
 * usleep, if it turns out that nanosleep() is unavailable.
 */

#  include <unistd.h>
static uint64_t ossl_sleep_millis(uint64_t millis)
{
    unsigned int s = millis < 1000LLU * UINT_MAX ? (unsigned int)(millis / 1000)
                                                 : UINT_MAX;
    unsigned int us = millis < 1000LLU * UINT_MAX
        ? (unsigned int)((millis % 1000) * 1000) : 0;
    unsigned int ret;

    if (s > 0) {
        ret = sleep(s);

        if (ret != 0)
            return ret;
    }
    /*
     * On NonStop with the PUT thread model, thread context switch is
     * cooperative, with usleep() being a "natural" context switch point.
     * We avoid checking us > 0 here, to allow that context switch to
     * happen.
     */
    return usleep(us);
}

# elif defined(__TANDEM) && !defined(_REENTRANT)

#  include <cextdecs.h(PROCESS_DELAY_)>
static uint64_t ossl_sleep_millis(uint64_t millis)
{
    /* HPNS does not support usleep for non threaded apps */
    PROCESS_DELAY_(millis * 1000);

    return 0;
}

# else

/* nanosleep is defined by POSIX.1-2001 */
#  include <time.h>
static uint64_t ossl_sleep_millis(uint64_t millis)
{
    struct timespec ts;

    ts.tv_sec = (long int) (millis / 1000);
    ts.tv_nsec = (long int) (millis % 1000) * 1000000ul;
    return nanosleep(&ts, NULL);
}

# endif
#elif defined(_WIN32) && !defined(OPENSSL_SYS_UEFI)
# include <windows.h>

static uint64_t ossl_sleep_millis(uint64_t millis)
{
    /*
     * Windows' Sleep() takes a DWORD argument, which is smaller than
     * a uint64_t, so we need to limit it to 49 days, which should be enough.
     */
    DWORD limited_millis = (DWORD)-1;

    if (millis < limited_millis)
        limited_millis = (DWORD)millis;
    Sleep(limited_millis);

    return 0;
}

#else
/* Fallback to a busy wait */
# define USE_SLEEP_SECS

static uint64_t ossl_sleep_secs(uint64_t secs)
{
    /*
     * sleep() takes an unsigned int argument, which is smaller than
     * a uint64_t, so it needs to be limited to 136 years which
     * should be enough even for Sleeping Beauty.
     */
    unsigned int limited_secs = UINT_MAX;

    if (secs < limited_secs)
        limited_secs = (unsigned int)secs;
    return sleep(limited_secs);
}

static uint64_t ossl_sleep_millis(uint64_t millis)
{
    const OSSL_TIME finish
        = ossl_time_add(ossl_time_now(), ossl_ms2time(millis));

    while (ossl_time_compare(ossl_time_now(), finish) < 0)
        /* busy wait */ ;

    return 0;
}
#endif /* defined(OPENSSL_SYS_UNIX) || defined(__DJGPP__) */

static uint64_t ossl_sleep_ex(uint64_t millis, bool interruptible)
{
    OSSL_TIME now = ossl_time_now();
    OSSL_TIME finish = ossl_time_add(now, ossl_ms2time(millis));
    uint64_t left = millis;
    uint64_t ret;

#if defined(USE_SLEEP_SECS)
    do {
        ret = ossl_sleep_secs(left / 1000);
        now = ossl_time_now();
        left = ossl_time2ms(ossl_time_subtract(finish, now));
        if (interruptible && ret && ossl_time_compare(now, finish) < 0)
            return left;
    } while (ossl_time_compare(now, finish) < 0 && left > 1000);

    if (ossl_time_compare(now, finish) >= 0)
        return 0;
#endif

    do {
        ret = ossl_sleep_millis(left);
        now = ossl_time_now();
        left = ossl_time2ms(ossl_time_subtract(finish, now));
        if (interruptible && ret && ossl_time_compare(now, finish) < 0)
            return left;
    } while (ossl_time_compare(now, finish) < 0);

    return 0;
}

uint64_t OSSL_sleep_interruptible(uint64_t millis)
{
    return ossl_sleep_ex(millis, true);
}

void OSSL_sleep(uint64_t millis)
{
    ossl_sleep_ex(millis, false);
}
