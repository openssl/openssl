/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "internal/e_os.h"

/* system-specific variants defining OSSL_sleep() */
#if defined(OPENSSL_SYS_UNIX) || defined(__DJGPP__)

void OSSL_sleep(uint64_t millis)
{
# ifdef OPENSSL_SYS_VXWORKS
    struct timespec ts;

    ts.tv_sec = (long int) (millis / 1000);
    ts.tv_nsec = (long int) (millis % 1000) * 1000000ul;
    nanosleep(&ts, NULL);
# elif defined(__TANDEM)
#  if !defined(_REENTRANT)
#   include <cextdecs.h(PROCESS_DELAY_)>

    /* HPNS does not support usleep for non threaded apps */
    PROCESS_DELAY_(millis * 1000);
#  elif defined(_SPT_MODEL_)
#   include <spthread.h>
#   include <spt_extensions.h>

    usleep(millis * 1000);
#  else
    usleep(millis * 1000);
#  endif
# else
    usleep(millis * 1000);
# endif
}
#elif defined(_WIN32)
# include <windows.h>

void OSSL_sleep(uint64_t millis)
{
    /*
     * Windows' Sleep() takes a DWORD argument, which is smaller than
     * a uint64_t, so we need to split the two to shut the compiler up.
     */
    DWORD dword_times = (DWORD)(millis >> sizeof(DWORD));
    DWORD i;

    for(i = dword_times; i-- > 0;)
        Sleep((DWORD)-1);
    /*
     * The loop above slept 1 millisec less on each iteration than it should,
     * this compensates by sleeping as many milliseconds as there were
     * iterations.  Yes, this is nit picky!
     */
    Sleep(dword_times);

    /* Now, sleep the remaining milliseconds */
    Sleep((DWORD)(millis & (DWORD)-1));
}
#else
/* Fallback to a busy wait */
# include "internal/time.h"

/*
 * This function takes unsigned int because sleep() does.  It's up to the
 * caller not to try to pass something larger.
 */
static void ossl_sleep_secs(unsigned int secs)
{
    sleep(secs);
}

static void ossl_sleep_millis(uint64_t millis)
{
    const OSSL_TIME finish
        = ossl_time_add(ossl_time_now(), ossl_ms2time(millis));

    while (ossl_time_compare(ossl_time_now(), finish) < 0)
        /* busy wait */ ;
}

void OSSL_sleep(uint64_t millis)
{
    uint64_t secs;

    ossl_sleep_secs((unsigned int)(millis / 1000));
    ossl_sleep_millis(millis % 1000);
}
#endif /* defined(OPENSSL_SYS_UNIX) || defined(__DJGPP__) */
