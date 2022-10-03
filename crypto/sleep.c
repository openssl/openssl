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
# include <unistd.h>

void OSSL_sleep(unsigned long millis)
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

void OSSL_sleep(unsigned long millis)
{
    Sleep(millis);
}
#else
/* Fallback to a busy wait */
# include "internal/time.h"

void OSSL_sleep(unsigned long millis)
{
    const OSSL_TIME finish
        = ossl_time_add(ossl_time_now(), ossl_ms2time(millis));

    while (ossl_time_compare(ossl_time_now(), finish) < 0)
        /* busy wait */ ;
}
#endif /* defined(OPENSSL_SYS_UNIX) || defined(__DJGPP__) */
