/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "rand_lcl.h"
#include <stdio.h>

#if !(defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_VMS) || defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_UEFI))

# if (defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_UEFI)) && \
        !defined(OPENSSL_RAND_SEED_NONE)
#  error "UEFI and VXWorks only support seeding NONE"
# endif

# if defined(OPENSSL_SYS_VOS)

#  ifndef OPENSSL_RAND_SEED_OS
#   error "Unsupported seeding method configured; must be os"
#  endif

#  if defined(OPENSSL_SYS_VOS_HPPA) && defined(OPENSSL_SYS_VOS_IA32)
#   error "Unsupported HP-PA and IA32 at the same time."
#  endif
#  if !defined(OPENSSL_SYS_VOS_HPPA) && !defined(OPENSSL_SYS_VOS_IA32)
#   error "Must have one of HP-PA or IA32"
#  endif

/*
 * The following algorithm repeatedly samples the real-time clock (RTC) to
 * generate a sequence of unpredictable data.  The algorithm relies upon the
 * uneven execution speed of the code (due to factors such as cache misses,
 * interrupts, bus activity, and scheduling) and upon the rather large
 * relative difference between the speed of the clock and the rate at which
 * it can be read.  If it is ported to an environment where execution speed
 * is more constant or where the RTC ticks at a much slower rate, or the
 * clock can be read with fewer instructions, it is likely that the results
 * would be far more predictable.  This should only be used for legacy
 * platforms.
 *
 * As a precaution, we generate four times the required amount of seed
 * data.
 */
int RAND_poll_ex(RAND_poll_cb rand_add, void *arg)
{
    short int code;
    gid_t curr_gid;
    pid_t curr_pid;
    uid_t curr_uid;
    int i, k;
    struct timespec ts;
    unsigned char v;
#  ifdef OPENSSL_SYS_VOS_HPPA
    long duration;
    extern void s$sleep(long *_duration, short int *_code);
#  else
    long long duration;
    extern void s$sleep2(long long *_duration, short int *_code);
#  endif

    /*
     * Seed with the gid, pid, and uid, to ensure *some* variation between
     * different processes.
     */
    curr_gid = getgid();
    rand_add(arg, &curr_gid, sizeof curr_gid, 0);
    curr_pid = getpid();
    rand_add(arg, &curr_pid, sizeof curr_pid, 0);
    curr_uid = getuid();
    rand_add(arg, &curr_uid, sizeof curr_uid, 0);

    for (i = 0; i < (RANDOMNESS_NEEDED * 4); i++) {
        /*
         * burn some cpu; hope for interrupts, cache collisions, bus
         * interference, etc.
         */
        for (k = 0; k < 99; k++)
            ts.tv_nsec = random();

#  ifdef OPENSSL_SYS_VOS_HPPA
        /* sleep for 1/1024 of a second (976 us).  */
        duration = 1;
        s$sleep(&duration, &code);
#  else
        /* sleep for 1/65536 of a second (15 us).  */
        duration = 1;
        s$sleep2(&duration, &code);
#  endif

        /* Get wall clock time, take 8 bits. */
        clock_gettime(CLOCK_REALTIME, &ts);
        v = (unsigned char)(ts.tv_nsec & 0xFF);
        rand_add(arg, &v, sizeof v, 1);
    }
    return 1;
}

# else

#  if defined(OPENSSL_RAND_SEED_EGD) && \
        (defined(OPENSSL_NO_EGD) || !defined(DEVRANDOM_EGD))
#   error "Seeding uses EGD but EGD is turned off or no device given"
#  endif

#  if defined(OPENSSL_RAND_SEED_DEVRANDOM) && !defined(DEVRANDOM)
#   error "Seeding uses urandom but DEVRANDOM is not configured"
#  endif

#  if defined(OPENSSL_RAND_SEED_OS)
#   if defined(DEVRANDOM)
#    define OPENSSL_RAND_SEED_DEVRANDOM
#   else
#    error "OS seeding requires DEVRANDOM to be configured"
#   endif
#  endif

#  if defined(OPENSSL_RAND_SEED_LIBRANDOM)
#   error "librandom not (yet) supported"
#  endif

/*
 * Try the various seeding methods in turn, exit when succesful.
 */
int RAND_poll_ex(RAND_poll_cb rand_add, void *arg)
{
#  ifdef OPENSSL_RAND_SEED_NONE
    return 0;
#  else
    int ok = 1;
    char temp[RANDOMNESS_NEEDED];
#   define TEMPSIZE (int)sizeof(temp)

#   ifdef OPENSSL_RAND_SEED_GETRANDOM
    {
        int i = getrandom(temp, TEMPSIZE, 0);

        if (i >= 0) {
            rand_add(arg, temp, i, i);
            if (i == TEMPSIZE)
                goto done;
        }
    }
#   endif

#   if defined(OPENSSL_RAND_SEED_LIBRANDOM)
    {
        /* Not yet implemented. */
    }
#   endif

#   ifdef OPENSSL_RAND_SEED_DEVRANDOM
    {
        static const char *paths[] = { DEVRANDOM, NULL };
        FILE *fp;
        int i;

        for (i = 0; paths[i] != NULL; i++) {
            if ((fp = fopen(paths[i], "rb")) == NULL)
                continue;
            setbuf(fp, NULL);
            if (fread(temp, 1, TEMPSIZE, fp) == TEMPSIZE) {
                rand_add(arg, temp, TEMPSIZE, TEMPSIZE);
                fclose(fp);
                goto done;
            }
            fclose(fp);
        }
    }
#   endif

#   ifdef OPENSSL_RAND_SEED_RDTSC
    rand_read_tsc(rand_add, arg);
#   endif

#   ifdef OPENSSL_RAND_SEED_RDCPU
    if (rand_read_cpu(rand_add, arg))
        goto done;
#   endif

#   ifdef OPENSSL_RAND_SEED_EGD
    {
        static const char *paths[] = { DEVRANDOM_EGD, NULL };
        int i;

        for (i = 0; paths[i] != NULL; i++) {
            if (RAND_query_egd_bytes(paths[i], temp, TEMPSIZE) == TEMPSIZE) {
                rand_add(arg, temp, TEMPSIZE, TEMPSIZE);
                goto done;
            }
        }
    }
#   endif

    ok = 0;

done:
    OPENSSL_cleanse(temp, TEMPSIZE);
    return ok;
#  endif
}
# endif

#endif
