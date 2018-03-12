/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
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

#if (defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_UEFI)) && \
        !defined(OPENSSL_RAND_SEED_NONE)
# error "UEFI and VXWorks only support seeding NONE"
#endif

#if !(defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32) \
    || defined(OPENSSL_SYS_VMS) || defined(OPENSSL_SYS_VXWORKS) \
    || defined(OPENSSL_SYS_UEFI))

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
 * As a precaution, we assume only 2 bits of entropy per byte.
 */
size_t RAND_POOL_acquire_entropy(RAND_POOL *pool)
{
    short int code;
    gid_t curr_gid;
    pid_t curr_pid;
    uid_t curr_uid;
    int i, k;
    size_t bytes_needed;
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
    RAND_POOL_add(pool, &curr_gid, sizeof(curr_gid), 0);
    curr_pid = getpid();
    RAND_POOL_add(pool, &curr_pid, sizeof(curr_pid), 0);
    curr_uid = getuid();
    RAND_POOL_add(pool, &curr_uid, sizeof(curr_uid), 0);

    bytes_needed = RAND_POOL_bytes_needed(pool, 2 /*entropy_per_byte*/);

    for (i = 0; i < bytes_needed; i++) {
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
        RAND_POOL_add(pool, arg, &v, sizeof(v) , 2);
    }
    return RAND_POOL_entropy_available(pool);
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
#   if !defined(DEVRANDOM)
#    error "OS seeding requires DEVRANDOM to be configured"
#   endif
#   define OPENSSL_RAND_SEED_DEVRANDOM
#   if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#    if __GLIBC_PREREQ(2, 25)
#     define OPENSSL_RAND_SEED_GETRANDOM
#    endif
#   endif
#  endif

#  ifdef OPENSSL_RAND_SEED_GETRANDOM
#   include <sys/random.h>
#  endif

#  if defined(OPENSSL_RAND_SEED_LIBRANDOM)
#   error "librandom not (yet) supported"
#  endif

/*
 * Try the various seeding methods in turn, exit when successful.
 *
 * TODO(DRBG): If more than one entropy source is available, is it
 * preferable to stop as soon as enough entropy has been collected
 * (as favored by @rsalz) or should one rather be defensive and add
 * more entropy than requested and/or from different sources?
 *
 * Currently, the user can select multiple entropy sources in the
 * configure step, yet in practice only the first available source
 * will be used. A more flexible solution has been requested, but
 * currently it is not clear how this can be achieved without
 * overengineering the problem. There are many parameters which
 * could be taken into account when selecting the order and amount
 * of input from the different entropy sources (trust, quality,
 * possibility of blocking).
 */
size_t RAND_POOL_acquire_entropy(RAND_POOL *pool)
{
#  ifdef OPENSSL_RAND_SEED_NONE
    return RAND_POOL_entropy_available(pool);
#  else
    size_t bytes_needed;
    size_t entropy_available = 0;
    unsigned char *buffer;

#   ifdef OPENSSL_RAND_SEED_GETRANDOM
    bytes_needed = RAND_POOL_bytes_needed(pool, 8 /*entropy_per_byte*/);
    buffer = RAND_POOL_add_begin(pool, bytes_needed);
    if (buffer != NULL) {
        size_t bytes = 0;

        if (getrandom(buffer, bytes_needed, 0) == (int)bytes_needed)
            bytes = bytes_needed;

        entropy_available = RAND_POOL_add_end(pool, bytes, 8 * bytes);
    }
    if (entropy_available > 0)
        return entropy_available;
#   endif

#   if defined(OPENSSL_RAND_SEED_LIBRANDOM)
    {
        /* Not yet implemented. */
    }
#   endif

#   ifdef OPENSSL_RAND_SEED_DEVRANDOM
    bytes_needed = RAND_POOL_bytes_needed(pool, 8 /*entropy_per_byte*/);
    if (bytes_needed > 0) {
        static const char *paths[] = { DEVRANDOM, NULL };
        FILE *fp;
        int i;

        for (i = 0; paths[i] != NULL; i++) {
            if ((fp = fopen(paths[i], "rb")) == NULL)
                continue;
            setbuf(fp, NULL);
            buffer = RAND_POOL_add_begin(pool, bytes_needed);
            if (buffer != NULL) {
                size_t bytes = 0;
                if (fread(buffer, 1, bytes_needed, fp) == bytes_needed)
                    bytes = bytes_needed;

                entropy_available = RAND_POOL_add_end(pool, bytes, 8 * bytes);
            }
            fclose(fp);
            if (entropy_available > 0)
                return entropy_available;

            bytes_needed = RAND_POOL_bytes_needed(pool, 8 /*entropy_per_byte*/);
        }
    }
#   endif

#   ifdef OPENSSL_RAND_SEED_RDTSC
    entropy_available = rand_acquire_entropy_from_tsc(pool);
    if (entropy_available > 0)
        return entropy_available;
#   endif

#   ifdef OPENSSL_RAND_SEED_RDCPU
    entropy_available = rand_acquire_entropy_from_cpu(pool);
    if (entropy_available > 0)
        return entropy_available;
#   endif

#   ifdef OPENSSL_RAND_SEED_EGD
    bytes_needed = RAND_POOL_bytes_needed(pool, 8 /*entropy_per_byte*/);
    if (bytes_needed > 0) {
        static const char *paths[] = { DEVRANDOM_EGD, NULL };
        int i;

        for (i = 0; paths[i] != NULL; i++) {
            buffer = RAND_POOL_add_begin(pool, bytes_needed);
            if (buffer != NULL) {
                size_t bytes = 0;
                int num = RAND_query_egd_bytes(paths[i],
                                               buffer, (int)bytes_needed);
                if (num == (int)bytes_needed)
                    bytes = bytes_needed;

                entropy_available = RAND_POOL_add_end(pool, bytes, 8 * bytes);
            }
            if (entropy_available > 0)
                return entropy_available;
        }
    }
#   endif

    return RAND_POOL_entropy_available(pool);
#  endif
}
# endif

#endif
