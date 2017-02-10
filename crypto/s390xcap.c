/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include "internal/cryptlib.h"
#include "s390x_arch.h"

static sigjmp_buf ill_jmp;
static void ill_handler(int sig)
{
    siglongjmp(ill_jmp, sig);
}

/*-
 * os-specific function to check if "vector enablement control"-bit and
 * "AFP register control"-bit in control register 0 are set.
 */
static int vx_enabled(void)
{
#if defined(OPENSSL_SYS_LINUX)
    FILE *fd;
    char buf[4096];

    if ((fd = fopen("/proc/cpuinfo", "r")) == NULL)
        return 0;

    buf[0] = '\0';

    while ((fgets(buf, sizeof(buf), fd) != NULL)
           && (strstr(buf, "features") != buf));

    fclose(fd);
    return (strstr(buf, " vx ") != NULL) ? 1 : 0;
#else
    return 0;
#endif
}

void OPENSSL_s390x_facilities(void);

void OPENSSL_cpuid_setup(void)
{
    sigset_t oset;
    struct sigaction ill_act, oact;
    uint64_t vec;
    char *env;
    int off;
    int i;

    if (OPENSSL_s390xcap_P[0])
        return;

    OPENSSL_s390xcap_P[0] = 1ULL << (8 * sizeof(uint64_t) - 1);

    memset(&ill_act, 0, sizeof(ill_act));
    ill_act.sa_handler = ill_handler;
    sigfillset(&ill_act.sa_mask);
    sigdelset(&ill_act.sa_mask, SIGILL);
    sigdelset(&ill_act.sa_mask, SIGTRAP);
    sigprocmask(SIG_SETMASK, &ill_act.sa_mask, &oset);
    sigaction(SIGILL, &ill_act, &oact);

    /* protection against missing store-facility-list-extended */
    if (sigsetjmp(ill_jmp, 1) == 0)
        OPENSSL_s390x_facilities();

    sigaction(SIGILL, &oact, NULL);
    sigprocmask(SIG_SETMASK, &oset, NULL);

    /* protection against disabled vector facility */
    if (!vx_enabled()) {
        OPENSSL_s390xcap_P[2] &= ~(S390X_STFLE_VXE | S390X_STFLE_VXD |
                                   S390X_STFLE_VX);
    }

    if ((env = getenv("OPENSSL_s390xcap")) != NULL) {
        for (i = 0; i < S390X_CAP_DWORDS; i++) {
            off = (env[0] == '~') ? 1 : 0;

            if (sscanf(env + off, "%llx", (unsigned long long *)&vec) == 1)
                OPENSSL_s390xcap_P[i] &= off ? ~vec : vec;

            if (i == S390X_STFLE_DWORDS - 1)
                env = strchr(env, '.');
            else
                env = strpbrk(env, ":.");

            if (env == NULL)
                break;

            if (env[0] == '.')
                i = S390X_STFLE_DWORDS - 1;

            env++;
        }
    }
}
