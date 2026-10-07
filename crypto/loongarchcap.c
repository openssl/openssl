/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include "internal/cryptlib.h"
#include "arch/loongarch_arch.h"

unsigned int OPENSSL_loongarch_hwcap_P = 0;

#if defined(__GNUC__)
__attribute__((constructor))
#endif
void OPENSSL_cpuid_setup(void)
{
    const char *env;
    static int trigger = 0;

    if (trigger)
        return;
    trigger = 1;

    OPENSSL_loongarch_hwcap_P = getauxval(AT_HWCAP);
    if ((env = getenv("OPENSSL_loongarch_hwcap")) != NULL) {
        int clear = *env == '~';
        const char *value = env + clear;
        char *end;
        unsigned long mask;

        /* Ignore malformed or out-of-range overrides. */
        if (*value < '0' || *value > '9')
            return;
        errno = 0;
        mask = strtoul(value, &end, 0);
        if (errno != 0 || *end != '\0' || mask > UINT_MAX)
            return;

        if (clear)
            OPENSSL_loongarch_hwcap_P &= ~(unsigned int)mask;
        else
            OPENSSL_loongarch_hwcap_P = (unsigned int)mask;
    }
}
