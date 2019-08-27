/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/crypto.h>
#include "internal/dso_conf.h"
#include "e_os.h"
#include "buildinf.h"
#include "internal/thread_once.h"

static char *seed_sources = NULL;
static CRYPTO_ONCE init_info = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(init_info_strings)
{
    {
        static char seeds[512] = "";

#define add_seeds_string(str)                                           \
        do {                                                            \
            if (seeds[0] != '\0')                                       \
                OPENSSL_strlcat(seeds, " ", sizeof(seeds));             \
            OPENSSL_strlcat(seeds, str, sizeof(seeds));                 \
        } while (0)
#define add_seeds_stringlist(label, strlist)                            \
        do {                                                            \
            add_seeds_string(label "(");                                \
            {                                                           \
                const char *dev[] = strlist;                            \
                int first = 1;                                          \
                                                                        \
                for (; *dev != NULL; dev++) {                           \
                    if (!first)                                         \
                        OPENSSL_strlcat(seeds, " ", sizeof(seeds));     \
                    first = 0;                                          \
                    OPENSSL_strlcat(seeds, *dev, sizeof(seeds));        \
                }                                                       \
            }                                                           \
            OPENSSL_strlcat(seeds, ")", sizeof(seeds));                 \
        } while (0)

#ifdef OPENSSL_RAND_SEED_NONE
        add_seeds_string("none");
#endif
#ifdef OPENSSL_RAND_SEED_RTDSC
        add_seeds_string("stdsc");
#endif
#ifdef OPENSSL_RAND_SEED_RDCPU
        add_seeds_string("rdrand ( rdseed rdrand )");
#endif
#ifdef OPENSSL_RAND_SEED_LIBRANDOM
        add_seeds_string("C-library-random");
#endif
#ifdef OPENSSL_RAND_SEED_GETRANDOM
        add_seeds_string("getrandom-syscall");
#endif
#ifdef OPENSSL_RAND_SEED_DEVRANDOM
        add_seeds_stringlist("random-device", { DEVRANDOM, NULL });
#endif
#ifdef OPENSSL_RAND_SEED_EGD
        add_seeds_stringlist("EGD", { DEVRANDOM_EGD, NULL });
#endif
#ifdef OPENSSL_RAND_SEED_OS
        add_seeds_string("os-specific");
#endif
        seed_sources = seeds;
    }
    return 1;
}

const char *OPENSSL_info(int t)
{
    /*
     * We don't care about the result.  Worst case scenario, the strings
     * won't be initialised, i.e. remain NULL, which means that the info
     * isn't available anyway...
     */
    (void)RUN_ONCE(&init_info, init_info_strings);

    switch (t) {
    case OPENSSL_INFO_CONFIG_DIR:
        return OPENSSLDIR;
    case OPENSSL_INFO_ENGINES_DIR:
        return ENGINESDIR;
    case OPENSSL_INFO_MODULES_DIR:
        return MODULESDIR;
    case OPENSSL_INFO_DSO_EXTENSION:
        return DSO_EXTENSION;
    case OPENSSL_INFO_DIR_FILENAME_SEPARATOR:
#if defined(_WIN32)
        return "\\";
#elif defined(__VMS)
        return "";
#else  /* Assume POSIX */
        return "/";
#endif
    case OPENSSL_INFO_LIST_SEPARATOR:
        {
            static const char list_sep[] = { LIST_SEPARATOR_CHAR, '\0' };
            return list_sep;
        }
    case OPENSSL_INFO_SEED_SOURCE:
        return seed_sources;
    default:
        break;
    }
    /* Not an error */
    return NULL;
}
