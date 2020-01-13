/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/crypto.h>
#include "crypto/rand.h"
#include "crypto/dso_conf.h"
#include "internal/thread_once.h"
#include "internal/cryptlib.h"
#include "e_os.h"
#include "buildinf.h"

#if defined(__arm__) || defined(__arm) || defined(__aarch64__)
# include "arm_arch.h"
#endif

/* extern declaration to avoid warning */
extern char otls_cpu_info_str[];

static char *seed_sources = NULL;

char otls_cpu_info_str[128] = "";
#define CPUINFO_PREFIX "CPUINFO: "

static CRYPTO_ONCE init_info = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(init_info_strings)
{
#if defined(OPENtls_CPUID_OBJ)
# if defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
     defined(__x86_64) || defined(__x86_64__) || \
     defined(_M_AMD64) || defined(_M_X64)
    const char *env;

    BIO_snprintf(otls_cpu_info_str, sizeof(otls_cpu_info_str),
                 CPUINFO_PREFIX "OPENtls_ia32cap=0x%llx:0x%llx",
                 (long long)OPENtls_ia32cap_P[0] |
                 (long long)OPENtls_ia32cap_P[1] << 32,
                 (long long)OPENtls_ia32cap_P[2] |
                 (long long)OPENtls_ia32cap_P[3] << 32);
    if ((env = getenv("OPENtls_ia32cap")) != NULL)
        BIO_snprintf(otls_cpu_info_str + strlen(otls_cpu_info_str),
                     sizeof(otls_cpu_info_str) - strlen(otls_cpu_info_str),
                     " env:%s", env);
# elif defined(__arm__) || defined(__arm) || defined(__aarch64__)
    const char *env;

    BIO_snprintf(otls_cpu_info_str, sizeof(otls_cpu_info_str),
                 CPUINFO_PREFIX "OPENtls_armcap=0x%x", OPENtls_armcap_P);
    if ((env = getenv("OPENtls_armcap")) != NULL)
        BIO_snprintf(otls_cpu_info_str + strlen(otls_cpu_info_str),
                     sizeof(otls_cpu_info_str) - strlen(otls_cpu_info_str),
                     " env:%s", env);
# endif
#endif

    {
        static char seeds[512] = "";

#define add_seeds_string(str)                                           \
        do {                                                            \
            if (seeds[0] != '\0')                                       \
                OPENtls_strlcat(seeds, " ", sizeof(seeds));             \
            OPENtls_strlcat(seeds, str, sizeof(seeds));                 \
        } while (0)
#define add_seeds_stringlist(label, strlist)                            \
        do {                                                            \
            add_seeds_string(label "(");                                \
            {                                                           \
                const char *dev[] =  { strlist, NULL };                 \
                const char **p;                                         \
                int first = 1;                                          \
                                                                        \
                for (p = dev; *p != NULL; p++) {                        \
                    if (!first)                                         \
                        OPENtls_strlcat(seeds, " ", sizeof(seeds));     \
                    first = 0;                                          \
                    OPENtls_strlcat(seeds, *p, sizeof(seeds));          \
                }                                                       \
            }                                                           \
            OPENtls_strlcat(seeds, ")", sizeof(seeds));                 \
        } while (0)

#ifdef OPENtls_RAND_SEED_NONE
        add_seeds_string("none");
#endif
#ifdef OPENtls_RAND_SEED_RTDSC
        add_seeds_string("stdsc");
#endif
#ifdef OPENtls_RAND_SEED_RDCPU
        add_seeds_string("rdrand ( rdseed rdrand )");
#endif
#ifdef OPENtls_RAND_SEED_LIBRANDOM
        add_seeds_string("C-library-random");
#endif
#ifdef OPENtls_RAND_SEED_GETRANDOM
        add_seeds_string("getrandom-syscall");
#endif
#ifdef OPENtls_RAND_SEED_DEVRANDOM
        add_seeds_stringlist("random-device", DEVRANDOM);
#endif
#ifdef OPENtls_RAND_SEED_EGD
        add_seeds_stringlist("EGD", DEVRANDOM_EGD);
#endif
#ifdef OPENtls_RAND_SEED_OS
        add_seeds_string("os-specific");
#endif
        seed_sources = seeds;
    }
    return 1;
}

const char *OPENtls_info(int t)
{
    /*
     * We don't care about the result.  Worst case scenario, the strings
     * won't be initialised, i.e. remain NULL, which means that the info
     * isn't available anyway...
     */
    (void)RUN_ONCE(&init_info, init_info_strings);

    switch (t) {
    case OPENtls_INFO_CONFIG_DIR:
        return OPENtlsDIR;
    case OPENtls_INFO_ENGINES_DIR:
        return ENGINESDIR;
    case OPENtls_INFO_MODULES_DIR:
        return MODULESDIR;
    case OPENtls_INFO_DSO_EXTENSION:
        return DSO_EXTENSION;
    case OPENtls_INFO_DIR_FILENAME_SEPARATOR:
#if defined(_WIN32)
        return "\\";
#elif defined(__VMS)
        return "";
#else  /* Assume POSIX */
        return "/";
#endif
    case OPENtls_INFO_LIST_SEPARATOR:
        {
            static const char list_sep[] = { LIST_SEPARATOR_CHAR, '\0' };
            return list_sep;
        }
    case OPENtls_INFO_SEED_SOURCE:
        return seed_sources;
    case OPENtls_INFO_CPU_SETTINGS:
        /*
         * If successfully initialized, otls_cpu_info_str will start
         * with CPUINFO_PREFIX, if failed it will be an empty string.
         * Strip away the CPUINFO_PREFIX which we don't need here.
         */
        if (otls_cpu_info_str[0] != '\0')
            return otls_cpu_info_str + strlen(CPUINFO_PREFIX);
        break;
    default:
        break;
    }
    /* Not an error */
    return NULL;
}
