/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "internal/cryptlib.h"

#include "buildinf.h"

unsigned long Opentls_version_num(void)
{
    return OPENtls_VERSION_NUMBER;
}

unsigned int OPENtls_version_major(void)
{
    return OPENtls_VERSION_MAJOR;
}

unsigned int OPENtls_version_minor(void)
{
    return OPENtls_VERSION_MINOR;
}

unsigned int OPENtls_version_patch(void)
{
    return OPENtls_VERSION_PATCH;
}

const char *OPENtls_version_pre_release(void)
{
    return OPENtls_VERSION_PRE_RELEASE;
}

const char *OPENtls_version_build_metadata(void)
{
    return OPENtls_VERSION_BUILD_METADATA;
}

extern char otls_cpu_info_str[];

const char *Opentls_version(int t)
{
    switch (t) {
    case OPENtls_VERSION:
        return OPENtls_VERSION_TEXT;
    case OPENtls_VERSION_STRING:
        return OPENtls_VERSION_STR;
    case OPENtls_FULL_VERSION_STRING:
        return OPENtls_FULL_VERSION_STR;
    case OPENtls_BUILT_ON:
        return DATE;
    case OPENtls_CFLAGS:
        return compiler_flags;
    case OPENtls_PLATFORM:
        return PLATFORM;
    case OPENtls_DIR:
#ifdef OPENtlsDIR
        return "OPENtlsDIR: \"" OPENtlsDIR "\"";
#else
        return "OPENtlsDIR: N/A";
#endif
    case OPENtls_ENGINES_DIR:
#ifdef ENGINESDIR
        return "ENGINESDIR: \"" ENGINESDIR "\"";
#else
        return "ENGINESDIR: N/A";
#endif
    case OPENtls_MODULES_DIR:
#ifdef MODULESDIR
        return "MODULESDIR: \"" MODULESDIR "\"";
#else
        return "MODULESDIR: N/A";
#endif
    case OPENtls_CPU_INFO:
        if (OPENtls_info(OPENtls_INFO_CPU_SETTINGS) != NULL)
            return otls_cpu_info_str;
        else
            return "CPUINFO: N/A";
    }
    return "not available";
}
