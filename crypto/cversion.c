/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

#include "buildinf.h"

#if !OPENSSL_API_3
unsigned long OpenSSL_version_num(void)
{
    return OPENSSL_VERSION_NUMBER;
}
#endif

unsigned int OPENSSL_version_major(void)
{
    return OPENSSL_VERSION_MAJOR;
}

unsigned int OPENSSL_version_minor(void)
{
    return OPENSSL_VERSION_MINOR;
}

unsigned int OPENSSL_version_patch(void)
{
    return OPENSSL_VERSION_PATCH;
}

const char *OPENSSL_version_pre_release(void)
{
    return OPENSSL_VERSION_PRE_RELEASE_STR;
}

const char *OPENSSL_version_build_metadata(void)
{
    return OPENSSL_VERSION_BUILD_METADATA_STR;
}

const char *OpenSSL_version(int t)
{
    switch (t) {
    case OPENSSL_VERSION:
        return OPENSSL_VERSION_TEXT;
    case OPENSSL_VERSION_STRING:
        return OPENSSL_VERSION_STR;
    case OPENSSL_FULL_VERSION_STRING:
        return OPENSSL_FULL_VERSION_STR;
    case OPENSSL_BUILT_ON:
        return DATE;
    case OPENSSL_CFLAGS:
        return compiler_flags;
    case OPENSSL_PLATFORM:
        return PLATFORM;
    case OPENSSL_DIR:
#ifdef OPENSSLDIR
        return "OPENSSLDIR: \"" OPENSSLDIR "\"";
#else
        return "OPENSSLDIR: N/A";
#endif
    case OPENSSL_ENGINES_DIR:
#ifdef ENGINESDIR
        return "ENGINESDIR: \"" ENGINESDIR "\"";
#else
        return "ENGINESDIR: N/A";
#endif
    }
    return "not available";
}
