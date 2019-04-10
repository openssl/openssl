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

const char *OPENSSL_info(int t)
{
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
    default:
        break;
    }
    /* Not an error */
    return NULL;
}
